use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use log::{debug, trace};
use smol::lock::RwLock;
use std::collections::BTreeMap;

pub type TunnelId = u64;

use crate::brokerimpl::{
    BrokerImpl, NodeRequestContext, Peer
};
use crate::shvnode::{self, SIG_LSMOD};
use crate::shvnode::{
    is_request_granted_methods, ProcessRequestRetval, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR,
    METH_LS,
};
use futures::FutureExt;
use futures::{select, AsyncReadExt, AsyncWriteExt};
use log::{error, log, Level};
use shvproto::{Map, MetaMap};
use shvrpc::metamethod::{AccessLevel, Flags, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, RqId};
use shvrpc::{Error, RpcMessage, RpcMessageMetaTags};
use smol::io::{BufReader, BufWriter};
use smol::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const META_METHOD_PRIVATE_DIR: MetaMethod = MetaMethod::new_static(METH_DIR, Flags::empty(), AccessLevel::SuperService, "DirParam", "DirResult", &[], "");
const META_METHOD_PRIVATE_LS: MetaMethod = MetaMethod::new_static(METH_LS, Flags::empty(), AccessLevel::SuperService, "LsParam", "LsResult", &[], "");

const METH_CREATE: &str = "create";
const METH_WRITE: &str = "write";
const METH_CLOSE: &str = "close";
const META_METH_CREATE: MetaMethod = MetaMethod::new_static(METH_CREATE, Flags::empty(), AccessLevel::Write, "{s:host}", "s", &[], "");
const META_METH_WRITE: MetaMethod = MetaMethod::new_static(METH_WRITE, Flags::empty(), AccessLevel::Write, "x", "x", &[], "");
const META_METH_CLOSE: MetaMethod = MetaMethod::new_static(METH_CLOSE, Flags::empty(), AccessLevel::Write, "", "b", &[], "");

const TUNNEL_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PRIVATE_LS,
    &META_METH_CREATE,
];
const OPEN_TUNNEL_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PRIVATE_DIR,
    &META_METHOD_PRIVATE_LS,
    &META_METH_WRITE,
    &META_METH_CLOSE,
];

pub(crate) struct TunnelNode {
    active_tunnels: Arc<RwLock<BTreeMap<TunnelId, ActiveTunnel>>>,
    next_tunnel_number: RwLock<TunnelId>,
}
impl TunnelNode {
    pub fn new() -> Self {
        TunnelNode {
            active_tunnels: Arc::new(RwLock::default()),
            next_tunnel_number: RwLock::new(1),
        }
    }
}

#[async_trait::async_trait]
impl ShvNode for TunnelNode {
    fn methods(&self, shv_path: &str) -> &'static [&'static MetaMethod] {
        if shv_path.is_empty() {
            TUNNEL_NODE_METHODS
        } else {
            OPEN_TUNNEL_NODE_METHODS
        }
    }
    async fn children(&self, shv_path: &str, _broker_state: &BrokerImpl) -> Option<Vec<String>> {
        let tunnels = active_tunnel_ids(&self.active_tunnels)
            .await
            .iter()
            .map(|id| format!("{}", *id))
            .collect();
        if shv_path.is_empty() {
            Some(tunnels)
        } else if tunnels.iter().any(|s| s == shv_path) {
            Some(vec![])
        } else {
            None
        }
    }

    async fn is_request_granted(&self, rq: &RpcFrame, _ctx: &NodeRequestContext) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            let methods = self.methods(shv_path);
            is_request_granted_methods(methods, rq)
        } else {
            is_request_granted_tunnel(&self.active_tunnels, shv_path, rq).await
        }
    }

    async fn process_request(
        &self,
        frame: &RpcFrame,
        ctx: &NodeRequestContext,
    ) -> shvnode::ProcessRequestResult {
        let method = frame.method().unwrap_or_default();
        let tunid = frame
            .shv_path()
            .unwrap_or_default()
            .parse::<TunnelId>()
            .ok();
        if let Some(tunid) = tunid {
            match method {
                METH_WRITE => {
                    let rq = frame.to_rpcmesage()?;
                    let data = rq.param().unwrap_or_default().as_blob().to_vec();
                    write_tunnel(
                        &self.active_tunnels,
                        tunid,
                        rq.request_id().unwrap_or_default(),
                        data,
                    ).await?;
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                METH_CLOSE => {
                    let is_active = last_tunnel_activity(&self.active_tunnels, tunid).await.is_some();
                    tunnel_close_handler(self.active_tunnels.clone(), ctx.state.peers.clone(), tunid);
                    Ok(ProcessRequestRetval::Retval(is_active.into()))
                }
                _ => Ok(ProcessRequestRetval::MethodNotFound),
            }
        } else {
            match method {
                METH_CREATE => {
                    let rq = frame.to_rpcmesage()?;
                    let param = rq.param().unwrap_or_default().as_map();
                    let host = param
                        .get("host")
                        .ok_or("'host' parameter must be provided")?
                        .as_str()
                        .to_string();
                    let (tunid, receiver) = create_tunnel(&self.next_tunnel_number, &self.active_tunnels, &rq).await?;
                    let rq_meta = rq.meta().clone();
                    let peers = ctx.state.peers.clone();
                    let active_tunnels = self.active_tunnels.clone();
                    smol::spawn(async move {
                        if let Err(e) = tunnel_task(tunid, rq_meta, host, receiver, peers.clone(), active_tunnels.clone()).await {
                            error!("{e}")
                        }
                        tunnel_close_handler(active_tunnels, peers, tunid);
                    }).detach();
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                _ => Ok(ProcessRequestRetval::MethodNotFound),
            }
        }
    }
}
#[derive(Debug)]
pub(crate) enum ToRemoteMsg {
    WriteData(RqId, Vec<u8>),
    DestroyConnection,
}
pub(crate) struct ActiveTunnel {
    pub(crate) caller_ids: Vec<PeerId>,
    pub(crate) sender: UnboundedSender<ToRemoteMsg>,
    pub(crate) last_activity: Option<Instant>,
}

pub(crate) async fn touch_tunnel(active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>, tunid: TunnelId) {
    if let Some(tun) = active_tunnels.write().await.get_mut(&tunid) {
        tun.last_activity = Some(Instant::now());
    }
}

pub(crate) async fn last_tunnel_activity(active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>, tunid: TunnelId) -> Option<Instant> {
    if let Some(tun) = active_tunnels.read().await.get(&tunid) {
        tun.last_activity
    } else {
        None
    }
}

pub(crate) async fn active_tunnel_ids(active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>) -> Vec<TunnelId> {
    active_tunnels
        .read()
        .await
        .iter()
        .filter(|(_id, tun)| tun.last_activity.is_some())
        .map(|(id, _tun)| *id)
        .collect()
}

pub(crate) async fn is_request_granted_tunnel(active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>, tunid: &str, frame: &RpcFrame) -> bool {
    let Ok(tunid) = tunid.parse::<TunnelId>() else {
        return false;
    };
    if let Some(tun) = active_tunnels.read().await.get(&tunid) {
        let cids = frame.caller_ids();
        cids == tun.caller_ids
            || AccessLevel::try_from(frame.access_level().unwrap_or(0))
                .unwrap_or(AccessLevel::Browse)
                == AccessLevel::Superuser
    } else {
        false
    }
}

pub(crate) async fn write_tunnel(
    active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>,
    tunid: TunnelId,
    rqid: RqId,
    data: Vec<u8>,
) -> shvrpc::Result<()> {
    if let Some(tun) = active_tunnels.write().await.get(&tunid) {
        let _ = tun.sender.unbounded_send(ToRemoteMsg::WriteData(rqid, data));
        Ok(())
    } else {
        Err(format!("Invalid tunnel ID: {tunid}").into())
    }
}

pub(crate) async fn close_tunnel(
    active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>,
    tunid: TunnelId,
) -> shvrpc::Result<Option<bool>> {
    debug!(target: "Tunnel", "close_tunnel: {tunid}");
    if let Some(tun) = active_tunnels.write().await.remove(&tunid) {
        let sender = tun.sender;
        smol::spawn(async move {
            let _ = sender.unbounded_send(ToRemoteMsg::DestroyConnection);
        })
        .detach();
        Ok(Some(tun.last_activity.is_some()))
    } else {
        Ok(None)
    }
}

pub(crate) async fn create_tunnel(
    next_tunnel_number: &RwLock<TunnelId>,
    active_tunnels: &RwLock<BTreeMap<TunnelId, ActiveTunnel>>,
    request: &shvrpc::RpcMessage,
) -> shvrpc::Result<(TunnelId, UnboundedReceiver<ToRemoteMsg>)> {
    let mut tunid_lock = next_tunnel_number.write().await;
    let tunid = *tunid_lock;
    *tunid_lock += 1;
    debug!(target: "Tunnel", "create_tunnel: {tunid}");
    let caller_ids = request.caller_ids();
    let (sender, receiver) = unbounded::<ToRemoteMsg>();
    let tun = ActiveTunnel {
        caller_ids,
        sender,
        last_activity: None,
    };
    active_tunnels.write().await.insert(tunid, tun);
    Ok((tunid, receiver))
}

pub(crate) fn tunnel_close_handler(
    active_tunnels: Arc<RwLock<BTreeMap<TunnelId, ActiveTunnel>>>,
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    tunid: TunnelId,
) {
    smol::spawn(async move {
        let closed = close_tunnel(&active_tunnels, tunid).await;
        if let Ok(Some(true)) = closed {
            let msg = RpcMessage::new_signal_with_source(format!(".app/tunnel/{tunid}"), SIG_LSMOD, METH_LS)
                .with_param(Map::from([(format!("{tunid}"), false.into())]));
            match msg.to_frame() {
                Ok(frame) => {
                    if let Err(e) = crate::brokerimpl::BrokerImpl::emit_rpc_signal_frame(&peers, 0, &frame).await {
                        log::error!("Failed to emit tunnel closed signal: {}", e);
                    }
                }
                Err(e) => log::error!("Failed to create tunnel closed signal frame: {}", e),
            }
        }
    }).detach();
}

pub(crate) async fn tunnel_task(
    tunnel_id: TunnelId,
    mut request_meta: MetaMap,
    addr: String,
    mut from_broker_receiver: UnboundedReceiver<ToRemoteMsg>,
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    active_tunnels: Arc<RwLock<BTreeMap<TunnelId, ActiveTunnel>>>,
) -> shvrpc::Result<()> {
    let peer_id = request_meta.pop_caller_id().ok_or("Invalid peer id")?;
    let mut response_meta = RpcFrame::prepare_response_meta(&request_meta)?;
    log!(target: "Tunnel", Level::Debug, "Tunnel: {tunnel_id}, connecting to: {addr} ...");
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            log!(target: "Tunnel", Level::Debug, "connected OK");
            BrokerImpl::send_response(&peers, peer_id, response_meta.clone(), Ok(format!("{tunnel_id}").into())).await?;
            stream
        }
        Err(e) => {
            BrokerImpl::send_response(&peers, peer_id, response_meta.clone(), Err(RpcError::new(RpcErrorCode::MethodCallException, e.to_string()))).await?;
            return Err(e.to_string().into());
        }
    };
    touch_tunnel(&active_tunnels, tunnel_id).await;
    let msg = RpcMessage::new_signal_with_source(format!(".app/tunnel/{tunnel_id}"), SIG_LSMOD, METH_LS)
        .with_param(Map::from([(format!("{tunnel_id}"), true.into())]));
    BrokerImpl::emit_rpc_signal_frame(&peers, 0, &msg.to_frame()?).await?;
    {
        let active_tunnels = active_tunnels.clone();
        let peers = peers.clone();
        smol::spawn(async move {
            const TIMEOUT: Duration = Duration::from_secs(60 * 60);
            loop {
                smol::Timer::after(TIMEOUT / 60).await;
                let last_activity = crate::tunnelnode::last_tunnel_activity(&active_tunnels, tunnel_id).await;
                if let Some(last_activity) = last_activity {
                    if Instant::now().duration_since(last_activity) > TIMEOUT {
                        debug!(target: "Tunnel", "Closing tunnel: {tunnel_id} as inactive for {TIMEOUT:#?}");
                        tunnel_close_handler(active_tunnels.clone(), peers.clone(), tunnel_id);
                        break;
                    }
                } else {
                    // tunnel closed already
                    break;
                }
            }
        }).detach();
    }
    let (socket_reader, socket_writer) = stream.split();
    let mut read_buff: [u8; 256] = [0; 256];
    let mut response_buff: Vec<u8> = vec![];
    let mut write_request_id = None;
    let mut read_seqno = 0;
    let mut socket_reader = BufReader::new(socket_reader);
    let (write_task_sender, mut write_task_receiver) = unbounded::<Vec<u8>>();
    smol::spawn(async move {
        log!(target: "Tunnel", Level::Debug, "ENTER write task");
        let mut socket_writer = BufWriter::new(socket_writer);
        loop {
            match write_task_receiver.recv().await {
                Ok(data) => {
                    trace!(target: "Tunnel", "write_task_receiver read {} bytes to write.", data.len());
                    if data.is_empty() {
                        break;
                    } else {
                        trace!(target: "Tunnel", "Write {} bytes to client socket.", data.len());
                        socket_writer.write_all(&data).await?;
                        socket_writer.flush().await?;
                        // println!("DATA written: {:?}", data);
                    }
                }
                Err(e) => {
                    error!("write broker channel error: {e}");
                    break;
                }
            }
        }
        log!(target: "Tunnel", Level::Debug, "EXIT write task");
        Ok::<(), Error>(())
    }).detach();

    loop {
        select! {
            bytes_read = socket_reader.read(&mut read_buff).fuse() => match bytes_read {
                Ok(bytes_read) => {
                    trace!(target: "Tunnel", "Read {bytes_read} bytes from client socket.");
                    touch_tunnel(&active_tunnels, tunnel_id).await;
                    if bytes_read == 0 {
                        trace!(target: "Tunnel", "Client socket closed.");
                        break;
                    } else {
                        let mut data = read_buff[.. bytes_read].to_vec();
                        response_buff.append(&mut data);
                        let mut response_meta = response_meta.clone();
                        response_meta.set_seqno(read_seqno);
                        read_seqno += 1;
                        BrokerImpl::send_response(&peers, peer_id, response_meta, Ok(std::mem::take(&mut response_buff).into())).await?;
                    }
                },
                Err(e) => {
                    error!("tunnel socket error: {e}");
                    break;
                }
            },
            cmd = from_broker_receiver.recv().fuse() => match cmd {
                Ok(cmd) => {
                    match cmd {
                        ToRemoteMsg::WriteData(rqid, data) => {
                            trace!(target: "Tunnel", "CMD WriteData, data size: {}", data.len());
                            touch_tunnel(&active_tunnels, tunnel_id).await;
                            if write_request_id.is_none() {
                                write_request_id = Some(rqid);
                                response_meta.set_request_id(rqid);
                                if !response_buff.is_empty() {
                                    trace!(target: "Tunnel", "to_broker_sender send: {} bytes to {peer_id}", response_buff.len());
                                    BrokerImpl::send_response(&peers, peer_id, response_meta.clone(), Ok(std::mem::take(&mut response_buff).into())).await?;
                                }
                            }
                            if !data.is_empty() {
                                trace!(target: "Tunnel", "write_task_sender send: {} bytes", data.len());
                                write_task_sender.unbounded_send(data)?;
                            }
                        }
                        ToRemoteMsg::DestroyConnection => {
                            trace!(target: "Tunnel", "CMD DestroyConnection");
                            if write_request_id.is_some() {
                                BrokerImpl::send_response(&peers, peer_id, response_meta.clone(), Err(RpcError::new(RpcErrorCode::MethodCallCancelled, format!("Tunnel: {tunnel_id} closed.")))).await?;
                            }
                            break
                        }
                    }
                }
                Err(e) => {
                    error!("read broker command error: {e}");
                    break
                },
            }
        }
    }
    // cancel write task
    write_task_sender.unbounded_send(vec![])?;
    tunnel_close_handler(active_tunnels.clone(), peers.clone(), tunnel_id);
    Ok(())
}
