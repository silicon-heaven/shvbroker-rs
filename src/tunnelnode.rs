use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use log::trace;
use smol::lock::RwLock;
use std::collections::BTreeMap;

use crate::brokerimpl::{
    BrokerCommand, BrokerImpl, NodeRequestContext, Peer, TunnelId
};
use crate::shvnode;
use crate::shvnode::{
    is_request_granted_methods, ProcessRequestRetval, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR,
    METH_LS,
};
use futures::FutureExt;
use futures::{select, AsyncReadExt, AsyncWriteExt};
use log::{error, log, Level};
use shvproto::MetaMap;
use shvrpc::metamethod::{AccessLevel, Flags, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, RqId};
use shvrpc::{Error, RpcMessageMetaTags};
use smol::io::{BufReader, BufWriter};
use smol::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

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

pub(crate) struct TunnelNode {}
impl TunnelNode {
    pub fn new() -> Self {
        TunnelNode {}
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
    async fn children(&self, shv_path: &str, broker_state: &BrokerImpl) -> Option<Vec<String>> {
        let tunnels = broker_state
            .active_tunnel_ids()
            .await
            .iter()
            .map(|id| format!("{}", *id))
            .collect();
        if shv_path.is_empty() {
            Some(tunnels)
        } else if tunnels.contains(&shv_path.to_string()) {
            Some(vec![])
        } else {
            None
        }
    }

    async fn is_request_granted(&self, rq: &RpcFrame, ctx: &NodeRequestContext) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            let methods = self.methods(shv_path);
            is_request_granted_methods(methods, rq)
        } else {
            ctx.state.is_request_granted_tunnel(shv_path, rq).await
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
                    ctx.state.write_tunnel(
                        tunid,
                        rq.request_id().unwrap_or_default(),
                        data,
                    ).await?;
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                METH_CLOSE => {
                    let is_active = ctx.state.is_tunnel_active(tunid).await;
                    let _ = ctx.state.command_sender.unbounded_send(BrokerCommand::TunnelClosed(tunid));
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
                    let (tunid, receiver) = ctx.state.create_tunnel(&rq).await?;
                    let rq_meta = rq.meta().clone();
                    let command_sender = ctx.state.command_sender.clone();
                    let peers = ctx.state.peers.clone();
                    let active_tunnels = ctx.state.active_tunnels.clone();
                    let cmd_sender_for_closed = command_sender.clone();
                    smol::spawn(async move {
                        if let Err(e) = tunnel_task(tunid, rq_meta, host, receiver, command_sender, peers, active_tunnels).await {
                            error!("{e}")
                        }
                        if let Err(e) = cmd_sender_for_closed.unbounded_send(BrokerCommand::TunnelClosed(tunid)) {
                            error!("Failed to send TunnelClosed for {tunid}: {e}");
                        }
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

pub(crate) async fn tunnel_task(
    tunnel_id: TunnelId,
    mut request_meta: MetaMap,
    addr: String,
    mut from_broker_receiver: UnboundedReceiver<ToRemoteMsg>,
    command_sender: UnboundedSender<BrokerCommand>,
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    active_tunnels: Arc<RwLock<BTreeMap<TunnelId, ActiveTunnel>>>,
) -> shvrpc::Result<()> {
    let peer_id = request_meta.pop_caller_id().ok_or("Invalid peer id")?;
    let mut response_meta = RpcFrame::prepare_response_meta(&request_meta)?;
    let to_broker_sender = command_sender.clone();
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
    BrokerImpl::touch_tunnel(&active_tunnels, tunnel_id).await;
    to_broker_sender.unbounded_send(BrokerCommand::TunnelActive(tunnel_id))?;
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
                    BrokerImpl::touch_tunnel(&active_tunnels, tunnel_id).await;
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
                            BrokerImpl::touch_tunnel(&active_tunnels, tunnel_id).await;
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
    to_broker_sender.unbounded_send(BrokerCommand::TunnelClosed(tunnel_id))?;
    Ok(())
}
