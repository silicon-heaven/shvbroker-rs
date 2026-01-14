use log::trace;
use crate::brokerimpl::{
    state_reader, state_writer, BrokerCommand, NodeRequestContext, SharedBrokerState, TunnelId,
};
use crate::shvnode;
use crate::shvnode::{
    is_request_granted_methods, ProcessRequestRetval, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR,
    METH_LS,
};
use futures::FutureExt;
use futures::{select, AsyncReadExt, AsyncWriteExt};
use log::{error, log, Level};
use shvproto::{MetaMap, RpcValue};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, RqId};
use shvrpc::{Error, RpcMessageMetaTags};
use smol::channel;
use smol::channel::{Receiver, Sender};
use smol::io::{BufReader, BufWriter};
use smol::net::TcpStream;
use std::time::Instant;

const META_METHOD_PRIVATE_DIR: MetaMethod = MetaMethod::new_static(METH_DIR, Flag::None as u32, AccessLevel::Superuser, "DirParam", "DirResult", &[], "");
const META_METHOD_PRIVATE_LS: MetaMethod = MetaMethod::new_static(METH_LS, Flag::None as u32, AccessLevel::Superuser, "LsParam", "LsResult", &[], "");

const METH_CREATE: &str = "create";
const METH_WRITE: &str = "write";
const METH_CLOSE: &str = "close";
const META_METH_CREATE: MetaMethod = MetaMethod::new_static(METH_CREATE, Flag::None as u32, AccessLevel::Write, "Map", "String", &[], "");
const META_METH_WRITE: MetaMethod = MetaMethod::new_static(METH_WRITE, Flag::None as u32, AccessLevel::Superuser, "Blob", "Blob", &[], "");
const META_METH_CLOSE: MetaMethod = MetaMethod::new_static(METH_CLOSE, Flag::None as u32, AccessLevel::Superuser, "Blob", "Blob", &[], "");

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
    async fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        let tunnels = state_reader(broker_state)
            .await
            .active_tunnel_ids()
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
            let shv_path = rq.shv_path().unwrap_or_default();
            let methods = self.methods(shv_path);
            is_request_granted_methods(methods, rq)
        } else {
            state_reader(&ctx.state).await.is_request_granted_tunnel(shv_path, rq)
        }
    }

    async fn process_request(
        &mut self,
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
                    state_reader(&ctx.state).await.write_tunnel(
                        tunid,
                        rq.request_id().unwrap_or_default(),
                        data,
                    )?;
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                METH_CLOSE => {
                    let command_sender = state_reader(&ctx.state).await.command_sender.clone();
                    let is_active = state_reader(&ctx.state).await.is_tunnel_active(tunid);
                    smol::spawn(async move {
                        let _ = command_sender
                            .send(BrokerCommand::TunnelClosed(tunid))
                            .await;
                    })
                    .detach();
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
                    let (tunid, receiver) = state_writer(&ctx.state).await.create_tunnel(&rq)?;
                    let rq_meta = rq.meta().clone();
                    let state = ctx.state.clone();
                    let command_sender = state_reader(&state).await.command_sender.clone();
                    smol::spawn(async move {
                        if let Err(e) = tunnel_task(tunid, rq_meta, host, receiver, state).await {
                            error!("{e}")
                        }
                        command_sender
                            .send(BrokerCommand::TunnelClosed(tunid))
                            .await
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
    pub(crate) sender: Sender<ToRemoteMsg>,
    pub(crate) last_activity: Option<Instant>,
}

pub(crate) async fn tunnel_task(
    tunnel_id: TunnelId,
    request_meta: MetaMap,
    addr: String,
    from_broker_receiver: Receiver<ToRemoteMsg>,
    state: SharedBrokerState,
) -> shvrpc::Result<()> {
    let peer_id = *request_meta.caller_ids().first().ok_or("Invalid peer id")?;
    let mut response_meta = RpcFrame::prepare_response_meta(&request_meta)?;
    let to_broker_sender = state_reader(&state).await.command_sender.clone();
    log!(target: "Tunnel", Level::Debug, "Tunnel: {tunnel_id}, connecting to: {addr} ...");
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            log!(target: "Tunnel", Level::Debug, "connected OK");
            to_broker_sender
                .send(BrokerCommand::SendResponse {
                    peer_id,
                    meta: response_meta.clone(),
                    result: Ok(format!("{tunnel_id}").into()),
                })
                .await?;
            stream
        }
        Err(e) => {
            to_broker_sender
                .send(BrokerCommand::SendResponse {
                    peer_id,
                    meta: response_meta.clone(),
                    result: Err(RpcError::new(RpcErrorCode::MethodCallException, e.to_string())),
                })
                .await?;
            return Err(e.to_string().into());
        }
    };
    state_writer(&state).await.touch_tunnel(tunnel_id);
    to_broker_sender
        .send(BrokerCommand::TunnelActive(tunnel_id))
        .await?;
    let (socket_reader, socket_writer) = stream.split();
    let mut read_buff: [u8; 256] = [0; 256];
    let mut response_buff: Vec<u8> = vec![];
    let mut write_request_id = None;
    let mut read_seqno = 0;
    let mut socket_reader = BufReader::new(socket_reader);
    let (write_task_sender, write_task_receiver) = channel::unbounded::<Vec<u8>>();
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
    fn make_response(peer_id: PeerId, response_meta: MetaMap, data: &mut Vec<u8>) -> BrokerCommand {
        let blob = RpcValue::from(&data[..]);
        data.clear();
        BrokerCommand::SendResponse {
            peer_id,
            meta: response_meta,
            result: Ok(blob),
        }
    }
    fn make_err_response(peer_id: PeerId, response_meta: MetaMap, err: RpcError) -> BrokerCommand {
        BrokerCommand::SendResponse {
            peer_id,
            meta: response_meta,
            result: Err(err),
        }
    }
    loop {
        select! {
            bytes_read = socket_reader.read(&mut read_buff).fuse() => match bytes_read {
                Ok(bytes_read) => {
                    trace!(target: "Tunnel", "Read {bytes_read} bytes from client socket.");
                    state_writer(&state).await.touch_tunnel(tunnel_id);
                    if bytes_read == 0 {
                        trace!(target: "Tunnel", "Client socket closed.");
                        break;
                    } else {
                        let mut data = read_buff[.. bytes_read].to_vec();
                        response_buff.append(&mut data);
                        let mut response_meta = response_meta.clone();
                        response_meta.set_seqno(read_seqno);
                        read_seqno += 1;
                        to_broker_sender.send(make_response(peer_id, response_meta, &mut response_buff)).await?;
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
                            state_writer(&state).await.touch_tunnel(tunnel_id);
                            if write_request_id.is_none() {
                                write_request_id = Some(rqid);
                                response_meta.set_request_id(rqid);
                                if !response_buff.is_empty() {
                                    trace!(target: "Tunnel", "to_broker_sender send: {} bytes to {peer_id}", response_buff.len());
                                    to_broker_sender.send(make_response(peer_id, response_meta.clone(), &mut response_buff)).await?;
                                }
                            }
                            if !data.is_empty() {
                                trace!(target: "Tunnel", "write_task_sender send: {} bytes", data.len());
                                write_task_sender.send(data).await?;
                            }
                        }
                        ToRemoteMsg::DestroyConnection => {
                            trace!(target: "Tunnel", "CMD DestroyConnection");
                            if write_request_id.is_some() {
                                to_broker_sender.send(make_err_response(peer_id, response_meta.clone(), RpcError::new(RpcErrorCode::MethodCallCancelled, format!("Tunnel: {tunnel_id} closed.")))).await?;
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
    write_task_sender.send(vec![]).await?;
    to_broker_sender
        .send(BrokerCommand::TunnelClosed(tunnel_id))
        .await?;
    Ok(())
}
