use std::time::{Instant};
use async_std::{channel, task};
use async_std::channel::{Receiver, Sender};
use async_std::io::{BufReader, BufWriter};
use async_std::net::{TcpStream};
use futures::{select, AsyncReadExt, AsyncWriteExt};
use shvproto::{MetaMap, RpcValue};
use shvrpc::{Error, RpcMessageMetaTags};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, RqId};
use crate::brokerimpl::{state_reader, state_writer, BrokerCommand, NodeRequestContext, SharedBrokerState};
use crate::shvnode::{is_request_granted_methods, ProcessRequestRetval, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR, METH_LS};
use futures::FutureExt;
use log::{error, log, Level};
use crate::shvnode;

const META_METHOD_PRIVATE_DIR: MetaMethod = MetaMethod { name: METH_DIR, flags: Flag::None as u32, access: AccessLevel::Superuser, param: "DirParam", result: "DirResult", signals: &[], description: "" };
const META_METHOD_PRIVATE_LS: MetaMethod = MetaMethod { name: METH_LS, flags: Flag::None as u32, access: AccessLevel::Superuser, param: "LsParam", result: "LsResult", signals: &[], description: "" };

const METH_CREATE: &str = "create";
const METH_WRITE: &str = "write";
const METH_CLOSE: &str = "close";
const META_METH_CREATE: MetaMethod = MetaMethod { name: METH_CREATE, flags: Flag::None as u32, access: AccessLevel::Write, param: "Map", result: "String", signals: &[], description: "" };
const META_METH_WRITE: MetaMethod = MetaMethod { name: METH_WRITE, flags: Flag::None as u32, access: AccessLevel::Superuser, param: "Blob", result: "Blob", signals: &[], description: "" };
const META_METH_CLOSE: MetaMethod = MetaMethod { name: METH_CLOSE, flags: Flag::None as u32, access: AccessLevel::Superuser, param: "Blob", result: "Blob", signals: &[], description: "" };

const TUNNEL_NODE_METHODS: &[&MetaMethod; 3] = &[&META_METHOD_PUBLIC_DIR, &META_METHOD_PRIVATE_LS, &META_METH_CREATE];
const OPEN_TUNNEL_NODE_METHODS: &[&MetaMethod; 4] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_WRITE, &META_METH_CLOSE];

pub(crate) struct TunnelNode {
}
impl TunnelNode {
    pub fn new() -> Self {
        TunnelNode {
        }
    }
}
impl ShvNode for TunnelNode {
    fn methods(&self, shv_path: &str) -> &'static [&'static MetaMethod] {
        if shv_path.is_empty() {
            TUNNEL_NODE_METHODS
        } else {
            OPEN_TUNNEL_NODE_METHODS
        }
    }
    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        let tunnels = state_reader(broker_state).active_tunnel_ids();
        if shv_path.is_empty() {
            Some(tunnels)
        } else if tunnels.contains(&shv_path.to_string()) {
            Some(vec![])
        } else {
            None
        }
    }

    fn is_request_granted(&self, rq: &RpcFrame, ctx: &NodeRequestContext) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            let shv_path = rq.shv_path().unwrap_or_default();
            let methods = self.methods(shv_path);
            is_request_granted_methods(methods, rq)
        } else {
            state_reader(&ctx.state).is_request_granted(shv_path, rq)
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvnode::ProcessRequestResult {
        let tunid = frame.shv_path().unwrap_or_default();
        let method = frame.method().unwrap_or_default();
        if tunid.is_empty() {
            match method {
                METH_CREATE => {
                    let rq = frame.to_rpcmesage()?;
                    let param = rq.param().unwrap_or_default().as_map();
                    let host = param.get("host").ok_or("'host' parameter must be provided")?.as_str().to_string();
                    let (tunid, receiver) = state_writer(&ctx.state).create_tunnel(&rq)?;
                    let rq_meta = rq.meta().clone();
                    let state = ctx.state.clone();
                    let command_sender = state_reader(&state).command_sender.clone();
                    let tunid2 = tunid.clone();
                    task::spawn(async move {
                        if let Err(e) = tunnel_task(tunid2.clone(), rq_meta, host, receiver, state).await {
                            error!("{}", e)
                        }
                        command_sender.send(BrokerCommand::TunnelClosed(tunid2)).await
                    });
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                _ => {
                    Ok(ProcessRequestRetval::MethodNotFound)
                }
            }
        } else {
            match method {
                METH_WRITE => {
                    let rq = frame.to_rpcmesage()?;
                    let data = rq.param().unwrap_or_default().as_blob().to_vec();
                    state_reader(&ctx.state).write_tunnel(tunid, rq.request_id().unwrap_or_default(), data)?;
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                METH_CLOSE => {
                    let command_sender = state_reader(&ctx.state).command_sender.clone();
                    let is_active = state_reader(&ctx.state).is_tunnel_active(tunid);
                    let tunid = tunid.to_string();
                    task::spawn(async move {
                        let _ = command_sender.send(BrokerCommand::TunnelClosed(tunid)).await;
                    });
                    Ok(ProcessRequestRetval::Retval(is_active.into()))
                }
                _ => {
                    Ok(ProcessRequestRetval::MethodNotFound)
                }
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

pub(crate) async fn tunnel_task(tunnel_id: String, request_meta: MetaMap, addr: String, from_broker_receiver: Receiver<ToRemoteMsg>, state: SharedBrokerState) -> shvrpc::Result<()> {
    let peer_id= *request_meta.caller_ids().first().ok_or("Invalid peer id")?;
    let mut response_meta = RpcFrame::prepare_response_meta(&request_meta)?;
    let to_broker_sender = state_reader(&state).command_sender.clone();
    log!(target: "Tunnel", Level::Debug, "connecting to: {addr} ...");
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            log!(target: "Tunnel", Level::Debug, "connected OK");
            to_broker_sender.send(BrokerCommand::SendResponse {
                peer_id,
                meta: response_meta.clone(),
                result: Ok(tunnel_id.clone().into()),
            }).await?;
            stream
        }
        Err(e) => {
            to_broker_sender.send(BrokerCommand::SendResponse {
                peer_id,
                meta: response_meta.clone(),
                result: Err(RpcError{ code: RpcErrorCode::MethodCallException, message: e.to_string() }),
            }).await?;
            return Err(e.to_string().into())
        }
    };
    state_writer(&state).touch_tunnel(&tunnel_id);
    to_broker_sender.send(BrokerCommand::TunnelActive(tunnel_id.clone())).await?;
    let (reader, writer) = stream.split();
    let mut read_buff: [u8; 256] = [0; 256];
    let mut response_buff: Vec<u8> = vec![];
    let mut write_request_id = None;
    let mut reader = BufReader::new(reader);
    let (write_task_sender, write_task_receiver) = channel::unbounded::<Vec<u8>>();
    task::spawn(async move {
        log!(target: "Tunnel", Level::Debug, "ENTER write task");
        let mut writer = BufWriter::new(writer);
        loop {
            match write_task_receiver.recv().await {
                Ok(data) => {
                    log!(target: "Tunnel", Level::Trace, "write_task_receiver read {} bytes to write.", data.len());
                    if data.is_empty() {
                        break;
                    } else {
                        log!(target: "Tunnel", Level::Trace, "Write {} bytes to client socket.", data.len());
                        writer.write_all(&data).await?;
                        writer.flush().await?;
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
    });
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
            bytes_read = reader.read(&mut read_buff).fuse() => match bytes_read {
                Ok(bytes_read) => {
                    log!(target: "Tunnel", Level::Trace, "Read {bytes_read} bytes from client socket.");
                    state_writer(&state).touch_tunnel(&tunnel_id);
                    if bytes_read == 0 {
                        log!(target: "Tunnel", Level::Trace, "Client socket closed.");
                        break;
                    } else {
                        let mut data = read_buff[.. bytes_read].to_vec();
                        response_buff.append(&mut data);
                        to_broker_sender.send(make_response(peer_id, response_meta.clone(), &mut response_buff)).await?;
                    }
                },
                Err(e) => {
                    error!("tunnel socket error: {e}");
                    break;
                }
            },
            cmd = from_broker_receiver.recv().fuse() => match cmd {
                Ok(cmd) => {
                    log!(target: "Tunnel", Level::Trace, "CMD: {:?}", cmd);
                    match cmd {
                        ToRemoteMsg::WriteData(rqid, data) => {
                            state_writer(&state).touch_tunnel(&tunnel_id);
                            if write_request_id.is_none() {
                                write_request_id = Some(rqid);
                                response_meta.set_request_id(rqid);
                                if !response_buff.is_empty() {
                                    log!(target: "Tunnel", Level::Trace, "to_broker_sender send: {} bytes to {peer_id}", response_buff.len());
                                    to_broker_sender.send(make_response(peer_id, response_meta.clone(), &mut response_buff)).await?;
                                }
                            }
                            if !data.is_empty() {
                                log!(target: "Tunnel", Level::Trace, "write_task_sender send: {} bytes", data.len());
                                write_task_sender.send(data).await?;
                            }
                        }
                        ToRemoteMsg::DestroyConnection => {
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
    to_broker_sender.send(BrokerCommand::TunnelClosed(tunnel_id)).await?;
    Ok(())
}