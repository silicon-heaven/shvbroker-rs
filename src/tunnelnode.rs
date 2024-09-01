use async_std::{channel, task};
use async_std::channel::{Receiver, Sender};
use async_std::io::{BufReader, BufWriter, WriteExt};
use async_std::net::{TcpStream};
use futures::{select, AsyncReadExt};
use shvproto::{MetaMap, RpcValue};
use shvrpc::{Error, RpcMessage, RpcMessageMetaTags};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RqId};
use crate::brokerimpl::{state_reader, state_writer, BrokerCommand, NodeRequestContext, SharedBrokerState};
use crate::shvnode::{is_request_granted_methods, ProcessRequestRetval, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR, METH_LS};
use futures::FutureExt;
use log::{debug, error};
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
        let tunnels = state_reader(broker_state).open_tunnel_ids();
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
                    let tunid = state_writer(&ctx.state).create_tunnel(frame)?;
                    Ok(ProcessRequestRetval::Retval(tunid.into()))
                }
                _ => {
                    Ok(ProcessRequestRetval::MethodNotFound)
                }
            }
        } else {
            match method {
                METH_WRITE => {
                    let rq = frame.to_rpcmesage()?;
                    let data = rq.result()?.as_blob().to_vec();
                    state_reader(&ctx.state).write_tunnel(tunid, rq.request_id().unwrap_or_default(), data)?;
                    Ok(ProcessRequestRetval::RetvalDeferred)
                }
                METH_CLOSE => {
                    let res = state_writer(&ctx.state).close_tunnel(tunid)?;
                    Ok(ProcessRequestRetval::Retval(res.into()))
                }
                _ => {
                    Ok(ProcessRequestRetval::MethodNotFound)
                }
            }
        }
    }
}
pub(crate) enum ToRemoteMsg {
    SendData(RqId, Vec<u8>),
    DestroyConnection,
}
pub(crate) struct OpenTunnelNode {
    pub(crate) caller_ids: Vec<PeerId>,
    pub(crate) sender: Sender<ToRemoteMsg>,
}

pub(crate) async fn tunnel_task(tunnel_id: String, request_meta: MetaMap, addr: String, from_broker_receiver: Receiver<ToRemoteMsg>, to_broker_sender: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let (reader, writer) = stream.split();
    let mut read_buff: [u8; 256] = [0; 256];
    let mut write_buff: Vec<u8> = vec![];
    let mut request_id = None;
    let mut response_meta = RpcMessage::from_meta(request_meta).meta().clone();
    let peer_id = 0;
    //let caller_ids = tunnel.caller_ids.clone();
    let mut reader = BufReader::new(reader);
    let mut fut_from_broker = from_broker_receiver.recv().fuse();
    let (write_task_sender, write_task_receiver) = channel::unbounded::<Vec<u8>>();
    task::spawn(async move {
        let mut writer = BufWriter::new(writer);
        loop {
            match write_task_receiver.recv().await {
                Ok(data) => {
                    if data.is_empty() {
                        break;
                    } else {
                        writer.write_all(&data).await?;
                    }
                }
                Err(e) => {
                    debug!("read broker channel error: {e}");
                    break;
                }
            }
        }
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
    loop {
        let make_response2 = make_response;
        select! {
            bytes_read = reader.read(&mut read_buff).fuse() => match bytes_read {
                Ok(bytes_read) => {
                    debug!("read: {bytes_read}");
                    if bytes_read == 0 {
                        debug!("socket closed?");
                        break;
                    } else {
                        let mut data = read_buff[.. bytes_read].to_vec();
                        write_buff.append(&mut data);
                        to_broker_sender.send(make_response(peer_id, response_meta.clone(), &mut write_buff)).await?;
                    }
                },
                Err(e) => {
                    error!("tunnel socket error: {e}");
                    break;
                }
            },
            cmd = fut_from_broker => match cmd {
                Ok(cmd) => {
                    match cmd {
                        ToRemoteMsg::SendData(rqid, data) => {
                            if request_id.is_none() {
                                request_id = Some(rqid);
                                response_meta.set_request_id(rqid);
                                if !write_buff.is_empty() {
                                    to_broker_sender.send(make_response2(peer_id, response_meta.clone(), &mut write_buff)).await?;
                                }
                            }
                            write_task_sender.send(data).await?;
                        }
                        ToRemoteMsg::DestroyConnection => { break }
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
    to_broker_sender.send(BrokerCommand::CloseTunnel(tunnel_id)).await?;
    Ok(())
}