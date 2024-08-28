use std::collections::BTreeMap;
use std::time::Duration;
use async_std::{channel, future, task};
use async_std::channel::{Receiver, Sender};
use async_std::io::{BufReader, BufWriter, WriteExt};
use async_std::net::{TcpStream};
use futures::{select, AsyncReadExt};
use shvproto::{RpcValue, Value};
use shvrpc::{Error, RpcMessageMetaTags};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RqId};
use crate::brokerimpl::{state_reader, BrokerCommand, NodeRequestContext, SharedBrokerState};
use crate::shvnode::{is_request_granted_methods, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR, METH_LS};
use futures::FutureExt;
use log::{debug, error};

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
    open_tunnels: BTreeMap<String, OpenTunnelNode>,
    next_tunnel_number: u64,
}
impl TunnelNode {
    pub fn new() -> Self {
        TunnelNode {
            open_tunnels: Default::default(),
            next_tunnel_number: 1,
        }
    }
    pub fn close_tunnel(&mut self, tunid: &str) -> shvrpc::Result<()> {
        if let Some(tun) = self.open_tunnels.remove(tunid) {
            let sender = tun.sender;
            task::spawn(async move {
                let _ = sender.send(ToRemoteMsg::DestroyConnection).await;
            });
        } else {
            // might be callback of previous close_tunel()
        }
        Ok(())
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
    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.open_tunnels.keys().map(|k| k.to_string()).collect())
        } else if self.open_tunnels.contains_key(shv_path) {
            Some(vec![])
        } else {
            None
        }
    }

    fn is_request_granted(&self, rq: &RpcFrame) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            let shv_path = rq.shv_path().unwrap_or_default();
            let methods = self.methods(shv_path);
            is_request_granted_methods(methods, rq)
        } else if let Some(t) = self.open_tunnels.get(shv_path) {
            let cids = rq.caller_ids();
            cids == t.caller_ids || AccessLevel::try_from(rq.access_level().unwrap_or(0)).unwrap_or(AccessLevel::Browse) == AccessLevel::Superuser
        } else {
            false
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvrpc::Result<Option<RpcValue>> {
        let shv_path = frame.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            match frame.method().unwrap_or_default() {
                METH_CREATE => {
                    let tunid = self.next_tunnel_number;
                    self.next_tunnel_number += 1;
                    let tunid = format!("{tunid}");
                    let rq = frame.to_rpcmesage()?;
                    let param = rq.param().unwrap_or_default().as_map();
                    let host = param.get("host").unwrap_or_default().to_string();
                    let (sender, receiver) = channel::unbounded::<ToRemoteMsg>();
                    task::spawn(tunnel_task(tunid.clone(), host, receiver, state_reader(&ctx.state).command_sender.clone()));
                    self.open_tunnels.insert(tunid.clone(), OpenTunnelNode { caller_ids: vec![], sender });
                    Ok(Some(tunid.into()))
                }
                _ => {
                    Ok(None)
                }
            }
        } else if let Some(tun) = self.open_tunnels.get_mut(shv_path) {
            tun.process_request(frame, ctx)
        } else {
            Err(format!("Invalid tunnel key: {shv_path}").into())
        }
    }
}
enum ToRemoteMsg {
    SendData(RqId, Vec<u8>),
    DestroyConnection,
}
pub(crate) struct OpenTunnelNode {
    caller_ids: Vec<PeerId>,
    sender: Sender<ToRemoteMsg>,
}
impl OpenTunnelNode {
    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvrpc::Result<Option<RpcValue>> {
        match frame.method().unwrap_or_default() {
            METH_WRITE => {
                let msg = frame.to_rpcmesage()?;
                let blob = msg.param().unwrap_or_default().clone();
                match blob.value() {
                    Value::String(s) => {
                        let meta= RpcFrame::prepare_response_meta(&frame.meta)?;
                        let peer_id = ctx.peer_id;
                        let blob = s.as_bytes().to_vec();
                        let state = ctx.state.clone();
                        task::spawn(async move {
                            println!("write blob: {:?}", blob);
                            let _ = future::timeout(Duration::from_secs(3), future::pending::<()>()).await;
                            let sender = state_reader(&state).command_sender.clone();
                            let _ = sender.send(BrokerCommand::SendResponse {
                                peer_id,
                                meta,
                                result: Ok("kkt".into()),
                            }).await;
                        });
                        Ok(None)
                    }
                    Value::Blob(b) => {
                        let blob = b;
                        println!("write blob: {:?}", blob);
                        Ok(Some(().into()))
                    }
                    _ => {
                        Err("Invalid write tunnel parameter.".into())
                    }
                }
            }
            METH_CLOSE => {
                let sender = self.sender.clone();
                task::spawn(async move {
                    let _ = sender.send(ToRemoteMsg::DestroyConnection);
                });
                Ok(Some(true.into()))
            }
            _ => {
                Ok(None)
            }
        }
    }
}

async fn tunnel_task(tunnel_id: String, addr: String, from_broker_receiver: Receiver<ToRemoteMsg>, destroy_tunnel_sender: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let (reader, writer) = stream.split();
    let mut read_buff: [u8; 256] = [0; 256];
    let mut response_data: Vec<u8> = vec![];
    let mut response_rqid: Option<RqId> = None;
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
                        writer.write_all(&*data).await?;
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
    async fn send_response(data: Vec<u8>) -> shvrpc::Result<()> {
        Ok(())
    }
    loop {
        select! {
            bytes_read = reader.read(&mut read_buff).fuse() => match bytes_read {
                Ok(bytes_read) => {
                    debug!("read: {bytes_read}");
                    if bytes_read == 0 {
                        debug!("socket closed?");
                        break;
                    } else {
                        let mut data = read_buff[.. bytes_read].to_vec();
                        response_data.append(&mut data);
                        if let Some(rqid) = response_rqid {
                            send_response(response_data).await?;
                            response_data = vec![];
                        }
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
                            response_rqid = Some(rqid);
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
    destroy_tunnel_sender.send(BrokerCommand::CloseTunnel(tunnel_id)).await?;
    Ok(())
}