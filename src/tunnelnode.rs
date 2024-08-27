use std::collections::BTreeMap;
use shvproto::{RpcValue, Value};
use shvrpc::{Error, RpcMessageMetaTags};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::PeerId;
use crate::brokerimpl::{NodeRequestContext, SharedBrokerState};
use crate::shvnode::{is_request_granted_methods, ShvNode, META_METHOD_PUBLIC_DIR, METH_DIR, METH_LS};

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

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> Result<Option<RpcValue>, Error> {
        let shv_path = frame.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            match frame.method().unwrap_or_default() {
                METH_CREATE => {
                    let tunid = self.next_tunnel_number;
                    self.next_tunnel_number += 1;
                    let tunid = format!("{tunid}");
                    self.open_tunnels.insert(tunid.clone(), OpenTunnelNode { caller_ids: vec![] });
                    Ok(Some(tunid.into()))
                }
                _ => {
                    Ok(None)
                }
            }
        } else if frame.method().unwrap_or_default() == METH_CLOSE {
            match self.open_tunnels.remove(shv_path) {
                None => {
                    Err(format!("Invalid tunnel key: {shv_path}").into())
                }
                Some(_) => {
                    Ok(Some(true.into()))
                }
            }
        } else if let Some(tun) = self.open_tunnels.get_mut(shv_path) {
            tun.process_request(frame, ctx)
        } else {
            Err(format!("Invalid tunnel key: {shv_path}").into())
        }
    }
}

pub(crate) struct OpenTunnelNode {
    caller_ids: Vec<PeerId>,
}
impl OpenTunnelNode {
    fn process_request(&mut self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> Result<Option<RpcValue>, Error> {
        match frame.method().unwrap_or_default() {
            METH_WRITE => {
                let msg = frame.to_rpcmesage()?;
                let blob = msg.param().unwrap_or_default().clone();
                match blob.value() {
                    Value::String(s) => {
                        let blob = s.as_bytes();
                        println!("write blob: {:?}", blob);
                        Ok(Some(().into()))
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
            _ => {
                Ok(None)
            }
        }
    }
}