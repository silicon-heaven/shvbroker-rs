use async_trait::async_trait;
use shvproto::{List, RpcValue, rpcvalue};
use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use shvrpc::rpc::SubscriptionParam;
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode};
use crate::broker::{BrokerToPeerMessage, PeerKind};
use crate::brokerimpl::{NodeRequestContext, SharedBrokerState, state_reader};
use crate::{node, shvnode};
use crate::shvnode::{AppDeviceNode, META_METHOD_DIR, META_METHOD_LS, METH_LS, ShvNode};

pub const DIR_BROKER: &str = ".broker";
pub const DIR_BROKER_CURRENT_CLIENT: &str = ".broker/currentClient";
pub const DIR_BROKER_ACCESS_MOUNTS: &str = ".broker/access/mounts";
pub const DIR_BROKER_ACCESS_USERS: &str = ".broker/access/users";
pub const DIR_BROKER_ACCESS_ROLES: &str = ".broker/access/roles";

pub const METH_CLIENT_INFO: &str = "clientInfo";
pub const METH_MOUNTED_CLIENT_INFO: &str = "mountedClientInfo";
pub const METH_CLIENTS: &str = "clients";
pub const METH_MOUNTS: &str = "mounts";
pub const METH_DISCONNECT_CLIENT: &str = "disconnectClient";

const META_METH_CLIENT_INFO: MetaMethod = MetaMethod { name: METH_CLIENT_INFO, param: "Int", result: "ClientInfo", access: AccessLevel::Service, flags: Flag::None as u32, description: "", signals: &[] };
const META_METH_MOUNTED_CLIENT_INFO: MetaMethod = MetaMethod { name: METH_MOUNTED_CLIENT_INFO, param: "String", result: "ClientInfo", access: AccessLevel::Service, flags: Flag::None as u32, description: "", signals: &[] };
const META_METH_CLIENTS: MetaMethod = MetaMethod { name: METH_CLIENTS, param: "void", result: "List[Int]", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "", signals: &[] };
const META_METH_MOUNTS: MetaMethod = MetaMethod { name: METH_MOUNTS, param: "void", result: "List[String]", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "", signals: &[] };
const META_METH_DISCONNECT_CLIENT: MetaMethod = MetaMethod { name: METH_DISCONNECT_CLIENT, param: "Int", result: "void", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "", signals: &[] };

pub const METH_INFO: &str = "info";
pub const METH_SUBSCRIBE: &str = "subscribe";
pub const METH_UNSUBSCRIBE: &str = "unsubscribe";
pub const METH_SUBSCRIPTIONS: &str = "subscriptions";


pub(crate) struct BrokerNode {}
impl BrokerNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}
const BROKER_NODE_METHODS: &[&MetaMethod; 7] = &[
    &META_METHOD_DIR,
    &META_METHOD_LS,
    &META_METH_CLIENT_INFO,
    &META_METH_MOUNTED_CLIENT_INFO,
    &META_METH_CLIENTS,
    &META_METH_MOUNTS,
    &META_METH_DISCONNECT_CLIENT,
];

#[async_trait]
impl ShvNode for BrokerNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_NODE_METHODS
    }

    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        Some(vec![])
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvrpc::Result<()> {
        let result = match ctx.method.name {
            node::METH_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let peer_id: PeerId = rq.param().unwrap_or_default().as_i64();
                let info = match state_reader(&ctx.broker_state).client_info(peer_id) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(info)
            }
            node::METH_MOUNTED_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let mount_point = rq.param().unwrap_or_default().as_str();
                let info = match state_reader(&ctx.broker_state).mounted_client_info(mount_point) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(info)
            }
            node::METH_CLIENTS => {
                let clients: rpcvalue::List = state_reader(&ctx.broker_state).peers.keys().map(|id| RpcValue::from(*id)).collect();
                Ok(clients.into())
            }
            node::METH_MOUNTS => {
                let mounts: List = state_reader(&ctx.broker_state).peers.values()
                    .map(|peer| if let PeerKind::Device {mount_point, ..} = &peer.peer_kind {Some(mount_point)} else {None})
                    .filter(|mount_point| mount_point.is_some())
                    .map(|mount_point| RpcValue::from(mount_point.unwrap()))
                    .collect();
                Ok(mounts.into())
            }
            node::METH_DISCONNECT_CLIENT => {
                if let Some(peer) = state_reader(&ctx.broker_state).peers.get(&ctx.peer_id) {
                    peer.sender.send(BrokerToPeerMessage::DisconnectByBroker).await?;
                    Ok(().into())
                } else {
                    Err(RpcError::new(RpcErrorCode::MethodCallException, format!("Disconnect client error - peer {} not found.", ctx.peer_id)))
                }
            }
            _ => {
                return Ok(())
            }
        };
        shvnode::send_response(&frame.meta, result, ctx).await
    }
}

const META_METH_INFO: MetaMethod = MetaMethod { name: METH_INFO, flags: Flag::None as u32, access: AccessLevel::Browse, param: "Int", result: "ClientInfo", signals: &[], description: "" };
const META_METH_SUBSCRIBE: MetaMethod = MetaMethod { name: METH_SUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_UNSUBSCRIBE: MetaMethod = MetaMethod { name: METH_UNSUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_SUBSCRIPTIONS: MetaMethod = MetaMethod { name: METH_SUBSCRIPTIONS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "void", result: "List", signals: &[], description: "" };

pub(crate) struct BrokerCurrentClientNode {}
impl BrokerCurrentClientNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

const BROKER_CURRENT_CLIENT_NODE_METHODS: &[&MetaMethod; 6] = &[
    &META_METHOD_DIR,
    &META_METHOD_LS,
    &META_METH_INFO,
    &META_METH_SUBSCRIBE,
    &META_METH_UNSUBSCRIBE,
    &META_METH_SUBSCRIPTIONS,
];

#[async_trait]
impl ShvNode for BrokerCurrentClientNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_CURRENT_CLIENT_NODE_METHODS
    }

    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        Some(vec![])
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvrpc::Result<()> {
        match ctx.method.name {
            node::METH_SUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                match SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default()) {
                    Ok(subscription) => {
                        let subs_added = self.subscribe(ctx.peer_id, &subscription)?;
                        Ok(Some(subs_added.into()))
                    }
                    Err(e) => {
                        let err = RpcError::new(RpcErrorCode::InvalidParam, e);
                        Some(Err(err))
                    }
                }
            }
            node::METH_UNSUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                match SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default()) {
                    Ok(subscription) => {
                        let subs_removed = self.unsubscribe(ctx.peer_id, &subscription)?;
                        Ok(Some(subs_removed.into()))
                    }
                    Err(e) => {
                        let err = RpcError::new(RpcErrorCode::InvalidParam, e);
                        Some(Err(err))
                    }
                }
            }
            node::METH_SUBSCRIPTIONS => {
                let result = state_reader(&self.state).subscriptions(ctx.peer_id)?;
                Ok(Some(result.into()))
            }
            node::METH_INFO => {
                let info = match state_reader(&self.state).client_info(ctx.peer_id) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(Some(info))
            }
            _ => {
                None
            }
        }
    }
}
pub const METH_VALUE: &str = "value";
pub const METH_SET_VALUE: &str = "setValue";
const META_METH_VALUE: MetaMethod = MetaMethod { name: METH_VALUE, flags: Flag::None as u32, access: AccessLevel::Read, param: "void", result: "Map", signals: &[], description: "" };
const META_METH_SET_VALUE: MetaMethod = MetaMethod { name: METH_SET_VALUE, flags: Flag::None as u32, access: AccessLevel::Read, param: "[String, Map | Null]", result: "void", signals: &[], description: "" };
pub(crate) struct BrokerAccessMountsNode {}
impl BrokerAccessMountsNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

const ACCESS_NODE_METHODS: &[&MetaMethod; 3] = &[&META_METHOD_DIR, &META_METHOD_LS, &META_METH_SET_VALUE];
const ACCESS_VALUE_NODE_METHODS: &[&MetaMethod; 3] = &[&META_METHOD_DIR, &META_METHOD_LS, &META_METH_VALUE];
#[async_trait]
impl ShvNode for crate::node::BrokerAccessMountsNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            ACCESS_NODE_METHODS
        } else {
            ACCESS_VALUE_NODE_METHODS
        }
    }

    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            let a = state_reader(broker_state).access.keys();
        } else {

        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> shvrpc::Result<()> {
        match ctx.method.name {
            node::METH_VALUE => {
                match state_reader(&ctx.broker_state).access_mount(&ctx.node_path) {
                    None => {
                        Some(Err(RpcError::new(RpcErrorCode::MethodCallException, format!("Invalid node key"))))
                    }
                    Some(mount) => {
                        Ok(Some(mount.to_rpcvalue()?))
                    }
                }
            }
            node::METH_SET_VALUE => {
                fn set_value(broker_state: &SharedBrokerState, frame: &RpcFrame) -> Result<(), String> {
                    let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                    let param = param.as_list();
                    let key = param.get(0).ok_or("Key is missing")?;
                    let n = RpcValue::null();
                    let mount = param.get(1).and_then(|m| if m.is_null() {None} else {Some(m)});
                    let mount = mount.map(|m| crate::config::Mount::try_from(mount)?);
                    crate::brokerimpl::state_writer(broker_state).set_access_mounts(key.as_str(), mount);
                    Ok(())
                }
                match set_value(ctx.broker_state, frame) {
                    Ok(_) => Ok(Some(().into())),
                    Err(e) => Some(Err(RpcError::new(RpcErrorCode::MethodCallException, format!("Invalid params: {e}")))),
                }
            }
            _ => {
                None
            }
        }
    }
}
