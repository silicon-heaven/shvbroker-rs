use std::collections::{BTreeMap, HashSet};
use std::format;
use log::{Level, log};
use shvrpc::metamethod::{Flag, MetaMethod};
use shvrpc::{metamethod, RpcMessageMetaTags};
use shvproto::{List, RpcValue, rpcvalue};
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpc::SubscriptionParam;
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode};
use shvrpc::util::strip_prefix_path;
use crate::brokerimpl::{BrokerToPeerMessage};
use crate::brokerimpl::{NodeRequestContext, SharedBrokerState, state_reader, state_writer};

pub const METH_DIR: &str = "dir";
pub const METH_LS: &str = "ls";
pub const METH_GET: &str = "get";
pub const METH_SET: &str = "set";
pub const SIG_CHNG: &str = "chng";
pub const SIG_LSMOD: &str = "lsmod";
pub const METH_NAME: &str = "name";
pub const METH_PING: &str = "ping";
pub const METH_SUBSCRIBE: &str = "subscribe";
pub const METH_UNSUBSCRIBE: &str = "unsubscribe";

pub const META_METHOD_PUBLIC_DIR: MetaMethod = MetaMethod { name: METH_DIR, flags: Flag::None as u32, access: AccessLevel::Browse, param: "DirParam", result: "DirResult", signals: &[], description: "" };
pub const META_METHOD_PUBLIC_LS: MetaMethod = MetaMethod { name: METH_LS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "LsParam", result: "LsResult", signals: &[], description: "" };
pub const PUBLIC_DIR_LS_METHODS: [MetaMethod; 2] = [META_METHOD_PUBLIC_DIR, META_METHOD_PUBLIC_LS];
pub const DOT_LOCAL_GRANT: &str = "dot_local";
pub const DOT_LOCAL_DIR: &str = ".local";
pub const DOT_LOCAL_HACK: &str = "dot-local-hack";
pub const DIR_APP: &str = ".app";
pub enum DirParam {
    Brief,
    Full,
    MethodExists(String),
}
impl From<Option<&RpcValue>> for DirParam {
    fn from(value: Option<&RpcValue>) -> Self {
        match value {
            Some(rpcval) => {
                if rpcval.is_string() {
                    DirParam::MethodExists(rpcval.as_str().into())
                } else if rpcval.as_bool() {
                    DirParam::Full
                } else {
                    DirParam::Brief
                }
            }
            None => {
                DirParam::Brief
            }
        }
    }
}

pub fn dir<'a>(mut methods: impl Iterator<Item=&'a MetaMethod>, param: DirParam) -> RpcValue {
    if let DirParam::MethodExists(ref method_name) = param {
        return methods.any(|mm| mm.name == method_name).into()
    }
    let mut lst = rpcvalue::List::new();
    for mm in methods {
        match param {
            DirParam::Brief => {
                lst.push(mm.to_rpcvalue(metamethod::DirFormat::IMap));
            }
            DirParam::Full => {
                lst.push(mm.to_rpcvalue(metamethod::DirFormat::Map));
            }
            _ => {}
        }
    }
    lst.into()
}

pub enum LsParam {
    List,
    Exists(String),
}
impl From<Option<&RpcValue>> for LsParam {
    fn from(value: Option<&RpcValue>) -> Self {
        match value {
            Some(rpcval) => {
                if rpcval.is_string() {
                    LsParam::Exists(rpcval.as_str().into())
                } else {
                    LsParam::List
                }
            }
            None => {
                LsParam::List
            }
        }
    }
}


pub fn process_local_dir_ls<V>(mounts: &BTreeMap<String, V>, frame: &RpcFrame) -> Option<Result<RpcValue, RpcError>> {
    let method = frame.method().unwrap_or_default();
    if !(method == METH_DIR || method == METH_LS) {
        return None
    }
    let shv_path = frame.shv_path().unwrap_or_default();
    let children = children_on_path(mounts, shv_path);
    let children = children.map(|children| {
        if frame.meta.get(DOT_LOCAL_HACK).is_some() {
            let mut children = children;
            children.insert(0, DOT_LOCAL_DIR.into());
            children
        } else {
            children
        }
    });
    let mount_pair = find_longest_prefix(mounts, shv_path);
    if mount_pair.is_none() && children.is_none() {
        // path doesn't exist
        return Some(Err(RpcError::new(RpcErrorCode::MethodNotFound, format!("Invalid shv path: {shv_path}"))))
    }
    let is_mount_point = mount_pair.is_some() && mount_pair.unwrap().1.is_empty();
    let is_remote_dir = mount_pair.is_some() && children.is_none();
    let is_tree_leaf = mount_pair.is_some() && children.is_some() && children.as_ref().unwrap().is_empty();
    //println!("shv path: {shv_path}, method: {method}, mount pair: {:?}", mount_pair);
    //println!("is_mount_point: {is_mount_point}, is_tree_leaf: {is_tree_leaf}");
    if method == METH_DIR && !is_mount_point && !is_remote_dir && !is_tree_leaf {
        // dir in the middle of the tree must be resolved locally
        if let Ok(rpcmsg) = frame.to_rpcmesage() {
            let dir = dir(PUBLIC_DIR_LS_METHODS.iter(), rpcmsg.param().into());
            return Some(Ok(dir))
        } else {
            return Some(Err(RpcError::new(RpcErrorCode::InvalidRequest, "Cannot convert RPC frame to Rpc message")))
        }
    }
    if method == METH_LS && !is_tree_leaf && !is_remote_dir  {
        // ls on not-leaf node must be resolved locally
        if let Ok(rpcmsg) = frame.to_rpcmesage() {
            let ls = ls_children_to_result(children, rpcmsg.param().into());
            return Some(ls)
        } else {
            return Some(Err(RpcError::new(RpcErrorCode::InvalidRequest, "Cannot convert RPC frame to Rpc message")))
        }
    }
    None
}
fn ls_children_to_result(children: Option<Vec<String>>, param: LsParam) -> Result<RpcValue, RpcError> {
    match param {
        LsParam::List => {
            match children {
                None => {
                    Err(RpcError::new(RpcErrorCode::MethodCallException, "Invalid shv path"))
                }
                Some(dirs) => {
                    let res: rpcvalue::List = dirs.iter().map(RpcValue::from).collect();
                    Ok(res.into())
                }
            }
        }
        LsParam::Exists(path) => {
            match children {
                None => {
                    Ok(false.into())
                }
                Some(children) => {
                    Ok(children.contains(&path).into())
                }
            }
        }
    }
}
pub fn children_on_path<V>(mounts: &BTreeMap<String, V>, path: &str) -> Option<Vec<String>> {
    let mut dirs: Vec<String> = Vec::new();
    let mut unique_dirs: HashSet<String> = HashSet::new();
    let mut dir_exists = false;
    for (key, _) in mounts.range(path.to_string()..) {
        if let Some(key_rest) = strip_prefix_path(key, path) {
            dir_exists = true;
            if !key_rest.is_empty() {
                let mut updirs = key_rest.split('/');
                if let Some(dir) = updirs.next()
                    && !unique_dirs.contains(dir) {
                        dirs.push(dir.to_string());
                        unique_dirs.insert(dir.to_string());
                    }
            }
        } else {
            break;
        }
    }
    if dir_exists {
        Some(dirs)
    } else {
        None
    }
}
pub fn find_longest_prefix<'a, V>(map: &BTreeMap<String, V>, shv_path: &'a str) -> Option<(&'a str, &'a str)> {
    let mut path = shv_path;
    let mut rest = "";
    loop {
        if map.contains_key(path) {
            return Some((path, rest))
        }
        if path.is_empty() {
            break;
        }
        if let Some(slash_ix) = path.rfind('/') {
            path = &shv_path[..slash_ix];
            rest = &shv_path[(slash_ix + 1)..];
        } else {
            path = "";
            rest = shv_path;
        };
    }
    None
}
pub(crate) enum ProcessRequestRetval {
    MethodNotFound,
    RetvalDeferred,
    Retval(RpcValue),
}
pub(crate) type ProcessRequestResult = Result<ProcessRequestRetval, shvrpc::Error>;
pub(crate) trait ShvNode : Send + Sync {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod];
    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>>;
    fn is_request_granted(&self, rq: &RpcFrame, _ctx: &NodeRequestContext) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        let methods = self.methods(shv_path);
        is_request_granted_methods(methods, rq)
    }
    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult;
}
impl dyn ShvNode {
    pub fn process_request_and_dir_ls(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        let result = self.process_request(frame, ctx);
        if let Ok(ProcessRequestRetval::MethodNotFound) = result {
            match frame.method().unwrap_or_default() {
                METH_DIR => {
                    let shv_path = frame.shv_path().unwrap_or_default();
                    let rq = frame.to_rpcmesage()?;
                    let resp = dir(self.methods(shv_path).iter().copied(), rq.param().into());
                    Ok(ProcessRequestRetval::Retval(resp))
                }
                METH_LS => {
                    let shv_path = frame.shv_path().unwrap_or_default();
                    let rq = frame.to_rpcmesage()?;
                    if let Some(children) = self.children(shv_path, &ctx.state) {
                        match LsParam::from(rq.param()) {
                            LsParam::List => {
                                Ok(ProcessRequestRetval::Retval(children.into()))
                            }
                            LsParam::Exists(path) => {
                                Ok(ProcessRequestRetval::Retval(children.iter().any(|s| s == &path).into()))
                            }
                        }

                    } else {
                        Err(format!("Invalid path: {shv_path}.").into())
                    }
                }
                _ => { Ok(ProcessRequestRetval::MethodNotFound) }
            }
        } else {
            result
        }
    }
}
pub fn is_request_granted_methods(methods: &'static[&'static MetaMethod], rq: &RpcFrame) -> bool {
    if let Some(rq_access) = rq.access_level() {
        let method = rq.method().unwrap_or_default();
        for mm in methods {
            if mm.name == method {
                return rq_access >= mm.access as i32
            }
        }
    }
    false
}

pub const METH_SHV_VERSION_MAJOR: &str = "shvVersionMajor";
pub const METH_SHV_VERSION_MINOR: &str = "shvVersionMinor";
pub const METH_VERSION: &str = "version";
pub const METH_SERIAL_NUMBER: &str = "serialNumber";


pub struct AppNode {
    pub shv_version_major: i32,
    pub shv_version_minor: i32,
}
impl AppNode {
    pub(crate) fn new() -> Self {
        AppNode {
            shv_version_major: 3,
            shv_version_minor: 0,
        }
    }
}

const META_METH_APP_SHV_VERSION_MAJOR: MetaMethod = MetaMethod { name: METH_SHV_VERSION_MAJOR, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "i", signals: &[], description: "" };
const META_METH_APP_SHV_VERSION_MINOR: MetaMethod = MetaMethod { name: METH_SHV_VERSION_MINOR, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "i", signals: &[], description: "" };
const META_METH_APP_NAME: MetaMethod = MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "s", signals: &[], description: "" };
const META_METH_APP_VERSION: MetaMethod = MetaMethod { name: METH_VERSION, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "s", signals: &[], description: "" };
const META_METH_APP_PING: MetaMethod = MetaMethod { name: METH_PING, flags: Flag::None as u32, access: AccessLevel::Browse, param: "", result: "n", signals: &[], description: "" };

const APP_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_APP_SHV_VERSION_MAJOR,
    &META_METH_APP_SHV_VERSION_MINOR,
    &META_METH_APP_NAME,
    &META_METH_APP_VERSION,
    &META_METH_APP_PING
];

impl ShvNode for AppNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        APP_NODE_METHODS
    }

    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_NAME => {
                Ok(ProcessRequestRetval::Retval(env!("CARGO_PKG_NAME").into()))
            }
            METH_VERSION => {
                Ok(ProcessRequestRetval::Retval(env!("CARGO_PKG_VERSION").into()))
            }
            METH_SHV_VERSION_MAJOR => {
                Ok(ProcessRequestRetval::Retval(self.shv_version_major.into()))
            }
            METH_SHV_VERSION_MINOR => {
                Ok(ProcessRequestRetval::Retval(self.shv_version_minor.into()))
            }
            METH_PING => {
                Ok(ProcessRequestRetval::Retval(().into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

const META_METH_VERSION: MetaMethod = MetaMethod { name: METH_VERSION, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", signals: &[], description: "" };
const META_METH_NAME: MetaMethod = MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", signals: &[], description: "" };
const META_METH_SERIAL_NUMBER: MetaMethod = MetaMethod { name: "serialNumber", flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", signals: &[], description: "" };

pub struct AppDeviceNode {
    pub device_name: &'static str,
    pub version: &'static str,
    pub serial_number: Option<String>,
}

const APP_DEVICE_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_NAME,
    &META_METH_VERSION,
    &META_METH_SERIAL_NUMBER
];

impl ShvNode for AppDeviceNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        APP_DEVICE_NODE_METHODS
    }

    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_NAME => {
                Ok(ProcessRequestRetval::Retval(self.device_name.into()))
            }
            METH_VERSION => {
                Ok(ProcessRequestRetval::Retval(self.version.into()))
            }
            METH_SERIAL_NUMBER => {
                Ok(ProcessRequestRetval::Retval(self.serial_number.as_ref().map(|s| s.to_string()).unwrap_or_default().into()))
            }
            METH_PING => {
                Ok(ProcessRequestRetval::Retval(().into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub const DIR_BROKER: &str = ".broker";
pub const DIR_BROKER_CURRENT_CLIENT: &str = ".broker/currentClient";
pub const DIR_BROKER_ACCESS_MOUNTS: &str = ".broker/access/mounts";
pub const DIR_BROKER_ACCESS_USERS: &str = ".broker/access/users";
pub const DIR_BROKER_ACCESS_ROLES: &str = ".broker/access/roles";

pub const DIR_SHV2_BROKER_APP: &str = ".broker/app";
pub const DIR_SHV2_BROKER_ETC_ACL_USERS: &str = ".broker/etc/acl/users";
pub const DIR_SHV2_BROKER_ETC_ACL_ROLES: &str = ".broker/etc/acl/roles";
pub const DIR_SHV2_BROKER_ETC_ACL_ACCESS: &str = ".broker/etc/acl/access";
pub const DIR_SHV2_BROKER_ETC_ACL_MOUNTS: &str = ".broker/etc/acl/mounts";

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
pub const METH_SUBSCRIPTIONS: &str = "subscriptions";
pub const METH_CHANGE_PASSWORD: &str = "changePassword";
pub const METH_ACCESS_LEVEL_FOR_METHOD_CALL: &str = "accessLevelForMethodCall";
pub const METH_USER_PROFILE: &str = "userProfile";
pub const METH_USER_ROLES: &str = "userRoles";


pub(crate) struct BrokerNode {}
impl BrokerNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}
const BROKER_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_CLIENT_INFO,
    &META_METH_MOUNTED_CLIENT_INFO,
    &META_METH_CLIENTS,
    &META_METH_MOUNTS,
    &META_METH_DISCONNECT_CLIENT,
];

impl ShvNode for BrokerNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_NODE_METHODS
    }

    fn children(&self, shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let peer_id: PeerId = rq.param().unwrap_or_default().as_i64();
                let info = match state_reader(&ctx.state).client_info(peer_id) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_MOUNTED_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let mount_point = rq.param().unwrap_or_default().as_str();
                let info = match state_reader(&ctx.state).mounted_client_info(mount_point) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_CLIENTS => {
                let clients: rpcvalue::List = state_reader(&ctx.state).peers.keys().map(|id| RpcValue::from(*id)).collect();
                Ok(ProcessRequestRetval::Retval(clients.into()))
            }
            METH_MOUNTS => {
                let mounts: List = state_reader(&ctx.state).peers.values()
                    .filter(|peer| peer.mount_point.is_some())
                    .map(|peer| if let Some(mount_point) = &peer.mount_point {RpcValue::from(mount_point)} else { RpcValue::null() } )
                    .collect();
                Ok(ProcessRequestRetval::Retval(mounts.into()))
            }
            METH_DISCONNECT_CLIENT => {
                if let Some(peer) = state_reader(&ctx.state).peers.get(&ctx.peer_id) {
                    let peer_sender = peer.sender.clone();
                    smol::spawn(async move {
                        let _ = peer_sender.send(BrokerToPeerMessage::DisconnectByBroker).await;
                    }).detach();
                    Ok(ProcessRequestRetval::Retval(().into()))
                } else {
                    Err(format!("Disconnect client error - peer {} not found.", ctx.peer_id).into())
                }
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

const META_METH_INFO: MetaMethod = MetaMethod { name: METH_INFO, flags: Flag::None as u32, access: AccessLevel::Browse, param: "Int", result: "ClientInfo", signals: &[], description: "" };
const META_METH_SUBSCRIBE: MetaMethod = MetaMethod { name: METH_SUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_UNSUBSCRIBE: MetaMethod = MetaMethod { name: METH_UNSUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_SUBSCRIPTIONS: MetaMethod = MetaMethod { name: METH_SUBSCRIPTIONS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "void", result: "Map", signals: &[], description: "" };
const META_METH_CHANGE_PASSWORD: MetaMethod = MetaMethod { name: METH_CHANGE_PASSWORD, flags: Flag::None as u32, access: AccessLevel::Write, param: "[s:old_password,s:new_password]", result: "Bool", signals: &[], description: r#"(params: ["old_password", "new_password"], old and new passwords are in plain format)"# };
const META_METH_ACCESS_LEVEL_FOR_METHOD_CALL: MetaMethod = MetaMethod { name: METH_ACCESS_LEVEL_FOR_METHOD_CALL, flags: Flag::None as u32, access: AccessLevel::Read, param: "[s:path,s:method]", result: "Int", signals: &[], description: r#"(params: ["shv_path", "method"]"# };
const META_METH_USER_PROFILE: MetaMethod = MetaMethod { name: METH_USER_PROFILE, flags: Flag::None as u32, access: AccessLevel::Read, param: "void", result: "RpcValue", signals: &[], description: "" };
const META_METH_USER_ROLES: MetaMethod = MetaMethod { name: METH_USER_ROLES, flags: Flag::None as u32, access: AccessLevel::Read, param: "void", result: "List", signals: &[], description: "" };

pub(crate) struct BrokerCurrentClientNode {}
impl BrokerCurrentClientNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

const BROKER_CURRENT_CLIENT_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_INFO,
    &META_METH_SUBSCRIBE,
    &META_METH_UNSUBSCRIBE,
    &META_METH_SUBSCRIPTIONS,
    &META_METH_CHANGE_PASSWORD,
    &META_METH_ACCESS_LEVEL_FOR_METHOD_CALL,
    &META_METH_USER_PROFILE,
    &META_METH_USER_ROLES,
];

impl BrokerCurrentClientNode {
    fn subscribe(peer_id: PeerId, subpar: &SubscriptionParam, state: &SharedBrokerState) -> shvrpc::Result<bool> {
        let res = state_writer(state).subscribe(peer_id, subpar);
        log!(target: "Subscr", Level::Debug, "subscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
    fn unsubscribe(peer_id: PeerId, subpar: &SubscriptionParam, state: &SharedBrokerState) -> shvrpc::Result<bool> {
        let res = state_writer(state).unsubscribe(peer_id, subpar);
        log!(target: "Subscr", Level::Debug, "unsubscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
}

impl ShvNode for BrokerCurrentClientNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_CURRENT_CLIENT_NODE_METHODS
    }

    fn children(&self, _shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        Some(vec![])
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_SUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_added = Self::subscribe(ctx.peer_id, &subscription, &ctx.state)?;
                Ok(ProcessRequestRetval::Retval(subs_added.into()))
            }
            METH_UNSUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_removed = Self::unsubscribe(ctx.peer_id, &subscription, &ctx.state)?;
                Ok(ProcessRequestRetval::Retval(subs_removed.into()))
            }
            METH_SUBSCRIPTIONS => {
                let result = state_reader(&ctx.state).subscriptions(ctx.peer_id)?;
                Ok(ProcessRequestRetval::Retval(result.into()))
            }
            METH_INFO => {
                let info = match state_reader(&ctx.state).client_info(ctx.peer_id) {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_CHANGE_PASSWORD => {
                const WRONG_FORMAT_ERR: &str = r#"Expected params format: ["<old_password>", "<new_password>"]"#;
                if !ctx.sql_available {
                    return Err("Cannot change password, access database is not available.".into());
                }
                let rq = &frame.to_rpcmesage()?;
                let mut params = rq
                    .param()
                    .ok_or_else(|| WRONG_FORMAT_ERR.to_string())
                    .and_then(|rv| Vec::<String>::try_from(rv)
                        .map_err(|e| format!("{WRONG_FORMAT_ERR}. Error: {e}"))
                    )?
                    .into_iter();

                let (old_password, new_password) = match (params.next(), params.next()) {
                    (Some(old_password), Some(new_password)) => (old_password, new_password),
                    _ => return Err(WRONG_FORMAT_ERR.into()),
                };

                if old_password.is_empty() || new_password.is_empty() {
                    return Err("Both old and new password mustn't be empty.".into());
                }

                let mut state = state_writer(&ctx.state);
                let Some(user_name) = state.peer_user(ctx.peer_id).map(String::from) else {
                    return Err("Undefined user".into());
                };
                if user_name.starts_with("ldap:") {
                    return Err("Can't change password, because you are logged in over LDAP".into());
                }
                if user_name.starts_with("azure:") {
                    return Err("Can't change password, because you are logged in over Azure".into());
                }
                let Some(mut user) = state.access_user(&user_name).cloned() else {
                    return Err(format!("Invalid user: {user_name})").into());
                };
                let current_password_sha1 = match &user.password {
                    crate::config::Password::Plain(password) => shvrpc::util::sha1_hash(password.as_bytes()),
                    crate::config::Password::Sha1(password) => password.clone(),
                };

                let old_password_sha1 = shvrpc::util::sha1_hash(old_password.as_bytes());

                if old_password_sha1 != current_password_sha1 {
                    return Err("Old password does not match.".into());
                }

                let new_password_sha1 = shvrpc::util::sha1_hash(new_password.as_bytes());
                user.password = crate::config::Password::Sha1(new_password_sha1);
                state.set_access_user(&user_name, Some(user));

                Ok(ProcessRequestRetval::Retval(true.into()))
            }
            METH_ACCESS_LEVEL_FOR_METHOD_CALL => {
                const WRONG_FORMAT_ERR: &str = r#"Expected params format: ["<shv_path>", "<method>"]"#;
                let rq = &frame.to_rpcmesage()?;
                let mut params = rq
                    .param()
                    .ok_or_else(|| WRONG_FORMAT_ERR.into())
                    .and_then(|rv| Vec::<String>::try_from(rv)
                        .map_err(|e| format!("{WRONG_FORMAT_ERR}. Error: {e}"))
                    )?
                    .into_iter();

                let (shv_path, method) = match (params.next(), params.next()) {
                    (Some(path), Some(method)) => (path, method),
                    _ => return Err(WRONG_FORMAT_ERR.into()),
                };

                let access_level = state_reader(&ctx.state)
                    .access_level_for_request_params(
                        ctx.peer_id,
                        &shv_path,
                        &method,
                        frame.tag(shvrpc::rpcmessage::Tag::AccessLevel as _).map(RpcValue::as_i32),
                        frame.tag(shvrpc::rpcmessage::Tag::Access as _).map(RpcValue::as_str),
                    )
                    .map(|(access_level, _)| access_level.unwrap_or_default())
                    .or_else(|rpc_err| if rpc_err.code == RpcErrorCode::PermissionDenied {
                        Ok(0)
                    } else {
                        Err(rpc_err)
                    })?;

                Ok(ProcessRequestRetval::Retval(access_level.into()))
            }
            METH_USER_PROFILE => {
                let state = state_reader(&ctx.state);
                let Some(user_name) = state.peer_user(ctx.peer_id) else {
                    return Err("Undefined user".into());
                };
                let merged_profile = state
                    .flatten_roles(user_name)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|role| state.access_role(role))
                    .filter_map(|role| role.profile.clone())
                    .fold(crate::config::ProfileValue::Null, |mut res, profile| {
                        res.merge(profile);
                        res
                    });
                Ok(ProcessRequestRetval::Retval(shvproto::to_rpcvalue(&merged_profile)?))
            }
            METH_USER_ROLES => {
                let state = state_reader(&ctx.state);
                let Some(user_name) = state.peer_user(ctx.peer_id) else {
                    return Err("Undefined user".into());
                };

                let result = state.flatten_roles(user_name).ok_or_else(|| RpcError::new(RpcErrorCode::InternalError, "A user needs to have at least one role defined"))?;
                Ok(ProcessRequestRetval::Retval(result.into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

const META_METHOD_PRIVATE_DIR: MetaMethod = MetaMethod { name: METH_DIR, flags: Flag::None as u32, access: AccessLevel::Read, param: "DirParam", result: "DirResult", signals: &[], description: "" };
const META_METHOD_PRIVATE_LS: MetaMethod = MetaMethod { name: METH_LS, flags: Flag::None as u32, access: AccessLevel::Read, param: "LsParam", result: "LsResult", signals: &[], description: "" };

pub const METH_VALUE: &str = "value";
pub const METH_SET_VALUE: &str = "setValue";
const META_METH_VALUE: MetaMethod = MetaMethod { name: METH_VALUE, flags: Flag::None as u32, access: AccessLevel::Read, param: "void", result: "Map", signals: &[], description: "" };
const META_METH_SET_VALUE: MetaMethod = MetaMethod { name: METH_SET_VALUE, flags: Flag::None as u32, access: AccessLevel::Write, param: "[String, Map | Null]", result: "void", signals: &[], description: "" };
const ACCESS_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_SET_VALUE];
const ACCESS_VALUE_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_VALUE];
pub(crate) struct BrokerAccessMountsNode {}
impl BrokerAccessMountsNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}
fn make_access_ro_error() -> String {
    "Broker config is read only, use --use-access-db config option.".to_string()
}
impl ShvNode for BrokerAccessMountsNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            ACCESS_NODE_METHODS
        } else {
            ACCESS_VALUE_NODE_METHODS
        }
    }

    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(state_reader(broker_state).access.mounts.keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match state_reader(&ctx.state).access_mount(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(mount) => {
                        Ok(ProcessRequestRetval::Retval(mount.to_rpcvalue()?))
                    }
                }
            }
            METH_SET_VALUE => {
                if !ctx.sql_available {
                    return Err(make_access_ro_error().into())
                }
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let mount = param.get(1).and_then(|m| if m.is_null() {None} else {Some(m)});
                let mount = mount.map(crate::config::Mount::try_from);
                let mount = match mount {
                    None => None,
                    Some(Ok(mount)) => {Some(mount)}
                    Some(Err(e)) => { return Err(e.into() )}
                };
                state_writer(&ctx.state).set_access_mount(key.as_str(), mount);
                Ok(ProcessRequestRetval::Retval(().into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessUsersNode {}
impl BrokerAccessUsersNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

impl ShvNode for crate::shvnode::BrokerAccessUsersNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            ACCESS_NODE_METHODS
        } else {
            ACCESS_VALUE_NODE_METHODS
        }
    }

    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(state_reader(broker_state).access.users.keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match state_reader(&ctx.state).access_user(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(user) => {
                        Ok(ProcessRequestRetval::Retval(user.to_rpcvalue()?))
                    }
                }
            }
            METH_SET_VALUE => {
                if !ctx.sql_available {
                    return Err(make_access_ro_error().into())
                }
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let rv = param.get(1).and_then(|m| if m.is_null() {None} else {Some(m)});
                let user = if let Some(rv) = rv {
                    match crate::config::User::try_from(rv) {
                        Ok(user) => { Some(user) }
                        Err(e) => {
                            return Err(e.into())
                        }
                    }
                } else {
                    None
                };
                state_writer(&ctx.state).set_access_user(key.as_str(), user);
                Ok(ProcessRequestRetval::Retval(().into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessRolesNode {}
impl crate::shvnode::BrokerAccessRolesNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
}

impl ShvNode for BrokerAccessRolesNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            ACCESS_NODE_METHODS
        } else {
            ACCESS_VALUE_NODE_METHODS
        }
    }

    fn children(&self, shv_path: &str, broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(state_reader(broker_state).access.roles.keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match state_reader(&ctx.state).access_role(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(role) => {
                        Ok(ProcessRequestRetval::Retval(role.to_rpcvalue()?))
                    }
                }
            }
            METH_SET_VALUE => {
                if !ctx.sql_available {
                    return Err(make_access_ro_error().into())
                }
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let rv = param.get(1).and_then(|m| if m.is_null() {None} else {Some(m)});
                let role = rv.map(crate::config::Role::try_from);
                let role = match role {
                    None => None,
                    Some(Ok(role)) => {Some(role)}
                    Some(Err(e)) => { return Err(e.into() )}
                };
                state_writer(&ctx.state).set_access_role(key.as_str(), role).map(|_| ProcessRequestRetval::Retval(().into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub const SHV2_METH_APP_VERSION: &str = "appVersion";
const SHV2_META_METH_APP_VERSION: MetaMethod = MetaMethod { name: SHV2_METH_APP_VERSION, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", signals: &[], description: "" };
const SHV2_BROKER_APP_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_APP_NAME, &SHV2_META_METH_APP_VERSION, &META_METH_APP_PING, &META_METH_SUBSCRIBE, &META_METH_UNSUBSCRIBE];

pub(crate) struct Shv2BrokerAppNode {}
impl Shv2BrokerAppNode {
    pub(crate) fn new() -> Self {
        Self {
        }
    }
    fn subscribe(peer_id: PeerId, subpar: &SubscriptionParam, state: &SharedBrokerState) -> shvrpc::Result<bool> {
        let ri_to_shv2_compat = |ri: &shvrpc::rpc::ShvRI| {
            let path = if !ri.path().ends_with("/**") {
                format!("{path}/**", path = ri.path())
            } else {
                ri.path().into()
            };
            shvrpc::rpc::ShvRI::from_path_method_signal(&path, ri.method(), ri.signal())
        };
        let subpar = SubscriptionParam {
            ri: ri_to_shv2_compat(&subpar.ri)
                .map_err(|err| format!("Cannot convert RI '{ri}' to shv2 compatible equivalent: {err}", ri = subpar.ri.as_str()))?,
            ttl: subpar.ttl,
        };
        let res = state_writer(state).subscribe(peer_id, &subpar);
        log!(target: "Subscr", Level::Debug, "subscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
    fn unsubscribe(peer_id: PeerId, subpar: &SubscriptionParam, state: &SharedBrokerState) -> shvrpc::Result<bool> {
        let res = state_writer(state).unsubscribe(peer_id, subpar);
        log!(target: "Subscr", Level::Debug, "unsubscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
}

impl ShvNode for Shv2BrokerAppNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        SHV2_BROKER_APP_NODE_METHODS
    }

    fn children(&self, _shv_path: &str, _broker_state: &SharedBrokerState) -> Option<Vec<String>> {
        Some(vec![])
    }

    fn process_request(&mut self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_PING => {
                Ok(ProcessRequestRetval::Retval(().into()))
            }
            METH_NAME => {
                Ok(ProcessRequestRetval::Retval(env!("CARGO_PKG_NAME").into()))
            }
            SHV2_METH_APP_VERSION => {
                Ok(ProcessRequestRetval::Retval(env!("CARGO_PKG_VERSION").into()))
            }
            METH_SUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_added = Self::subscribe(ctx.peer_id, &subscription, &ctx.state)?;
                Ok(ProcessRequestRetval::Retval(subs_added.into()))
            }
            METH_UNSUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_removed = Self::unsubscribe(ctx.peer_id, &subscription, &ctx.state)?;
                Ok(ProcessRequestRetval::Retval(subs_removed.into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_mounts() {
        let mut mounts = BTreeMap::new();
        mounts.insert(".broker".into(), ());
        mounts.insert(".broker/client/1".into(), ());
        mounts.insert(".broker/client/2".into(), ());
        mounts.insert(".broker/currentClient".into(), ());
        mounts.insert("test/device".into(), ());

        assert_eq!(super::find_longest_prefix(&mounts, ".broker/client"), Some((".broker", "client")));
        assert_eq!(super::find_longest_prefix(&mounts, "test"), None);
        assert_eq!(super::find_longest_prefix(&mounts, "test/device"), Some(("test/device", "")));
        assert_eq!(super::find_longest_prefix(&mounts, "test/devic"), None);

        assert_eq!(super::children_on_path(&mounts, ""), Some(vec![".broker", "test"].into_iter().map(|s| s.to_string()).collect()));
        assert_eq!(super::children_on_path(&mounts, ".broker"), Some(vec!["client", "currentClient"].into_iter().map(|s| s.to_string()).collect()));
        assert_eq!(super::children_on_path(&mounts, ".broker/client"), Some(vec!["1", "2"].into_iter().map(|s| s.to_string()).collect()));
        assert_eq!(super::children_on_path(&mounts, "test"), Some(vec!["device"].into_iter().map(|s| s.to_string()).collect()));
        assert_eq!(super::children_on_path(&mounts, ".broker/currentClient"), Some(vec![].into_iter().map(|s: &str/* Type */| s.to_string()).collect()));
        assert_eq!(super::children_on_path(&mounts, "test/device/1"), None);
        assert_eq!(super::children_on_path(&mounts, "test1"), None);
        assert_eq!(super::children_on_path(&mounts, "test/devic"), None);
    }
}
