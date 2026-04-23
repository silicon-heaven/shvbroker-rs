use std::collections::{BTreeMap, HashMap};
use std::format;
use std::sync::Arc;
use log::{Level, log};
use shvrpc::metamethod::{Flags, MetaMethod};
use shvrpc::util::{children_on_path, find_longest_path_prefix};
use shvrpc::{metamethod, RpcMessageMetaTags};
use shvproto::{List, RpcValue, rpcvalue};
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpc::SubscriptionParam;
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode};
use futures::channel::mpsc::UnboundedSender;
use crate::brokerimpl::{BrokerImpl, BrokerToPeerMessage, LastLogin, ParsedAccessRule, Peer, SubscriptionCommand, user_base_roles};
use crate::config::AccessConfig;
use smol::lock::RwLock;
use crate::brokerimpl::NodeRequestContext;

pub const METH_DIR: &str = "dir";
pub const METH_LS: &str = "ls";
pub const METH_GET: &str = "get";
pub const METH_SET: &str = "set";
pub const SIG_CHNG: &str = "chng";
pub const SIG_LSMOD: &str = "lsmod";
pub const SIG_MNTMOD: &str = "mntmod";
pub const METH_NAME: &str = "name";
pub const METH_PING: &str = "ping";
pub const METH_SUBSCRIBE: &str = "subscribe";
pub const METH_UNSUBSCRIBE: &str = "unsubscribe";

pub const META_METHOD_PUBLIC_DIR: MetaMethod = MetaMethod::new_static(METH_DIR, Flags::empty(), AccessLevel::Browse, "DirParam",  "DirResult", &[], "");
pub const META_METHOD_PUBLIC_LS: MetaMethod = MetaMethod::new_static(METH_LS, Flags::empty(), AccessLevel::Browse, "LsParam",  "LsResult", &[], "");
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
            Some(rpcval) if rpcval.is_string() => DirParam::MethodExists(rpcval.as_str().into()),
            Some(rpcval) if rpcval.as_bool() => DirParam::Full,
            Some(_) | None => DirParam::Brief,
        }
    }
}

pub fn dir<'a>(mut methods: impl Iterator<Item=&'a MetaMethod>, param: DirParam) -> RpcValue {
    let serializer = match param {
        DirParam::MethodExists(method_name) => return methods.any(|mm| mm.name == method_name).into(),
        DirParam::Brief => metamethod::DirFormat::IMap,
        DirParam::Full => metamethod::DirFormat::Map,
    };

    methods.map(|mm| mm.to_rpcvalue(serializer)).collect::<Vec<_>>().into()
}

pub enum LsParam {
    List,
    Exists(String),
}

impl From<Option<&RpcValue>> for LsParam {
    fn from(value: Option<&RpcValue>) -> Self {
        match value {
            Some(rpcval) if rpcval.is_string() => LsParam::Exists(rpcval.as_str().into()),
            Some(_) | None => LsParam::List
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
    let mount_pair = find_longest_path_prefix(mounts, shv_path);
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
pub(crate) enum ProcessRequestRetval {
    MethodNotFound,
    RetvalDeferred,
    Retval(RpcValue),
}
pub(crate) type ProcessRequestResult = Result<ProcessRequestRetval, shvrpc::Error>;
#[async_trait::async_trait]
pub(crate) trait ShvNode : Send + Sync {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod];
    async fn children(&self, shv_path: &str) -> Option<Vec<String>>;
    async fn is_request_granted(&self, rq: &RpcFrame, _ctx: &NodeRequestContext) -> bool {
        let shv_path = rq.shv_path().unwrap_or_default();
        let methods = self.methods(shv_path);
        is_request_granted_methods(methods, rq)
    }
    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult;
}
impl dyn ShvNode {
    pub async fn process_request_and_dir_ls(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        let result = self.process_request(frame, ctx).await;
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
                    if let Some(children) = self.children(shv_path).await {
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

const META_METH_APP_SHV_VERSION_MAJOR: MetaMethod = MetaMethod::new_static(METH_SHV_VERSION_MAJOR, Flags::IsGetter, AccessLevel::Browse, "", "i", &[], "");
const META_METH_APP_SHV_VERSION_MINOR: MetaMethod = MetaMethod::new_static(METH_SHV_VERSION_MINOR, Flags::IsGetter, AccessLevel::Browse, "", "i", &[], "");
const META_METH_APP_NAME: MetaMethod = MetaMethod::new_static(METH_NAME, Flags::IsGetter, AccessLevel::Browse, "", "s", &[], "");
const META_METH_APP_VERSION: MetaMethod = MetaMethod::new_static(METH_VERSION, Flags::IsGetter, AccessLevel::Browse, "", "s", &[], "");
const META_METH_APP_PING: MetaMethod = MetaMethod::new_static(METH_PING, Flags::empty(), AccessLevel::Browse, "", "n", &[], "");

const APP_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_APP_SHV_VERSION_MAJOR,
    &META_METH_APP_SHV_VERSION_MINOR,
    &META_METH_APP_NAME,
    &META_METH_APP_VERSION,
    &META_METH_APP_PING
];

#[async_trait::async_trait]
impl ShvNode for AppNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        APP_NODE_METHODS
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    async fn process_request(&self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> ProcessRequestResult {
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

const META_METH_VERSION: MetaMethod = MetaMethod::new_static(METH_VERSION, Flags::IsGetter, AccessLevel::Browse, "", "", &[], "");
const META_METH_NAME: MetaMethod = MetaMethod::new_static(METH_NAME, Flags::IsGetter, AccessLevel::Browse, "", "", &[], "");
const META_METH_SERIAL_NUMBER: MetaMethod = MetaMethod::new_static("serialNumber", Flags::IsGetter, AccessLevel::Browse, "", "", &[], "");

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

#[async_trait::async_trait]
impl ShvNode for AppDeviceNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        APP_DEVICE_NODE_METHODS
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    async fn process_request(&self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> ProcessRequestResult {
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
pub const DIR_BROKER_ACCESS_ALLOWED_IPS: &str = ".broker/access/allowedIps";
pub const DIR_BROKER_ACCESS_LAST_LOGIN: &str = ".broker/access/lastLogin";

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
pub const METH_BROKER_ID: &str = "brokerId";

const META_METH_CLIENT_INFO: MetaMethod = MetaMethod::new_static(METH_CLIENT_INFO, Flags::empty(), AccessLevel::Service, "Int", "ClientInfo", &[], "");
const META_METH_MOUNTED_CLIENT_INFO: MetaMethod = MetaMethod::new_static(METH_MOUNTED_CLIENT_INFO, Flags::empty(), AccessLevel::Service, "String", "ClientInfo", &[], "");
const META_METH_CLIENTS: MetaMethod = MetaMethod::new_static(METH_CLIENTS, Flags::empty(), AccessLevel::SuperService, "void", "List[Int]", &[], "");
const META_METH_USER_ACCESS_LEVEL_FOR_METHOD_CALL: MetaMethod = MetaMethod::new_static(
    METH_USER_ACCESS_LEVEL_FOR_METHOD_CALL,
    Flags::empty(),
    AccessLevel::Service,
    "[s:username,s:path,s:method]",
    "Int",
    &[],
    r#"params: ["username", "shv_path", "method"]
    only works for currently logged-in clients"#,
);
const META_METH_MOUNTS: MetaMethod = MetaMethod::new_static(METH_MOUNTS, Flags::empty(), AccessLevel::SuperService, "void", "List[String]", &[], "");
const META_METH_DISCONNECT_CLIENT: MetaMethod = MetaMethod::new_static(METH_DISCONNECT_CLIENT, Flags::empty(), AccessLevel::SuperService, "Int", "void", &[], "");
const META_METH_BROKER_ID: MetaMethod = MetaMethod::new_static(METH_BROKER_ID, Flags::IsGetter, AccessLevel::Service, "", "String", &[], "");

pub const METH_INFO: &str = "info";
pub const METH_SUBSCRIPTIONS: &str = "subscriptions";
pub const METH_CHANGE_PASSWORD: &str = "changePassword";
pub const METH_ACCESS_LEVEL_FOR_METHOD_CALL: &str = "accessLevelForMethodCall";
pub const METH_USER_ACCESS_LEVEL_FOR_METHOD_CALL: &str = "userAccessLevelForMethodCall";
pub const METH_USER_PROFILE: &str = "userProfile";
pub const METH_USER_ROLES: &str = "userRoles";


pub(crate) struct BrokerNode {
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    broker_name: Option<String>,
    role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>,
    oauth2_user_groups: Arc<RwLock<BTreeMap<PeerId, Vec<String>>>>,
    access: Arc<RwLock<AccessConfig>>,
}

impl BrokerNode {
    pub(crate) fn new(peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>, broker_name: Option<String>, role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>, oauth2_user_groups: Arc<RwLock<BTreeMap<PeerId, Vec<String>>>>, access: Arc<RwLock<AccessConfig>>,) -> Self {
        Self {
            peers,
            broker_name,
            role_access_rules,
            oauth2_user_groups,
            access,
        }
    }
}
const BROKER_NODE_METHODS: &[&MetaMethod] = &[
    &META_METHOD_PUBLIC_DIR,
    &META_METHOD_PUBLIC_LS,
    &META_METH_CLIENT_INFO,
    &META_METH_MOUNTED_CLIENT_INFO,
    &META_METH_CLIENTS,
    &META_METH_USER_ACCESS_LEVEL_FOR_METHOD_CALL,
    &META_METH_MOUNTS,
    &META_METH_DISCONNECT_CLIENT,
    &META_METH_BROKER_ID,
];

#[async_trait::async_trait]
impl ShvNode for BrokerNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_NODE_METHODS
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(vec![])
        } else {
            None
        }
    }

    async fn process_request(&self, frame: &RpcFrame, _ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let peer_id: PeerId = rq.param().unwrap_or_default().try_into()?;
                let info = match client_info(&self.peers, peer_id).await {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_MOUNTED_CLIENT_INFO => {
                let rq = &frame.to_rpcmesage()?;
                let mount_point = rq.param().unwrap_or_default().try_into()?;
                let info = match BrokerImpl::mounted_client_info(&self.peers, mount_point).await {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_CLIENTS => {
                let clients: rpcvalue::List = self.peers.read().await.keys().map(|id| RpcValue::from(*id)).collect();
                Ok(ProcessRequestRetval::Retval(clients.into()))
            }
            METH_MOUNTS => {
                let mounts: List = self.peers.read().await.values()
                    .filter(|peer| peer.mount_point.is_some())
                    .map(|peer| if let Some(mount_point) = &peer.mount_point {RpcValue::from(mount_point)} else { RpcValue::null() } )
                    .collect();
                Ok(ProcessRequestRetval::Retval(mounts.into()))
            }
            METH_DISCONNECT_CLIENT => {
                let rq = &frame.to_rpcmesage()?;
                let peer_id: PeerId = rq.param().unwrap_or_default().try_into()?;
                if let Some(peer) = self.peers.read().await.get(&peer_id) {
                    let peer_sender = peer.sender.clone();
                    smol::spawn(async move {
                        let _ = peer_sender.unbounded_send(BrokerToPeerMessage::DisconnectByBroker {reason: Some(format!("Disconnected by .broker:{METH_DISCONNECT_CLIENT}"))});
                    }).detach();
                    Ok(ProcessRequestRetval::Retval(().into()))
                } else {
                    Err(format!("Disconnect client error - peer {peer_id} not found.").into())
                }
            }
            METH_BROKER_ID => {
                Ok(ProcessRequestRetval::Retval(self.broker_name.clone().into()))
            }
            METH_USER_ACCESS_LEVEL_FOR_METHOD_CALL => {
                const WRONG_FORMAT_ERR: &str = r#"Expected params format: ["<username>", "<shv_path>", "<method>"]"#;
                let rq = &frame.to_rpcmesage()?;
                let params = rq
                    .param()
                    .ok_or_else(|| WRONG_FORMAT_ERR.into())
                    .and_then(|rv| Vec::<String>::try_from(rv)
                        .map_err(|e| format!("{WRONG_FORMAT_ERR}. Error: {e}"))
                    )?;

                let [username, shv_path, method] = params.as_slice() else {
                    return Err(WRONG_FORMAT_ERR.into());
                };
                let Some(peer_id) = self.peers.read().await
                    .iter()
                    .find_map(|(peer_id, peer)| match &peer.peer_kind {
                        crate::brokerimpl::PeerKind::Client { user } | crate::brokerimpl::PeerKind::Device { user , ..} if user == username => Some(*peer_id),
                        _ => None,
                    }) else {
                        return Err("Couldn't determine access level".into());
                    };

                let access_level = BrokerImpl::access_level_for_request_params(
                    &self.peers,
                    &self.role_access_rules,
                    &self.oauth2_user_groups,
                    &self.access,
                    peer_id,
                    shv_path,
                    method,
                    None,
                )
                    .await
                    .map(|(access_level, _)| access_level.unwrap_or_default())
                    .or_else(|rpc_err| if rpc_err.code == RpcErrorCode::PermissionDenied.into() {
                        Ok(0)
                    } else {
                        Err(rpc_err)
                    })?;

                Ok(ProcessRequestRetval::Retval(access_level.into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

const META_METH_INFO: MetaMethod = MetaMethod::new_static(METH_INFO, Flags::empty(), AccessLevel::Browse, "Int", "ClientInfo", &[], "");
const META_METH_SUBSCRIBE: MetaMethod = MetaMethod::new_static(METH_SUBSCRIBE, Flags::empty(), AccessLevel::Browse, "SubscribeParams", "void", &[], "");
const META_METH_UNSUBSCRIBE: MetaMethod = MetaMethod::new_static(METH_UNSUBSCRIBE, Flags::empty(), AccessLevel::Browse, "SubscribeParams", "void", &[], "");
const META_METH_SUBSCRIPTIONS: MetaMethod = MetaMethod::new_static(METH_SUBSCRIPTIONS, Flags::empty(), AccessLevel::Browse, "void", "Map", &[], "");
const META_METH_CHANGE_PASSWORD: MetaMethod = MetaMethod::new_static(
    METH_CHANGE_PASSWORD,
    Flags::empty(),
    AccessLevel::Write,
    "[s:old_password,s:new_password]",
    "Bool",
    &[],
    r#"(params: ["old_password", "new_password"], old and new passwords are in plain format)"#
);
const META_METH_ACCESS_LEVEL_FOR_METHOD_CALL: MetaMethod = MetaMethod::new_static(
    METH_ACCESS_LEVEL_FOR_METHOD_CALL,
    Flags::empty(),
    AccessLevel::Read,
    "[s:path,s:method]",
    "Int",
    &[],
    r#"(params: ["shv_path", "method"]"#,
);

const META_METH_USER_PROFILE: MetaMethod = MetaMethod::new_static(METH_USER_PROFILE, Flags::empty(), AccessLevel::Read, "void", "RpcValue", &[], "");
const META_METH_USER_ROLES: MetaMethod = MetaMethod::new_static(METH_USER_ROLES, Flags::empty(), AccessLevel::Read, "void", "List", &[], "");

pub(crate) struct BrokerCurrentClientNode {
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    subscr_cmd_sender: UnboundedSender<SubscriptionCommand>,
    sql_connection: Option<async_sqlite::Client>,
    access: Arc<RwLock<AccessConfig>>,
    oauth2_user_groups: Arc<RwLock<BTreeMap<PeerId, Vec<String>>>>,
    role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>,
}
impl BrokerCurrentClientNode {
    pub(crate) fn new(
        peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
        subscr_cmd_sender: UnboundedSender<SubscriptionCommand>,
        sql_connection: Option<async_sqlite::Client>,
        access: Arc<RwLock<AccessConfig>>,
        oauth2_user_groups: Arc<RwLock<BTreeMap<PeerId, Vec<String>>>>,
        role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>,
    ) -> Self {
        Self {
            peers,
            subscr_cmd_sender,
            sql_connection,
            access,
            oauth2_user_groups,
            role_access_rules,
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
    async fn subscribe(&self, peer_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        let res = BrokerImpl::subscribe(&self.peers, &self.subscr_cmd_sender, peer_id, subpar).await;
        log!(target: "Subscr", Level::Debug, "subscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
    async fn unsubscribe(&self, peer_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        let res = BrokerImpl::unsubscribe(&self.peers, &self.subscr_cmd_sender, peer_id, subpar).await;
        log!(target: "Subscr", Level::Debug, "unsubscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
}

pub(crate) async fn client_info(peers: &RwLock<BTreeMap<PeerId, Peer>>, peer_id: PeerId) -> Option<rpcvalue::Map> {
    peers.read().await.get(&peer_id).map(BrokerImpl::peer_to_info)
}

#[async_trait::async_trait]
impl ShvNode for BrokerCurrentClientNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        BROKER_CURRENT_CLIENT_NODE_METHODS
    }

    async fn children(&self, _shv_path: &str) -> Option<Vec<String>> {
        Some(vec![])
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_SUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_added = self.subscribe(ctx.peer_id, &subscription).await?;
                Ok(ProcessRequestRetval::Retval(subs_added.into()))
            }
            METH_UNSUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_removed = self.unsubscribe(ctx.peer_id, &subscription).await?;
                Ok(ProcessRequestRetval::Retval(subs_removed.into()))
            }
            METH_SUBSCRIPTIONS => {
                let result = BrokerImpl::subscriptions(&self.peers, ctx.peer_id).await?;
                Ok(ProcessRequestRetval::Retval(result.into()))
            }
            METH_INFO => {
                let info = match client_info(&self.peers, ctx.peer_id).await {
                    None => { RpcValue::null() }
                    Some(info) => { RpcValue::from(info) }
                };
                Ok(ProcessRequestRetval::Retval(info))
            }
            METH_CHANGE_PASSWORD => {
                const WRONG_FORMAT_ERR: &str = r#"Expected params format: ["<old_password>", "<new_password>"]"#;
                let Some(sql_connection) = &self.sql_connection else {
                    return Err("Cannot change password, access database is not available.".into());
                };
                let rq = &frame.to_rpcmesage()?;
                let params = rq
                    .param()
                    .ok_or_else(|| WRONG_FORMAT_ERR.to_string())
                    .and_then(|rv| Vec::<String>::try_from(rv)
                        .map_err(|e| format!("{WRONG_FORMAT_ERR}. Error: {e}"))
                    )?;

                let [old_password, new_password] = params.as_slice() else {
                    return Err(WRONG_FORMAT_ERR.into());
                };

                if old_password.is_empty() || new_password.is_empty() {
                    return Err("Both old and new password mustn't be empty.".into());
                }

                let Some(user_name) = self.peers.read().await.get(&ctx.peer_id).map(Peer::user).map(ToOwned::to_owned) else {
                    return Err("Undefined user".into());
                };
                if user_name.starts_with("ldap:") {
                    return Err("Can't change password, because you are logged in over LDAP".into());
                }
                if user_name.starts_with("azure:") {
                    return Err("Can't change password, because you are logged in over Azure".into());
                }
                let mut access = self.access.write().await;
                let Some(user) = access.access_user(&user_name) else {
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
                let mut user = user.clone();
                user.password = crate::config::Password::Sha1(new_password_sha1);
                let res = access.set_access_user(&user_name, Some(user), sql_connection).await?;
                Ok(ProcessRequestRetval::Retval(res))
            }
            METH_ACCESS_LEVEL_FOR_METHOD_CALL => {
                const WRONG_FORMAT_ERR: &str = r#"Expected params format: ["<shv_path>", "<method>"]"#;
                let rq = &frame.to_rpcmesage()?;
                let params = rq
                    .param()
                    .ok_or_else(|| WRONG_FORMAT_ERR.into())
                    .and_then(|rv| Vec::<String>::try_from(rv)
                        .map_err(|e| format!("{WRONG_FORMAT_ERR}. Error: {e}"))
                    )?;

                let [shv_path, method] = params.as_slice() else {
                    return Err(WRONG_FORMAT_ERR.into());
                };

                let access_level = BrokerImpl::access_level_for_request_params(
                        &self.peers,
                        &self.role_access_rules,
                        &self.oauth2_user_groups,
                        &self.access,
                        ctx.peer_id,
                        shv_path,
                        method,
                        None,
                    )
                    .await
                    .map(|(access_level, _)| access_level.unwrap_or_default())
                    .or_else(|rpc_err| if rpc_err.code == RpcErrorCode::PermissionDenied.into() {
                        Ok(0)
                    } else {
                        Err(rpc_err)
                    })?;

                Ok(ProcessRequestRetval::Retval(access_level.into()))
            }
            METH_USER_PROFILE => {
                let peers = self.peers.read().await;
                let Some(peer) = peers.get(&ctx.peer_id) else {
                    return Err(RpcError::new(RpcErrorCode::InternalError, "Peer must exist").into());
                };
                let user_roles = user_base_roles(&*self.oauth2_user_groups.read().await, &*self.access.read().await, peer);
                let access = self.access.read().await;
                let merged_profile = access.flatten_roles(user_roles.as_slice())
                    .iter()
                    .flat_map(|role| access.access_role(role))
                    .flat_map(|role| role.profile.clone())
                    .fold(None, |mut res: Option<crate::config::ProfileValue>, profile| {
                        match &mut res {
                            Some(res) => res.merge(profile),
                            None => res = Some(profile),
                        }
                        res
                    });
                Ok(ProcessRequestRetval::Retval(shvproto::to_rpcvalue(&merged_profile)?))
            }
            METH_USER_ROLES => {
                let peers = self.peers.read().await;
                let Some(peer) = peers.get(&ctx.peer_id) else {
                    return Err(RpcError::new(RpcErrorCode::InternalError, "Peer must exist").into());
                };
                let user_roles = user_base_roles(&*self.oauth2_user_groups.read().await, &*self.access.read().await, peer);

                if user_roles.is_empty() {
                    return Err(RpcError::new(RpcErrorCode::InternalError, "A user needs to have at least one role defined").into());
                }

                Ok(ProcessRequestRetval::Retval(self.access.read().await.flatten_roles(user_roles.as_slice()).into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

const META_METHOD_PRIVATE_DIR: MetaMethod = MetaMethod::new_static(METH_DIR, Flags::empty(), AccessLevel::Read, "DirParam", "DirResult", &[], "");
const META_METHOD_PRIVATE_LS: MetaMethod = MetaMethod::new_static(METH_LS, Flags::empty(), AccessLevel::Read, "LsParam", "LsResult", &[], "");

pub const METH_VALUE: &str = "value";
pub const METH_SET_VALUE: &str = "setValue";
pub const METH_DEACTIVATE: &str = "deactivate";
pub const METH_ACTIVATE: &str = "activate";

const META_METH_VALUE: MetaMethod = MetaMethod::new_static(METH_VALUE, Flags::empty(), AccessLevel::Superuser, "void", "Map", &[], "");
const META_METH_SET_VALUE: MetaMethod = MetaMethod::new_static(METH_SET_VALUE, Flags::empty(), AccessLevel::Superuser, "[String, Map | Null]", "void", &[], "");
const META_METH_DEACTIVATE: MetaMethod = MetaMethod::new_static(METH_DEACTIVATE, Flags::empty(), AccessLevel::Superuser, "Null", "void", &[], "");
const META_METH_ACTIVATE: MetaMethod = MetaMethod::new_static(METH_ACTIVATE, Flags::empty(), AccessLevel::Superuser, "Null", "void", &[], "");
const SET_VALUE_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_SET_VALUE];
const VALUE_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_VALUE];
const USER_ACCESS_VALUE_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_VALUE, &META_METH_ACTIVATE, &META_METH_DEACTIVATE];
pub(crate) struct BrokerAccessMountsNode {
    sql_connection: Option<async_sqlite::Client>,
    access: Arc<RwLock<AccessConfig>>,
}
impl BrokerAccessMountsNode {
    pub(crate) fn new(sql_connection: Option<async_sqlite::Client>, access: Arc<RwLock<AccessConfig>>) -> Self {
        Self {
            sql_connection,
            access,
        }
    }
}
fn make_access_ro_error() -> String {
    "Broker config is read only, use --use-access-db config option.".to_string()
}
#[async_trait::async_trait]
impl ShvNode for BrokerAccessMountsNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            SET_VALUE_NODE_METHODS
        } else {
            VALUE_NODE_METHODS
        }
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.access.read().await.mounts().keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match self.access.read().await.access_mount(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(mount) => {
                        Ok(ProcessRequestRetval::Retval(mount.to_rpcvalue()?))
                    }
                }
            }
            METH_SET_VALUE => {
                let Some(sql_connection) = &self.sql_connection else {
                    return Err(make_access_ro_error().into())
                };
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let mount = param.get(1).filter(|&m| !m.is_null());
                let mount = mount.map(crate::config::Mount::try_from);
                let mount = match mount {
                    None => None,
                    Some(Ok(mount)) => {Some(mount)}
                    Some(Err(e)) => { return Err(e.into() )}
                };
                let res = self.access.write().await.set_access_mount(key.as_str(), mount, sql_connection).await?;
                Ok(ProcessRequestRetval::Retval(res))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessUsersNode {
    sql_connection: Option<async_sqlite::Client>,
    access: Arc<RwLock<AccessConfig>>,
}
impl BrokerAccessUsersNode {
    pub(crate) fn new(sql_connection: Option<async_sqlite::Client>, access: Arc<RwLock<AccessConfig>>) -> Self {
        Self {
            sql_connection,
            access,
        }
    }
}

#[async_trait::async_trait]
impl ShvNode for crate::shvnode::BrokerAccessUsersNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            SET_VALUE_NODE_METHODS
        } else {
            USER_ACCESS_VALUE_NODE_METHODS
        }
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.access.read().await.users().keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        const DEACTIVATE: bool = true;
        const ACTIVATE: bool = false;
        let process_activation_change = async |new_deactivated| {
            let Some(sql_connection) = &self.sql_connection else {
                return Err(make_access_ro_error().into())
            };
            let mut access = self.access.write().await;
            let user = access.access_user(&ctx.node_path).cloned();
            match user {
                None => {
                    Err(format!("Invalid node key: {}", &ctx.node_path).into())
                }
                Some(mut user) => {
                    if user.deactivated == new_deactivated {
                        return Err(format!("User {username} already {what}", username = &ctx.node_path, what = if new_deactivated { "deactivated" } else { "activated" }).into());
                    }
                    user.deactivated = new_deactivated;
                    let res = access.set_access_user(&ctx.node_path, Some(user), sql_connection).await?;
                    Ok(ProcessRequestRetval::Retval(res))
                }
            }
        };

        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match self.access.read().await.access_user(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(user) => {
                        Ok(ProcessRequestRetval::Retval(user.to_rpcvalue()?))
                    }
                }
            }
            METH_DEACTIVATE => process_activation_change(DEACTIVATE).await,
            METH_ACTIVATE => process_activation_change(ACTIVATE).await,
            METH_SET_VALUE => {
                let Some(sql_connection) = &self.sql_connection else {
                    return Err(make_access_ro_error().into())
                };
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let rv = param.get(1).filter(|&m| !m.is_null());
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
                let res = self.access.write().await.set_access_user(key.as_str(), user, sql_connection).await?;
                Ok(ProcessRequestRetval::Retval(res))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessRolesNode {
    sql_connection: Option<async_sqlite::Client>,
    access: Arc<RwLock<AccessConfig>>,
    role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>,
}
impl crate::shvnode::BrokerAccessRolesNode {
    pub(crate) fn new(sql_connection: Option<async_sqlite::Client>, access: Arc<RwLock<AccessConfig>>, role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>) -> Self {
        Self {
            sql_connection,
            access,
            role_access_rules,
        }
    }
}

#[async_trait::async_trait]
impl ShvNode for BrokerAccessRolesNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            SET_VALUE_NODE_METHODS
        } else {
            VALUE_NODE_METHODS
        }
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.access.read().await.roles().keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match self.access.read().await.access_role(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(role) => {
                        Ok(ProcessRequestRetval::Retval(role.to_rpcvalue()?))
                    }
                }
            }
            METH_SET_VALUE => {
                let Some(sql_connection) = &self.sql_connection else {
                    return Err(make_access_ro_error().into())
                };
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?.clone();
                let rv = param.get(1).filter(|&m| !m.is_null());
                let role = rv.map(crate::config::Role::try_from);
                let role = match role {
                    None => None,
                    Some(Ok(role)) => {Some(role)}
                    Some(Err(e)) => { return Err(e.into() )}
                };
                let res = self.access.write().await.set_access_role(key.as_str(), role, &self.role_access_rules, sql_connection).await?;
                Ok(ProcessRequestRetval::Retval(res))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessAllowedIpsNode {
    sql_connection: Option<async_sqlite::Client>,
    access: Arc<RwLock<AccessConfig>>,
}
impl BrokerAccessAllowedIpsNode {
    pub(crate) fn new(sql_connection: Option<async_sqlite::Client>, access: Arc<RwLock<AccessConfig>>) -> Self {
        Self {
            sql_connection,
            access,
        }
    }
}

#[async_trait::async_trait]
impl ShvNode for BrokerAccessAllowedIpsNode {
    fn methods(&self, shv_path: &str) -> &'static[&'static MetaMethod] {
        if shv_path.is_empty() {
            SET_VALUE_NODE_METHODS
        } else {
            VALUE_NODE_METHODS
        }
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.access.read().await.allowed_ips().keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                match self.access.read().await.access_allowed_ips(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(allowed_ips) => {
                        Ok(ProcessRequestRetval::Retval(serde_json::to_string(&allowed_ips)?.into()))
                    }
                }
            }
            METH_SET_VALUE => {
                let Some(sql_connection) = &self.sql_connection else {
                    return Err(make_access_ro_error().into())
                };
                let param = frame.to_rpcmesage()?.param().ok_or("Invalid params")?.clone();
                let param = param.as_list();
                let key = param.first().ok_or("Key is missing")?;
                let allowed_ips = param.get(1).filter(|&m| !m.is_null());
                let allowed_ips: Option<Result<Vec<ipnet::IpNet>,_>> = allowed_ips
                    .map(|val| val
                        .as_list()
                        .iter()
                        .map(|ip| ip
                            .as_str()
                            .parse()
                        ).collect::<Result<Vec<_>,_>>());
                let allowed_ips  = match allowed_ips {
                    None => None,
                    Some(Ok(allowed_ips)) => {Some(allowed_ips)}
                    Some(Err(e)) => { return Err(e.into() )}
                };
                let res = self.access.write().await.set_allowed_ips(key.as_str(), allowed_ips, sql_connection).await?;
                Ok(ProcessRequestRetval::Retval(res))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub(crate) struct BrokerAccessLastLoginNode {
    last_login: Arc<RwLock<LastLogin>>,
}
impl BrokerAccessLastLoginNode {
    pub(crate) fn new(last_login: Arc<RwLock<LastLogin>>) -> Self {
        Self {
            last_login,
        }
    }
}

#[async_trait::async_trait]
impl ShvNode for BrokerAccessLastLoginNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        VALUE_NODE_METHODS
    }

    async fn children(&self, shv_path: &str) -> Option<Vec<String>> {
        if shv_path.is_empty() {
            Some(self.last_login.read().await.get().keys().map(|m| m.to_string()).collect())
        } else {
            Some(vec![])
        }
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
        match frame.method().unwrap_or_default() {
            METH_VALUE => {
                if ctx.node_path.is_empty() {
                    return Ok(ProcessRequestRetval::Retval(self.last_login.read().await.get().clone().into()));
                }

                match self.last_login.read().await.get().get(&ctx.node_path) {
                    None => {
                        Err(format!("Invalid node key: {}", &ctx.node_path).into())
                    }
                    Some(dt) => {
                        Ok(ProcessRequestRetval::Retval(shvproto::to_rpcvalue(&dt)?))
                    }
                }
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}

pub const SHV2_METH_APP_VERSION: &str = "appVersion";
const SHV2_META_METH_APP_VERSION: MetaMethod = MetaMethod::new_static(SHV2_METH_APP_VERSION, Flags::IsGetter, AccessLevel::Browse, "", "", &[], "");
const SHV2_BROKER_APP_NODE_METHODS: &[&MetaMethod] = &[&META_METHOD_PRIVATE_DIR, &META_METHOD_PRIVATE_LS, &META_METH_APP_NAME, &SHV2_META_METH_APP_VERSION, &META_METH_APP_PING, &META_METH_SUBSCRIBE, &META_METH_UNSUBSCRIBE];

pub(crate) struct Shv2BrokerAppNode {
    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    subscr_cmd_sender: UnboundedSender<SubscriptionCommand>,
}
impl Shv2BrokerAppNode {
    pub(crate) fn new(peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>, subscr_cmd_sender: UnboundedSender<SubscriptionCommand>) -> Self {
        Self {
            peers,
            subscr_cmd_sender,
        }
    }

    async fn subscribe(&self, peer_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
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
        let res = BrokerImpl::subscribe(&self.peers, &self.subscr_cmd_sender, peer_id, &subpar).await;
        log!(target: "Subscr", Level::Debug, "subscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }

    async fn unsubscribe(&self, peer_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        let res = BrokerImpl::unsubscribe(&self.peers, &self.subscr_cmd_sender, peer_id, subpar).await;
        log!(target: "Subscr", Level::Debug, "unsubscribe handler for peer id: {peer_id} - {subpar}, res: {res:?}");
        res
    }
}

#[async_trait::async_trait]
impl ShvNode for Shv2BrokerAppNode {
    fn methods(&self, _shv_path: &str) -> &'static[&'static MetaMethod] {
        SHV2_BROKER_APP_NODE_METHODS
    }

    async fn children(&self, _shv_path: &str) -> Option<Vec<String>> {
        Some(vec![])
    }

    async fn process_request(&self, frame: &RpcFrame, ctx: &NodeRequestContext) -> ProcessRequestResult {
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
                let subs_added = self.subscribe(ctx.peer_id, &subscription).await?;
                Ok(ProcessRequestRetval::Retval(subs_added.into()))
            }
            METH_UNSUBSCRIBE => {
                let rq = &frame.to_rpcmesage()?;
                let subscription = SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default())?;
                let subs_removed = self.unsubscribe(ctx.peer_id, &subscription).await?;
                Ok(ProcessRequestRetval::Retval(subs_removed.into()))
            }
            _ => {
                Ok(ProcessRequestRetval::MethodNotFound)
            }
        }
    }
}
