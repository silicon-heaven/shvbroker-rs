use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use crate::shvnode::{META_METHOD_DIR, META_METHOD_LS, ShvNode};

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
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_CLIENT_INFO,
            &META_METH_MOUNTED_CLIENT_INFO,
            &META_METH_CLIENTS,
            &META_METH_MOUNTS,
            &META_METH_DISCONNECT_CLIENT,
        ] }
    }
}

const META_METH_INFO: MetaMethod = MetaMethod { name: METH_INFO, flags: Flag::None as u32, access: AccessLevel::Browse, param: "Int", result: "ClientInfo", signals: &[], description: "" };
const META_METH_SUBSCRIBE: MetaMethod = MetaMethod { name: METH_SUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_UNSUBSCRIBE: MetaMethod = MetaMethod { name: METH_UNSUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", signals: &[], description: "" };
const META_METH_SUBSCRIPTIONS: MetaMethod = MetaMethod { name: METH_SUBSCRIPTIONS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "void", result: "List", signals: &[], description: "" };

pub(crate) struct BrokerCurrentClientNode {}
impl BrokerCurrentClientNode {
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_INFO,
            &META_METH_SUBSCRIBE,
            &META_METH_UNSUBSCRIBE,
            &META_METH_SUBSCRIPTIONS,
        ] }
    }
}
pub const METH_VALUE: &str = "value";
pub const METH_SET_VALUE: &str = "setValue";
const META_METH_VALUE: MetaMethod = MetaMethod { name: METH_VALUE, flags: Flag::None as u32, access: AccessLevel::Read, param: "void", result: "Map", signals: &[], description: "" };
const META_METH_SET_VALUE: MetaMethod = MetaMethod { name: METH_SET_VALUE, flags: Flag::None as u32, access: AccessLevel::Read, param: "[String, Map | Null]", result: "void", signals: &[], description: "" };
pub(crate) struct BrokerAccessMountsNode {}
impl BrokerAccessMountsNode {
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_SET_VALUE,
        ] }
    }
}
pub(crate) struct BrokerAccessUsersNode {}
impl crate::node::BrokerAccessUsersNode {
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: ACCESS_NODE_METHODS.into() }
    }
}
pub(crate) const ACCESS_NODE_METHODS: &[&MetaMethod; 3] = &[&META_METHOD_DIR, &META_METHOD_LS, &META_METH_SET_VALUE];
pub(crate) const ACCESS_VALUE_NODE_METHODS: &[&MetaMethod; 3] = &[&META_METHOD_DIR, &META_METHOD_LS, &META_METH_VALUE];
pub(crate) struct BrokerAccessRolesNode {}
impl crate::node::BrokerAccessRolesNode {
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_SET_VALUE,
        ] }
    }
}



