use shvrpc::metamethod::{AccessLevel, Flag, MetaMethod};
use crate::shvnode::{META_METHOD_DIR, META_METHOD_LS, ShvNode};

pub const DIR_APP_BROKER: &str = ".app/broker";
pub const DIR_APP_BROKER_CURRENTCLIENT: &str = ".app/broker/currentClient";

pub const METH_CLIENT_INFO: &str = "clientInfo";
pub const METH_MOUNTED_CLIENT_INFO: &str = "mountedClientInfo";
pub const METH_CLIENTS: &str = "clients";
pub const METH_MOUNTS: &str = "mounts";
pub const METH_DISCONNECT_CLIENT: &str = "disconnectClient";

const META_METH_CLIENT_INFO: MetaMethod = MetaMethod { name: METH_CLIENT_INFO, param: "Int", result: "ClientInfo", access: AccessLevel::Service, flags: Flag::None as u32, description: "" };
const META_METH_MOUNTED_CLIENT_INFO: MetaMethod = MetaMethod { name: METH_MOUNTED_CLIENT_INFO, param: "String", result: "ClientInfo", access: AccessLevel::Service, flags: Flag::None as u32, description: "" };
const META_METH_CLIENTS: MetaMethod = MetaMethod { name: METH_CLIENTS, param: "void", result: "List[Int]", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "" };
const META_METH_MOUNTS: MetaMethod = MetaMethod { name: METH_MOUNTS, param: "void", result: "List[String]", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "" };
const META_METH_DISCONNECT_CLIENT: MetaMethod = MetaMethod { name: METH_DISCONNECT_CLIENT, param: "Int", result: "void", access: AccessLevel::SuperService, flags: Flag::None as u32, description: "" };
// pub enum BrokerNodeCommand {
//     ClientInfo(CliId),
//     MountedClientInfo(String),
//     Clients,
//     Mounts,
//     DisconnectClient(CliId),
//     CurrentClientInfo,
//     Subscribe(Subscription),
//     Unsubscribe(Subscription),
//     Subscriptions,
// }

pub const METH_INFO: &str = "info";
pub const METH_SUBSCRIBE: &str = "subscribe";
pub const METH_UNSUBSCRIBE: &str = "unsubscribe";
pub const METH_SUBSCRIPTIONS: &str = "subscriptions";


pub(crate) struct AppBrokerNode {}
impl AppBrokerNode {
    pub fn new_shvnode(&self) -> ShvNode {
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

    // fn process_request(&mut self, rq: &RpcMessage) -> RequestCommand<BrokerNodeCommand> {
    //     match rq.method() {
    //         Some(METH_CLIENT_INFO) => {
    //             let client_id = rq.param().unwrap_or_default().as_i32();
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::ClientInfo(client_id))
    //         }
    //         Some(METH_MOUNTED_CLIENT_INFO) => {
    //             let mount_point = rq.param().unwrap_or_default().as_str();
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::MountedClientInfo(mount_point.to_owned()))
    //         }
    //         Some(METH_CLIENTS) => {
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::Clients)
    //         }
    //         Some(METH_MOUNTS) => {
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::Mounts)
    //         }
    //         Some(METH_DISCONNECT_CLIENT) => {
    //             let client_id = rq.param().unwrap_or_default().as_i32();
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::DisconnectClient(client_id))
    //         }
    //         _ => {
    //             ShvNode::<BrokerNodeCommand>::process_dir_ls(self, rq)
    //         }
    //     }
    // }
}

const META_METH_INFO: MetaMethod = MetaMethod { name: METH_INFO, flags: Flag::None as u32, access: AccessLevel::Browse, param: "Int", result: "ClientInfo", description: "" };
const META_METH_SUBSCRIBE: MetaMethod = MetaMethod { name: METH_SUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", description: "" };
const META_METH_UNSUBSCRIBE: MetaMethod = MetaMethod { name: METH_UNSUBSCRIBE, flags: Flag::None as u32, access: AccessLevel::Browse, param: "SubscribeParams", result: "void", description: "" };
const META_METH_SUBSCRIPTIONS: MetaMethod = MetaMethod { name: METH_SUBSCRIPTIONS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "void", result: "List", description: "" };

pub(crate) struct AppBrokerCurrentClientNode {}
impl AppBrokerCurrentClientNode {
    pub fn new_shvnode(&self) -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_INFO,
            &META_METH_SUBSCRIBE,
            &META_METH_UNSUBSCRIBE,
            &META_METH_SUBSCRIPTIONS,
        ] }
    }

    // fn process_request(&mut self, rq: &RpcMessage) -> RequestCommand<BrokerNodeCommand> {
    //     match rq.method() {
    //         Some(METH_INFO) => {
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::CurrentClientInfo)
    //         }
    //         Some(METH_SUBSCRIBE) => {
    //             let subscription = Subscription::from_rpcvalue(rq.param().unwrap_or_default());
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::Subscribe(subscription))
    //         }
    //         Some(METH_UNSUBSCRIBE) => {
    //             let subscription = Subscription::from_rpcvalue(rq.param().unwrap_or_default());
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::Unsubscribe(subscription))
    //         }
    //         Some(METH_SUBSCRIPTIONS) => {
    //             RequestCommand::<BrokerNodeCommand>::Custom(BrokerNodeCommand::Subscriptions)
    //         }
    //         _ => {
    //             ShvNode::<BrokerNodeCommand>::process_dir_ls(self, rq)
    //         }
    //     }
    // }
}


