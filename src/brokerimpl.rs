use std::collections::{BTreeMap, HashMap, VecDeque};
use async_std::channel::{Receiver, Sender, unbounded};
use async_std::task;
use log::{debug, error, info, log, warn};
use crate::broker::{BrokerToPeerMessage, Device, Mount, ParsedAccessRule, Peer, PeerKind, BrokerCommand, PendingRpcCall, SubscribePath};
use crate::config::{AccessControl, Password};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{CliId, RpcError, RpcErrorCode, Tag};
use shvproto::{List, RpcValue, rpcvalue};
use shvrpc::rpc::{ShvRI, SubscriptionParam, Subscription};
use crate::shvnode::{DIR_APP, AppNode, find_longest_prefix, METH_DIR, METH_LS, process_local_dir_ls, ShvNode};
use shvrpc::util::{join_path, sha1_hash, split_glob_on_match};
use log::Level;
use crate::node::{DIR_BROKER_CURRENTCLIENT, DIR_BROKER, BrokerCurrentClientNode, BrokerNode, METH_SUBSCRIBE};
use shvrpc::metamethod::{MetaMethod, AccessLevel};
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use crate::{node, shvnode};

pub struct BrokerImpl {
    peers: HashMap<CliId, Peer>,
    mounts: BTreeMap<String, Mount>,
    access: AccessControl,
    role_access: HashMap<String, Vec<ParsedAccessRule>>,
    pending_rpc_calls: Vec<PendingRpcCall>,
    pub(crate) command_sender: Sender<BrokerCommand>,
    pub(crate) command_receiver: Receiver<BrokerCommand>,

    node_app: AppNode,
    node_app_broker: BrokerNode,
    node_app_broker_currentclient: BrokerCurrentClientNode,

}

impl BrokerImpl {
    pub(crate) fn new(access: AccessControl) -> Self {
        let (command_sender, command_receiver) = unbounded();
        let mut role_access: HashMap<String, Vec<ParsedAccessRule>> = Default::default();
        for (name, role) in &access.roles {
            let mut list = vec![];
            for rule in &role.access {
                match ParsedAccessRule::new(&ShvRI::try_from(&*rule.shv_ri).expect("Valid SHV RI"), &rule.grant) {
                    Ok(rule) => {
                        list.push(rule);
                    }
                    Err(err) => {
                        panic!("Parse access rule: {} error: {}", rule.shv_ri, err);
                    }
                }
            }
            if !list.is_empty() {
                role_access.insert(name.clone(), list);
            }
        }
        let mut broker = Self {
            peers: Default::default(),
            mounts: Default::default(),
            access,
            role_access,
            pending_rpc_calls: vec![],
            command_sender,
            command_receiver,
            node_app: AppNode {
                app_name: "shvbroker",
                shv_version_major: 3,
                shv_version_minor: 0,
            },
            node_app_broker: BrokerNode {},
            node_app_broker_currentclient: BrokerCurrentClientNode {},
        };
        broker.mounts.insert(DIR_APP.into(), Mount::Node(broker.node_app.new_shvnode()));
        broker.mounts.insert(DIR_BROKER.into(), Mount::Node(broker.node_app_broker.new_shvnode()));
        broker.mounts.insert(DIR_BROKER_CURRENTCLIENT.into(), Mount::Node(broker.node_app_broker_currentclient.new_shvnode()));
        broker
    }

    pub(crate) async fn process_rpc_frame(&mut self, peer_id: CliId, frame: RpcFrame) -> shvrpc::Result<()> {
        if frame.is_request() {
            let shv_path = frame.shv_path().unwrap_or_default().to_string();
            let method = frame.method().unwrap_or_default().to_string();
            let response_meta= RpcFrame::prepare_response_meta(&frame.meta)?;
            // println!("response meta: {:?}", response_meta);
            let (grant_access_level, grant_access) = match self.grant_for_request(peer_id, &frame) {
                Ok(grant) => { grant }
                Err(err) => {
                    self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result: Err(err) }).await?;
                    return Ok(())
                }
            };
            if let Some(result) = process_local_dir_ls(&self.mounts, &frame) {
                self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result }).await?;
                return Ok(())
            }
            if let Some((mount_point, node_path)) = find_longest_prefix(&self.mounts, &shv_path) {
                let mount = self.mounts.get_mut(mount_point).unwrap();
                match mount {
                    Mount::Peer(device) => {
                        let mut frame = frame;
                        frame.push_caller_id(peer_id);
                        frame.set_shvpath(node_path);
                        frame.set_tag(Tag::AccessLevel as i32, grant_access_level.map(RpcValue::from));
                        frame.set_tag(Tag::Access as i32, grant_access.map(RpcValue::from));
                        let device_peer_id = device.peer_id;
                        self.peers.get(&device_peer_id).ok_or("client ID must exist")?.sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
                    }
                    Mount::Node(node) => {
                        let mut frame = frame;
                        frame.set_shvpath(node_path);
                        frame.set_tag(Tag::AccessLevel as i32, grant_access_level.map(RpcValue::from));
                        frame.set_tag(Tag::Access as i32, grant_access.map(RpcValue::from));
                        if let Some(method) = node.is_request_granted(&frame) {
                            let ctx = NodeRequestContext {
                                peer_id,
                                command_sender: self.command_sender.clone(),
                                mount_point: mount_point.to_string(),
                                methods: node.methods.clone(),
                                method,
                            };
                            self.process_node_request(frame, ctx).await?;
                        } else {
                            let err = RpcError::new(RpcErrorCode::PermissionDenied, format!("Method doesn't exist or request to call {}:{} is not granted.", shv_path, frame.method().unwrap_or_default()));
                            self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result: Err(err) }).await?;
                        }
                    }
                }

            } else {
                let err = RpcError::new(RpcErrorCode::MethodNotFound, format!("Invalid shv path {}:{}()", shv_path, method));
                self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result: Err(err) }).await?;
                return Ok(());
            }
        } else if frame.is_response() {
            let mut frame = frame;
            if let Some(client_id) = frame.pop_caller_id() {
                let peer = self.peers.get(&client_id).unwrap();
                peer.sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
            } else {
                self.process_pending_broker_rpc_call(peer_id, frame).await?;
            }
        } else if frame.is_signal() {
            if let Some(mount_point) = self.client_id_to_mount_point(peer_id) {
                let new_path = shvrpc::util::join_path(&mount_point, frame.shv_path().unwrap_or_default());
                for (cli_id, peer) in self.peers.iter() {
                    let ri = ShvRI::from_path_method_signal(&new_path, frame.source().unwrap_or_default(), frame.method());
                    if &peer_id != cli_id && peer.is_signal_subscribed(&ri) {
                        let mut frame = frame.clone();
                        frame.set_shvpath(&new_path);
                        peer.sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
                    }
                }
            }
        }
        Ok(())
    }
    async fn start_broker_rpc_call(&mut self, request: RpcMessage, pending_call: PendingRpcCall) -> shvrpc::Result<()> {
        //self.pending_calls.retain(|r| !r.sender.is_closed());
        let peer = self.peers.get(&pending_call.client_id).ok_or(format!("Invalid client ID: {}", pending_call.client_id))?;
        // let rqid = data.request.request_id().ok_or("Missing request ID")?;
        peer.sender.send(BrokerToPeerMessage::SendMessage(request)).await?;
        self.pending_rpc_calls.push(pending_call);
        Ok(())
    }
    async fn process_pending_broker_rpc_call(&mut self, client_id: CliId, response_frame: RpcFrame) -> shvrpc::Result<()> {
        assert!(response_frame.is_response());
        assert!(response_frame.caller_ids().is_empty());
        let rqid = response_frame.request_id().ok_or("Request ID must be set.")?;
        let mut pending_call_ix = None;
        for (ix, pc) in self.pending_rpc_calls.iter().enumerate() {
            if pc.request_id == rqid && pc.client_id == client_id {
                pending_call_ix = Some(ix);
                break;
            }
        }
        if let Some(ix) = pending_call_ix {
            let pending_call = self.pending_rpc_calls.remove(ix);
            pending_call.response_sender.send(response_frame).await?;
        }
        Ok(())
    }
    pub async fn process_broker_command(&mut self, broker_command: BrokerCommand) -> shvrpc::Result<()> {
        match broker_command {
            BrokerCommand::FrameReceived { client_id, frame } => {
                if let Err(err) = self.process_rpc_frame(client_id, frame).await {
                    warn!("Process RPC frame error: {err}");
                }
            }
            BrokerCommand::NewPeer { client_id, sender, peer_kind } => {
                if self.peers.insert(client_id, Peer::new(peer_kind, sender)).is_some() {
                    // this might happen when connection to parent broker is restored
                    // after parent broker reset
                    // note that parent broker connection has always ID == 1
                    debug!("Client ID: {client_id} exists already!");
                }
            },
            BrokerCommand::RegisterDevice { client_id, device_id, mount_point, subscribe_path } => {
                self.mount_device(client_id, device_id, mount_point, subscribe_path).await?;
            },
            BrokerCommand::SetSubscribeMethodPath { peer_id: client_id, subscribe_path } => {
                self.set_subscribe_path(client_id, subscribe_path)?;
            }
            BrokerCommand::PeerGone { peer_id } => {
                self.peers.remove(&peer_id);
                info!("Client id: {} disconnected.", peer_id);
                if let Some(path) = self.client_id_to_mount_point(peer_id) {
                    info!("Unmounting path: '{}'", path);
                    self.mounts.remove(&path);
                }
                let client_path = join_path(DIR_BROKER, &format!("client/{}", peer_id));
                self.mounts.remove(&client_path);
                self.pending_rpc_calls.retain(|c| c.client_id != peer_id);
            }
            BrokerCommand::GetPassword { client_id, user } => {
                let shapwd = self.sha_password(&user);
                let peer = self.peers.get_mut(&client_id).expect("valid peer ID");
                peer.user = user.clone();
                peer.sender.send(BrokerToPeerMessage::PasswordSha1(shapwd)).await?;
            }
            //BrokerCommand::SendFrame{ peer_id, frame } => {
            //    let peer = self.peers.get_mut(&peer_id).expect("valid peer ID");
            //    peer.sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
            //}
            BrokerCommand::SendResponse { peer_id, meta, result } => {
                let peer = self.peers.get_mut(&peer_id).expect("valid peer ID");
                let mut msg = RpcMessage::from_meta(meta);
                msg.set_result_or_error(result);
                peer.sender.send(BrokerToPeerMessage::SendFrame(RpcFrame::from_rpcmessage(&msg)?)).await?;
            }
            BrokerCommand::RpcCall { client_id, request, response_sender } => {
                let rq_id = request.request_id().unwrap_or_default();
                let mut rq2 = request;
                // broker calls can have any access level, set 'su' to bypass client access control
                rq2.set_access_level(AccessLevel::Superuser);
                self.start_broker_rpc_call(rq2, PendingRpcCall {
                    client_id,
                    request_id: rq_id,
                    response_sender,
                }).await?
            }
            BrokerCommand::PropagateSubscriptions { client_id } => {
                self.propagate_subscriptions_to_mounted_device(client_id)?
            }
        }
        Ok(())
    }
    pub(crate) fn set_subscribe_path(&mut self, client_id: CliId, subscribe_path: SubscribePath) -> shvrpc::Result<()> {
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        log!(target: "Subscr", Level::Debug, "Device mounted on: {:?}, client ID: {client_id} has subscribe method path set to: {:?}", peer.mount_point, subscribe_path);
        peer.subscribe_path = Some(subscribe_path);
        Ok(())
    }
    pub fn sha_password(&self, user: &str) -> Option<Vec<u8>> {
        match self.access.users.get(user) {
            None => None,
            Some(user) => {
                match &user.password {
                    Password::Plain(password) => {
                        Some(sha1_hash(password.as_bytes()))
                    }
                    Password::Sha1(password) => {
                        Some(password.as_bytes().into())
                    }
                }
            }
        }
    }
    pub(crate) async fn mount_device(&mut self, client_id: i32, device_id: Option<String>, mount_point: Option<String>, subscribe_path: Option<SubscribePath>) -> shvrpc::Result<()> {
        let client_path = join_path(DIR_BROKER, &format!("client/{}", client_id));
        self.mounts.insert(client_path, Mount::Peer(Device { peer_id: client_id }));
        let mount_point = 'mount_point: {
            if let Some(ref mount_point) = mount_point {
                if mount_point.starts_with("test/") {
                    info!("Client id: {} mounted on path: '{}'", client_id, &mount_point);
                    break 'mount_point Some(mount_point.clone());
                }
            }
            if let Some(device_id) = &device_id {
                match self.access.mounts.get(device_id) {
                    None => {
                        warn!("Cannot find mount-point for device ID: {device_id}");
                        None
                    }
                    Some(mount) => {
                        let mount_point = mount.mount_point.clone();
                        info!("Client id: {}, device id: {} mounted on path: '{}'", client_id, device_id, &mount_point);
                        Some(mount_point)
                    }
                }
            } else {
                None
            }
        };
        if let Some(mount_point) = &mount_point {
            if let Some(peer) = self.peers.get_mut(&client_id) {
                peer.mount_point = Some(mount_point.clone());
                peer.subscribe_path = subscribe_path;
                self.mounts.insert(mount_point.clone(), Mount::Peer(Device { peer_id: client_id }));
                if peer.subscribe_path.is_none() {
                    self.device_capabilities_discovery_async(client_id)?;
                }
            } else {
                warn!("Cannot mount device with invalid client ID: {client_id}");
            }
        } else {
            self.set_subscribe_path(client_id, SubscribePath::NotBroker)?;
        };
        Ok(())
    }
    fn propagate_subscription_to_matching_devices(&mut self, new_subscription: &SubscriptionParam) -> shvrpc::Result<()> {
        // compare new_subscription with all mount-points to check
        // whether it should be propagated also to mounted device
        let mut to_subscribe = vec![];
        for (mount_point, mount) in self.mounts.iter() {
            if let Mount::Peer(device) = mount {
                if let Some(peer) = self.peers.get(&device.peer_id) {
                    if peer.is_broker()? {
                        if let Ok(Some((_local, remote))) = split_glob_on_match(&new_subscription.ri.path(), mount_point) {
                            let ri = ShvRI::from_path_method_signal(remote, new_subscription.ri.method(), new_subscription.ri.signal());
                            to_subscribe.push((device.peer_id, SubscriptionParam{ ri, ttl: new_subscription.ttl }));
                        }
                    }
                }
            }
        }
        for (client_id, subpar) in to_subscribe {
            let to_subscribe = vec![subpar];
            self.call_subscribe_async(client_id, to_subscribe)?;
        }
        Ok(())
    }
    fn device_capabilities_discovery_async(&mut self, client_id: i32) -> shvrpc::Result<()> {
        // let peer = self.peers.get(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        // let mount_point = peer.mount_point.clone().ok_or_else(|| format!("Mount point is missing, client ID: {client_id}"))?;
        let broker_command_sender = self.command_sender.clone();
        task::spawn(async move {
            async fn check_path(client_id: CliId, path: &str, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<bool> {
                let (response_sender, response_receiver) = unbounded();
                let request = RpcMessage::new_request(path, METH_DIR, Some(METH_SUBSCRIBE.into()));
                let cmd = BrokerCommand::RpcCall {
                    client_id,
                    request,
                    response_sender,
                };
                broker_command_sender.send(cmd).await?;
                let resp = response_receiver.recv().await?.to_rpcmesage()?;
                if let Ok(val) = resp.result() {
                    if !val.is_null() {
                        let cmd = BrokerCommand::SetSubscribeMethodPath {
                            peer_id: client_id,
                            subscribe_path: SubscribePath::CanSubscribe(path.to_string()),
                        };
                        broker_command_sender.send(cmd).await?;
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            let found_cmd = BrokerCommand::PropagateSubscriptions { client_id };
            if let Ok(true) = check_path(client_id, "/.broker/currentClient", &broker_command_sender).await {
                let _ = broker_command_sender.send(found_cmd).await;
            } else if let Ok(true) = check_path(client_id, ".app/broker/currentClient", &broker_command_sender).await{
                let _ = broker_command_sender.send(found_cmd).await;
            } else if let Ok(true) = check_path(client_id,"/.app/broker/currentClient", &broker_command_sender).await {
                let _ = broker_command_sender.send(found_cmd).await;
            } else {
                let cmd = BrokerCommand::SetSubscribeMethodPath {
                    peer_id: client_id,
                    subscribe_path: SubscribePath::NotBroker,
                };
                let _ = broker_command_sender.send(cmd).await;
            }
        });
        Ok(())
    }
    fn propagate_subscriptions_to_mounted_device(&mut self, client_id: CliId) -> shvrpc::Result<()> {
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        //let subscribe_path = peer.broker_subscribe_path()?;
        let mount_point = peer.mount_point.clone().ok_or_else(|| format!("Mount point is missing, client ID: {client_id}"))?;
        let mut to_subscribe = Vec::new();
        for peer in self.peers.values() {
            for peer_sub in &peer.subscriptions {
                match split_glob_on_match(peer_sub.glob.path_str(), &mount_point) {
                    Ok(split) => {
                        if let Some((_local, remote)) = split {
                            let ri = ShvRI::from_path_method_signal(remote, peer_sub.glob.method_str(), peer_sub.glob.signal_str());
                            let newsub = SubscriptionParam{ ri, ttl: peer_sub.param.ttl };
                            if to_subscribe.iter().find(|s| *s == &newsub).is_none() {
                                to_subscribe.push(newsub);
                            }
                        }
                    }
                    Err(e) => {
                        error!("split_glob_on_match error '{}'.", e)
                    }
                }
            }
        }
        self.call_subscribe_async(client_id, to_subscribe)?;
        Ok(())
    }
    fn call_subscribe_async(&mut self, client_id: CliId, subscriptions: Vec<SubscriptionParam>) -> shvrpc::Result<()> {
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let mount_point = peer.mount_point.clone();
        let broker_command_sender = self.command_sender.clone();
        //info!("call_subscribe_async mount: {:?} client_id {:?} subscriptions {:?}", mount_point, client_id, subscriptions);
        let subscribe_path = peer.broker_subscribe_path()?;
        task::spawn(async move {
            async fn call_subscribe(client_id: CliId, subscribe_path: &str, subscription: SubscriptionParam, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<()> {
                let (response_sender, response_receiver) = unbounded();
                let cmd = BrokerCommand::RpcCall {
                    client_id,
                    request: RpcMessage::new_request(subscribe_path, METH_SUBSCRIBE, Some(subscription.to_rpcvalue())),
                    response_sender,
                };
                broker_command_sender.send(cmd).await?;
                response_receiver.recv().await?.to_rpcmesage()?;
                Ok(())
            }
            for subscription in subscriptions {
                log!(target: "Subscr", Level::Debug, "Propagating subscription {:?} to client ID: {client_id} mounted on {:?}", subscription, mount_point);
                let _ = call_subscribe(client_id, &subscribe_path, subscription, &broker_command_sender).await;
            }
        });
        Ok(())
    }
    pub fn client_id_to_mount_point(&self, client_id: CliId) -> Option<String> {
        match self.peers.get(&client_id) {
            None => None,
            Some(peer) => peer.mount_point.clone()
        }
    }
    pub(crate) fn flatten_roles(&self, user: &str) -> Option<Vec<String>> {
        if let Some(user) = self.access.users.get(user) {
            let mut queue: VecDeque<String> = VecDeque::new();
            fn enqueue(queue: &mut VecDeque<String>, role: &str) {
                let role = role.to_string();
                if !queue.contains(&role) {
                    queue.push_back(role);
                }
            }
            for role in user.roles.iter() { enqueue(&mut queue, role); }
            let mut flatten_roles = Vec::new();
            while !queue.is_empty() {
                let role_name = queue.pop_front().unwrap();
                if let Some(role) = self.access.roles.get(&role_name) {
                    for role in role.roles.iter() { enqueue(&mut queue, role); }
                }
                flatten_roles.push(role_name);
            }
            Some(flatten_roles)
        } else {
            None
        }
    }
    fn grant_for_request(&self, client_id: CliId, frame: &RpcFrame) -> Result<(Option<i32>, Option<String>), RpcError> {
        log!(target: "Access", Level::Debug, "======================= grant_for_request {}", &frame);
        let shv_path = frame.shv_path().unwrap_or_default();
        let method = frame.method().unwrap_or_default();
        //let source = frame.source().unwrap_or_default();
        if method.is_empty() {
            return Err(RpcError::new(RpcErrorCode::PermissionDenied, "Method is empty"))
        }
        let peer = self.peers.get(&client_id).ok_or_else(|| RpcError::new(RpcErrorCode::InternalError, "Peer not found"))?;
        let ri = ShvRI::from_path_method_signal(shv_path, method, None);
        match peer.peer_kind {
            PeerKind::Client => {
                log!(target: "Access", Level::Debug, "Peer: {}", client_id);
                if let Some(flatten_roles) = self.flatten_roles(&peer.user) {
                    log!(target: "Access", Level::Debug, "user: {}, flatten roles: {:?}", &peer.user, flatten_roles);
                    for role_name in flatten_roles {
                        if let Some(rules) = self.role_access.get(&role_name) {
                            log!(target: "Access", Level::Debug, "----------- access for role: {}", role_name);
                            for rule in rules {
                                log!(target: "Access", Level::Debug, "\trule: {}", rule.glob.as_str());
                                if rule.glob.match_shv_ri(&ri) {
                                    log!(target: "Access", Level::Debug, "\t\t HIT");
                                    return Ok((Some(rule.access_level as i32), Some(rule.access.clone())));
                                }
                            }
                        }
                    }
                }
                return Err(RpcError::new(RpcErrorCode::PermissionDenied, format!("Access denied for user: {}", peer.user)))
            }
            PeerKind::ParentBroker => {
                log!(target: "Access", Level::Debug, "ParentBroker: {}", client_id);
                let access = frame.tag(Tag::Access as i32);
                let access_level = frame.tag(Tag::AccessLevel as i32);
                if access_level.is_some() || access.is_some() {
                    log!(target: "Access", Level::Debug, "\tGranted access: {:?}, access level: {:?}", access, access_level);
                    return Ok((access_level.map(RpcValue::as_i32), access.map(RpcValue::as_str).map(|s| s.to_string())))
                } else {
                    log!(target: "Access", Level::Debug, "\tPermissionDenied");
                    return Err(RpcError::new(RpcErrorCode::PermissionDenied, ""))
                }
            }
        }
    }
    fn peer_to_info(client_id: CliId, peer: &Peer) -> rpcvalue::Map {
        let subs: List = peer.subscriptions.iter().map(|subs| subs.param.to_rpcvalue()).collect();
        rpcvalue::Map::from([
            ("clientId".to_string(), client_id.into()),
            ("userName".to_string(), RpcValue::from(&peer.user)),
            ("mountPoint".to_string(), RpcValue::from(peer.mount_point.clone().unwrap_or_default())),
            ("subscriptions".to_string(), subs.into()),
        ]
        )
    }
    fn client_info(&mut self, client_id: CliId) -> Option<rpcvalue::Map> {
        self.peers.get(&client_id).map(|peer| BrokerImpl::peer_to_info(client_id, peer))
    }
    async fn disconnect_client(&mut self, client_id: CliId) -> shvrpc::Result<()> {
        let peer = self.peers.get(&client_id).ok_or("Invalid client ID")?;
        peer.sender.send(BrokerToPeerMessage::DisconnectByBroker).await?;
        Ok(())
    }
    fn mounted_client_info(&mut self, mount_point: &str) -> Option<rpcvalue::Map> {
        for (client_id, peer) in &self.peers {
            if let Some(mount_point1) = &peer.mount_point {
                if mount_point1 == mount_point {
                    return Some(BrokerImpl::peer_to_info(*client_id, peer));
                }
            }
        }
        None
    }
    async fn subscribe(&mut self, client_id: CliId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        log!(target: "Subscr", Level::Debug, "New subscription for client id: {} - {:?}", client_id, subpar);
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let ri = subpar.ri.normalized();
        if peer.subscriptions.iter().find(|sub| sub.param.ri == ri).is_some() {
            return Ok(false);
        }
        let subpar = SubscriptionParam { ri, ttl: subpar.ttl };
        peer.subscriptions.push(Subscription::new(&subpar)?);
        self.propagate_subscription_to_matching_devices(&subpar)?;
        Ok(true)
    }
    fn unsubscribe(&mut self, client_id: CliId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        log!(target: "Subscr", Level::Debug, "Remove subscription for client id: {} - {:?}", client_id, subpar);
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let cnt = peer.subscriptions.len();
        let ri = subpar.ri.normalized();
        peer.subscriptions.retain(|subscr| subscr.param.ri != ri);
        Ok(cnt != peer.subscriptions.len())
    }
    fn subscriptions(&self, client_id: CliId) -> shvrpc::Result<List> {
        let peer = self.peers.get(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let subs: List = peer.subscriptions.iter().map(|subs| subs.param.to_rpcvalue()).collect();
        Ok(subs)
    }
    async fn process_node_request(&mut self, frame: RpcFrame, ctx: NodeRequestContext) -> shvrpc::Result<()> {
        let method_not_found_error = || {
            Err(RpcError::new(RpcErrorCode::MethodNotFound, format!("Unknown method {}:{}", ctx.mount_point, frame.method().unwrap_or_default())))
        };
        let result = 'block: {
            if ctx.method.name == METH_DIR {
                let result = ShvNode::process_dir(&ctx.methods, &frame.to_rpcmesage()?);
                break 'block result;
            }
            let rq = frame.to_rpcmesage()?;
            if ctx.method.name == METH_LS {
                let result = ShvNode::process_ls(&frame.to_rpcmesage()?);
                break 'block result;
            }
            match ctx.mount_point.as_str() {
                DIR_APP => {
                    match ctx.method.name {
                        shvnode::METH_NAME => {
                            break 'block Ok(self.node_app.app_name.into());
                        }
                        shvnode::METH_SHV_VERSION_MAJOR => {
                            break 'block Ok(self.node_app.shv_version_major.into());
                        }
                        shvnode::METH_SHV_VERSION_MINOR => {
                            break 'block Ok(self.node_app.shv_version_minor.into());
                        }
                        shvnode::METH_PING => {
                            break 'block Ok(().into());
                        }
                        _ => {
                            break 'block method_not_found_error();
                        }
                    }
                }
                DIR_BROKER => {
                    match ctx.method.name {
                        node::METH_CLIENT_INFO => {
                            let peer_id = rq.param().unwrap_or_default().as_i32();
                            let info = match self.client_info(peer_id) {
                                None => { RpcValue::null() }
                                Some(info) => { RpcValue::from(info) }
                            };
                            break 'block Ok(info);
                        }
                        node::METH_MOUNTED_CLIENT_INFO => {
                            let mount_point = rq.param().unwrap_or_default().as_str();
                            let info = match self.mounted_client_info(mount_point) {
                                None => { RpcValue::null() }
                                Some(info) => { RpcValue::from(info) }
                            };
                            break 'block Ok(info);
                        }
                        node::METH_CLIENTS => {
                            let clients: rpcvalue::List = self.peers.keys().map(|id| RpcValue::from(*id)).collect();
                            break 'block Ok(clients.into());
                        }
                        node::METH_MOUNTS => {
                            let mounts: List = self.peers.iter().filter(|(_id, peer)| peer.mount_point.is_some()).map(|(_id, peer)| {
                                RpcValue::from(peer.mount_point.clone().unwrap())
                            }).collect();
                            break 'block Ok(mounts.into());
                        }
                        node::METH_DISCONNECT_CLIENT => {
                            let peer_id = rq.param().unwrap_or_default().as_i32();
                            let result = self.disconnect_client(peer_id).await
                                .map(|_| RpcValue::null())
                                .map_err(|err| RpcError::new(RpcErrorCode::MethodCallException, format!("Disconnect client error - {}", err)));
                            break 'block result;
                        }
                        _ => {
                            break 'block method_not_found_error();
                        }
                    }
                }
                DIR_BROKER_CURRENTCLIENT => {
                    match ctx.method.name {
                        node::METH_SUBSCRIBE => {
                            match SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default()) {
                                Ok(subscription) => {
                                    let subs_added = self.subscribe(ctx.peer_id, &subscription).await?;
                                    break 'block Ok(subs_added.into());
                                }
                                Err(e) => {
                                    let err = RpcError::new(RpcErrorCode::InvalidParam, e);
                                    break 'block Err(err);
                                }
                            }
                        }
                        node::METH_UNSUBSCRIBE => {
                            match SubscriptionParam::from_rpcvalue(rq.param().unwrap_or_default()) {
                                Ok(subscription) => {
                                    let subs_removed = self.unsubscribe(ctx.peer_id, &subscription)?;
                                    break 'block Ok(subs_removed.into());
                                }
                                Err(e) => {
                                    let err = RpcError::new(RpcErrorCode::InvalidParam, e);
                                    break 'block Err(err);
                                }
                            }
                        }
                        node::METH_SUBSCRIPTIONS => {
                            let result = self.subscriptions(ctx.peer_id)?;
                            break 'block Ok(result.into());
                        }
                        node::METH_INFO => {
                            let info = match self.client_info(ctx.peer_id) {
                                None => { RpcValue::null() }
                                Some(info) => { RpcValue::from(info) }
                            };
                            break 'block Ok(info);
                        }
                        _ => {
                            break 'block method_not_found_error();
                        }
                    }
                }
                _ => {
                    break 'block method_not_found_error();
                }
            }
        };
        let response_meta = shvrpc::rpcframe::RpcFrame::prepare_response_meta(&frame.meta)?;
        let cmd = BrokerCommand::SendResponse {
            peer_id: ctx.peer_id,
            meta: response_meta,
            result,
        };
        ctx.command_sender.send(cmd).await?;
        Ok(())
    }
}

struct NodeRequestContext {
    peer_id: CliId,
    command_sender: Sender<BrokerCommand>,
    mount_point: String,
    methods: Vec<&'static MetaMethod>,
    method: &'static MetaMethod,
}
