use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use async_std::channel::{Receiver, Sender, unbounded};
use async_std::task;
use log::{error, info, log, warn};
use crate::broker::{BrokerToPeerMessage, Mount, ParsedAccessRule, Peer, PeerKind, BrokerCommand, PendingRpcCall, SubscribePath};
use crate::config::{AccessControl, Password};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, Tag};
use shvproto::{List, RpcValue, rpcvalue};
use shvrpc::rpc::{ShvRI, SubscriptionParam, Subscription};
use crate::shvnode::{DIR_APP, AppNode, find_longest_prefix, METH_DIR, METH_LS, process_local_dir_ls, ShvNode};
use shvrpc::util::{join_path, sha1_hash, split_glob_on_match};
use log::Level;
use crate::node::{DIR_BROKER_CURRENTCLIENT, DIR_BROKER, METH_SUBSCRIBE, DIR_BROKER_CLIENT};
use shvrpc::metamethod::{MetaMethod, AccessLevel};
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use crate::{node, shvnode};

pub struct BrokerState {
    peers: BTreeMap<PeerId, Peer>,
    mounts: BTreeMap<String, Mount>,
    access: AccessControl,
    role_access: HashMap<String, Vec<ParsedAccessRule>>,

    pub(crate) command_sender: Sender<BrokerCommand>,
}
type SharedBrokerState = Arc<RwLock<BrokerState>>;
impl BrokerState {
    fn grant_for_request(&self, client_id: PeerId, frame: &RpcFrame) -> Result<(Option<i32>, Option<String>), RpcError> {
        log!(target: "Access", Level::Debug, "======================= grant_for_request {}", &frame);
        let shv_path = frame.shv_path().unwrap_or_default();
        let method = frame.method().unwrap_or_default();
        //let source = frame.source().unwrap_or_default();
        if method.is_empty() {
            return Err(RpcError::new(RpcErrorCode::PermissionDenied, "Method is empty"))
        }
        let peer = self.peers.get(&client_id).ok_or_else(|| RpcError::new(RpcErrorCode::InternalError, "Peer not found"))?;
        let ri = match ShvRI::from_path_method_signal(shv_path, method, None) {
            Ok(ri) => { ri }
            Err(e) => {
                return Err(RpcError::new(RpcErrorCode::InvalidRequest, e))
            }
        };
        match peer.peer_kind {
            PeerKind::ParentBroker => {
                log!(target: "Access", Level::Debug, "ParentBroker: {}", client_id);
                let access = frame.tag(Tag::Access as i32);
                let access_level = frame.tag(Tag::AccessLevel as i32);
                if access_level.is_some() || access.is_some() {
                    log!(target: "Access", Level::Debug, "\tGranted access: {:?}, access level: {:?}", access, access_level);
                    Ok((access_level.map(RpcValue::as_i32), access.map(RpcValue::as_str).map(|s| s.to_string())))
                } else {
                    log!(target: "Access", Level::Debug, "\tPermissionDenied");
                    Err(RpcError::new(RpcErrorCode::PermissionDenied, ""))
                }
            }
            _ => {
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
                Err(RpcError::new(RpcErrorCode::PermissionDenied, format!("Access denied for user: {}", peer.user)))
            }
        }
    }
    fn flatten_roles(&self, user: &str) -> Option<Vec<String>> {
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
    fn remove_peer(&mut self, peer_id: PeerId) -> shvrpc::Result<()> {
        info!("Client id: {} disconnected.", peer_id);
        self.peers.remove(&peer_id);
        self.mounts.retain(|_, v| if let Mount::Peer(id) = v { *id != peer_id } else { true });
        Ok(())
    }
    fn set_subscribe_path(&mut self, peer_id: PeerId, subscribe_path: SubscribePath) -> shvrpc::Result<()> {
        let peer = self.peers.get_mut(&peer_id).ok_or("Peer not found")?;
        if let PeerKind::Device { subscribe_path: subpath, .. } = &mut peer.peer_kind {
            *subpath = Some(subscribe_path);
            Ok(())
        } else {
            Err("Not a device".into())
        }
    }
    fn add_peer(&mut self, peer_id: PeerId, user: String, peer_kind: PeerKind, mount_point: Option<String>, device_id: Option<String>, sender: Sender<BrokerToPeerMessage>) -> shvrpc::Result<()> {
        if self.peers.contains_key(&peer_id) {
            // this might happen when connection to parent broker is restored
            // after parent broker reset
            // note that parent broker connection has always ID == 1
            panic!("Peer ID: {peer_id} exists already!");
        }
        let client_path = join_path(DIR_BROKER, &format!("client/{}", peer_id));
        let effective_mount_point = 'mount_point: {
            if let Some(ref mount_point) = mount_point {
                if mount_point.starts_with("test/") {
                    info!("Client id: {} mounted on path: '{}'", peer_id, &mount_point);
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
                        info!("Client id: {}, device id: {} mounted on path: '{}'", peer_id, device_id, &mount_point);
                        Some(mount_point)
                    }
                }
            } else {
                None
            }
        };
        let effective_peer_kind = match peer_kind {
            PeerKind::ParentBroker => { PeerKind::ParentBroker }
            _ => {
                if let Some(mount_point) = &effective_mount_point {
                    PeerKind::Device{ device_id, mount_point: mount_point.clone(), subscribe_path: None }
                } else {
                    PeerKind::Client
                }
            }
        };
        let peer = Peer {
            peer_kind: effective_peer_kind,
            user,
            sender,
            subscriptions: vec![],
        };
        self.peers.insert(peer_id, peer);
        self.mounts.insert(client_path, Mount::Peer(peer_id));
        if let Some(mount_point) = effective_mount_point {
            self.mounts.insert(mount_point, Mount::Peer(peer_id));
        }
        Ok(())
    }
    fn sha_password(&self, user: &str) -> Option<Vec<u8>> {
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
    fn peer_to_info(client_id: PeerId, peer: &Peer) -> rpcvalue::Map {
        let subs: List = peer.subscriptions.iter().map(|subs| subs.param.to_rpcvalue()).collect();
        let (device_id, mount_point) = if let PeerKind::Device { mount_point, device_id, .. } = &peer.peer_kind {
            (device_id.clone().unwrap_or_default(), mount_point.clone())
        } else {
            ("".to_owned(), "".to_owned())
        };
        rpcvalue::Map::from([
            ("clientId".to_string(), client_id.into()),
            ("userName".to_string(), RpcValue::from(&peer.user)),
            ("deviceId".to_string(), RpcValue::from(device_id)),
            ("mountPoint".to_string(), RpcValue::from(mount_point)),
            ("subscriptions".to_string(), subs.into()),
        ]
        )
    }
    fn client_info(&self, client_id: PeerId) -> Option<rpcvalue::Map> {
        self.peers.get(&client_id).map(|peer| BrokerState::peer_to_info(client_id, peer))
    }
    fn mounted_client_info(&self, mount_point: &str) -> Option<rpcvalue::Map> {
        for (client_id, peer) in &self.peers {
            if let PeerKind::Device {mount_point: mount_point1, ..} = &peer.peer_kind {
                if mount_point1 == mount_point {
                    return Some(BrokerState::peer_to_info(*client_id, peer));
                }
            }
        }
        None
    }
    fn subscriptions(&self, client_id: PeerId) -> shvrpc::Result<List> {
        let peer = self.peers.get(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let subs: List = peer.subscriptions.iter().map(|subs| subs.param.to_rpcvalue()).collect();
        Ok(subs)
    }
    fn subscribe(&mut self, client_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<Option<SubscriptionParam>> {
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        if peer.subscriptions.iter().any(|sub| sub.param.ri == subpar.ri) {
            return Ok(None);
        }
        peer.subscriptions.push(Subscription::new(subpar)?);
        Ok(Some(subpar.clone()))
    }
    fn unsubscribe(&mut self, client_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        log!(target: "Subscr", Level::Debug, "Remove subscription for client id: {} - {:?}", client_id, subpar);
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        let cnt = peer.subscriptions.len();
        peer.subscriptions.retain(|subscr| subscr.param.ri != subpar.ri);
        Ok(cnt != peer.subscriptions.len())
    }
    fn is_subscribe_path_resolved(&self, peer_id: PeerId) -> shvrpc::Result<Option<SubscribePath>> {
        let peer = self.peers.get(&peer_id).ok_or_else(|| format!("Invalid peer ID: {peer_id}"))?;
        if let PeerKind::Device{ subscribe_path, .. } = &peer.peer_kind {
            Ok(subscribe_path.clone())
        } else {
            Err(format!("Not device: {:?}", peer).into())
        }
    }
}
pub struct BrokerImpl {
    state: SharedBrokerState,
    pending_rpc_calls: Vec<PendingRpcCall>,
    pub(crate) command_sender: Sender<BrokerCommand>,
    pub(crate) command_receiver: Receiver<BrokerCommand>,

    //node_app: AppNode,
    //node_app_broker: BrokerNode,
    //node_broker_currentclient: BrokerCurrentClientNode,

}
fn state_reader(state: &SharedBrokerState) -> RwLockReadGuard<BrokerState> {
    state.read().unwrap()
}
fn state_writer(state: &SharedBrokerState) -> RwLockWriteGuard<BrokerState> {
    state.write().unwrap()
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
        let mut state = BrokerState {
            peers: Default::default(),
            mounts: Default::default(),
            access,
            role_access,
            command_sender: command_sender.clone(),
        };
        state.mounts.insert(DIR_APP.into(), Mount::Node(crate::shvnode::AppNode::new_shvnode()));
        state.mounts.insert(DIR_BROKER.into(), Mount::Node(crate::node::BrokerNode::new_shvnode()));
        state.mounts.insert(DIR_BROKER_CURRENTCLIENT.into(), Mount::Node(crate::node::BrokerCurrentClientNode::new_shvnode()));
        Self {
            state: Arc::new(RwLock::new(state)),
            pending_rpc_calls: vec![],
            command_sender,
            command_receiver,
            //node_app_broker: BrokerNode {},
            //node_broker_currentclient: BrokerCurrentClientNode {},
        }
    }

    pub(crate) async fn process_rpc_frame(&mut self, peer_id: PeerId, frame: RpcFrame) -> shvrpc::Result<()> {
        if frame.is_request() {
            let shv_path = frame.shv_path().unwrap_or_default().to_string();
            let method = frame.method().unwrap_or_default().to_string();
            let response_meta= RpcFrame::prepare_response_meta(&frame.meta)?;
            // println!("response meta: {:?}", response_meta);
            let access = state_reader(&self.state).grant_for_request(peer_id, &frame);
            let (grant_access_level, grant_access) = match access {
                Ok(grant) => { grant }
                Err(err) => {
                    self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result: Err(err) }).await?;
                    return Ok(())
                }
            };
            let local_result = process_local_dir_ls(&state_reader(&self.state).mounts, &frame);
            if let Some(result) = local_result {
                self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result }).await?;
                return Ok(())
            }
            //let state = self.state.read().map_err(|e| e.to_string())?;
            let paths = find_longest_prefix(&self.state.read().map_err(|e| e.to_string())?.mounts, &shv_path);
            if let Some((mount_point, node_path)) = paths {
                let mount = self.state.read().map_err(|e| e.to_string())?.mounts.get(mount_point).expect("Should be mounted").clone();
                match mount {
                    Mount::Peer(device_peer_id) => {
                        let mut frame = frame;
                        frame.push_caller_id(peer_id);
                        frame.set_shvpath(node_path);
                        frame.set_tag(Tag::AccessLevel as i32, grant_access_level.map(RpcValue::from));
                        frame.set_tag(Tag::Access as i32, grant_access.map(RpcValue::from));
                        let sender = self.state.read().map_err(|e| e.to_string())?.peers.get(&device_peer_id).ok_or("client ID must exist")?.sender.clone();
                        sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
                        return Ok(())
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
                                methods: node.methods,
                                method,
                            };
                            // drop(state);
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
            }
            return Ok(());
        } else if frame.is_response() {
            let mut frame = frame;
            if let Some(client_id) = frame.pop_caller_id() {
                let sender = {
                    let state = self.state.read().map_err(|e| e.to_string())?;
                    state.peers.get(&client_id).map(|p| p.sender.clone())
                };
                if let Some(sender) = sender {
                    sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
                }
            } else {
                self.process_pending_broker_rpc_call(peer_id, frame).await?;
            }
        } else if frame.is_signal() {
            let mut frames = vec![];
            {
                let state = self.state.read().map_err(|e| e.to_string())?;
                if let Some(peer) = state.peers.get(&peer_id) {
                    if let PeerKind::Device {mount_point, .. } = &peer.peer_kind {
                        let new_path = join_path(mount_point, frame.shv_path().unwrap_or_default());
                        for (cli_id, peer) in state.peers.iter() {
                            let ri = ShvRI::from_path_method_signal(&new_path, frame.source().unwrap_or_default(), frame.method())?;
                            if &peer_id != cli_id && peer.is_signal_subscribed(&ri) {
                                let mut frame = frame.clone();
                                frame.set_shvpath(&new_path);
                                frames.push((frame, peer.sender.clone()));
                            }
                        }
                    }
                }
            }
            for (frame, sender) in frames {
                sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
            }
        }
        Ok(())
    }
    async fn start_broker_rpc_call(&mut self, request: RpcMessage, pending_call: PendingRpcCall) -> shvrpc::Result<()> {
        //self.pending_calls.retain(|r| !r.sender.is_closed());
        let sender = {
            let state = self.state.read().map_err(|e| e.to_string())?;
            let peer = state.peers.get(&pending_call.client_id).ok_or(format!("Invalid client ID: {}", pending_call.client_id))?;
            // let rqid = data.request.request_id().ok_or("Missing request ID")?;
            self.pending_rpc_calls.push(pending_call);
            peer.sender.clone()
        };
        sender.send(BrokerToPeerMessage::SendMessage(request)).await?;
        Ok(())
    }
    async fn process_pending_broker_rpc_call(&mut self, client_id: PeerId, response_frame: RpcFrame) -> shvrpc::Result<()> {
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
            BrokerCommand::NewPeer { client_id,
                user,
                peer_kind,
                mount_point,
                device_id,
                sender} => {
                state_writer(&self.state).add_peer(client_id, user, peer_kind, mount_point, device_id, sender)?;
                self.propagate_subscriptions_to_mounted_device(client_id)?
            },
            BrokerCommand::PeerGone { peer_id } => {
                info!("Client id: {} disconnected.", peer_id);
                state_writer(&self.state).remove_peer(peer_id)?;
                self.pending_rpc_calls.retain(|c| c.client_id != peer_id);
            }
            BrokerCommand::GetPassword { sender, user } => {
                let shapwd = state_reader(&self.state).sha_password(&user);
                sender.send(BrokerToPeerMessage::PasswordSha1(shapwd)).await?;
            }
            BrokerCommand::SendResponse { peer_id, meta, result } => {
                let mut msg = RpcMessage::from_meta(meta);
                msg.set_result_or_error(result);
                let peer_sender = state_reader(&self.state).peers.get(&peer_id).ok_or("Invalid peer ID")?.sender.clone();
                peer_sender.send(BrokerToPeerMessage::SendFrame(RpcFrame::from_rpcmessage(&msg)?)).await?;
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
        }
        Ok(())
    }
    fn propagate_subscription_to_matching_devices(&mut self, peer_id: PeerId, new_subscription: &SubscriptionParam) -> shvrpc::Result<()> {
        // compare new_subscription with all mount-points to check
        // whether it should be propagated also to mounted device
        let mut to_subscribe = vec![];
        for (mount_point, mount) in state_reader(&self.state).mounts.iter() {
            if mount_point.starts_with(DIR_BROKER_CLIENT) {
                continue;
            }
            if let Mount::Peer(device_peer_id) = mount {
                if *device_peer_id == peer_id {
                    continue;
                }
                if let Ok(Some((_local, remote))) = split_glob_on_match(new_subscription.ri.path(), mount_point) {
                    log!(target: "Subscr", Level::Debug, "ADD to subscribe: {}:{}:{:?}", remote, new_subscription.ri.method(), new_subscription.ri.signal());
                    let ri = ShvRI::from_path_method_signal(remote, new_subscription.ri.method(), new_subscription.ri.signal())?;
                    to_subscribe.push((*device_peer_id, SubscriptionParam{ ri, ttl: new_subscription.ttl }));
                }
            }
        }
        let state = self.state.clone();
        task::spawn(async move {
            for (peer_id, subpar) in to_subscribe {
                let to_subscribe = vec![subpar];
                crate::spawn_and_log_error(BrokerImpl::call_subscribe(state.clone(), peer_id, to_subscribe));
            }
        });
        Ok(())
    }
    async fn check_subscribe_path(state: SharedBrokerState, client_id: PeerId) -> shvrpc::Result<SubscribePath> {
        log!(target: "Subscr", Level::Debug, "check_subscribe_path, peer_id: {client_id}");
        if let Some(subpath) = state_reader(&state).is_subscribe_path_resolved(client_id)? {
            log!(target: "Subscr", Level::Debug, "Device subscribe path resolved already, peer_id: {client_id}, path: {:?}", &subpath);
            return Ok(subpath)
        }
        async fn check_path(client_id: PeerId, path: &str, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<Option<String>> {
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
                    return Ok(Some(path.to_string()));
                }
            }
            Ok(None)
        }
        let broker_command_sender = state_reader(&state).command_sender.clone();
        let mut subscribe_path = SubscribePath::NotBroker;
        for path in ["/.broker/currentClient", "/.broker/app"] {
            match check_path(client_id, path, &broker_command_sender).await {
                Ok(path) => {
                    if path.is_some() {
                        subscribe_path = SubscribePath::CanSubscribe(path.unwrap().clone());
                        break;
                    }
                }
                Err(e) => {
                    error!("Error checking subscribe path: {e}");
                }
            }
        }
        log!(target: "Subscr", Level::Debug, "Device subscribe path found, peer_id: {client_id}, path: {:?}", &subscribe_path);
        state.write().unwrap().set_subscribe_path(client_id, subscribe_path.clone())?;
        Ok(subscribe_path)
    }
    async fn call_subscribe(state: SharedBrokerState, peer_id: PeerId, subscriptions: Vec<SubscriptionParam>) -> shvrpc::Result<()> {
        log!(target: "Subscr", Level::Debug, "call_subscribe, peer_id: {peer_id}, subscriptions: {:?}", &subscriptions);
        let subscribe_path = Self::check_subscribe_path(state.clone(), peer_id).await?;
        if let SubscribePath::CanSubscribe(subscribe_path) = subscribe_path {
            async fn call_subscribe1(client_id: PeerId, subscribe_path: &str, subscription: SubscriptionParam, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<()> {
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
            let broker_command_sender = state_reader(&state).command_sender.clone();
            for subscription in subscriptions {
                log!(target: "Subscr", Level::Debug, "Propagating subscription {:?} to client ID: {peer_id}", subscription);
                let _ = call_subscribe1(peer_id, &subscribe_path, subscription, &broker_command_sender).await;
            }
        }
        Ok(())
    }
    fn propagate_subscriptions_to_mounted_device(&self, peer_id: PeerId) -> shvrpc::Result<()> {
        let mut to_subscribe = Vec::new();
        {
            let peers = &state_reader(&self.state).peers;
            let peer = peers.get(&peer_id).ok_or_else(|| format!("Invalid client ID: {peer_id}"))?;
            if let PeerKind::Device {mount_point, ..} = &peer.peer_kind {
                for peer in peers.values() {
                    for peer_sub in &peer.subscriptions {
                        match split_glob_on_match(peer_sub.glob.path_str(), mount_point) {
                            Ok(split) => {
                                if let Some((_local, remote)) = split {
                                    let ri = ShvRI::from_path_method_signal(remote, peer_sub.glob.method_str(), peer_sub.glob.signal_str())?;
                                    let newsub = SubscriptionParam { ri, ttl: peer_sub.param.ttl };
                                    if !to_subscribe.iter().any(|s| *s == newsub) {
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
            }
        }
        let state = self.state.clone();
        crate::spawn_and_log_error(BrokerImpl::call_subscribe(state, peer_id, to_subscribe));
        Ok(())
    }
    async fn disconnect_client(&mut self, client_id: PeerId) -> shvrpc::Result<()> {
        let sender = {
            let state = self.state.read().map_err(|e| e.to_string())?;
            state.peers.get(&client_id).ok_or("Invalid client ID")?.sender.clone()
        };
        sender.send(BrokerToPeerMessage::DisconnectByBroker).await?;
        Ok(())
    }
    async fn subscribe(&mut self, peer_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        log!(target: "Subscr", Level::Debug, "New subscription for peer id: {} - {:?}", peer_id, subpar);
        let subpar = self.state.write().map_err(|e| e.to_string())?.subscribe(peer_id, subpar)?;
        match subpar {
            Some(subpar) => {
                self.propagate_subscription_to_matching_devices(peer_id, &subpar)?;
                Ok(true)
            }
            None => {
                Ok(false)
            }
        }
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
                    const APP_NODE: AppNode = AppNode {
                        app_name: "shvbroker",
                        shv_version_major: 3,
                        shv_version_minor: 0,
                    };
                    match ctx.method.name {
                        shvnode::METH_NAME => {
                            break 'block Ok(APP_NODE.app_name.into());
                        }
                        shvnode::METH_SHV_VERSION_MAJOR => {
                            break 'block Ok(APP_NODE.shv_version_major.into());
                        }
                        shvnode::METH_SHV_VERSION_MINOR => {
                            break 'block Ok(APP_NODE.shv_version_minor.into());
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
                            let info = match state_reader(&self.state).client_info(peer_id) {
                                None => { RpcValue::null() }
                                Some(info) => { RpcValue::from(info) }
                            };
                            break 'block Ok(info);
                        }
                        node::METH_MOUNTED_CLIENT_INFO => {
                            let mount_point = rq.param().unwrap_or_default().as_str();
                            let info = match state_reader(&self.state).mounted_client_info(mount_point) {
                                None => { RpcValue::null() }
                                Some(info) => { RpcValue::from(info) }
                            };
                            break 'block Ok(info);
                        }
                        node::METH_CLIENTS => {
                            let state = self.state.read().map_err(|e| e.to_string())?;
                            let clients: rpcvalue::List = state.peers.keys().map(|id| RpcValue::from(*id)).collect();
                            break 'block Ok(clients.into());
                        }
                        node::METH_MOUNTS => {
                            let state = self.state.read().map_err(|e| e.to_string())?;
                            let mounts: List = state.peers.values()
                                .map(|peer| if let PeerKind::Device {mount_point, ..} = &peer.peer_kind {Some(mount_point)} else {None})
                                .filter(|mount_point| mount_point.is_some())
                                .map(|mount_point| RpcValue::from(mount_point.unwrap()))
                                .collect();
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
                                    let subs_removed = state_writer(&self.state).unsubscribe(ctx.peer_id, &subscription)?;
                                    break 'block Ok(subs_removed.into());
                                }
                                Err(e) => {
                                    let err = RpcError::new(RpcErrorCode::InvalidParam, e);
                                    break 'block Err(err);
                                }
                            }
                        }
                        node::METH_SUBSCRIPTIONS => {
                            let result = state_reader(&self.state).subscriptions(ctx.peer_id)?;
                            break 'block Ok(result.into());
                        }
                        node::METH_INFO => {
                            let info = match state_reader(&self.state).client_info(ctx.peer_id) {
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
    peer_id: PeerId,
    command_sender: Sender<BrokerCommand>,
    mount_point: String,
    methods: Vec<&'static MetaMethod>,
    method: &'static MetaMethod,
}

#[cfg(test)]
mod test {
    use crate::brokerimpl::BrokerImpl;
    use crate::config::BrokerConfig;
    use crate::brokerimpl::state_reader;

    #[test]
    fn test_broker() {
        let config = BrokerConfig::default();
        let access = config.access.clone();
        let broker = BrokerImpl::new(access);
        let roles = state_reader(&broker.state).flatten_roles("child-broker").unwrap();
        assert_eq!(roles, vec!["child-broker", "device", "client", "ping", "subscribe", "browse"]);
    }
}
