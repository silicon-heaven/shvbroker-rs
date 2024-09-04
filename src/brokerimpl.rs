use async_std::{channel, task};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ops::Add;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};
use async_std::channel::{Receiver, Sender, unbounded};
use async_std::{future};
use async_std::net::TcpListener;
use log::{debug, error, info, log, warn};
use crate::config::{AccessConfig, BrokerConfig, Password};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode, RqId, Tag};
use shvproto::{Map, MetaMap, RpcValue, rpcvalue};
use shvrpc::rpc::{Glob, ShvRI, SubscriptionParam};
use crate::shvnode::{AppNode, BrokerAccessMountsNode, BrokerAccessRolesNode, BrokerAccessUsersNode, BrokerCurrentClientNode, BrokerNode, DIR_APP, DIR_BROKER, DIR_BROKER_ACCESS_MOUNTS, DIR_BROKER_ACCESS_ROLES, DIR_BROKER_ACCESS_USERS, DIR_BROKER_CURRENT_CLIENT, find_longest_prefix, METH_DIR, METH_SUBSCRIBE, process_local_dir_ls, ShvNode, ProcessRequestRetval};
use shvrpc::util::{join_path, sha1_hash, split_glob_on_match};
use log::Level;
use shvrpc::metamethod::{AccessLevel};
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use crate::spawn::spawn_and_log_error;
use futures::select;
use crate::peer;
use crate::peer::next_peer_id;
use async_std::stream::StreamExt;
use futures::FutureExt;
use shvrpc::rpcmessage::Tag::RevCallerIds;
use crate::brokerimpl::BrokerCommand::ExecSql;
use crate::tunnelnode::{tunnel_task, OpenTunnelNode, ToRemoteMsg, TunnelNode};

#[derive(Debug)]
pub(crate)  struct Subscription {
    pub(crate) param: SubscriptionParam,
    pub(crate) glob: Glob,
    pub(crate) subscribed: Instant,
}
#[derive(Debug)]
pub(crate)  struct ForwardedSubscription {
    pub(crate) param: SubscriptionParam,
    pub(crate) subscribed: Option<Instant>,
}

impl Subscription {
    pub(crate) fn new(subpar: &SubscriptionParam) -> shvrpc::Result<Self> {
        let glob = subpar.ri.to_glob()?;
        Ok(Self {
            param: subpar.clone(),
            glob,
            subscribed: Instant::now(),
        })
    }
    pub(crate) fn match_shv_ri(&self, shv_ri: &ShvRI) -> bool {
        self.glob.match_shv_ri(shv_ri)
    }
}

#[derive(Debug)]
pub(crate) enum BrokerCommand {
    GetPassword {
        sender: Sender<BrokerToPeerMessage>,
        user: String,
    },
    NewPeer {
        peer_id: PeerId,
        peer_kind: PeerKind,
        user: String,
        mount_point: Option<String>,
        device_id: Option<String>,
        sender: Sender<BrokerToPeerMessage>,
    },
    FrameReceived {
        peer_id: PeerId,
        frame: RpcFrame,
    },
    PeerGone {
        peer_id: PeerId,
    },
    SendResponse {peer_id: PeerId, meta: MetaMap, result: Result<RpcValue, RpcError>},
    SendSignal {shv_path: String, signal: String, source: String, param: RpcValue},
    RpcCall {
        client_id: PeerId,
        request: RpcMessage,
        response_sender: Sender<RpcFrame>,
    },
    ExecSql {
        query: String,
    },
    CloseTunnel(String),
}

#[derive(Debug)]
pub(crate) enum BrokerToPeerMessage {
    PasswordSha1(Option<Vec<u8>>),
    SendFrame(RpcFrame),
    SendMessage(RpcMessage),
    DisconnectByBroker,
}

#[derive(Debug, Clone)]
pub(crate) enum SubscribePath {
    NotBroker,
    CanSubscribe(String),
}
#[derive(Debug, Clone)]
pub(crate) enum PeerKind {
    Client,
    ParentBroker,
    Device {
        device_id: Option<String>,
        mount_point: String,
        subscribe_path: Option<SubscribePath>,
    },
}
#[derive(Debug)]
pub(crate) struct Peer {
    pub(crate) peer_kind: PeerKind,
    pub(crate) user: String,
    pub(crate) sender: Sender<BrokerToPeerMessage>,
    pub(crate) subscriptions: Vec<Subscription>,
    pub(crate) forwarded_subscriptions: Vec<ForwardedSubscription>,
}

impl Peer {
    pub(crate) fn is_signal_subscribed(&self, signal: &ShvRI) -> bool {
        for subs in self.subscriptions.iter() {
            //println!("{signal} matches {} -> {}", subs.glob.as_str(), subs.match_shv_ri(signal));
            if subs.match_shv_ri(signal) {
                return true;
            }
        }
        false
    }
}

pub(crate) enum Mount {
    Peer(PeerId),
    Node,
}

pub(crate) struct ParsedAccessRule {
    pub(crate) glob: shvrpc::rpc::Glob,
    // Needed in order to pass 'dot-local' in 'Access' meta-attribute
    // to support the dot-local hack on older brokers
    pub(crate) access: String,
    pub(crate) access_level: AccessLevel,
}

impl ParsedAccessRule {
    pub fn new(shv_ri: &ShvRI, grant: &str) -> shvrpc::Result<Self> {
        Ok(Self {
            glob: shv_ri.to_glob()?,
            access: grant.to_string(),
            access_level: grant
                .split(',')
                .find_map(AccessLevel::from_str)
                .unwrap_or_else(|| panic!("Invalid access grant `{grant}`")),
        })
    }
}

pub(crate) struct PendingRpcCall {
    pub(crate) client_id: PeerId,
    pub(crate) request_meta: MetaMap,
    pub(crate) response_sender: Sender<RpcFrame>,
    pub(crate) started: Instant,
}

pub(crate) async fn broker_loop(broker: BrokerImpl) {
    let mut broker = broker;
    loop {
        select! {
            command = broker.command_receiver.recv().fuse() => match command {
                Ok(command) => {
                    if let Err(err) = broker.process_broker_command(command).await {
                        warn!("Process broker command error: {}", err);
                    }
                }
                Err(err) => {
                    warn!("Receive broker command error: {}", err);
                }
            },
        }
    }
}

pub async fn accept_loop(config: BrokerConfig, access: AccessConfig, sql_connection: Option<rusqlite::Connection>) -> shvrpc::Result<()> {
    if let Some(address) = config.listen.tcp.clone() {
        let broker_impl = BrokerImpl::new(access, sql_connection);
        let broker_sender = broker_impl.command_sender.clone();
        let parent_broker_peer_config = config.parent_broker.clone();
        let broker_task = task::spawn(broker_loop(broker_impl));
        if parent_broker_peer_config.enabled {
            let peer_id = next_peer_id();
            crate::spawn_and_log_error(peer::parent_broker_peer_loop_with_reconnect(peer_id, parent_broker_peer_config, broker_sender.clone()));
        }
        info!("Listening on TCP: {}", address);
        let listener = TcpListener::bind(address).await?;
        info!("bind OK");
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let peer_id = next_peer_id();
            debug!("Accepting from: {}", stream.peer_addr()?);
            crate::spawn_and_log_error(peer::try_peer_loop(peer_id, broker_sender.clone(), stream));
        }
        drop(broker_sender);
        broker_task.await;
    } else {
        return Err("No port to listen on specified".into());
    }
    Ok(())
}

pub struct BrokerState {
    pub(crate) peers: BTreeMap<PeerId, Peer>,
    mounts: BTreeMap<String, Mount>,
    pub(crate) access: AccessConfig,
    role_access: HashMap<String, Vec<ParsedAccessRule>>,

    pub(crate) command_sender: Sender<BrokerCommand>,

    open_tunnels: BTreeMap<String, OpenTunnelNode>,
    next_tunnel_number: u64,
}
pub(crate) type SharedBrokerState = Arc<RwLock<BrokerState>>;
impl BrokerState {
    fn mount_point(&self, peer_id: PeerId) -> Option<String> {
        self.peers.get(&peer_id)
            .and_then(|peer| {
                if let PeerKind::Device { mount_point, .. } = &peer.peer_kind {
                    if mount_point.is_empty() {
                        None
                    } else {
                        Some(mount_point.clone())
                    }
                } else { None }
            })
    }
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
            forwarded_subscriptions: vec![],
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
        let subs = Self::subscriptions_to_map(&peer.subscriptions);
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
    pub(crate) fn client_info(&self, client_id: PeerId) -> Option<rpcvalue::Map> {
        self.peers.get(&client_id).map(|peer| BrokerState::peer_to_info(client_id, peer))
    }
    pub(crate) fn mounted_client_info(&self, mount_point: &str) -> Option<rpcvalue::Map> {
        for (client_id, peer) in &self.peers {
            if let PeerKind::Device {mount_point: mount_point1, ..} = &peer.peer_kind {
                if mount_point1 == mount_point {
                    return Some(BrokerState::peer_to_info(*client_id, peer));
                }
            }
        }
        None
    }
    fn subscriptions_to_map(subscriptions: &[Subscription]) -> Map {
        subscriptions.iter().map(|subscr| {
            match subscr.param.ttl {
                None => {
                    let key = subscr.glob.as_str().to_string();
                    (key, ().into())
                }
                Some(ttl) => {
                    let key = subscr.glob.as_str().to_string();
                    let ttl = Instant::now() + Duration::from_secs(ttl as u64) - subscr.subscribed;
                    (key, (ttl.as_secs() as i64).into())
                }
            }
        }).collect()
    }
    pub(crate) fn subscriptions(&self, client_id: PeerId) -> shvrpc::Result<Map> {
        let peer = self.peers.get(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        Ok(Self::subscriptions_to_map(&peer.subscriptions))
    }
    pub(crate) fn subscribe(&mut self, client_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        let peer = self.peers.get_mut(&client_id).ok_or_else(|| format!("Invalid client ID: {client_id}"))?;
        if let  Some(sub) = peer.subscriptions.iter_mut().find(|sub| sub.param.ri == subpar.ri) {
            log!(target: "Subscr", Level::Debug, "Changing subscription TTL for client id: {} - {:?}", client_id, subpar);
            sub.param.ttl = subpar.ttl;
            Ok(false)
        } else {
            log!(target: "Subscr", Level::Debug, "Adding subscription for client id: {} - {:?}", client_id, subpar);
            peer.subscriptions.push(Subscription::new(subpar)?);
            Ok(true)
        }
    }
    pub(crate) fn unsubscribe(&mut self, client_id: PeerId, subpar: &SubscriptionParam) -> shvrpc::Result<bool> {
        log!(target: "Subscr", Level::Debug, "Removing subscription for client id: {} - {:?}", client_id, subpar);
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
    pub(crate) fn gc_subscriptions(&mut self) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            peer.subscriptions.retain(|subscr| {
                match subscr.param.ttl {
                    None => {
                        true
                    }
                    Some(ttl) => {
                        let expired = now - subscr.subscribed > Duration::from_secs(ttl as u64);
                        if expired {
                            log!(target: "Subscr", Level::Debug, "Subscription expired: {:?}", subscr.param);
                        }
                        !expired
                    }
                }
            });
        }
    }
    pub(crate) fn update_forwarded_subscriptions(&mut self) -> shvrpc::Result<()> {
        let mut fwd_subs: HashSet<ShvRI> = Default::default();
        for peer in self.peers.values() {
            for subscr in &peer.subscriptions {
                fwd_subs.insert(subscr.param.ri.clone());
            }
        }
        const DEFAULT_TTL: Option<u32> = Some(10 * 60);
        let mut to_forward: HashMap<PeerId, HashSet<ShvRI>> = Default::default();
        for (peer_id, peer) in &self.peers {
            if let PeerKind::Device { mount_point, subscribe_path: Some(SubscribePath::CanSubscribe(_)), .. } = &peer.peer_kind {
                for ri in &fwd_subs {
                    if let Ok(Some((_local, remote))) = split_glob_on_match(ri.path(), mount_point) {
                        log!(target: "Subscr", Level::Debug, "Schedule forward subscription: {}:{}:{:?}", remote, ri.method(), ri.signal());
                        let ri = ShvRI::from_path_method_signal(remote, ri.method(), ri.signal())?;
                        if let Some(val) = to_forward.get_mut(peer_id) {
                            val.insert(ri);
                        } else {
                            let mut set1: HashSet<ShvRI> = Default::default();
                            set1.insert(ri);
                            to_forward.insert(*peer_id, set1);
                        }
                    }
                }
            }
        }
        for (peer_id, peer) in &mut self.peers {
            if let Some(to_fwd_peer) = to_forward.get_mut(peer_id) {
                // remove fwd subscritions not found in to_fwd_peer
                peer.forwarded_subscriptions.retain_mut(|subs| {
                    if to_fwd_peer.contains(&subs.param.ri) {
                        to_fwd_peer.remove(&subs.param.ri);
                        if let Some(subscribed) = &subs.subscribed {
                            if let Some(ttl) = subs.param.ttl {
                                let expires = subscribed.add(Duration::from_secs(ttl as u64 - 10));
                                if expires < Instant::now() {
                                    // subscriptions near to expiration, schedule subscribe RPC call
                                    subs.subscribed = None;
                                }
                            }
                        }
                        true
                    } else {
                        false
                    }
                });
                // add new fwd subscriptions
                for ri in to_fwd_peer.iter() {
                    peer.forwarded_subscriptions.push(ForwardedSubscription {
                        param: SubscriptionParam { ri: ri.clone(), ttl: DEFAULT_TTL },
                        subscribed: None,
                    });
                }
            }
        }
        Ok(())
    }
    pub(crate) fn access_mount(&self, id: &str) -> Option<&crate::config::Mount> {
        self.access.mounts.get(id)
    }
    pub(crate) fn set_access_mount(&mut self, id: &str, mount: Option<crate::config::Mount>) {
        let sqlop = if let Some(mount) = mount {
            let json = serde_json::to_string(&mount).unwrap_or_else(|e| {
                error!("Generate SQL statement error: {e}");
                "".to_string()
            });
            let sql = if self.access.mounts.contains_key(id) {
                UpdateSqlOperation::Update { id, json }
            } else {
                UpdateSqlOperation::Insert { id, json }
            };
            self.access.mounts.insert(id.to_string(), mount);
            sql
        } else {
            self.access.mounts.remove(id);
            UpdateSqlOperation::Delete { id }
        };
        self.uddate_sql("mounts", sqlop);
    }
    pub(crate) fn access_user(&self, id: &str) -> Option<&crate::config::User> {
        self.access.users.get(id)
    }
    pub(crate) fn set_access_user(&mut self, id: &str, user: Option<crate::config::User>) {
        let sqlop = if let Some(user) = user {
            let json = serde_json::to_string(&user).unwrap_or_else(|e| {
                error!("Generate SQL statement error: {e}");
                "".to_string()
            });
            let sql = if self.access.users.contains_key(id) {
                UpdateSqlOperation::Update { id, json }
            } else {
                UpdateSqlOperation::Insert { id, json }
            };
            self.access.users.insert(id.to_string(), user);
            sql
        } else {
            self.access.users.remove(id);
            UpdateSqlOperation::Delete { id }
        };
        self.uddate_sql("users", sqlop);
    }
    pub(crate) fn access_role(&self, id: &str) -> Option<&crate::config::Role> {
        self.access.roles.get(id)
    }
    pub(crate) fn set_access_role(&mut self, id: &str, role: Option<crate::config::Role>) {
        let sqlop = if let Some(role) = role {
            let json = serde_json::to_string(&role).unwrap_or_else(|e| {
                error!("Generate SQL statement error: {e}");
                "".to_string()
            });
            let sql = if self.access.roles.contains_key(id) {
                UpdateSqlOperation::Update { id, json }
            } else {
                UpdateSqlOperation::Insert { id, json }
            };
            self.access.roles.insert(id.to_string(), role);
            sql
        } else {
            self.access.roles.remove(id);
            UpdateSqlOperation::Delete { id }
        };
        self.uddate_sql("roles", sqlop);
    }
    fn uddate_sql(&self, table: &str, oper: UpdateSqlOperation) {
        let query = match oper {
            UpdateSqlOperation::Insert { id, json } => {
                format!("INSERT INTO {} (id, def) VALUES ('{}', '{}');", table, id, json)
            }
            UpdateSqlOperation::Update { id, json } => {
                format!("UPDATE {} SET def = '{}' WHERE id = '{}';", table, json, id)
            }
            UpdateSqlOperation::Delete { id } => {
                format!("DELETE FROM {} WHERE id = '{}';", table, id)
            }
        };
        let sender = self.command_sender.clone();
        task::spawn(async move {
            let _ = sender.send(ExecSql { query }).await;
        });
    }
    pub(crate) fn create_tunnel(&mut self, frame: &RpcFrame) -> shvrpc::Result<()> {
        let tunid = self.next_tunnel_number;
        self.next_tunnel_number += 1;
        let tunid = format!("{tunid}");
        debug!("create_tunnel: {tunid}");
        let rq = frame.to_rpcmesage()?;
        let caller_ids = rq.caller_ids();
        let param = rq.param().unwrap_or_default().as_map();
        let host = param.get("host").ok_or("'host' parameter must be provided")?.as_str().to_string();
        let (sender, receiver) = channel::unbounded::<ToRemoteMsg>();
        let tun = OpenTunnelNode { caller_ids, sender };
        let rq_meta = frame.meta.clone();
        self.open_tunnels.insert(tunid.clone(), tun);
        let command_sender = self.command_sender.clone();
        task::spawn(async move {
            command_sender.send(BrokerCommand::SendSignal {
                shv_path: format!(".app/tunnel/{tunid}"),
                signal: "lsmod".to_string(),
                source: "ls".to_string(),
                param: Map::from([(tunid.clone(), true.into())]).into(),
            }).await?;
            if let Err(e) = tunnel_task(tunid.clone(), rq_meta, host, receiver, command_sender.clone()).await {
                error!("{}", e)
            }
            command_sender.send(BrokerCommand::CloseTunnel(tunid)).await
        });
        Ok(())
    }
    pub(crate) fn close_tunnel(&mut self, tunid: &str) -> shvrpc::Result<bool> {
        if let Some(tun) = self.open_tunnels.remove(tunid) {
            let sender = tun.sender;
            task::spawn(async move {
                let _ = sender.send(ToRemoteMsg::DestroyConnection).await;
            });
            Ok(true)
        } else {
            // might be callback of previous close_tunel()
            Ok(false)
        }
    }
    pub(crate) fn open_tunnel_ids(&self) -> Vec<String> {
        let keys = self.open_tunnels.keys().cloned().collect();
        keys
    }
    pub(crate) fn is_request_granted(&self, tunid: &str, frame: &RpcFrame) -> bool {
        if let Some(tun) = self.open_tunnels.get(tunid) {
            let cids = frame.caller_ids();
            cids == tun.caller_ids || AccessLevel::try_from(frame.access_level().unwrap_or(0)).unwrap_or(AccessLevel::Browse) == AccessLevel::Superuser
        } else {
            false
        }
    }
    pub(crate) fn write_tunnel(&self, tunid: &str, rqid: RqId, data: Vec<u8>) -> shvrpc::Result<()> {
        if let Some(tun) = self.open_tunnels.get(tunid) {
            let sender = tun.sender.clone();
            task::spawn(async move {
                sender.send(ToRemoteMsg::SendData(rqid, data)).await
            });
            Ok(())
        } else {
            Err(format!("Invalid tunnel ID: {tunid}").into())
        }
    }
}
enum UpdateSqlOperation<'a> {
    Insert{id: &'a str, json: String},
    Update{id: &'a str, json: String},
    Delete{id: &'a str},
}
pub struct BrokerImpl {
    pub(crate) state: SharedBrokerState,
    nodes: BTreeMap<String, Box<dyn ShvNode>>,

    pending_rpc_calls: Vec<PendingRpcCall>,
    pub(crate) command_sender: Sender<BrokerCommand>,
    pub(crate) command_receiver: Receiver<BrokerCommand>,

    pub(crate) sql_connection: Option<rusqlite::Connection>,
}
pub(crate) fn state_reader(state: &SharedBrokerState) -> RwLockReadGuard<BrokerState> {
    state.read().unwrap()
}
pub(crate) fn state_writer(state: &SharedBrokerState) -> RwLockWriteGuard<BrokerState> {
    state.write().unwrap()
}
impl BrokerImpl {
    pub(crate) fn new(access: AccessConfig, sql_connection: Option<rusqlite::Connection>) -> Self {
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
        let state = BrokerState {
            peers: Default::default(),
            mounts: Default::default(),
            access,
            role_access,
            command_sender: command_sender.clone(),
            open_tunnels: Default::default(),
            next_tunnel_number: 1,
        };
        let mut broker = Self {
            state: Arc::new(RwLock::new(state)),
            nodes: Default::default(),
            pending_rpc_calls: vec![],
            command_sender,
            command_receiver,
            sql_connection,
        };
        let mut add_node = |path: &str, node: Box<dyn ShvNode>| {
            state_writer(&broker.state).mounts.insert(path.into(), Mount::Node);
            broker.nodes.insert(path.into(), node);
        };
        add_node(DIR_APP, Box::new(AppNode::new()));
        add_node(".app/tunnel", Box::new(TunnelNode::new()));
        add_node(DIR_BROKER, Box::new(BrokerNode::new()));
        add_node(DIR_BROKER_CURRENT_CLIENT, Box::new(BrokerCurrentClientNode::new()));
        add_node(DIR_BROKER_ACCESS_MOUNTS, Box::new(BrokerAccessMountsNode::new()));
        add_node(DIR_BROKER_ACCESS_USERS, Box::new(BrokerAccessUsersNode::new()));
        add_node(DIR_BROKER_ACCESS_ROLES, Box::new(BrokerAccessRolesNode::new()));
        broker
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
                enum Action {
                    ToPeer(Sender<BrokerToPeerMessage>, BrokerToPeerMessage),
                    NodeRequest{ node_id: String, frame: RpcFrame, ctx: NodeRequestContext },
                }
                let action = {
                    let mut frame = frame;
                    frame.push_caller_id(peer_id);
                    frame.set_shvpath(node_path);
                    frame.set_tag(Tag::AccessLevel as i32, grant_access_level.map(RpcValue::from));
                    frame.set_tag(Tag::Access as i32, grant_access.map(RpcValue::from));
                    let state = state_reader(&self.state);
                    match state.mounts.get(mount_point).expect("Should be mounted") {
                        Mount::Peer(device_peer_id) => {
                            let sender = state.peers.get(device_peer_id).ok_or("client ID must exist")?.sender.clone();
                            Action::ToPeer(sender, BrokerToPeerMessage::SendFrame(frame))
                        }
                        Mount::Node => {
                            Action::NodeRequest {
                                node_id: mount_point.to_string(),
                                frame,
                                ctx: NodeRequestContext {
                                    peer_id,
                                    node_path: node_path.to_string(),
                                    state: self.state.clone(),
                                    sql_available: self.sql_connection.is_some(),
                                },
                            }
                        }
                    }
                };
                match action {
                    Action::ToPeer(sender, msg) => {
                        sender.send(msg).await?;
                        return Ok(())
                    }
                    Action::NodeRequest { node_id, frame, ctx } => {
                        let node = self.nodes.get_mut(&node_id).expect("Should be mounted");
                        if node.is_request_granted(&frame, &ctx) {
                            let result = match node.process_request_and_dir_ls(&frame, &ctx) {
                                Err(e) => {
                                    Err(RpcError::new(RpcErrorCode::MethodCallException, e.to_string()))
                                }
                                Ok(ProcessRequestRetval::MethodNotFound) => {
                                    Err(RpcError::new(RpcErrorCode::MethodNotFound, format!("Method {}:{} not found.", shv_path, frame.method().unwrap_or_default())))
                                }
                                Ok(ProcessRequestRetval::RetvalDeferred) => {
                                    return Ok(())
                                }
                                Ok(ProcessRequestRetval::Retval(result)) => {
                                    Ok(result)
                                }
                            };
                            self.command_sender.send(BrokerCommand::SendResponse { peer_id, meta: response_meta, result }).await?;
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
            if let Some(fwd_peer_id) = frame.pop_caller_id() {
                if frame.tag(RevCallerIds as i32).is_some() {
                    frame.push_caller_id(peer_id);
                }
                let sender = state_reader(&self.state).peers.get(&fwd_peer_id).map(|p| p.sender.clone());
                if let Some(sender) = sender {
                    sender.send(BrokerToPeerMessage::SendFrame(frame)).await?;
                } else {
                    warn!("Cannot find peer for response peer-id: {fwd_peer_id}");
                }
            } else {
                self.process_pending_broker_rpc_call(peer_id, frame).await?;
            }
        } else if frame.is_signal() {
            let mut frames = vec![];
            {
                let state = state_reader(&self.state);
                if let Some(peer) = state.peers.get(&peer_id) {
                    if let PeerKind::Device {mount_point, .. } = &peer.peer_kind {
                        let new_path = join_path(mount_point, frame.shv_path().unwrap_or_default());
                        for (tested_peer_id, peer) in state.peers.iter() {
                            let ri = ShvRI::from_path_method_signal(&new_path, frame.source().unwrap_or_default(), frame.method())?;
                            if &peer_id != tested_peer_id && peer.is_signal_subscribed(&ri) {
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
            let request_id = pc.request_meta.request_id().unwrap_or_default();
            if request_id == rqid && pc.client_id == client_id {
                pending_call_ix = Some(ix);
                break;
            }
        }
        if let Some(ix) = pending_call_ix {
            let pending_call = self.pending_rpc_calls.remove(ix);
            pending_call.response_sender.send(response_frame).await?;
        }
        self.gc_pending_rpc_calls().await?;
        Ok(())
    }
    async fn gc_pending_rpc_calls(&mut self) -> shvrpc::Result<()> {
        let now = Instant::now();
        const TIMEOUT: Duration = Duration::from_secs(60);
        // unfortunately `extract_if()` is not stabilized yet
        let mut timeouted = vec![];
        self.pending_rpc_calls.retain(|pending_call| {
            if now.duration_since(pending_call.started) > TIMEOUT {
                let mut msg = RpcMessage::from_meta(pending_call.request_meta.clone());
                msg.set_error(RpcError::new(RpcErrorCode::MethodCallTimeout, "Method call timeout"));
                timeouted.push((msg, pending_call.response_sender.clone()));
                false
            } else {
                true
            }
        });
        for (msg, sender) in timeouted {
            sender.send(msg.to_frame()?).await?;
        }
        Ok(())
    }

    async fn process_broker_command(&mut self, broker_command: BrokerCommand) -> shvrpc::Result<()> {
        match broker_command {
            BrokerCommand::FrameReceived { peer_id: client_id, frame } => {
                if let Err(err) = self.process_rpc_frame(client_id, frame).await {
                    warn!("Process RPC frame error: {err}");
                }
            }
            BrokerCommand::NewPeer {
                peer_id,
                user,
                peer_kind,
                mount_point,
                device_id,
                sender} => {
                info!("New peer, id: {peer_id}.");
                state_writer(&self.state).add_peer(peer_id, user, peer_kind, mount_point, device_id, sender)?;
                spawn_and_log_error(Self::on_device_mounted(self.state.clone(), peer_id));
            }
            BrokerCommand::PeerGone { peer_id } => {
                info!("Peer gone, id: {peer_id}.");
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
            BrokerCommand::SendSignal { shv_path, signal, source, param } => {
                let msg = RpcMessage::new_signal_with_source(&shv_path, &signal, &source, Some(param));
                let senders: Vec<_> = state_reader(&self.state).peers.values().map(|peer| peer.sender.clone()).collect();
                for sender in senders {
                    sender.send(BrokerToPeerMessage::SendFrame(RpcFrame::from_rpcmessage(&msg)?)).await?;
                }
            }
            BrokerCommand::RpcCall { client_id, request, response_sender } => {
                let request_meta = request.meta().clone();
                let mut rq2 = request;
                // broker calls can have any access level, set 'su' to bypass client access control
                rq2.set_access_level(AccessLevel::Superuser);
                self.start_broker_rpc_call(rq2, PendingRpcCall {
                    client_id,
                    request_meta,
                    response_sender,
                    started: Instant::now(),
                }).await?
            }
            BrokerCommand::ExecSql { query } => {
                if let Some(connection) = &self.sql_connection {
                    connection.execute(&query, ()).unwrap_or_else(|e| {
                        error!("SQL exec error: {e}");
                        0
                    });
                } else {
                    error!("SQL config is disabled, use --use-access-db CLI switch.")
                }
            }
            BrokerCommand::CloseTunnel(tunnel_id) => {
                if state_writer(&self.state).close_tunnel(&tunnel_id)? {
                    self.command_sender.send(BrokerCommand::SendSignal {
                        shv_path: format!(".app/tunnel/{tunnel_id}"),
                        signal: "lsmod".to_string(),
                        source: "ls".to_string(),
                        param: Map::from([(tunnel_id, false.into())]).into(),
                    }).await?;
                }
            }
        }
        Ok(())
    }
    async fn on_device_mounted(state: SharedBrokerState, peer_id: PeerId) -> shvrpc::Result<()> {
        let mount_point = state_reader(&state).mount_point(peer_id);
        if mount_point.is_some() {
            state_writer(&state).gc_subscriptions();
            if let SubscribePath::CanSubscribe(_) = BrokerImpl::check_subscribe_path(state.clone(), peer_id).await? {
                state_writer(&state).update_forwarded_subscriptions().unwrap();
                Self::renew_forwarded_subscriptions(state.clone()).await?;
            }
        }
        Ok(())
    }
    async fn check_subscribe_path(state: SharedBrokerState, client_id: PeerId) -> shvrpc::Result<SubscribePath> {
        log!(target: "Subscr", Level::Debug, "check_subscribe_path, peer_id: {client_id}");
        if let Some(subpath) = state_reader(&state).is_subscribe_path_resolved(client_id)? {
            log!(target: "Subscr", Level::Debug, "Device subscribe path resolved already, peer_id: {client_id}, path: {:?}", &subpath);
            return Ok(subpath)
        }
        async fn check_path_with_timeout(client_id: PeerId, path: &str, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<Option<String>> {
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
            let dur = Duration::from_secs(5);
            let fut = check_path(client_id, path, broker_command_sender);
            match future::timeout(dur, fut).await {
                Ok(res) => {
                    res
                }
                Err(err) => {
                    Err(err.into())
                }
            }
        }
        let broker_command_sender = state_reader(&state).command_sender.clone();
        let mut subscribe_path = SubscribePath::NotBroker;
        for path in [".broker/currentClient", ".broker/app"] {
            match check_path_with_timeout(client_id, path, &broker_command_sender).await {
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
    pub(crate) async fn renew_forwarded_subscriptions(state: SharedBrokerState) -> shvrpc::Result<()> {
        let mut to_subscribe: HashMap<_, _> = Default::default();
        for (peer_id, peer) in &mut state_writer(&state).peers {
            if let PeerKind::Device { subscribe_path: Some(SubscribePath::CanSubscribe(subpath)), .. } = &peer.peer_kind {
                let mut to_subscribe_peer: Vec<_> = Default::default();
                for subscr in &mut peer.forwarded_subscriptions {
                    if subscr.subscribed.is_none() {
                        subscr.subscribed = Some(Instant::now());
                        to_subscribe_peer.push(subscr.param.clone());
                    }
                }
                to_subscribe.insert(*peer_id, (subpath.clone(), to_subscribe_peer));
            }
        }
        for (peer_id, (subpath, to_subscribe)) in to_subscribe {
            for subpar in to_subscribe {
                match Self::call_subscribe_with_timeout(state.clone(), peer_id, &subpath, subpar).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Call subscribe error: {e}")
                    }
                }
            }
        }
        Ok(())
    }
    async fn call_subscribe_with_timeout(state: SharedBrokerState, peer_id: PeerId, subscribe_path: &str, subscription: SubscriptionParam) -> shvrpc::Result<()> {
        let broker_command_sender = state_reader(&state).command_sender.clone();
        async fn call_subscribe1(peer_id: PeerId, subscribe_path: &str, subscription: SubscriptionParam, broker_command_sender: &Sender<BrokerCommand>) -> shvrpc::Result<()> {
            log!(target: "Subscr", Level::Debug, "call_subscribe, peer_id: {peer_id}, subscriptions: {:?}", &subscription);
            let (response_sender, response_receiver) = unbounded();
            let cmd = BrokerCommand::RpcCall {
                client_id: peer_id,
                request: RpcMessage::new_request(subscribe_path, METH_SUBSCRIBE, Some(subscription.to_rpcvalue())),
                response_sender,
            };
            broker_command_sender.send(cmd).await?;
            response_receiver.recv().await?.to_rpcmesage()?;
            Ok(())
        }
        const TIMEOUT: u64 = 10;
        match future::timeout(Duration::from_secs(TIMEOUT), call_subscribe1(peer_id, subscribe_path, subscription.clone(), &broker_command_sender)).await {
            Ok(r) => {
                match r {
                    Ok(_) => {
                        log!(target: "Subscr", Level::Debug, "call_subscribe SUCCESS, peer_id: {peer_id}, subscriptions: {:?}", &subscription);
                    }
                    Err(e) => {
                        log!(target: "Subscr", Level::Error, "call_subscribe error: {e}, peer_id: {peer_id}, subscriptions: {:?}", &subscription);
                        // remove subscription error, it will be scheduled again on next update_forwarded_subscriptions() run
                        if let Some(peer) = state_writer(&state).peers.get_mut(&peer_id) {
                            peer.forwarded_subscriptions.retain(|subscr| {subscription.ri.as_str() != subscr.param.ri.as_str()});
                        }
                    }
                }
            }
            Err(_) => {
                log!(target: "Subscr", Level::Error, "call_subscribe timeout after {TIMEOUT} sec, peer_id: {peer_id}, subscriptions: {:?}", &subscription);
                // remove subscription on timeout, it will be scheduled again on next update_forwarded_subscriptions() run
                if let Some(peer) = state_writer(&state).peers.get_mut(&peer_id) {
                    peer.forwarded_subscriptions.retain(|subscr| {subscription.ri.as_str() != subscr.param.ri.as_str()});
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct NodeRequestContext {
    pub(crate) peer_id: PeerId,
    pub(crate) node_path: String,
    pub(crate) state: SharedBrokerState,
    pub(crate) sql_available: bool,
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
        let broker = BrokerImpl::new(access, None);
        let roles = state_reader(&broker.state).flatten_roles("child-broker").unwrap();
        assert_eq!(roles, vec!["child-broker", "device", "client", "ping", "subscribe", "browse"]);
    }
}
