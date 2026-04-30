use crate::config::{AccessConfig, AccessRule, ConnectionMountSettings, Listen, Password, Role, SharedBrokerConfig, UpdateSqlOperation, parse_role_access_rules};
use crate::shvnode::{
    AppNode, BrokerAccessAllowedIpsNode, BrokerAccessLastLoginNode, BrokerAccessMountsNode, BrokerAccessRolesNode, BrokerAccessUsersNode, BrokerCurrentClientNode, BrokerNode, DIR_APP, DIR_BROKER, DIR_BROKER_ACCESS_ALLOWED_IPS, DIR_BROKER_ACCESS_LAST_LOGIN, DIR_BROKER_ACCESS_MOUNTS, DIR_BROKER_ACCESS_ROLES, DIR_BROKER_ACCESS_USERS, DIR_BROKER_CURRENT_CLIENT, DIR_SHV2_BROKER_APP, DIR_SHV2_BROKER_ETC_ACL_MOUNTS, DIR_SHV2_BROKER_ETC_ACL_USERS, METH_LS, METH_SUBSCRIBE, METH_UNSUBSCRIBE, ProcessRequestRetval, SIG_LSMOD, SIG_MNTMOD, Shv2BrokerAppNode, ShvNode, process_local_dir_ls
};
use crate::spawn::spawn_and_log_error;
use crate::sql::{TBL_LAST_LOGIN, update_sql};
use crate::tunnelnode::TunnelNode;
use crate::{cut_prefix, peer, serial};
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use futures::stream::FuturesUnordered;
use futures::{AsyncRead, AsyncWrite, FutureExt};
use futures::StreamExt;
use futures::select;
use futures_rustls::pki_types::{CertificateDer, PrivateKeyDer};
use log::Level;
use log::{debug, error, info, log, warn};
use shvproto::{DateTime, Map, MetaMap, RpcValue};
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpc::{Glob, ShvRI, SubscriptionParam};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::Tag::RevCallerIds;
use shvrpc::rpcmessage::{PeerId, Response, RpcError, RpcErrorCode, Tag};
use shvrpc::util::{find_longest_path_prefix, join_path, sha1_hash, split_glob_on_match};
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use smol_timeout::TimeoutExt;
use url::Url;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use smol::lock::RwLock;
use std::time::{Duration, Instant};
use peer::SESSION_TOKEN_PREFIX;

#[derive(Debug)]
pub(crate) struct Subscription {
    pub(crate) param: SubscriptionParam,
    pub(crate) glob: Glob,
    pub(crate) subscribed: Instant,
}
#[derive(Debug)]
pub(crate) struct ForwardedSubscription {
    pub(crate) param: SubscriptionParam,
    pub(crate) count: u32,
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

pub struct SessionToken(pub String);

#[derive(Debug)]
pub enum BrokerCommand {
    CheckAuth {
        sender: oneshot::Sender<Option<SessionToken>>,
        peer_id: PeerId,
        ip_addr: Option<core::net::IpAddr>,
        nonce: Option<String>,
        user: String,
        password: String,
        login_type: String,
    },
    CheckToken {
        sender: oneshot::Sender<Option<(String, SessionToken)>>,
        peer_id: PeerId,
        ip_addr: Option<core::net::IpAddr>,
        token: String,
    },
    #[cfg(any(feature = "entra-id", feature = "google-auth"))]
    SetOAuth2Groups {
        sender: oneshot::Sender<SessionToken>,
        peer_id: PeerId,
        user: String,
        groups: Vec<String>,
    },
    NewPeer {
        peer_id: PeerId,
        peer_kind: PeerKind,
        sender: UnboundedSender<BrokerToPeerMessage>,
    },
    FrameReceived {
        peer_id: PeerId,
        frame: RpcFrame,
    },
    PeerGone {
        peer_id: PeerId,
    },
    RpcCall {
        peer_id: PeerId,
        request: RpcMessage,
        response_sender: UnboundedSender<RpcFrame>,
    },
}

#[derive(Debug)]
pub enum BrokerToPeerMessage {
    SendFrame(RpcFrame),
    DisconnectByBroker {
        reason: Option<String>,
    },
}

const SUBSCRIBE_PATH_API_V2: &str = ".broker/app";
const SUBSCRIBE_PATH_API_V3: &str = ".broker/currentClient";

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SubscribeApi {
    V2,
    V3,
}

impl SubscribeApi {
    pub(crate) fn path(&self) -> &'static str {
        match self {
            SubscribeApi::V2 => SUBSCRIBE_PATH_API_V2,
            SubscribeApi::V3 => SUBSCRIBE_PATH_API_V3,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerKind {
    Client {
        user: String,
    },
    Broker(ConnectionMountSettings),
    Device {
        user: String,
        device_id: Option<String>,
        mount_point: Option<String>,
    },
}

impl PeerKind {
    pub fn user(&self) -> &str {
        match self {
            PeerKind::Client { user, .. } => user,
            PeerKind::Broker(connection_settings) => &connection_settings.exported_root_user,
            PeerKind::Device { user, .. } => user,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Peer {
    pub(crate) peer_id: PeerId,
    pub(crate) peer_kind: PeerKind,
    pub(crate) sender: UnboundedSender<BrokerToPeerMessage>,
    pub(crate) mount_point: Option<String>,
    pub(crate) subscribe_api: Option<SubscribeApi>,
    pub(crate) subscriptions: Vec<Subscription>,
    pub(crate) forwarded_subscriptions: Vec<ForwardedSubscription>,
}

impl Peer {
    pub(crate) fn is_signal_subscribed(&self, signal: &ShvRI) -> bool {
        self.subscriptions.iter().any(|subscr| subscr.match_shv_ri(signal))
    }

    pub(crate) fn add_forwarded_subscription(&mut self, ri: &ShvRI, subscr_tx: &UnboundedSender<SubscriptionCommand>) -> shvrpc::Result<bool> {
        debug!(target: "Subscr", "add_forwarded_subscription, peer_id: {peer_id}, ri: {ri}", peer_id = self.peer_id);
        let Some((subscribe_path, forwarded_ri)) = self.forwarded_subscription_params(ri)? else {
            return Ok(false)
        };
        debug!(target: "Subscr", "  forwarded_ri: {forwarded_ri}");
        if let Some(subscr) = self.forwarded_subscriptions.iter_mut().find(|subscr| subscr.param.ri == forwarded_ri) {
            subscr.count += 1;
            debug!(target: "Subscr", "  refcount increased to: {refcount}", refcount = subscr.count);
            return Ok(false)
        }

        debug!(target: "Subscr", "  new subscription on the peer");
        let subscr_param = SubscriptionParam {
            ri: forwarded_ri,
            ttl: None,
        };

        self.forwarded_subscriptions.push(ForwardedSubscription {
            param: subscr_param.clone(),
            count: 1,
        });

        Ok(subscr_tx.unbounded_send(SubscriptionCommand {
            peer_id: self.peer_id,
            api: subscribe_path,
            param: subscr_param,
            action: SubscriptionAction::Subscribe,
        })
        .map(|_| true)?)
    }

    pub(crate) fn remove_forwarded_subscription(&mut self, ri: &ShvRI, subscr_tx: &UnboundedSender<SubscriptionCommand>) -> shvrpc::Result<bool> {
        debug!(target: "Subscr", "remove_forwarded_subscription, peer_id: {peer_id}, ri: {ri}", peer_id = self.peer_id);
        let Some((subscribe_api, forwarded_ri)) = self.forwarded_subscription_params(ri)? else {
            return Ok(false)
        };
        debug!(target: "Subscr", "  forwarded_ri: {forwarded_ri}");
        let Some(subscr_idx) = self.forwarded_subscriptions.iter().position(|subscr| subscr.param.ri == forwarded_ri) else {
            return Ok(false)
        };
        let subscr = &mut self.forwarded_subscriptions[subscr_idx];
        if subscr.count > 1 {
            subscr.count -= 1;
            debug!(target: "Subscr", "  refcount decreased to: {refcount}", refcount = subscr.count);
            return Ok(false)
        }
        debug!(target: "Subscr", "  remove subscription from the peer");
        let subscr = self.forwarded_subscriptions.remove(subscr_idx);

        subscr_tx.unbounded_send(SubscriptionCommand {
            peer_id: self.peer_id,
            api: subscribe_api,
            param: subscr.param,
            action: SubscriptionAction::Unsubscribe,
        })?;
       Ok(true)
    }

    fn forwarded_subscription_params(&self, ri: &ShvRI) -> shvrpc::Result<Option<(SubscribeApi, ShvRI)>> {
        let (Some(mount_point), Some(subscribe_api)) = (&self.mount_point, self.subscribe_api) else {
            return Ok(None)
        };
        let Ok(Some((_, forwarded_path))) = split_glob_on_match(ri.path(), mount_point) else {
            return Ok(None)
        };
        let forwarded_ri = ShvRI::from_path_method_signal(forwarded_path, ri.method(), ri.signal())?;
        Ok(Some((subscribe_api, forwarded_ri)))
    }
}

pub(crate) struct SubscriptionCommand {
    peer_id: PeerId,
    api: SubscribeApi,
    param: SubscriptionParam,
    action: SubscriptionAction,
}

#[derive(Debug, Clone, Copy)]
enum SubscriptionAction {
    Subscribe,
    Unsubscribe,
}

impl SubscriptionAction {
    fn method_name(&self) -> &'static str {
        match self {
            SubscriptionAction::Subscribe => METH_SUBSCRIBE,
            SubscriptionAction::Unsubscribe => METH_UNSUBSCRIBE,
        }
    }
}

fn shv_path_glob_to_prefix(path: &str) -> String {
    path
        .split('/')
        .take_while(|segment| !segment.contains('*'))
        .collect::<Vec<_>>()
        .join("/")
}

static G_PEER_COUNT: AtomicI64 = AtomicI64::new(0);
pub fn next_peer_id() -> i64 {
    let old_id = G_PEER_COUNT.fetch_add(1, Ordering::SeqCst);
    old_id + 1
}

pub(crate) enum Mount {
    Peer(PeerId),
    Node,
}

pub struct ParsedAccessRule {
    pub(crate) glob: shvrpc::rpc::Glob,
    // Needed in order to pass 'dot_local' in 'Access' meta-attribute
    // to support the dot_local hack on older brokers
    pub(crate) access: String,
    pub(crate) access_level: AccessLevel,
}
impl TryFrom<&AccessRule> for ParsedAccessRule {
    type Error = shvrpc::Error;

    fn try_from(rule: &AccessRule) -> Result<Self, Self::Error> {
        let ri = ShvRI::try_from(rule.shv_ri.as_str()).map_err(|err| { format!("Parse RI: {} error: {err}", rule.shv_ri) })?;
        ParsedAccessRule::new(&ri, &rule.grant)
    }
}
impl ParsedAccessRule {
    pub fn new(shv_ri: &ShvRI, grant: &str) -> shvrpc::Result<Self> {
        Ok(Self {
            glob: shv_ri.to_glob()?,
            access: grant.to_string(),
            access_level: grant
                .split(',')
                .find_map(AccessLevel::from_str)
                .ok_or_else(|| format!("Invalid access grant `{grant}`"))?,
        })
    }
}

pub(crate) struct PendingRpcCall {
    pub(crate) peer_id: PeerId,
    pub(crate) request_meta: MetaMap,
    pub(crate) response_sender: UnboundedSender<RpcFrame>,
    pub(crate) started: Instant,
}

pub(crate) async fn broker_loop(mut broker: BrokerImpl, mut command_receiver: UnboundedReceiver<BrokerCommand>) {
    let session_token_expiration_task = {
        let session_tokens = broker.session_tokens.clone();

        smol::spawn(async move {
            loop {
                let mut interval = futures::FutureExt::fuse(smol::Timer::interval(Duration::from_hours(1)));
                select! {
                    _ = interval => {
                        let mut session_tokens = session_tokens.write().await;
                        const HOURS_BEFORE_EXPIRATION: i64 = 12;
                        let threshold = shvproto::DateTime::now().add_hours(-HOURS_BEFORE_EXPIRATION);
                        session_tokens.retain(|session| {
                            session.last_activity >= threshold
                        });
                    },
                    complete => break,
                }
            }
            log::debug!("periodic sync task finished");
        })
    };
    loop {
        select! {
            command = command_receiver.recv().fuse() => match command {
                Ok(command) => {
                    if let Err(err) = broker.process_broker_command(command).await {
                        warn!("Process broker command error: {err}");
                    }
                }
                Err(err) => {
                    warn!("Receive broker command error: {err}");
                }
            },
            complete => break,
        }
    }

    session_token_expiration_task.cancel().await;
}

#[derive(Copy, Clone)]
pub(crate) enum ServerMode {
    Tcp,
    WebSocket,
}

struct TlsConfig {
    cert: String,
    key: String,
}

pub(crate) fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(path)?))
        .collect::<Result<Vec<_>,_>>()
}

fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(path)?))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("No private key found in {path}")))
}

pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

pub(crate) type AsyncReadWriteBox = Box<dyn AsyncReadWrite + Unpin + Send>;

async fn server_accept_loop(
    address: String,
    tls_config: Option<TlsConfig>,
    server_mode: ServerMode,
    broker_sender: UnboundedSender<BrokerCommand>,
    broker_config: SharedBrokerConfig,
) -> shvrpc::Result<()> {
    let listener = smol::net::TcpListener::bind(&address)
        .await
        .map_err(|err| format!("Cannot listen on address {address}: {err}"))?;

    match server_mode {
        ServerMode::Tcp => info!("Listening on TCP: {address}"),
        ServerMode::WebSocket => info!("Listening on WebSocket: {address}"),
    }

    let tls_acceptor = if let Some(tls_config) = &tls_config {
        info!("TLS enabled");
        let server_config = futures_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(futures_rustls::rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(load_certs(&tls_config.cert)?, load_private_key(&tls_config.key)?)?;
        Some(futures_rustls::TlsAcceptor::from(Arc::new(server_config)))
    } else {
        None
    };

    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                error!("Failed to accept a TCP connection at {address}: {err}, waiting one second before accepting another connection");
                smol::Timer::after(Duration::from_secs(1)).await;
                continue;
            }
        };

        let peer_id = next_peer_id();
        let peer_addr = stream.peer_addr().as_ref().map(core::net::SocketAddr::ip).ok();
        info!("Accepted TCP connection from peer: {peer_addr:?}, peer_id: {peer_id}");

        let stream: AsyncReadWriteBox = if let Some(tls_acceptor) = tls_acceptor.as_ref().cloned() {
            match tls_acceptor.accept(stream).await {
                Ok(stream) => {
                    info!("TLS handshake OK, peer: {peer_addr:?}, peer_id: {peer_id}");
                    Box::new(stream)
                }
                Err(err) => {
                    error!("TLS handshake FAILED, peer: {peer_addr:?}, err: {err}");
                    smol::Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
            }
        } else {
            Box::new(stream)
        };

        spawn_and_log_error(peer::try_server_peer_loop(peer_id, peer_addr, server_mode, broker_sender.clone(), stream, broker_config.clone()));
    }
    Ok(())
}

pub async fn run_broker(broker_impl: BrokerImpl, command_receiver: UnboundedReceiver<BrokerCommand>) -> shvrpc::Result<()> {
    let broker_sender = broker_impl.command_sender.clone();
    let broker_config = broker_impl.config.clone();
    let broker_task = smol::spawn(broker_loop(broker_impl, command_receiver));
    for Listen { url } in &broker_config.listen {
        let address_string = |url: &Url| {
            format!("{host}:{port}",
                host = url.host_str().unwrap_or("localhost"),
                port = url.port().unwrap_or_else(||
                    match url.scheme() {
                        "tcp" => 3755,
                        "ssl" => 3756,
                        "ws" => 8755,
                        "wss" => 8766,
                        _ => 3755,
                    })
            )
        };
        let tls_config = |url: &Url| {
            let cert = url
                .query_pairs()
                .find_map(|(k, v)| (k == "cert").then_some(v))
                .ok_or_else(|| format!("Unspecified `cert` option in url: {url}"))?;
            let key = url
                .query_pairs()
                .find_map(|(k, v)| (k == "key").then_some(v))
                .ok_or_else(|| format!("Unspecified `key` option in url: {url}"))?;
            Ok::<_, String>(TlsConfig {
                cert: cert.into(),
                key: key.into(),
            })
        };

        match url.scheme() {
            "tcp" => spawn_and_log_error(server_accept_loop(address_string(url), None, ServerMode::Tcp, broker_sender.clone(), broker_config.clone())),
            "ssl" => spawn_and_log_error(server_accept_loop(address_string(url), Some(tls_config(url)?), ServerMode::Tcp, broker_sender.clone(), broker_config.clone())),
            "ws" => spawn_and_log_error(server_accept_loop(address_string(url), None, ServerMode::WebSocket, broker_sender.clone(), broker_config.clone())),
            "wss" => spawn_and_log_error(server_accept_loop(address_string(url), Some(tls_config(url)?), ServerMode::WebSocket, broker_sender.clone(), broker_config.clone())),
            "serial" | "tty" => spawn_and_log_error(serial::try_serial_peer_loop(next_peer_id(), broker_sender.clone(), url.path().into(), broker_config.clone())),
            _ => { }
        }
    }

    let broker_peers = &broker_config.connections;
    for peer_config in broker_peers {
        debug!("{} enabled: {}", peer_config.name, peer_config.enabled);
        if !peer_config.enabled {
            continue
        }
        let scheme = peer_config.client.url.scheme();
        if !["tcp", "ssl", "serial"].contains(&scheme) {
            if !cfg!(feature = "can") || scheme != "can" {
                // CAN connections are handled below
                error!("URL scheme {scheme} is not supported for a broker connection");
            }
            continue
        }
        let peer_id = next_peer_id();
        spawn_and_log_error(peer::broker_as_client_peer_loop_with_reconnect(peer_id, peer_config.clone(), broker_sender.clone()));
    }

    #[cfg(feature = "can")]
    for can_interface_config in can_interfaces_config(&broker_config) {
        spawn_and_log_error(peer::can_interface_task(can_interface_config, broker_sender.clone(), broker_config.clone()));
    }

    drop(broker_sender);
    broker_task.await;
    Ok(())
}

#[cfg(feature = "can")]
#[derive(Clone,Debug)]
pub(crate) struct CanConnectionConfig {
    pub local_address: u8,
    pub peer_address: u8,
    pub login_params: shvrpc::client::LoginParams,
    pub connection_settings: ConnectionMountSettings,
    pub reconnect_interval: Duration,
}

#[cfg(feature = "can")]
#[derive(Debug,Default)]
pub(crate) struct CanInterfaceConfig {
    pub interface: String,
    pub listen_addrs: Vec<u8>,
    pub connections: Vec<CanConnectionConfig>,
}

#[cfg(feature = "can")]
fn can_interfaces_config(broker_config: &crate::config::BrokerConfig) -> Vec<CanInterfaceConfig> {
    let mut interfaces: HashMap<String, CanInterfaceConfig> = HashMap::new();

    for Listen { url } in &broker_config.listen {
        if url.scheme() != "can" {
            continue
        }

        let iface = url.path();

        let Some(listen_addr) = url
            .query_pairs()
            .find(|(k, _)| k == "address")
            .and_then(|(_,v)| v
                .parse::<u8>()
                .inspect_err(|e| error!("Cannot parse CAN address from URL: {url}, {e}")).ok()
            ) else
        {
            continue
        };

        let iface_cfg = interfaces
            .entry(iface.to_string())
            .or_insert_with(|| CanInterfaceConfig { interface: iface.into(), ..Default::default() });

        iface_cfg.listen_addrs.push(listen_addr);
    }

    for connection_config in &broker_config.connections {
        let client_config = &connection_config.client;
        if !connection_config.enabled || client_config.url.scheme() != "can" {
            continue
        }

        let iface = client_config.url.path();

        let Some(local_address) = client_config.url
            .query_pairs()
            .find(|(k, _)| k == "local_address")
            .and_then(|(_,v)| v
                .parse::<u8>()
                .inspect_err(|e| error!("Cannot parse local CAN address from URL: {url}, {e}", url = client_config.url)).ok()
            ) else
        {
            continue
        };

        let Some(peer_address) = client_config.url
            .query_pairs()
            .find(|(k, _)| k == "peer_address")
            .and_then(|(_,v)| v
                .parse::<u8>()
                .inspect_err(|e| error!("Cannot parse peer CAN address from URL: {url}, {e}", url = client_config.url)).ok()
            ) else
        {
            continue
        };

        let login_params = crate::peer::login_params_from_client_config(client_config);
        let connection_settings = connection_config.connection_settings.clone();

        let reconnect_interval = connection_config.client.reconnect_interval.unwrap_or_else(|| {
            const DEFAULT_RECONNECT_INTERVAL_SEC: u64 = 10;
            debug!("Peer broker connection reconnect interval is not set explicitly, default value {DEFAULT_RECONNECT_INTERVAL_SEC}s will be used.");
            std::time::Duration::from_secs(DEFAULT_RECONNECT_INTERVAL_SEC)
        });

        let iface_cfg = interfaces
            .entry(iface.to_string())
            .or_insert_with(|| CanInterfaceConfig { interface: iface.into(), ..Default::default() });

        iface_cfg.connections.push(CanConnectionConfig { local_address, peer_address, login_params, reconnect_interval, connection_settings });
    }

    interfaces.into_values().collect()
}


struct DisconnectPeerReason {
    msg: String,
    msg_for_peer: Option<String>,
}

// Fetches base defined roles for a user.
pub(crate) fn user_base_roles(oauth2_user_groups: &BTreeMap<PeerId, Vec<String>>, access_config: &AccessConfig, peer: &Peer) -> Vec<String> {
    if let Some(roles) = oauth2_user_groups.get(&peer.peer_id) {
        return roles.clone()
    }

    access_config
        .access_user(peer.peer_kind.user())
        .map(|user| user.roles.clone())
        .unwrap_or_default()
}

fn parse_config_roles(roles: &BTreeMap<String, Role>) -> HashMap<String, Vec<ParsedAccessRule>> {
    roles.
        iter()
        .map(|(name, role)| {
            (name.clone(), parse_role_access_rules(role).expect("Parse access rule error"))
        })
        .collect()

}

#[derive(Debug)]
pub(crate) struct Session {
    last_activity: DateTime,
    user: String,
    token: String,
}

#[derive(Debug, Default)]
pub struct LastLogin(BTreeMap<String, shvproto::DateTime>);

impl LastLogin {
    pub fn new(map: BTreeMap<String, shvproto::DateTime>) -> Self {
        Self(map)
    }

    pub fn get(&self) -> &BTreeMap<String, shvproto::DateTime> {
        &self.0
    }

    pub async fn set_last_login(&mut self, id: &str, timestamp: shvproto::DateTime, sql_connection: Option<&async_sqlite::Client>) -> shvrpc::Result<Option<shvproto::DateTime>> {
        let json = serde_json::to_string(&timestamp).unwrap_or_else(|e| {
            error!("Generate SQL entry error: {e}");
            "".to_string()
        });
        if let Some(sql_connection) = sql_connection {
            let sqlop = if self.0.contains_key(id) {
                UpdateSqlOperation::Update { table: TBL_LAST_LOGIN, id, json }
            } else {
                UpdateSqlOperation::Insert { table: TBL_LAST_LOGIN, id, json }
            };

            update_sql(vec![sqlop], sql_connection).await?;
        }

        Ok(self.0.insert(id.to_string(), timestamp))
    }
}

pub struct BrokerImpl {
    config: SharedBrokerConfig,
    nodes: BTreeMap<String, Box<dyn ShvNode>>,

    peers: Arc<RwLock<BTreeMap<PeerId, Peer>>>,
    mounts: BTreeMap<String, Mount>,
    access: Arc<RwLock<AccessConfig>>,
    role_access_rules: Arc<RwLock<HashMap<String, Vec<ParsedAccessRule>>>>,

    oauth2_user_groups: Arc<RwLock<BTreeMap<PeerId, Vec<String>>>>,

    // session_token -> username
    session_tokens: Arc<RwLock<Vec<Session>>>,

    last_login: Arc<RwLock<LastLogin>>,

    command_sender: UnboundedSender<BrokerCommand>,
    subscr_cmd_sender: UnboundedSender<SubscriptionCommand>,

    sql_connection: Option<async_sqlite::Client>,

    pending_rpc_calls: Vec<PendingRpcCall>,
}

fn split_last_fragment(mount_point: &str) -> (&str, &str) {
    if let Some(ix) = mount_point.rfind('/') {
        let dir = &mount_point[ix + 1..];
        let prefix = &mount_point[..ix];
        (prefix, dir)
    } else {
        ("", mount_point)
    }
}

async fn forward_subscriptions_task(
    mut subscr_cmd_receiver: UnboundedReceiver<SubscriptionCommand>,
    mut broker_command_sender: UnboundedSender<BrokerCommand>,
) -> shvrpc::Result<()>
{
    const TIMEOUT: Duration = Duration::from_secs(10);
    const RETRY_DELAY: Duration = Duration::from_secs(10);

    #[derive(Debug)]
    struct SubscriptionParamWrapper(SubscriptionParam);

    impl PartialEq for SubscriptionParamWrapper {
        fn eq(&self, other: &Self) -> bool {
            self.0.ri == other.0.ri
        }
    }

    impl Eq for SubscriptionParamWrapper { }

    impl std::hash::Hash for SubscriptionParamWrapper {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.0.ri.hash(state);
        }
    }

    let mut scheduled_retries: HashMap<(PeerId, SubscribeApi, SubscriptionParamWrapper), Instant> = HashMap::new();

    async fn call_subscribe_action(
        action: SubscriptionAction,
        peer_id: PeerId,
        subscribe_api: SubscribeApi,
        subscription: SubscriptionParam,
        broker_command_sender: &UnboundedSender<BrokerCommand>,
    ) -> shvrpc::Result<()> {
        let path = subscribe_api.path();
        let method = action.method_name();
        let param = match subscribe_api {
            SubscribeApi::V2 => {
                let ri = &subscription.ri;
                shvproto::make_map!(
                    "path" => shv_path_glob_to_prefix(ri.path()),
                    "source" => if ri.method() == "*" { "" } else { ri.method() },
                    "method" => ri.signal().unwrap_or_default(),
                    "signal" => ri.signal().unwrap_or_default(),
                ).into()
            }
            SubscribeApi::V3 => match action {
                SubscriptionAction::Subscribe => subscription.to_rpcvalue(),
                SubscriptionAction::Unsubscribe => subscription.ri.to_string().into(),
            },
        };
        debug!(target: "Subscr", "calling {method}, peer_id: {peer_id}, path: {path}, param: {param}");
        let (response_sender, mut response_receiver) = unbounded();
        let cmd = BrokerCommand::RpcCall {
            peer_id,
            request: RpcMessage::new_request(path, method).with_param(param),
            response_sender,
        };
        broker_command_sender
            .unbounded_send(cmd)?;
        response_receiver
            .recv()
            .await?
            .to_rpcmesage()?;
        Ok(())
    }

    async fn call_subscribe_action_with_timeout(
        action: SubscriptionAction,
        peer_id: PeerId,
        subscribe_api: SubscribeApi,
        subscription: SubscriptionParam,
        broker_command_sender: &mut UnboundedSender<BrokerCommand>,
        timeout: Duration,
    ) -> Result<(), ()> {
        let method = action.method_name();
        let res = call_subscribe_action(
            action,
            peer_id,
            subscribe_api,
            subscription.clone(),
            broker_command_sender,
        )
        .timeout(timeout)
        .await;

        match res {
            Some(Ok(_)) => {
                debug!(target: "Subscr", "call {method} SUCCESS, peer_id: {peer_id}, subscription: {subscription:?}");
                Ok(())
            }
            Some(Err(e)) => {
                error!(target: "Subscr", "call {method} error: {e}, peer_id: {peer_id}, subscription: {subscription:?}");
                // Do not retry the subscribe on an RpcError unless it's timeout.
                // We assume that the call would end up with the same error, so
                // we rather return Ok here and just log the error.
                Ok(())
            }
            None => {
                error!(target: "Subscr", "call {method} TIMEOUT after {timeout:?}, peer_id: {peer_id}, subscription: {subscription:?}");
                Err(())
            }
        }
    }

    loop {
        let next_retry_time = scheduled_retries
            .values()
            .min()
            .copied();
        let now = Instant::now();
        let next_delay = next_retry_time
            .map(|t| t.saturating_duration_since(now));

        let mut next_cmd_fut = subscr_cmd_receiver.next().fuse();
        let mut sleep_fut = std::pin::pin!(FutureExt::fuse(
                async move {
                    if let Some(delay) = next_delay {
                        smol::Timer::after(delay).await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                }
        ));

        debug!(target: "Subscr", "scheduled retries: {scheduled_retries:?}");

        futures::select! {
            maybe_cmd = next_cmd_fut => {
                let Some(SubscriptionCommand { peer_id, api, param, action }) = maybe_cmd else {
                    break
                };

                let key = (peer_id, api, SubscriptionParamWrapper(param.clone()));

                match action {
                    SubscriptionAction::Unsubscribe => {
                        scheduled_retries.remove(&key);
                        call_subscribe_action_with_timeout(action, peer_id, api, param, &mut broker_command_sender, TIMEOUT).await.ok();
                    }

                    SubscriptionAction::Subscribe => {
                        let result = call_subscribe_action_with_timeout(action, peer_id, api, param, &mut broker_command_sender, TIMEOUT).await;

                        if result.is_err() {
                            scheduled_retries.insert(key, Instant::now() + RETRY_DELAY);
                        } else {
                            scheduled_retries.remove(&key);
                        }
                    }
                }
            }

            _ = sleep_fut => {
                let now = Instant::now();
                let results = scheduled_retries
                    .iter()
                    .filter_map(|(key, time)| (*time <= now).then_some(key))
                    .map(|(peer_id, api, SubscriptionParamWrapper(param))| {
                        let (peer_id, api, param) = (*peer_id, *api, param.clone());
                        let mut broker_command_sender = broker_command_sender.clone();
                        async move {
                            let res = call_subscribe_action_with_timeout(SubscriptionAction::Subscribe, peer_id, api, param.clone(), &mut broker_command_sender, TIMEOUT).await;
                            ((peer_id, api, SubscriptionParamWrapper(param)), res)
                        }
                    })
                    .collect::<FuturesUnordered<_>>()
                    .collect::<Vec<_>>()
                    .await;

                for (key, res) in results {
                    if res.is_err() {
                        scheduled_retries.insert(key, Instant::now() + RETRY_DELAY);
                    } else {
                        scheduled_retries.remove(&key);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn set_subscribe_api(peers: &RwLock<BTreeMap<PeerId, Peer>>, peer_id: PeerId, subscribe_api: Option<SubscribeApi>) -> shvrpc::Result<()> {
    let mut peers = peers.write().await;
    let peer = peers.get_mut(&peer_id).ok_or("Peer not found")?;
    peer.subscribe_api = subscribe_api;
    Ok(())
}

async fn check_subscribe_api(peers: &RwLock<BTreeMap<PeerId, Peer>>, command_sender: UnboundedSender<BrokerCommand>, peer_id: PeerId) -> shvrpc::Result<Option<SubscribeApi>> {
    log!(target: "Subscr", Level::Debug, "check_subscribe_api, peer_id: {peer_id}");
    let broker_command_sender = command_sender.clone();
    let subscribe_api = {
        let (response_sender, mut response_receiver) = unbounded();
        let request = RpcMessage::new_request(".broker", METH_LS);
        let cmd = BrokerCommand::RpcCall {
            peer_id,
            request,
            response_sender,
        };
        broker_command_sender.unbounded_send(cmd)?;
        let resp = response_receiver.recv().await?.to_rpcmesage()?;
        match resp.response() {
            // Ok => this is a broker, and only V2 brokers have "clients", otherwise we'll assume V3.
            // Rust broker with SHV2 compatibility do not have "clients", just "client".
            Ok(Response::Success(result)) => {
                if result.as_list().iter().any(|elem| elem.as_str() == "clients") {
                    Some(SubscribeApi::V2)
                } else {
                    Some(SubscribeApi::V3)
                }
            }
            Ok(Response::Delay(_)) => return Err("Delay messages are not supported in SHV API version discovery.".into()),
            // .broker:ls failed, so this is not a broker.
            Err(_) => None,
        }
    };

    log!(target: "Subscr", Level::Debug, "Device subscribe API for peer_id {peer_id} detected: {subscribe_api:?}");
    set_subscribe_api(peers, peer_id, subscribe_api).await?;
    Ok(subscribe_api)
}

impl BrokerImpl {
    pub fn new(
        config: SharedBrokerConfig,
        access: AccessConfig,
        last_login: LastLogin,
        command_sender: UnboundedSender<BrokerCommand>,
        sql_connection: Option<async_sqlite::Client>,
    ) -> Self {
        let (subscr_cmd_sender, subscr_cmd_receiver) = futures::channel::mpsc::unbounded();
        spawn_and_log_error(forward_subscriptions_task(subscr_cmd_receiver, command_sender.clone()));
        let mut nodes: BTreeMap<String, Box<dyn ShvNode>> = Default::default();
        let mut mounts: BTreeMap<String, Mount> = Default::default();
        let peers = Arc::<RwLock<BTreeMap<PeerId, Peer>>>::default();
        let role_access_rules = Arc::new(RwLock::new(parse_config_roles(access.roles())));
        let access = Arc::new(RwLock::new(access));
        let oauth2_user_groups = Arc::new(RwLock::new(Default::default()));
        let last_login = Arc::new(RwLock::new(last_login));
        let mut add_node = |path: &str, node: Box<dyn ShvNode>| {
            mounts
                .insert(path.into(), Mount::Node);
            nodes.insert(path.into(), node);
        };
        add_node(DIR_APP, Box::new(AppNode::new()));
        if config.tunnelling.enabled {
            add_node(".app/tunnel", Box::new(TunnelNode::new(peers.clone())));
            if let Some(tsub_dir) = &config.tunnelling.tsub_dir {
                add_node(tsub_dir, Box::new(TunnelNode::new(peers.clone())));
            }
        }
        add_node(DIR_BROKER, Box::new(BrokerNode::new(peers.clone(), config.name.clone(), role_access_rules.clone(), oauth2_user_groups.clone(), access.clone())));
        add_node(
            DIR_BROKER_CURRENT_CLIENT,
            Box::new(BrokerCurrentClientNode::new(peers.clone(), subscr_cmd_sender.clone(), sql_connection.clone(), access.clone(), oauth2_user_groups.clone(), role_access_rules.clone())),
        );
        add_node(
            DIR_BROKER_ACCESS_MOUNTS,
            Box::new(BrokerAccessMountsNode::new(sql_connection.clone(), access.clone())),
        );
        add_node(
            DIR_BROKER_ACCESS_USERS,
            Box::new(BrokerAccessUsersNode::new(sql_connection.clone(), access.clone())),
        );
        add_node(
            DIR_BROKER_ACCESS_ROLES,
            Box::new(BrokerAccessRolesNode::new(sql_connection.clone(), access.clone(), role_access_rules.clone())),
        );
        add_node(
            DIR_BROKER_ACCESS_ALLOWED_IPS,
            Box::new(BrokerAccessAllowedIpsNode::new(sql_connection.clone(), access.clone())),
        );
        add_node(
            DIR_BROKER_ACCESS_LAST_LOGIN,
            Box::new(BrokerAccessLastLoginNode::new(last_login.clone())),
        );
        if config.shv2_compatibility {
            add_node(
                DIR_SHV2_BROKER_APP,
                Box::new(Shv2BrokerAppNode::new(peers.clone(), subscr_cmd_sender.clone())),
            );
            add_node(
                DIR_SHV2_BROKER_ETC_ACL_MOUNTS,
                Box::new(BrokerAccessMountsNode::new(sql_connection.clone(), access.clone())),
            );
            add_node(
                DIR_SHV2_BROKER_ETC_ACL_USERS,
                Box::new(BrokerAccessUsersNode::new(sql_connection.clone(), access.clone())),
            );
        }

        Self {
            nodes,
            pending_rpc_calls: vec![],
            command_sender,
            config: config.clone(),
            peers,
            mounts,
            access,
            role_access_rules,
            oauth2_user_groups,
            subscr_cmd_sender,
            sql_connection,
            session_tokens: Arc::new(RwLock::default()),
            last_login,
        }
    }

    async fn process_rpc_frame(&mut self, peer_id: PeerId, frame: RpcFrame) -> shvrpc::Result<()> {
        if frame.is_request() {
            let mut frame = frame;
            if let Some(mut req_user_id) = frame.user_id() {
                let peers = self.peers.read().await;
                let peer = peers.get(&peer_id).ok_or_else(|| RpcError::new(RpcErrorCode::InternalError, "Peer not found"))?;
                let user_roles = user_base_roles(&*self.oauth2_user_groups.read().await, &*self.access.read().await, peer);
                let flatten_roles = self.access.read().await.flatten_roles(user_roles.as_slice());
                let user = peer.peer_kind.user();

                // We only trust user_id chains from peers with the trusted_user_ids_role.
                if !flatten_roles.contains(&self.config.trusted_user_ids_role) {
                    req_user_id = "";
                }

                let broker_id = self.config.name.as_ref()
                    .map(|broker_id| format!(":{broker_id}"))
                    .unwrap_or_default();
                let user_id_chain = format!("{req_user_id}{maybe_semicolon}{user}{broker_id}", maybe_semicolon = if !req_user_id.is_empty() {";"} else {""});
                frame.set_user_id(&user_id_chain);
            }
            let shv_path = frame.shv_path().unwrap_or_default().to_string();
            let method = frame.method().unwrap_or_default().to_string();
            let response_meta = RpcFrame::prepare_response_meta(&frame.meta)?;
            let access = Self::access_level_for_request_params(
                &self.peers,
                &self.role_access_rules,
                &self.oauth2_user_groups,
                &self.access,
                peer_id,
                &shv_path,
                &method,
                frame.tag(Tag::AccessLevel as i32).map(RpcValue::as_i32)).await;
            let (grant_access_level, grant_access) = match access {
                Ok(grant) => grant,
                Err(err) => {
                    Self::send_response(&self.peers, peer_id, response_meta, Err(err)).await?;
                    return Ok(());
                }
            };
            let local_result = process_local_dir_ls(&self.mounts, &frame);
            if let Some(result) = local_result {
                Self::send_response(&self.peers, peer_id, response_meta, result).await?;
                return Ok(());
            }
            //let self.= self.read().map_err(|e| e.to_string())?;
            let paths = find_longest_path_prefix(
                &self.mounts,
                &shv_path,
            );
            if let Some((mount_point, node_path)) = paths {
                enum Action {
                    ToPeer(UnboundedSender<BrokerToPeerMessage>, BrokerToPeerMessage),
                    NodeRequest {
                        node_id: String,
                        frame: RpcFrame,
                        ctx: NodeRequestContext,
                    },
                }
                let action = {
                    let mut frame = frame;
                    frame.push_caller_id(peer_id);
                    frame.set_shvpath(node_path);
                    frame.set_tag(Tag::AccessLevel as i32, grant_access_level.map(RpcValue::from));
                    frame.set_tag(Tag::Access as i32, grant_access.map(RpcValue::from));
                    match self.mounts.get(mount_point).expect("Should be mounted") {
                        Mount::Peer(device_peer_id) => {
                            let sender = self
                                .peers
                                .read()
                                .await
                                .get(device_peer_id)
                                .ok_or("peer ID must exist")?
                                .sender
                                .clone();
                            Action::ToPeer(sender, BrokerToPeerMessage::SendFrame(frame))
                        }
                        Mount::Node => Action::NodeRequest {
                            node_id: mount_point.to_string(),
                            frame,
                            ctx: NodeRequestContext {
                                peer_id,
                                node_path: node_path.to_string(),
                            },
                        },
                    }
                };
                match action {
                    Action::ToPeer(sender, msg) => {
                        sender.unbounded_send(msg)?;
                        return Ok(());
                    }
                    Action::NodeRequest { node_id, frame, ctx, } => {
                        let node = self.nodes.get(&node_id).expect("Should be mounted");
                        if node.is_request_granted(&frame, &ctx).await {
                            let result = match node.process_request_and_dir_ls(&frame, &ctx).await {
                                Err(e) => Err(RpcError::new(
                                    RpcErrorCode::MethodCallException,
                                    e.to_string(),
                                )),
                                Ok(ProcessRequestRetval::MethodNotFound) => Err(RpcError::new(
                                    RpcErrorCode::MethodNotFound,
                                    format!(
                                        "Method {}:{} not found.",
                                        shv_path,
                                        frame.method().unwrap_or_default()
                                    ),
                                )),
                                Ok(ProcessRequestRetval::RetvalDeferred) => return Ok(()),
                                Ok(ProcessRequestRetval::Retval(result)) => Ok(result),
                            };
                            Self::send_response(&self.peers, peer_id, response_meta, result).await?;
                        } else {
                            let err = RpcError::new(
                                RpcErrorCode::PermissionDenied,
                                format!(
                                    "Method doesn't exist or request to call {}:{} is not granted.",
                                    shv_path,
                                    frame.method().unwrap_or_default()
                                ),
                            );
                            Self::send_response(&self.peers, peer_id, response_meta, Err(err)).await?;
                        }
                    }
                }
            } else {
                let err = RpcError::new(
                    RpcErrorCode::MethodNotFound,
                    format!("Invalid shv path {shv_path}:{method}()"),
                );
                Self::send_response(&self.peers, peer_id, response_meta, Err(err)).await?;
            }
            return Ok(());
        } else if frame.is_response() {
            let mut frame = frame;
            if let Some(fwd_peer_id) = frame.pop_caller_id() {
                if frame.tag(RevCallerIds as i32).is_some() {
                    frame.push_caller_id(peer_id);
                }
                let sender = self
                    .peers
                    .read()
                    .await
                    .get(&fwd_peer_id)
                    .map(|p| p.sender.clone());
                if let Some(sender) = sender {
                    sender.unbounded_send(BrokerToPeerMessage::SendFrame(frame))?;
                } else {
                    warn!("Cannot find peer for response peer-id: {fwd_peer_id}");
                }
            } else {
                self.process_pending_broker_rpc_call(peer_id, frame).await?;
            }
        } else if frame.is_signal() {
            Self::emit_rpc_signal_frame(&self.peers, peer_id, &frame).await?;
        }
        Ok(())
    }
    pub(crate) async fn emit_rpc_signal_frame(
        peers: &RwLock<BTreeMap<PeerId, Peer>>,
        originating_peer_id: PeerId,
        signal_frame: &RpcFrame,
    ) -> shvrpc::Result<()> {
        assert!(signal_frame.is_signal());
        let frames: Vec<_> = {
            let mut shv_path = signal_frame.shv_path().unwrap_or_default().to_string();
            if let Some(peer) = peers.read().await.get(&originating_peer_id) {
                if let PeerKind::Broker(connection_settings) = &peer.peer_kind {
                    // remove imported_shv_root in notifications coming from broker
                    if let Some(new_path) = cut_prefix(&shv_path, &connection_settings.imported_shv_root) {
                        shv_path = new_path;
                    }
                }
                if let Some(mount_point) = &peer.mount_point {
                    shv_path = join_path(mount_point, &shv_path);
                }
            }
            let ri = ShvRI::from_path_method_signal(
                &shv_path,
                signal_frame.source().unwrap_or("get"),
                signal_frame.method(),
            )?;
            peers
                .read()
                .await
                .values()
                .filter(|peer| peer.is_signal_subscribed(&ri))
                .map(|peer| {
                    let mut frame = signal_frame.clone();
                    frame.set_shvpath(&shv_path);
                    (frame, peer.sender.clone())
                })
                .collect()
        };
        for (frame, sender) in frames {
            sender.unbounded_send(BrokerToPeerMessage::SendFrame(frame))?;
        }
        Ok(())
    }

    async fn start_broker_rpc_call(
        &mut self,
        request: RpcMessage,
        pending_call: PendingRpcCall,
    ) -> shvrpc::Result<()> {
        let sender = self
            .peers
            .read()
            .await
            .get(&pending_call.peer_id)
            .ok_or(format!("Invalid peer ID: {}", pending_call.peer_id))?
            .sender
            .clone();
        // let rqid = data.request.request_id().ok_or("Missing request ID")?;
        self.pending_rpc_calls.push(pending_call);
        sender.unbounded_send(BrokerToPeerMessage::SendFrame(request.to_frame()?))?;
        Ok(())
    }
    async fn process_pending_broker_rpc_call(
        &mut self,
        peer_id: PeerId,
        response_frame: RpcFrame,
    ) -> shvrpc::Result<()> {
        assert!(response_frame.is_response());
        assert!(response_frame.caller_ids().is_empty());
        let rqid = response_frame
            .request_id()
            .ok_or("Request ID must be set.")?;
        let pending_call_ix = self.pending_rpc_calls.iter().position(|pc| {
            let request_id = pc.request_meta.request_id().unwrap_or_default();
            request_id == rqid && pc.peer_id == peer_id
        });
        if let Some(ix) = pending_call_ix {
            let pending_call = self.pending_rpc_calls.remove(ix);
            pending_call.response_sender.unbounded_send(response_frame)?;
        }
        Self::gc_pending_rpc_calls(&mut self.pending_rpc_calls).await?;
        Ok(())
    }
    async fn gc_pending_rpc_calls(pending_rpc_calls: &mut Vec<PendingRpcCall>) -> shvrpc::Result<()> {
        let now = Instant::now();
        const TIMEOUT: Duration = Duration::from_secs(60);
        let timed_out = pending_rpc_calls
            .extract_if(.., |pending_call| now.duration_since(pending_call.started) > TIMEOUT);
        for timed_out_pending_call in timed_out {
            let mut msg = RpcMessage::from_meta(timed_out_pending_call.request_meta.clone());
            msg.set_error(RpcError::new(
                    RpcErrorCode::MethodCallTimeout,
                    "Method call timeout",
            ));
            timed_out_pending_call.response_sender.unbounded_send(msg.to_frame()?)?;
        }
        Ok(())
    }

    async fn user_is_allowed_to_login(&self, peer_id: PeerId, user: &str, ip_addr: Option<core::net::IpAddr>) -> bool {
        if let Some(ip_addr) = ip_addr && !self.login_allowed_from_ip(user, ip_addr).await {
            info!("peer_id({peer_id}): login disallowed, because the peer's IP address ({ip_addr}) is not allowed");
            return false;
        }

        if self.user_deactivated(user).await {
            return false;
        }

        true
    }

    async fn get_or_create_token(&self, user: &str) -> SessionToken {
        let mut session_tokens = self.session_tokens.write().await;
        let token = if let Some(Session { token, ..}) = session_tokens.iter().find(|session| session.user == user) {
            token.clone()
        } else {
            let token = uuid::Uuid::new_v4().to_string();
            session_tokens.push(Session { last_activity: shvproto::DateTime::now(), user: user.to_string(), token: token.clone() });
            token
        };

        SessionToken(format!("{SESSION_TOKEN_PREFIX}{token}"))
    }

    async fn process_broker_command(&mut self, broker_command: BrokerCommand) -> shvrpc::Result<()> {
        match broker_command {
            BrokerCommand::FrameReceived {
                peer_id,
                frame,
            } => {
                if let Err(err) = self.process_rpc_frame(peer_id, frame).await {
                    warn!("Process RPC frame error: {err}");
                }
            }
            BrokerCommand::NewPeer {
                peer_id: new_peer_id,
                peer_kind,
                sender,
            } => {
                let user = peer_kind.user();
                let previous_login = self.last_login.write().await
                    .set_last_login(user, shvproto::DateTime::now(), self.sql_connection.as_ref())
                    .await
                    .inspect_err(|err| log::error!("Unable to set last_login for {user}: {err}"))
                    .ok();
                debug!("New peer, id: {new_peer_id}, user: {user:?}, last_login: {previous_login:?}");
                let peer_add_result = self.add_peer(new_peer_id, peer_kind, sender.clone()).await;
                if let Err(DisconnectPeerReason {msg, msg_for_peer}) = peer_add_result  {
                    sender.unbounded_send(BrokerToPeerMessage::DisconnectByBroker {reason: msg_for_peer})?;
                    return Err(msg.into());
                };

                let mount_point = Self::mount_point(&self.peers, new_peer_id).await;
                if let Some(mount_point) = mount_point {
                    let (shv_path, dir) = split_last_fragment(&mount_point);
                    let msg = RpcMessage::new_signal_with_source(shv_path, SIG_LSMOD, METH_LS)
                        .with_param(Map::from([(dir.to_string(), true.into())]));
                    Self::emit_rpc_signal_frame(&self.peers, 0, &msg.to_frame()?)
                        .await?;

                    let msg = RpcMessage::new_signal(&mount_point, SIG_MNTMOD)
                        .with_param(true);
                    Self::emit_rpc_signal_frame(&self.peers, 0, &msg.to_frame()?)
                        .await?;

                    let peers = self.peers.clone();
                    let command_sender = self.command_sender.clone();
                    let subscr_cmd_sender = self.subscr_cmd_sender.clone();

                    spawn_and_log_error(async move {
                        if check_subscribe_api(peers.as_ref(), command_sender, new_peer_id).await?.is_none() {
                            return Ok(());
                        }
                        let forwarded_ris = peers.read()
                            .await
                            .iter()
                            .filter_map(|(peer_id, peer)| (*peer_id != new_peer_id).then_some(peer))
                            .flat_map(|peer| peer.subscriptions.iter().map(|s| s.param.ri.clone()))
                            .collect::<Vec<_>>();
                        if let Some(new_peer) = peers.write().await.get_mut(&new_peer_id) {
                            for ri in forwarded_ris {
                                new_peer
                                    .add_forwarded_subscription(&ri, &subscr_cmd_sender)
                                    .inspect_err(|e| warn!("Cannot add forwarded subscription: {ri} to peer: {new_peer_id}, err: {e}"))
                                    .ok();
                                }
                        }
                        Ok(())
                    });
                }
            }
            BrokerCommand::PeerGone { peer_id } => {
                debug!("Peer gone, id: {peer_id}.");
                let mount_point = self.remove_peer(peer_id).await?;
                if let Some(mount_point) = mount_point {
                    let mut lsmod_path = mount_point.as_ref();
                    let mut lsmod_value = "";
                    while !mount_point.is_empty() {
                        (lsmod_path, lsmod_value) = split_last_fragment(lsmod_path);
                        if self.mounts.keys().map(|path| split_last_fragment(path).0).any(|path| path == lsmod_path) {
                            break;
                        }
                    }

                    debug!("Unmounting peer id: {peer_id} from: {mount_point}.");
                    let msg = RpcMessage::new_signal_with_source( lsmod_path, SIG_LSMOD, METH_LS)
                        .with_param(Map::from([(lsmod_value.to_string(), false.into())]));
                    Self::emit_rpc_signal_frame(&self.peers, 0, &msg.to_frame()?)
                        .await?;

                    let msg = RpcMessage::new_signal( &mount_point, SIG_MNTMOD)
                        .with_param(false);
                    Self::emit_rpc_signal_frame(&self.peers, 0, &msg.to_frame()?)
                        .await?;
                }
                self.pending_rpc_calls.retain(|c| c.peer_id != peer_id);
            }
            BrokerCommand::CheckToken { sender, peer_id, ip_addr, token } => {
                let result = 'result: {
                    let mut session_tokens = self.session_tokens.write().await;
                    let Some(Session { last_activity, user, ..}) = session_tokens.iter_mut().find(|session| session.token == token) else {
                        break 'result None;
                    };

                    if !self.user_is_allowed_to_login(peer_id, user, ip_addr).await {
                        break 'result None;
                    }

                    *last_activity = shvproto::DateTime::now();

                    Some((user.clone(), SessionToken(token)))
                };

                if sender.send(result).is_err() {
                    debug!("CheckToken receiver dropped before sending the response");
                }
            },
            BrokerCommand::CheckAuth {
                sender,
                ip_addr,
                peer_id,
                nonce,
                user,
                password,
                login_type
            } => {
                let result = 'result: {
                    if !self.user_is_allowed_to_login(peer_id, &user, ip_addr).await {
                        break 'result false;
                    }

                    let Some(shapwd) = self.sha_password(&user).await else {
                        break 'result false;
                    };

                    match login_type.as_str() {
                        "PLAIN" => {
                            let client_shapass = sha1_hash(password.as_bytes());
                            client_shapass == shapwd
                        },
                        "SHA1" => {
                            if let Some(nonce) = &nonce {
                                let mut data = nonce.as_bytes().to_vec();
                                data.extend_from_slice(shapwd.as_bytes());
                                password == sha1_hash(&data)
                            } else {
                                debug!("peer_id({peer_id}): user tried SHA1 login without using `:hello`");
                                false
                            }
                        },
                        _ => {
                            debug!("peer_id({peer_id}): unknown login type '{login_type}'");
                            false
                        }
                    }
                };

                let result = if result {
                    Some(self.get_or_create_token(&user).await)
                } else {
                    None
                };
                if sender.send(result).is_err() {
                    debug!("CheckAuth receiver dropped before sending the response");
                }
            }
            #[cfg(any(feature = "entra-id", feature = "google-auth"))]
            BrokerCommand::SetOAuth2Groups { peer_id, sender, user, groups } => {
                self
                    .oauth2_user_groups
                    .write()
                    .await
                    .insert(peer_id, groups);

                let session_token = self.get_or_create_token(&user).await;
                if sender.send(session_token).is_err() {
                    debug!("SetOAuth2Groups receiver dropped before sending the response");
                }
            }
            BrokerCommand::RpcCall {
                peer_id,
                request,
                response_sender,
            } => {
                let request_meta = request.meta().clone();
                let mut rq2 = request;
                // broker calls can have any access level, set 'su' to bypass client access control
                rq2.set_access_level(AccessLevel::Superuser);
                self.start_broker_rpc_call(
                    rq2,
                    PendingRpcCall {
                        peer_id,
                        request_meta,
                        response_sender,
                        started: Instant::now(),
                    },
                )
                .await?
            }
        }
        Ok(())
    }

    async fn mount_point(peers: &RwLock<BTreeMap<PeerId, Peer>>, peer_id: PeerId) -> Option<String> {
        peers
            .read()
            .await
            .get(&peer_id)
            .and_then(|peer| peer.mount_point.clone())
    }

    #[expect(clippy::too_many_arguments, reason = "It's fine for now, might fix this later")]
    pub(crate) async fn access_level_for_request_params(
        peers: &RwLock<BTreeMap<PeerId, Peer>>,
        role_access_rules: &RwLock<HashMap<String, Vec<ParsedAccessRule>>>,
        oauth2_user_groups: &RwLock<BTreeMap<PeerId, Vec<String>>>,
        access: &RwLock<AccessConfig>,
        peer_id: PeerId,
        shv_path: &str,
        method: &str,
        access_level: Option<i32>,
    ) -> Result<(Option<i32>, Option<String>), RpcError>
    {
        if method.is_empty() {
            return Err(RpcError::new(
                RpcErrorCode::PermissionDenied,
                "Method is empty",
            ));
        }
        let peers = peers.read().await;
        let peer = peers
            .get(&peer_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::InternalError, "Peer not found"))?;
        let ri = match ShvRI::from_path_method_signal(shv_path, method, None) {
            Ok(ri) => ri,
            Err(e) => return Err(RpcError::new(RpcErrorCode::InvalidRequest, e)),
        };
        log!(target: "Access", Level::Debug, "SHV RI: {ri}");

        let access_level_from_flatten_roles = async |flatten_roles: Vec<String>| {
            let access_roles = role_access_rules.read().await;
            let found_grant = flatten_roles
                .into_iter()
                .filter_map(|role_name| access_roles.get(&role_name)
                    .inspect(|_| log!(target: "Access", Level::Debug, "----------- access for role: {role_name}"))
                )
                .find_map(|rules| {
                    rules
                        .iter()
                        .inspect(|rule| log!(target: "Access", Level::Debug, "\trule: {}", rule.glob.as_str()))
                        .find(|rule| rule.glob.match_shv_ri(&ri))
                })
                .inspect(|_| log!(target: "Access", Level::Debug, "\t\t HIT"))
                .map(|rule| (rule.access_level as i32, rule.access.clone()));

            match found_grant {
                Some((access_level, access)) => Ok((Some(access_level), Some(access))),
                None => Err(
                    RpcError::new(
                        RpcErrorCode::PermissionDenied,
                        format!("Access denied for client: {peer_id}, user: '{user}'", user = peer.peer_kind.user()),
                    )
                ),
            }
        };
        let oauth2_user_groups = oauth2_user_groups.read().await;
        let access_config = access.read().await;
        let user_roles = user_base_roles(&oauth2_user_groups, &access_config, peer);
        // request from logged-in user,
        // it can be client, device, child broker or parent broker as client
        let flatten_roles = access_config.flatten_roles(user_roles.as_slice());
        log!(target: "Access", Level::Debug, "User: '{user}', flatten roles: {:?}", flatten_roles, user = peer.peer_kind.user());
        // client (especially parent broker) can set access level for its request
        // cap it to the maximum level allowed by its access rights configured in the broker
        let mut max_level = access_level_from_flatten_roles(flatten_roles).await;
        if let Ok((Some(max_level), _access)) = &mut max_level
            && let Some(access_level) = access_level
                && *max_level > access_level {
                    log!(target: "Access", Level::Debug, "\tAccess level requested by client: {access_level} capped to: {max_level}");
                    *max_level = access_level;
                }
        max_level
    }

    async fn remove_peer(&mut self, peer_id: PeerId) -> shvrpc::Result<Option<String>> {
        let mount_point = Self::mount_point(&self.peers, peer_id).await;
        if let Some(mount_point) = mount_point.as_ref() {
            info!("Unmounting peer: {peer_id} at: {mount_point}");
        }
        let mut peers = self.peers.write().await;
        if let Some(removed_peer) = peers.remove(&peer_id) {
            for subscr in removed_peer.subscriptions {
                let ri = subscr.param.ri;
                for peer in peers.values_mut() {
                    peer.remove_forwarded_subscription(&ri, &self.subscr_cmd_sender)
                        .inspect_err(|e| warn!("Cannot remove forwarded subscription: {ri} from peer: {peer_id}, err: {e}"))
                        .ok();
                }
            }
        }
        self.mounts.retain(|_k, v| {
            if let Mount::Peer(id) = v
                && *id == peer_id {
                    return false;
                }
            true
        });
        Ok(mount_point)
    }

    async fn add_peer(&mut self, peer_id: PeerId, peer_kind: PeerKind, sender: UnboundedSender<BrokerToPeerMessage>) -> Result<(), DisconnectPeerReason> {
        if self.peers.read().await.contains_key(&peer_id) {
            // this might happen when connection to parent broker is restored
            // after parent broker reset
            panic!("Peer ID: {peer_id} exists already!");
        }
        let client_path = join_path(DIR_BROKER, format!("client/{peer_id}"));
        let effective_mount_point = match &peer_kind {
            PeerKind::Client { .. } => None,
            PeerKind::Broker(connection_settings) => {
                if connection_settings.mount_point.is_empty() {
                    None
                } else {
                    Some(connection_settings.mount_point.clone())
                }
            }
            PeerKind::Device {
                device_id,
                mount_point,
                ..
            } => 'find_mount: {
                if let Some(mount_point) = mount_point
                    && mount_point.starts_with("test/") {
                        info!("Peer id: {} mounted on path: '{}'", peer_id, &mount_point);
                        break 'find_mount Some(mount_point.clone());
                    }
                if let Some(device_id) = &device_id {
                    match self.access.read().await.access_mount(device_id) {
                        None => {
                            let msg = format!("Cannot find mount point for device ID: '{device_id}'");
                            return Err(DisconnectPeerReason {
                                msg_for_peer: Some(msg.clone()),
                                msg,
                            });
                        }
                        Some(mount) => {
                            let mount_point = mount.mount_point.clone();
                            info!(
                                "Peer id: {}, device id: {} mounted on path: '{}'",
                                peer_id, device_id, &mount_point
                            );
                            break 'find_mount Some(mount_point);
                        }
                    }
                }
                None
            }
        };

        if let Some(mount_point) = effective_mount_point.as_ref() {
            if let Some(mount) = self.mounts.get(mount_point) {
                return Err(DisconnectPeerReason {
                    msg: format!("peer({peer_id}): can't mount on {mount_point}, because it is already mounted as: {mount}", mount = match mount {
                        Mount::Peer(id) => format!("peer_id({id})"),
                        Mount::Node => "internal-node".to_string(),
                    }),
                    msg_for_peer: Some(format!("Can't mount on {mount_point}, because it is already mounted")),
                });
            }
            info!("Mounting peer: {peer_id} at: {mount_point}");
            self.mounts.insert(mount_point.clone(), Mount::Peer(peer_id));
        }

        self.mounts.insert(client_path, Mount::Peer(peer_id));

        let peer = Peer {
            peer_id,
            peer_kind,
            sender,
            mount_point: effective_mount_point,
            subscribe_api: None,
            subscriptions: vec![],
            forwarded_subscriptions: vec![],
        };
        self.peers.write().await.insert(peer_id, peer);
        Ok(())
    }

    async fn user_deactivated(&self, user: &str) -> bool {
        self.access.read().await.access_user(user).is_some_and(|user| user.deactivated)
    }

    async fn login_allowed_from_ip(&self, user: &str, ip: core::net::IpAddr) -> bool {
        let access = self.access.read().await;
        let Some(allowed_ips) = access.access_allowed_ips(user) else {
            return true;
        };

        allowed_ips.iter().any(|allowed_ip| allowed_ip.contains(&ip))
    }

    async fn sha_password(&self, user: &str) -> Option<String> {
        self.access.read().await.access_user(user).map(|user| match &user.password {
            Password::Plain(password) => sha1_hash(password.as_bytes()),
            Password::Sha1(password) => password.clone(),
        })
    }

    pub(crate) async fn send_response(peers: &RwLock<BTreeMap<PeerId, Peer>>, peer_id: PeerId, meta: MetaMap, result: Result<RpcValue, RpcError>) -> shvrpc::Result<()> {
        let peer_sender = peers
            .read()
            .await
            .get(&peer_id)
            .ok_or("Invalid peer ID")?
            .sender
            .clone();
        let mut msg = RpcMessage::from_meta(meta);
        msg.set_result_or_error(result);
        peer_sender.unbounded_send(BrokerToPeerMessage::SendFrame(RpcFrame::from_rpcmessage(&msg)?))?;
        Ok(())
    }
}

pub(crate) struct NodeRequestContext {
    pub(crate) peer_id: PeerId,
    pub(crate) node_path: String,
}

#[cfg(test)]
mod test {
    use futures::channel::mpsc::unbounded;
    use futures::channel::oneshot;

    use crate::brokerimpl::BrokerCommand;
    use crate::brokerimpl::LastLogin;
    use crate::brokerimpl::shv_path_glob_to_prefix;
    use crate::brokerimpl::BrokerImpl;
    use crate::config::AccessConfig;
    use crate::config::Password;
    use crate::config::{BrokerConfig, SharedBrokerConfig};

    smol_macros::test! {
        async fn test_broker() {
            let config = BrokerConfig::default();
            let access = config.access.clone();
            let roles = access.flatten_roles(access.access_user("child-broker").unwrap().roles.as_slice());
            assert_eq!(
                roles,
                vec![
                    "child-broker",
                    "device",
                    "client",
                    "ping",
                    "subscribe",
                    "browse"
                ]
            );
        }
    }

    smol_macros::test! {
        async fn test_check_auth() {
            let config = BrokerConfig::default();
            let access = config.access.clone();
            let mut users = access.users().clone();
            users.insert("deactivated_user".to_string(), crate::config::User {
                password: Password::Plain("some_pw".to_string()),
                roles: Default::default(),
                deactivated: true,
            });

            users.insert("localhost_user".to_string(), crate::config::User {
                password: Password::Plain("some_pw".to_string()),
                roles: Default::default(),
                deactivated: false,
            });

            let mut allowed_ips = access.allowed_ips().clone();
            allowed_ips.insert("localhost_user".to_string(), vec!["127.0.0.1/24".parse().unwrap()]);
            let access = AccessConfig::new(users, access.roles().clone(), access.mounts().clone(), allowed_ips);

            for ((user, password, ip_addr), expected_result) in [
                (("viewer", "viewer", None), true),
                (("viewer", "wrong-password", None), false),
                (("nonexisting_user", "some_pw", None), false),
                (("deactivated_user", "some_pw", None), false),
                (("localhost_user", "some_pw", None), true),
                (("localhost_user", "some_pw", Some("127.0.0.1".parse().unwrap())), true),
                (("localhost_user", "some_pw", Some("127.0.0.2".parse().unwrap())), true),
                (("localhost_user", "some_pw", Some("10.0.0.1".parse().unwrap())), false),
            ] {
                let (command_sender, _) = unbounded();
                let mut broker = BrokerImpl::new(SharedBrokerConfig::new(config.clone()), access.clone(), LastLogin::default(), command_sender, None);
                let (sender, mut reader) = oneshot::channel();
                broker.process_broker_command(BrokerCommand::CheckAuth {
                    sender,
                    peer_id: 0,
                    ip_addr,
                    nonce: None,
                    user: user.to_string(),
                    password: password.to_string(),
                    login_type: "PLAIN".to_string()
                }).await.expect("Sending commands must work");

                let resp = reader.try_recv().expect("Receiving responses must work").expect("We need to have a value");
                assert_eq!(resp.is_some(), expected_result);
            }
        }
    }

    #[test]
    fn test_shv_path_glob_to_prefix() {
        for (glob, prefix) in [
            ("**", ""),
            ("*", ""),
            ("**/", ""),
            ("*/", ""),
            ("a", "a"),
            ("a/b", "a/b"),
            ("*/b", ""),
            ("a/*/c", "a"),
            ("a/**/c", "a"),
            ("a/b/c/**", "a/b/c"),
            ("a/b/c/*", "a/b/c"),
            ("a/b/c/**/d", "a/b/c"),
            ("a/b/c/*/d", "a/b/c"),
            ("a/b/c/foo*/d", "a/b/c"),
            ("a/b/c/*foo/d", "a/b/c"),
        ] {
            let res = shv_path_glob_to_prefix(glob);
            assert_eq!(res, prefix);
        }
    }
}
