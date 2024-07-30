use async_std::{task};
use async_std::channel::Sender;
use async_std::net::TcpListener;
use crate::config::{AccessControl, BrokerConfig};
use shvrpc::metamethod::AccessLevel;
use log::{debug, info, warn};
use shvproto::{MetaMap, RpcValue};
use shvrpc::rpc::{ShvRI, Subscription};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{PeerId, RpcError, RqId};
use crate::shvnode::{ShvNode};
use async_std::stream::StreamExt;
use futures::select;
use futures::FutureExt;
use shvrpc::RpcMessage;
use crate::brokerimpl::{BrokerImpl};
use crate::peer;

#[derive(Debug)]
pub(crate) enum BrokerCommand {
    GetPassword {
        sender: Sender<BrokerToPeerMessage>,
        user: String,
    },
    NewPeer {
        client_id: PeerId,
        peer_kind: PeerKind,
        user: String,
        mount_point: Option<String>,
        device_id: Option<String>,
        sender: Sender<BrokerToPeerMessage>,
    },
    FrameReceived {
        client_id: PeerId,
        frame: RpcFrame,
    },
    PeerGone {
        peer_id: PeerId,
    },
    SendResponse {peer_id: PeerId, meta: MetaMap, result: Result<RpcValue, RpcError>},
    //CallSubscribeOnPeer {
    //    peer_id: CliId,
    //    subscriptions: Vec<SubscriptionParam>,
    //},
    RpcCall {
        client_id: PeerId,
        request: RpcMessage,
        response_sender: Sender<RpcFrame>,
    },
    //SetSubscribeMethodPath {
    //    peer_id: CliId,
    //    subscribe_path: SubscribePath,
    //},
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
}

impl Peer {
    pub(crate) fn is_signal_subscribed(&self, signal: &ShvRI) -> bool {
        for subs in self.subscriptions.iter() {
            if subs.match_shv_ri(signal) {
                return true;
            }
        }
        false
    }
    //pub fn subscribe_path(&self) -> Option<&SubscribePath> {
    //    if let PeerKind::Device(path) = &self.peer_kind {
    //        path.as_ref()
    //    } else {
    //        None
    //    }
    //}
}

#[derive(Debug, Clone)]
pub(crate) enum Mount {
    Peer(PeerId),
    Node(ShvNode),
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
    pub(crate) request_id: RqId,
    pub(crate) response_sender: Sender<RpcFrame>,
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

pub async fn accept_loop(config: BrokerConfig, access: AccessControl) -> shvrpc::Result<()> {
    if let Some(address) = config.listen.tcp.clone() {
        let broker_impl = BrokerImpl::new(access);
        let broker_sender = broker_impl.command_sender.clone();
        let parent_broker_peer_config = config.parent_broker.clone();
        let broker_task = task::spawn(crate::broker::broker_loop(broker_impl));
        if parent_broker_peer_config.enabled {
            crate::spawn_and_log_error(peer::parent_broker_peer_loop_with_reconnect(1, parent_broker_peer_config, broker_sender.clone()));
        }
        info!("Listening on TCP: {}", address);
        let listener = TcpListener::bind(address).await?;
        info!("bind OK");
        let mut client_id = 2; // parent broker has client_id == 1
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            debug!("Accepting from: {}", stream.peer_addr()?);
            crate::spawn_and_log_error(peer::peer_loop(client_id, broker_sender.clone(), stream));
            client_id += 1;
        }
        drop(broker_sender);
        broker_task.await;
    } else {
        return Err("No port to listen on specified".into());
    }
    Ok(())
}

