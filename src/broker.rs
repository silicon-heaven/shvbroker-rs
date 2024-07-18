use async_std::{task};
use async_std::channel::Sender;
use async_std::net::TcpListener;
use crate::config::{AccessControl, BrokerConfig};
use shvrpc::metamethod::AccessLevel;
use log::{debug, info, warn};
use shvproto::{MetaMap, RpcValue};
use shvrpc::rpc::{SubscriptionPattern};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{CliId, RpcError, RqId};
use crate::shvnode::{ShvNode};
use async_std::stream::StreamExt;
use futures::select;
use futures::FutureExt;
use shvrpc::RpcMessage;
use crate::brokerimpl::BrokerImpl;
use crate::peer;

#[derive(Debug)]
pub(crate) enum BrokerCommand {
    GetPassword {
        client_id: CliId,
        user: String,
    },
    NewPeer {
        client_id: CliId,
        sender: Sender<BrokerToPeerMessage>,
        peer_kind: PeerKind,
    },
    RegisterDevice {
        client_id: CliId,
        device_id: Option<String>,
        mount_point: Option<String>,
        subscribe_path: Option<SubscribePath>,
    },
    FrameReceived {
        client_id: CliId,
        frame: RpcFrame,
    },
    PeerGone {
        peer_id: CliId,
    },
    //SendFrame { peer_id: CliId, frame: RpcFrame },
    SendResponse {peer_id: CliId, meta: MetaMap, result: Result<RpcValue, RpcError>},
    RpcCall{
        client_id: CliId,
        request: RpcMessage,
        response_sender: Sender<RpcFrame>,
    },
    SetSubscribeMethodPath {
        peer_id: CliId,
        subscribe_path: SubscribePath,
    },
    PropagateSubscriptions{
        client_id: CliId,
    },
}

#[derive(Debug)]
pub(crate) enum BrokerToPeerMessage {
    PasswordSha1(Option<Vec<u8>>),
    SendFrame(RpcFrame),
    SendMessage(RpcMessage),
    DisconnectByBroker,
}

#[derive(Debug)]
pub enum PeerKind {
    Client,
    ParentBroker,
}

#[derive(Debug)]
pub(crate) struct Peer {
    pub(crate) sender: Sender<BrokerToPeerMessage>,
    pub(crate) user: String,
    pub(crate) mount_point: Option<String>,
    pub(crate) subscriptions: Vec<SubscriptionPattern>,
    pub(crate) peer_kind: PeerKind,
    pub(crate) subscribe_path: Option<SubscribePath>,
}

impl Peer {
    pub(crate) fn new(peer_kind: PeerKind, sender: Sender<BrokerToPeerMessage>) -> Self {
        Self {
            sender,
            user: "".to_string(),
            mount_point: None,
            subscriptions: vec![],
            peer_kind,
            subscribe_path: None,
        }
    }
    pub(crate) fn is_signal_subscribed(&self, path: &str, signal: &str, source: &str) -> bool {
        for subs in self.subscriptions.iter() {
            if subs.match_shv_method(path, signal, source) {
                return true;
            }
        }
        false
    }
    pub fn is_broker(&self) -> shvrpc::Result<bool> {
        match &self.subscribe_path {
            None => { Err(format!("Device mounted on: {:?} - not checked for broker capability yet.", self.mount_point).into()) }
            Some(path) => {
                match path {
                    SubscribePath::NotBroker => { Ok(false) }
                    SubscribePath::CanSubscribe(_) => { Ok(true) }
                }
            }
        }
    }
    pub fn broker_subscribe_path(&self) -> shvrpc::Result<String> {
        match &self.subscribe_path {
            None => { Err(format!("Device mounted on: {:?} - not checked for broker capability yet.", self.mount_point).into()) }
            Some(path) => {
                match path {
                    SubscribePath::NotBroker => { Err("Not broker".into()) }
                    SubscribePath::CanSubscribe(path) => { Ok(path.to_string()) }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SubscribePath {
    NotBroker,
    CanSubscribe(String),
}

pub(crate) struct Device {
    pub(crate) peer_id: CliId,
}

impl Device {
}


pub(crate) enum Mount {
    Peer(Device),
    Node(ShvNode),
}

pub(crate) struct ParsedAccessRule {
    pub(crate) path_signal_source: SubscriptionPattern,
    // Needed in order to pass 'dot-local' in 'Access' meta-attribute
    // to support the dot-local hack on older brokers
    pub(crate) grant_str: String,
    pub(crate) grant_lvl: AccessLevel,
}

impl ParsedAccessRule {
    pub fn new(paths: &str, signal: &str, source: &str, grant: &str) -> shvrpc::Result<Self> {
        let subpat = SubscriptionPattern::new(paths, signal, source)?;
        Ok(Self {
            path_signal_source: subpat,
            grant_str: grant.to_string(),
            grant_lvl: grant
                .split(',')
                .find_map(AccessLevel::from_str)
                .unwrap_or_else(|| panic!("Invalid access grant `{grant}`")),
        })
    }
}

pub(crate) struct PendingRpcCall {
    pub(crate) client_id: CliId,
    pub(crate) request_id: RqId,
    pub(crate) response_sender: Sender<RpcFrame>,
}

pub(crate) async fn broker_loop(mut broker: BrokerImpl) {
    loop {
        select! {
            command = broker.command_receiver.recv().fuse() => match command {
                Ok(command) => {
                    if let Err(err) = broker.process_broker_command(command).await {
                        warn!("Process broker command error: {}", err);
                    }
                }
                Err(err) => {
                    warn!("Reseive broker command error: {}", err);
                }
            },
        }
    }
}

pub async fn accept_loop(config: BrokerConfig, access: AccessControl) -> shvrpc::Result<()> {
    if let Some(address) = config.listen.tcp.clone() {
        let broker = BrokerImpl::new(access);
        let broker_sender = broker.command_sender.clone();
        let parent_broker_peer_config = config.parent_broker.clone();
        let broker_task = task::spawn(crate::broker::broker_loop(broker));
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

