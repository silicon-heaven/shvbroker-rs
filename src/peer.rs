use std::collections::HashMap;
use std::pin::pin;
use std::time::Duration;

use async_tungstenite::WebSocketStream;
use futures::channel::mpsc::UnboundedSender;
use futures::select;
use futures::stream::FuturesUnordered;
use futures::FutureExt;
use futures::io::BufWriter;
use futures::StreamExt;
use log::{debug, error, info, warn};
use rand::distr::{Alphanumeric, SampleString};
use shvproto::make_list;
use shvproto::RpcValue;
use shvrpc::canrw::CanFrameReader;
use shvrpc::canrw::CanFrameWriter;
use shvrpc::client::ClientConfig;
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpcmessage::{PeerId, Tag};
use shvrpc::{client, RpcMessage, RpcMessageMetaTags};
use shvrpc::client::LoginParams;
use shvrpc::rpcframe::{Protocol, RpcFrame};
use smol::Task;
use socketcan::CanFdFrame;
use crate::brokerimpl::next_peer_id;
use crate::config::CanConnectionConfig;
use crate::config::CanInterfaceConfig;
use crate::shvnode::{DOT_LOCAL_DIR, DOT_LOCAL_HACK, DOT_LOCAL_GRANT, METH_PING, METH_SUBSCRIBE, METH_UNSUBSCRIBE};
use shvrpc::util::{join_path, login_from_url, sha1_hash, starts_with_path, strip_prefix_path};
use crate::brokerimpl::{BrokerCommand, BrokerToPeerMessage, PeerKind};
use shvrpc::framerw::{FrameReader, FrameWriter};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::streamrw::{StreamFrameReader, StreamFrameWriter};
use shvrpc::websocketrw::{WebSocketFrameReader,WebSocketFrameWriter};
use smol::channel;
use smol::channel::Sender;
use smol::io::BufReader;
use smol::net::TcpStream;
use crate::config::{BrokerConnectionConfig, ConnectionKind, SharedBrokerConfig};
use crate::cut_prefix;
use crate::serial::create_serial_frame_reader_writer;

#[cfg(feature = "entra-id")]
use shvproto::make_map;
#[cfg(feature = "entra-id")]
use async_compat::CompatExt;

pub(crate) async fn try_server_tcp_peer_loop(
    peer_id: PeerId,
    broker_writer: Sender<BrokerCommand>,
    stream: TcpStream,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    info!("Entering TCP peer loop, peer: {peer_id}.");
    match server_tcp_peer_loop(peer_id, broker_writer.clone(), stream, broker_config).await {
        Ok(_) => {
            info!("Client loop exit OK, peer id: {peer_id}");
        }
        Err(e) => {
            warn!("Client loop exit ERROR, peer id: {peer_id}, error: {e}");
        }
    }
    broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
    Ok(())
}
async fn server_tcp_peer_loop(
    peer_id: PeerId,
    broker_writer: Sender<BrokerCommand>,
    stream: TcpStream,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {

    let (socket_reader, socket_writer) = (stream.clone(), stream);

    let brd = BufReader::new(socket_reader);
    let bwr = BufWriter::new(socket_writer);

    let frame_reader = StreamFrameReader::new(brd).with_peer_id(peer_id);
    let frame_writer = StreamFrameWriter::new(bwr).with_peer_id(peer_id);

    server_peer_loop(peer_id, broker_writer, frame_reader, frame_writer, broker_config).await
}

pub(crate) async fn try_server_ws_peer_loop(
    peer_id: PeerId,
    broker_writer: Sender<BrokerCommand>,
    stream: WebSocketStream<TcpStream>,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    info!("Entering WS peer loop client ID: {peer_id}.");
    match server_ws_peer_loop(peer_id, broker_writer.clone(), stream, broker_config).await {
        Ok(_) => {
            info!("Client loop exit OK, peer id: {peer_id}");
        }
        Err(e) => {
            error!("Client loop exit ERROR, peer id: {peer_id}, error: {e}");
        }
    }
    broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
    Ok(())
}
async fn server_ws_peer_loop(
    peer_id: PeerId,
    broker_writer: Sender<BrokerCommand>,
    stream: WebSocketStream<TcpStream>,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    use futures::StreamExt;
    let (socket_sink, socket_stream) = stream.split();
    let frame_reader = WebSocketFrameReader::new(socket_stream).with_peer_id(peer_id);
    let frame_writer = WebSocketFrameWriter::new(socket_sink).with_peer_id(peer_id);

    server_peer_loop(peer_id, broker_writer, frame_reader, frame_writer, broker_config).await
}
pub(crate) async fn server_peer_loop(
    peer_id: PeerId,
    broker_writer: Sender<BrokerCommand>,
    mut frame_reader: impl FrameReader + std::marker::Send,
    mut frame_writer: impl FrameWriter + Send,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    debug!("Entering peer loop client ID: {peer_id}.");

    let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();

    'session_loop: loop {
        let mut device_options = RpcValue::null();
        let mut user;
        let mut nonce = None;
        'login_loop: loop {
            let frame = frame_reader.receive_frame().await?;
            if frame.protocol == Protocol::ResetSession {
                continue 'session_loop;
            }
            let rpcmsg = frame.to_rpcmesage()?;
            let resp_meta = RpcFrame::prepare_response_meta(&frame.meta)?;
            let method = rpcmsg.method().unwrap_or("");
            match method {
                "hello" => {
                    debug!("Client ID: {peer_id}, hello received.");
                    let nonce: &String = nonce.get_or_insert_with(|| Alphanumeric.sample_string(&mut rand::rng(), 16));
                    let mut result = shvproto::Map::new();
                    result.insert("nonce".into(), RpcValue::from(nonce));
                    frame_writer.send_result(resp_meta, result.into()).await?;
                },
                "workflows" => {
                    debug!("Client ID: {peer_id}, workflows received.");
                    #[cfg_attr(not(feature = "entra-id"), allow(unused_mut))]
                    let mut workflows = make_list!(
                        "PLAIN",
                        "SHA1",
                    );

                    #[cfg(feature = "entra-id")]
                    {
                        if let Some(azure_config) = &broker_config.azure {
                            workflows.push(make_map!{
                                "type" => "oauth2-azure",
                                "clientId" => azure_config.client_id.clone(),
                                "authorizeUrl" => azure_config.authorize_url.clone(),
                                "tokenUrl" => azure_config.token_url.clone(),
                                "scopes" => azure_config.scopes.clone(),
                            }.into());
                        }
                    }

                    frame_writer.send_result(resp_meta, workflows.into()).await?;
                },
                "login" => {
                    debug!("Client ID: {peer_id}, login received.");
                    let params = rpcmsg.param().ok_or("No login params")?.as_map();
                    let login = params.get("login").ok_or("Invalid login params")?.as_map();
                    let login_type = login.get("type").map(|v| v.as_str()).unwrap_or("");
                    let password = login.get(if login_type == "TOKEN" {"token"} else {"password"}).ok_or("Password login param is missing")?.as_str();

                    if login_type == "TOKEN" || login_type == "AZURE" {
                        #[cfg(not(feature = "entra-id"))]
                        {
                            frame_writer.send_error(resp_meta, "Entra ID login is not supported on this broker.").await?;
                            continue 'login_loop;
                        }
                        #[cfg(feature = "entra-id")]
                        {
                            const AZURE_TOKEN_PREFIX: &str = "oauth2-azure:";
                            let access_token = if login_type == "AZURE" {
                                password
                            } else if let Some(access_token) = password.strip_prefix(AZURE_TOKEN_PREFIX) {
                                access_token
                            } else {
                                frame_writer.send_error(resp_meta, "Unsupported token type.").await?;
                                continue 'login_loop;
                            };

                            let Some(azure_config) = &broker_config.azure else {
                                frame_writer.send_error(resp_meta, "Azure is not configured on this broker.").await?;
                                continue 'login_loop;
                            };

                            let client = reqwest::Client::new();

                            #[derive(serde::Deserialize)]
                            struct MeResponse {
                                mail: String
                            }
                            const GRAPH_ME_URL: &str = "https://graph.microsoft.com/v1.0/me";
                            let me_response = client
                                .get(GRAPH_ME_URL)
                                .header("Authorization", format!("Bearer {access_token}"))
                                .send()
                                .compat()
                                .await?
                                .json::<MeResponse>()
                                .await?;

                            user = me_response.mail;

                            #[derive(serde::Deserialize)]
                            struct TransitiveMemberOfValue {
                                #[serde(rename = "@odata.type")]
                                value_type: String,
                                id: String
                            }

                            #[derive(serde::Deserialize)]
                            struct TransitiveMemberOfResponse {
                                value: Vec<TransitiveMemberOfValue>
                            }
                            const GRAPH_TRANSITIVE_MEMBER_OF_URL: &str = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf";
                            let groups_response = client
                                .get(GRAPH_TRANSITIVE_MEMBER_OF_URL)
                                .header("Authorization", format!("Bearer {access_token}"))
                                .send()
                                .compat()
                                .await?
                                .json::<TransitiveMemberOfResponse>()
                                .await?;

                            let groups_from_azure = groups_response.value
                                .into_iter()
                                .filter(|group| group.value_type == "#microsoft.graph.group")
                                .map(|group| group.id);

                            let mut mapped_groups = groups_from_azure
                                .flat_map(|azure_group| azure_config.group_mapping
                                    .get(&azure_group)
                                    .cloned()
                                    .unwrap_or_default())
                                .collect::<Vec<_>>();

                            if mapped_groups.is_empty() {
                                warn!(target: "Azure", "Client ID: {peer_id}, no relevant groups in Azure.");
                                frame_writer.send_error(resp_meta, "No relevant Azure groups found.").await?;
                                continue 'login_loop;
                            }

                            debug!(target: "Azure", "Client ID: {peer_id} (azure), groups: {mapped_groups:?}");
                            let mut result = shvproto::Map::new();
                            result.insert("clientId".into(), RpcValue::from(peer_id));
                            frame_writer.send_result(resp_meta.clone(), result.into()).await?;
                            if let Some(options) = params.get("options")
                                && let Some(device) = options.as_map().get("device") {
                                    device_options = device.clone();
                                }
                            mapped_groups.insert(0, user.clone());
                            broker_writer.send(BrokerCommand::SetAzureGroups { peer_id, groups: mapped_groups}).await?;
                            break 'login_loop;
                        }
                    }

                    user = login.get("user").ok_or("User login param is missing")?.as_str().to_string();

                    broker_writer.send(BrokerCommand::GetPassword { sender: peer_writer.clone(), user: user.as_str().to_string() }).await?;
                    match peer_reader.recv().await? {
                        BrokerToPeerMessage::PasswordSha1(broker_shapass) => {
                            let chkpwd = || {
                                match broker_shapass {
                                    None => {false}
                                    Some(broker_shapass) => {
                                        match login_type {
                                            "PLAIN" => {
                                                let client_shapass = sha1_hash(password.as_bytes());
                                                client_shapass == broker_shapass
                                            },
                                            "SHA1" => {
                                                if let Some(nonce) = &nonce {
                                                    let mut data = nonce.as_bytes().to_vec();
                                                    data.extend_from_slice(&broker_shapass[..]);
                                                    let broker_shapass = sha1_hash(&data);
                                                    //info!("nonce: {}", nonce);
                                                    //info!("client password: {}", password);
                                                    //info!("broker password: {}", std::str::from_utf8(&broker_shapass).unwrap());
                                                    password.as_bytes() == broker_shapass
                                                } else {
                                                    debug!("Client ID: {peer_id}, user tried SHA1 login without using `:hello`.");
                                                    false
                                                }
                                            },
                                            _ => {
                                                debug!("Client ID: {peer_id}, unknown login type '{login_type}'.");
                                                false
                                            }
                                        }
                                    }
                                }
                            };
                            if chkpwd() {
                                debug!("Client ID: {peer_id}, password OK.");
                                let mut result = shvproto::Map::new();
                                result.insert("clientId".into(), RpcValue::from(peer_id));
                                frame_writer.send_result(resp_meta, result.into()).await?;
                                if let Some(options) = params.get("options")
                                    && let Some(device) = options.as_map().get("device") {
                                        device_options = device.clone();
                                    }
                                break 'login_loop;
                            } else {
                                warn!("Peer: {peer_id}, invalid login credentials.");
                                frame_writer.send_error(resp_meta, "Invalid login credentials.").await?;
                                continue 'login_loop;
                            }
                        }
                        _ => {
                            panic!("Internal error, PeerEvent::PasswordSha1 expected");
                        }
                    }
                },
                _ => {
                    frame_writer.send_error(resp_meta, "Invalid login message.").await?;
                }
            }
        }
        let device_id = device_options.as_map().get("deviceId").map(|v| v.as_str().to_string());
        let mount_point = device_options.as_map().get("mountPoint").map(|v| v.as_str().to_string());
        info!("Client ID: {peer_id} login success.");
        let peer_kind = if device_id.is_some() || mount_point.is_some() {
            PeerKind::Device {
                user: user.clone(),
                device_id,
                mount_point,
            }
        } else {
            PeerKind::Client { user: user.clone() }
        };
        broker_writer.send(
            BrokerCommand::NewPeer {
                peer_id,
                peer_kind,
                sender: peer_writer.clone()
            }).await?;

        let mut fut_receive_frame = frame_reader.receive_frame().fuse();
        let mut fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
        loop {
            select! {
                frame = fut_receive_frame => match frame {
                    Ok(frame) => {
                        if frame.protocol == Protocol::ResetSession {
                            // delete peer state
                            broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
                            continue 'session_loop;
                        }
                        let mut frame = frame;
                        if frame.is_request() && let Some(req_user_id) = frame.user_id() {
                                let broker_id = broker_config.name.as_ref()
                                        .map(|name| format!(":{name}"))
                                        .unwrap_or_default();
                                let user_id_chain = if req_user_id.is_empty() {
                                    format!("{user}{broker_id}")
                                } else {
                                    format!("{req_user_id};{user}{broker_id}")
                                };
                                frame.set_user_id(&user_id_chain);
                            }
                        broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
                        drop(fut_receive_frame);
                        fut_receive_frame = frame_reader.receive_frame().fuse();
                    }
                    Err(e) => {
                        debug!("Peer socket closed: {}", &e);
                        break 'session_loop;
                    }
                },
                event = fut_receive_broker_event => match event {
                    Err(e) => {
                        debug!("Broker to Peer channel closed: {}", &e);
                        break 'session_loop;
                    }
                    Ok(event) => {
                        match event {
                            BrokerToPeerMessage::PasswordSha1(_) => {
                                panic!("PasswordSha1 cannot be received here")
                            }
                            BrokerToPeerMessage::DisconnectByBroker => {
                                info!("Disconnected by broker, client ID: {peer_id}");
                                break 'session_loop;
                            }
                            BrokerToPeerMessage::SendFrame(frame) => {
                                frame_writer.send_frame(frame).await?;
                            }
                        }
                        fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
                    }
                }
            }
        }
    }

    info!("Client ID: {peer_id} gone.");
    Ok(())
}
pub(crate) async fn broker_as_client_peer_loop_with_reconnect(peer_id: PeerId, config: BrokerConnectionConfig, broker_writer: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    info!("Spawning broker peer connection loop: {}", config.name);
    let reconnect_interval = config.client.reconnect_interval.unwrap_or_else(|| {
        const DEFAULT_RECONNECT_INTERVAL_SEC: u64 = 10;
        info!("Parent broker connection reconnect interval is not set explicitly, default value {DEFAULT_RECONNECT_INTERVAL_SEC} will be used.");
        std::time::Duration::from_secs(DEFAULT_RECONNECT_INTERVAL_SEC)
    });
    info!("Reconnect interval set to: {reconnect_interval:?}");
    loop {
        info!("Connecting to broker peer id: {peer_id} with url: {}", config.client.url);
        match broker_as_client_peer_loop_from_url(peer_id, config.clone(), broker_writer.clone()).await {
            Ok(_) => {
                info!("Peer broker loop finished without error");
            }
            Err(err) => {
                error!("Peer broker loop finished with error: {err}");
            }
        }
        broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
        info!("Reconnecting to peer broker after: {reconnect_interval:?}");
        smol::Timer::after(reconnect_interval).await;
    }
}

fn is_dot_local_granted(frame: &RpcFrame) -> bool {
    frame.access_level()
        .is_some_and(|access| access == AccessLevel::Superuser as i32)
        ||
        frame.tag(Tag::Access as i32)
            .map(RpcValue::as_str)
            .is_some_and(|s| s.split(',')
                .any(|access| access == DOT_LOCAL_GRANT))
}
fn is_dot_local_request(frame: &RpcFrame) -> bool {
    let shv_path = frame.shv_path().unwrap_or_default();
    if starts_with_path(shv_path, DOT_LOCAL_DIR) {
        return is_dot_local_granted(frame);
    }
    false
}
async fn process_broker_client_peer_frame(peer_id: PeerId, frame: RpcFrame, connection_kind: &ConnectionKind, broker_writer: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    match &connection_kind {
        ConnectionKind::ToParentBroker{ .. } => {
            // Only RPC requests can be received from parent broker,
            // no signals, no responses
            if frame.is_request() {
                let mut frame = frame;
                frame = fix_request_frame_shv_root(frame, connection_kind)?;
                broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
            } else if frame.is_response() {
                broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
            } else {
                warn!("RPC signal should not be received from client connection to parent broker: {}", &frame);
            }
        }
        ConnectionKind::ToChildBroker{ .. } => {
            // Only RPC signals and responses can be received from child broker,
            // no requests
            if frame.is_signal() || frame.is_response() {
                broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
            } else {
                warn!("RPC request should not be received from client connection to child broker: {}", &frame);
            }
        }
    };
    Ok(())
}
async fn broker_as_client_peer_loop_from_url(peer_id: PeerId, config: BrokerConnectionConfig, broker_writer: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let url = &config.client.url;
    let scheme = url.scheme();
    if scheme == "tcp" {
        let (host, port) = (url.host_str().unwrap_or_default(), url.port().unwrap_or(3755));
        let address = format!("{host}:{port}");
        // Establish a connection
        debug!("Connecting to broker TCP peer: {address}");
        let reader = TcpStream::connect(&address).await?;
        let writer = reader.clone();

        let brd = BufReader::new(reader);
        let bwr = BufWriter::new(writer);
        let frame_reader = StreamFrameReader::new(brd).with_peer_id(peer_id);
        let frame_writer = StreamFrameWriter::new(bwr).with_peer_id(peer_id);
        broker_as_client_peer_loop(
            peer_id,
            login_params_from_client_config(&config.client),
            config.client.heartbeat_interval,
            config.connection_kind,
            false,
            broker_writer,
            frame_reader,
            frame_writer,
        ).await
    } else if scheme == "serial" {
        let port_name = url.path();
        debug!("Connecting to broker serial peer: {port_name}");
        let (frame_reader, frame_writer) = create_serial_frame_reader_writer(port_name, peer_id)?;
        broker_as_client_peer_loop(
            peer_id,
            login_params_from_client_config(&config.client),
            config.client.heartbeat_interval,
            config.connection_kind,
            true,
            broker_writer,
            frame_reader,
            frame_writer,
        ).await
    } else {
        Err(format!("Scheme {scheme} is not supported yet.").into())
    }
}

fn login_params_from_client_config(client_config: &ClientConfig) -> LoginParams {
    let (user, password) = login_from_url(&client_config.url);
    LoginParams {
        user,
        password,
        mount_point: client_config.mount.clone().unwrap_or_default().to_owned(),
        device_id: client_config.device_id.clone().unwrap_or_default().to_owned(),
        heartbeat_interval: client_config.heartbeat_interval,
        ..Default::default()
    }
}

pub(crate) async fn can_interface_task(can_interface_config: CanInterfaceConfig, broker_sender: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let can_iface = &can_interface_config.interface;
    let broker_address = can_interface_config.address;

    use shvrpc::canrw::{
        ShvCanFrame,
        AckFrame as ShvCanAckFrame,
        DataFrame as ShvCanDataFrame
    };

    struct PeerChannels {
        writer_ack_tx: UnboundedSender<ShvCanAckFrame>,
        reader_frames_tx: UnboundedSender<ShvCanDataFrame>,
    }

    let mut peers_channels = HashMap::<u8, PeerChannels>::new();
    let mut peers_tasks: FuturesUnordered<Task<(PeerId, u8, shvrpc::Result<()>)>> = FuturesUnordered::new();

    let (writer_frames_tx, mut writer_frames_rx) = futures::channel::mpsc::unbounded();
    let (reader_ack_tx, mut reader_ack_rx) = futures::channel::mpsc::unbounded();

    fn run_peer_task(
        broker_address: u8,
        connection_config: CanConnectionConfig,
        tasks: &mut FuturesUnordered<Task<(PeerId, u8, shvrpc::Result<()>)>>,
        channels: &mut HashMap::<u8, PeerChannels>,
        broker_sender: Sender<BrokerCommand>,
        writer_frames_tx: UnboundedSender<ShvCanDataFrame>,
        reader_ack_tx: UnboundedSender<ShvCanAckFrame>,
    ) {
        let peer_address = connection_config.address;
        let (writer_ack_tx, writer_ack_rx) = futures::channel::mpsc::unbounded();
        let (reader_frames_tx, reader_frames_rx) = futures::channel::mpsc::unbounded();
        channels.insert(peer_address, PeerChannels { writer_ack_tx, reader_frames_tx });
        tasks.push(smol::spawn(async move {
            let peer_id = next_peer_id();
            let frame_reader = CanFrameReader::new(reader_frames_rx, reader_ack_tx, peer_id, peer_address);
            let frame_writer = CanFrameWriter::new(writer_frames_tx, writer_ack_rx, peer_id, peer_address, broker_address);

            let res = broker_as_client_peer_loop(
                peer_id,
                connection_config.to_login_params(),
                connection_config.heartbeat_interval,
                connection_config.connection_kind,
                false, // FIXME
                broker_sender,
                frame_reader,
                frame_writer,
            ).await;

            (peer_id, peer_address, res)
        }));
    }

    for connection_config in &can_interface_config.connections {
        if !connection_config.enabled {
            continue;
        }
        run_peer_task(
            broker_address,
            connection_config.clone(),
            &mut peers_tasks,
            &mut peers_channels,
            broker_sender.clone(),
            writer_frames_tx.clone(),
            reader_ack_tx.clone()
        );

    }

    'init_iface: loop {
        let socket = socketcan::smol::CanFdSocket::open(can_iface)
            .map_err(|err| format!("Cannot open CAN interface {can_iface}: {err}"))?;

        let mut read_frame = pin!(socket.read_frame().fuse());
        loop {
            futures::select! {
                maybe_frame = read_frame => {
                    match maybe_frame {
                        Ok(frame) => {
                            match frame {
                                socketcan::CanAnyFrame::Normal(_) | socketcan::CanAnyFrame::Fd(_)  => {
                                    // Handle classic 2.0 frames and FD frames the same way
                                    let fd_frame: CanFdFrame = match frame.try_into() {
                                        Ok(fd_frame) => fd_frame,
                                        Err(err) => {
                                            error!("Normal or FD frame should be convertible to FD frame: {err}, frame: {frame:?}");
                                            continue
                                        }
                                    };
                                    let Ok(shvcan_frame) = ShvCanFrame::try_from(&fd_frame) else {
                                        continue
                                    };
                                    let header = shvcan_frame.header();
                                    if header.dst() != broker_address {
                                        continue;
                                    }

                                    let peer_address = header.src();
                                    if let std::collections::hash_map::Entry::Occupied(entry) = peers_channels.entry(peer_address) {
                                        let peer_channels = entry.get();
                                        match shvcan_frame {
                                            ShvCanFrame::Data(data_frame) => {
                                                peer_channels
                                                    .reader_frames_tx
                                                    .unbounded_send(data_frame)
                                                    .unwrap_or_else(|e| warn!("Cannot send a data frame to task of peer {peer_address}: {e}"));
                                                }
                                            ShvCanFrame::Ack(ack_frame) => {
                                                peer_channels
                                                    .writer_ack_tx
                                                    .unbounded_send(ack_frame)
                                                    .unwrap_or_else(|e| warn!("Cannot send an ACK frame to task of peer {peer_address}: {e}"));
                                                }
                                            ShvCanFrame::Terminate(_terminate_frame) => {
                                                entry.remove();
                                            }
                                        }
                                    }
                                }
                                socketcan::CanAnyFrame::Remote(can_remote_frame) => {
                                    // Ignore remote frames
                                    debug!("CAN remote frame received on {can_iface}: {can_remote_frame:?}");
                                }
                                socketcan::CanAnyFrame::Error(can_error_frame) => {
                                    debug!("CAN error frame received on {can_iface}: {can_error_frame:?}");
                                },
                            }
                        }
                        Err(err) => {
                            warn!("Error reading from CAN interface {can_iface}: {err}");
                            continue 'init_iface;
                        }
                    }
                }
                data_frame = writer_frames_rx.select_next_some() => {
                    let fd_frame = match CanFdFrame::try_from(&data_frame) {
                        Ok(fd_frame) => fd_frame,
                        Err(err) => {
                            error!("Cannot convert CAN SHV DataFrame to FD frame: {err}, frame: {data_frame:?}");
                            continue
                        }
                    };
                    socket
                        .write_frame(&fd_frame)
                        .await
                        .unwrap_or_else(|e| warn!("Cannot send CAN FD frame: {e}, frame: {fd_frame:?}"));
                }
                ack_frame = reader_ack_rx.select_next_some() => {
                    let fd_frame = match CanFdFrame::try_from(&ack_frame) {
                        Ok(fd_frame) => fd_frame,
                        Err(err) => {
                            error!("Cannot convert CAN SHV AckFrame to FD frame: {err}, frame: {ack_frame:?}");
                            continue
                        }
                    };
                    socket
                        .write_frame(&fd_frame)
                        .await
                        .unwrap_or_else(|e| warn!("Cannot send CAN FD frame: {e}, frame: {fd_frame:?}"));
                }
                (peer_id, peer_address, result) = peers_tasks.select_next_some() => {
                    match result {
                        Ok(_) => info!("CAN peer ID: {peer_id}, address: 0x{peer_address:x} task finished successfuly"),
                        Err(err) => warn!("CAN peer ID: {peer_id}, address: 0x{peer_address:x} task finished with error: {err}"),
                    }
                    broker_sender.send(BrokerCommand::PeerGone { peer_id }).await?;
                    // TODO: Run after reconnect interval
                    if let Some(connection_cfg) = can_interface_config.connections.iter().find(|cfg| cfg.address == peer_address) {
                        run_peer_task(
                            broker_address,
                            connection_cfg.clone(),
                            &mut peers_tasks,
                            &mut peers_channels,
                            broker_sender.clone(),
                            writer_frames_tx.clone(),
                            reader_ack_tx.clone(),
                        );
                    }
                }
            }
        }
    }

    // Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn broker_as_client_peer_loop(
    peer_id: PeerId,
    login_params: LoginParams,
    heartbeat_interval: Duration,
    connection_kind: ConnectionKind,
    reset_session: bool,
    broker_writer: Sender<BrokerCommand>,
    mut frame_reader: impl FrameReader + Send,
    mut frame_writer: impl FrameWriter + Send,
) -> shvrpc::Result<()>
{
    info!("Heartbeat interval set to: {:?}", &heartbeat_interval);
    client::login(&mut frame_reader, &mut frame_writer, &login_params, reset_session).await?;

    match &connection_kind {
        ConnectionKind::ToParentBroker { .. } => {
            info!("Login to parent broker OK");
        }
        ConnectionKind::ToChildBroker { .. } => {
            info!("Login to child broker OK");
        }
    }

    let (broker_to_peer_sender, broker_to_peer_receiver) = channel::unbounded::<BrokerToPeerMessage>();
    broker_writer.send(BrokerCommand::NewPeer {
        peer_id,
        peer_kind: PeerKind::Broker(connection_kind.clone()),
        sender: broker_to_peer_sender,
    }).await?;

    let mut fut_receive_frame = frame_reader.receive_frame().fuse();
    let mut fut_receive_broker_event = Box::pin(broker_to_peer_receiver.recv()).fuse();
    let make_timeout = || {
        Box::pin(smol::Timer::after(heartbeat_interval)).fuse()
        // Box::pin(timeout(heartbeat_interval, futures::future::pending::<()>())).fuse()
    };
    let mut fut_timeout = make_timeout();
    loop {
        select! {
            _ = fut_timeout => {
                // send heartbeat
                let msg = RpcMessage::new_request(".app", METH_PING, None);
                debug!("sending ping");
                frame_writer.send_message(msg).await?;
                fut_timeout = make_timeout();
            },
            res_frame = fut_receive_frame => match res_frame {
                Ok(frame) => {
                    process_broker_client_peer_frame(peer_id, frame, &connection_kind, broker_writer.clone()).await?;
                    drop(fut_receive_frame);
                    fut_receive_frame = frame_reader.receive_frame().fuse();
                }
                Err(e) => {
                    return Err(format!("Read frame error: {e}").into());
                }
            },
            event = fut_receive_broker_event => match event {
                Err(e) => {
                    debug!("broker loop has closed peer channel, client ID {peer_id}");
                    return Err(e.into());
                }
                Ok(event) => {
                    match event {
                        BrokerToPeerMessage::PasswordSha1(_) => {
                            panic!("PasswordSha1 cannot be received here")
                        }
                        BrokerToPeerMessage::DisconnectByBroker => {
                            info!("Disconnected by parent broker, client ID: {peer_id}");
                            break;
                        }
                        BrokerToPeerMessage::SendFrame(frame) => {
                            // log!(target: "RpcMsg", Level::Debug, "<---- Send frame, client id: {}", client_id);
                            let mut frame = frame;
                            match &connection_kind {
                                ConnectionKind::ToParentBroker{shv_root} => {
                                    if frame.is_signal()
                                        && let Some(new_path) = cut_prefix(frame.shv_path().unwrap_or_default(), shv_root) {
                                            frame.set_shvpath(&new_path);
                                        }
                                }
                                ConnectionKind::ToChildBroker{ .. } => {
                                    if frame.is_request() {
                                        frame = fix_request_frame_shv_root(frame, &connection_kind)?;
                                    }
                                }
                            }
                            debug!("Sending rpc frame");
                            frame_writer.send_frame(frame).await?;
                            fut_timeout = make_timeout();
                        }
                    }
                    fut_receive_broker_event = Box::pin(broker_to_peer_receiver.recv()).fuse();
                }
            }
        }
    };
    Ok(())
}
fn fix_request_frame_shv_root(mut frame: RpcFrame, connection_kind: &ConnectionKind) -> shvrpc::Result<RpcFrame> {
    let shv_path = frame.shv_path().unwrap_or_default().to_owned();
    let (add_dot_local_hack, shv_root) = match connection_kind {
        ConnectionKind::ToParentBroker { shv_root } => {
            (shv_path.is_empty(), shv_root)
        }
        ConnectionKind::ToChildBroker { shv_root, .. } => {
            (&shv_path == shv_root, shv_root)
        }
    };
    // println!("current path: {shv_path}");
    let shv_path = if starts_with_path(&shv_path, ".broker") {
        if frame.method() == Some(METH_SUBSCRIBE) || frame.method() == Some(METH_UNSUBSCRIBE) {
            // prepend exported root to subscribed path
            frame = fix_subscribe_param(frame, shv_root)?;
        }
        shv_path
    } else if is_dot_local_request(&frame) {
        // hack to enable parent broker to call paths under exported_root
        strip_prefix_path(&shv_path, DOT_LOCAL_DIR).expect("DOT_LOCAL_DIR").to_string()
    } else {
        if add_dot_local_hack && is_dot_local_granted(&frame) {
            frame.meta.insert(DOT_LOCAL_HACK, true.into());
        }
        join_path(shv_root, &shv_path)
    };
    frame.set_shvpath(&shv_path);
    // println!("new path: {}", frame.shv_path().unwrap_or_default());
    Ok(frame)
}
fn fix_subscribe_param(frame: RpcFrame, exported_root: &str) -> shvrpc::Result<RpcFrame> {
    let mut msg = frame.to_rpcmesage()?;
    let mut subpar = SubscriptionParam::from_rpcvalue(msg.param().unwrap_or_default())?;
    let new_path = join_path(exported_root, subpar.ri.path());
    subpar.ri = ShvRI::from_path_method_signal(&new_path, subpar.ri.method(), subpar.ri.signal())?;
    msg.set_param(subpar.to_rpcvalue());
    msg.to_frame()
}
