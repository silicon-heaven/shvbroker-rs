use std::sync::atomic::{AtomicI64, Ordering};
use futures::select;
use futures::FutureExt;
use futures::io::BufWriter;
use graph_rs_sdk::GraphClient;
use log::{debug, error, info, warn};
use rand::distr::{Alphanumeric, SampleString};
use shvproto::{make_list, make_map, RpcValue};
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpcmessage::{PeerId, Tag};
use shvrpc::{client, RpcMessage, RpcMessageMetaTags};
use shvrpc::client::LoginParams;
use shvrpc::rpcframe::RpcFrame;
use crate::shvnode::{DOT_LOCAL_DIR, DOT_LOCAL_HACK, DOT_LOCAL_GRANT, METH_PING, METH_SUBSCRIBE, METH_UNSUBSCRIBE};
use shvrpc::util::{join_path, login_from_url, sha1_hash, starts_with_path, strip_prefix_path};
use crate::brokerimpl::{BrokerCommand, BrokerToPeerMessage, PeerKind};
use shvrpc::framerw::{FrameReader, FrameWriter};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::streamrw::{StreamFrameReader, StreamFrameWriter};
use smol::{channel};
use smol::channel::Sender;
use smol::io::BufReader;
use smol::net::TcpStream;
use crate::config::{AzureConfig, BrokerConnectionConfig, ConnectionKind};
use crate::cut_prefix;
use crate::serial::create_serial_frame_reader_writer;

static G_PEER_COUNT: AtomicI64 = AtomicI64::new(0);
pub(crate)  fn next_peer_id() -> i64 {
    let old_id = G_PEER_COUNT.fetch_add(1, Ordering::SeqCst);
    old_id + 1
}

pub(crate) async fn try_server_peer_loop(peer_id: PeerId, broker_writer: Sender<BrokerCommand>, stream: TcpStream, azure_config: Option<AzureConfig>) -> shvrpc::Result<()> {
    match server_peer_loop1(peer_id, broker_writer.clone(), stream, azure_config).await {
        Ok(_) => {
            debug!("Client loop exit OK, peer id: {peer_id}");
        }
        Err(e) => {
            debug!("Client loop exit ERROR, peer id: {peer_id}, error: {e}");
        }
    }
    broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
    Ok(())
}
async fn server_peer_loop1(peer_id: PeerId, broker_writer: Sender<BrokerCommand>, stream: TcpStream, azure_config: Option<AzureConfig>) -> shvrpc::Result<()> {

    let (socket_reader, socket_writer) = (stream.clone(), stream);

    let brd = BufReader::new(socket_reader);
    let bwr = BufWriter::new(socket_writer);

    let mut frame_reader = StreamFrameReader::new(brd);
    let mut frame_writer = StreamFrameWriter::new(bwr);
    frame_reader.set_peer_id(peer_id);
    frame_writer.set_peer_id(peer_id);

    server_peer_loop(peer_id, broker_writer, frame_reader, frame_writer, azure_config).await
}
pub(crate) async fn server_peer_loop(peer_id: PeerId, broker_writer: Sender<BrokerCommand>, mut frame_reader: impl FrameReader, mut frame_writer: impl FrameWriter + Send, azure_config: Option<AzureConfig>) -> shvrpc::Result<()> {
    debug!("Entering peer loop client ID: {peer_id}.");
    frame_reader.set_peer_id(peer_id);
    frame_writer.set_peer_id(peer_id);

    let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();

    let mut device_options = RpcValue::null();
    let mut user;
    let mut nonce = None;
    'login_loop: loop {
        let frame = frame_reader.receive_frame().await?;
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
                let mut workflows = make_list!{
                    "PLAIN",
                    "SHA1",
                };
                if let Some(azure_config) = &azure_config {
                    workflows.push(make_map!{
                        "type" => "oauth2-azure",
                        "clientId" => azure_config.client_id.clone(),
                        "authorizeUrl" => azure_config.authorize_url.clone(),
                        "tokenUrl" => azure_config.token_url.clone(),
                        "scopes" => azure_config.scopes.clone(),
                    }.into());
                };
                frame_writer.send_result(resp_meta, workflows.into()).await?;
            },
            "login" => {
                debug!("Client ID: {peer_id}, login received.");
                let params = rpcmsg.param().ok_or("No login params")?.as_map();
                let login = params.get("login").ok_or("Invalid login params")?.as_map();
                user = login.get("user").ok_or("User login param is missing")?.as_str().to_string();
                let login_type = login.get("type").map(|v| v.as_str()).unwrap_or("");
                let password = login.get(if login_type == "TOKEN" {"token"} else {"password"}).ok_or("Password login param is missing")?.as_str();

                if login_type == "TOKEN" || login_type == "AZURE" {
                    const AZURE_TOKEN_PREFIX: &str = "oauth2-azure:";
                    let access_token = if login_type == "AZURE" {
                        password
                    } else if let Some(access_token) = password.strip_prefix(AZURE_TOKEN_PREFIX) {
                        access_token
                    } else {
                        frame_writer.send_error(resp_meta, "Unsupported token type.").await?;
                        continue 'login_loop;
                    };

                    let Some(azure_config) = &azure_config else {
                        frame_writer.send_error(resp_meta, "Azure is not configured on this broker.").await?;
                        continue 'login_loop;
                    };

                    let client = GraphClient::new(access_token);

                    #[derive(serde::Deserialize)]
                    struct MeResponse {
                        mail: String
                    }
                    let me_response = client
                        .me()
                        .get_user()
                        .send()
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

                    let groups_response = client
                        .me()
                        .transitive_member_of()
                        .list_transitive_member_of()
                        .send()
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
                        debug!(target: "Azure", "Client ID: {peer_id}, no relevant groups in Azure.");
                        frame_writer.send_error(resp_meta, "No relevant Azure groups found.").await?;
                        continue 'login_loop;
                    }

                    debug!(target: "Azure", "Client ID: {peer_id} (azure), groups: {:?}", mapped_groups);
                    let mut result = shvproto::Map::new();
                    result.insert("clientId".into(), RpcValue::from(peer_id));
                    frame_writer.send_result(resp_meta.clone(), result.into()).await?;
                    if let Some(options) = params.get("options") {
                        if let Some(device) = options.as_map().get("device") {
                            device_options = device.clone();
                        }
                    }
                    mapped_groups.insert(0, user.clone());
                    broker_writer.send(BrokerCommand::SetAzureGroups { peer_id, groups: mapped_groups}).await?;
                    break 'login_loop;
                }

                broker_writer.send(BrokerCommand::GetPassword { sender: peer_writer.clone(), user: user.as_str().to_string() }).await.unwrap();
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
                            if let Some(options) = params.get("options") {
                                if let Some(device) = options.as_map().get("device") {
                                    device_options = device.clone();
                                }
                            }
                            break 'login_loop;
                        } else {
                            debug!("Client ID: {peer_id}, invalid login credentials.");
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
            user,
            device_id,
            mount_point,
        }
    } else {
        PeerKind::Client { user }
    };
    broker_writer.send(
        BrokerCommand::NewPeer {
            peer_id,
            peer_kind,
            sender: peer_writer
        }).await?;

    let mut fut_receive_frame = frame_reader.receive_frame().fuse();
    let mut fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
    loop {
        select! {
            frame = fut_receive_frame => match frame {
                Ok(frame) => {
                    broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
                    drop(fut_receive_frame);
                    fut_receive_frame = frame_reader.receive_frame().fuse();
                }
                Err(e) => {
                    debug!("Peer socket closed: {}", &e);
                    break;
                }
            },
            event = fut_receive_broker_event => match event {
                Err(e) => {
                    debug!("Broker to Peer channel closed: {}", &e);
                    break;
                }
                Ok(event) => {
                    match event {
                        BrokerToPeerMessage::PasswordSha1(_) => {
                            panic!("PasswordSha1 cannot be received here")
                        }
                        BrokerToPeerMessage::DisconnectByBroker => {
                            info!("Disconnected by broker, client ID: {peer_id}");
                            break;
                        }
                        BrokerToPeerMessage::SendFrame(frame) => {
                            // log!(target: "RpcMsg", Level::Debug, "<---- Send frame, client id: {}", client_id);
                            frame_writer.send_frame(frame).await?;
                        }
                    }
                    fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
                }
            }
        }
    }
    info!("Client ID: {peer_id} gone.");
    Ok(())
}
pub(crate) async fn client_peer_loop_with_reconnect(peer_id: PeerId, config: BrokerConnectionConfig, broker_writer: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let reconnect_interval = config.client.reconnect_interval.unwrap_or_else(|| {
        const DEFAULT_RECONNECT_INTERVAL_SEC: u64 = 10;
        info!("Parent broker connection reconnect interval is not set explicitly, default value {DEFAULT_RECONNECT_INTERVAL_SEC} will be used.");
        std::time::Duration::from_secs(DEFAULT_RECONNECT_INTERVAL_SEC)
    });
    info!("Reconnect interval set to: {:?}", reconnect_interval);
    loop {
        match broker_client_connection_loop(peer_id, config.clone(), broker_writer.clone()).await {
            Ok(_) => {
                info!("Parent broker peer loop finished without error");
            }
            Err(err) => {
                error!("Parent broker peer loop finished with error: {err}");
            }
        }
        broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
        info!("Reconnecting to parent broker after: {:?}", reconnect_interval);
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
async fn broker_client_connection_loop(peer_id: PeerId, config: BrokerConnectionConfig, broker_writer: Sender<BrokerCommand>) -> shvrpc::Result<()> {
    let url = &config.client.url;
    let scheme = url.scheme();
    if scheme == "tcp" {
        let (host, port) = (url.host_str().unwrap_or_default(), url.port().unwrap_or(3755));
        let address = format!("{host}:{port}");
        // Establish a connection
        info!("Connecting to broker peer: tcp://{address}");
        let reader = TcpStream::connect(&address).await?;
        let writer = reader.clone();

        let brd = BufReader::new(reader);
        let bwr = BufWriter::new(writer);
        let frame_reader = StreamFrameReader::new(brd);
        let frame_writer = StreamFrameWriter::new(bwr);
        return broker_client_connection_loop2(peer_id, config, broker_writer, frame_reader, frame_writer).await
    } else if scheme == "serial" {
        let port_name = url.path();
        let (frame_reader, frame_writer) = create_serial_frame_reader_writer(port_name)?;
        return broker_client_connection_loop2(peer_id, config, broker_writer, frame_reader, frame_writer).await
    }
    Err(format!("Scheme {scheme} is not supported yet.").into())
}
async fn broker_client_connection_loop2(peer_id: PeerId, config: BrokerConnectionConfig, broker_writer: Sender<BrokerCommand>, mut frame_reader: impl FrameReader + Send, mut frame_writer: impl FrameWriter + Send) -> shvrpc::Result<()> {
    frame_reader.set_peer_id(peer_id);
    frame_writer.set_peer_id(peer_id);

    // login
    let url = &config.client.url;
    let (user, password) = login_from_url(url);
    let heartbeat_interval = config.client.heartbeat_interval;
    let login_params = LoginParams{
        user,
        password,
        mount_point: config.client.mount.clone().unwrap_or_default().to_owned(),
        device_id: config.client.device_id.clone().unwrap_or_default().to_owned(),
        heartbeat_interval,
        ..Default::default()
    };

    match &config.connection_kind {
        ConnectionKind::ToParentBroker { .. } => {
            info!("Login to parent broker OK");
        }
        ConnectionKind::ToChildBroker { .. } => {
            info!("Login to child broker OK");
        }
    }
    info!("Heartbeat interval set to: {:?}", &heartbeat_interval);
    client::login(&mut frame_reader, &mut frame_writer, &login_params).await?;

    let (broker_to_peer_sender, broker_to_peer_receiver) = channel::unbounded::<BrokerToPeerMessage>();
    broker_writer.send(BrokerCommand::NewPeer {
        peer_id,
        peer_kind: PeerKind::Broker(config.connection_kind.clone()),
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
                    process_broker_client_peer_frame(peer_id, frame, &config.connection_kind, broker_writer.clone()).await?;
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
                            match &config.connection_kind {
                                ConnectionKind::ToParentBroker{shv_root} => {
                                    if frame.is_signal() {
                                        if let Some(new_path) = cut_prefix(frame.shv_path().unwrap_or_default(), shv_root) {
                                            frame.set_shvpath(&new_path);
                                        }
                                    }
                                }
                                ConnectionKind::ToChildBroker{ .. } => {
                                    if frame.is_request() {
                                        frame = fix_request_frame_shv_root(frame, &config.connection_kind)?;
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
