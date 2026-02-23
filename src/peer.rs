use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use duration_str::HumanFormat;
use futures::select;
use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::FutureExt;
use futures::io::BufWriter;
use futures::StreamExt;
use log::{debug, error, info, warn};
use rand::distr::{Alphanumeric, SampleString};
use rand::RngExt;
use rustls_platform_verifier::BuilderVerifierExt;
use shvproto::make_list;
use shvproto::RpcValue;
use shvproto::make_map;
use shvrpc::client::ClientConfig;
use shvrpc::framerw::ReceiveFrameError;
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpcmessage::RpcError;
use shvrpc::rpcmessage::RpcErrorCode;
use shvrpc::rpcmessage::{PeerId, Tag};
use shvrpc::{client, RpcMessage, RpcMessageMetaTags};
use shvrpc::client::LoginParams;
use shvrpc::rpcframe::{Protocol, RpcFrame};
use smol::Timer;
use smol::future::FutureExt as _;

use crate::brokerimpl::load_certs;
use crate::brokerimpl::AsyncReadWriteBox;
use crate::brokerimpl::ServerMode;
use crate::shvnode::{DOT_LOCAL_DIR, DOT_LOCAL_HACK, DOT_LOCAL_GRANT, METH_PING, METH_SUBSCRIBE, METH_UNSUBSCRIBE};
use shvrpc::util::{join_path, login_from_url, starts_with_path, strip_prefix_path};
use crate::brokerimpl::{BrokerCommand, BrokerToPeerMessage, PeerKind};
use shvrpc::framerw::{FrameReader, FrameWriter};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::streamrw::{StreamFrameReader, StreamFrameWriter};
use shvrpc::websocketrw::{WebSocketFrameReader,WebSocketFrameWriter};
use futures_rustls::rustls::ClientConfig as TlsClientConfig;
use smol::channel;
use smol::channel::Sender;
use smol::io::BufReader;
use smol::net::TcpStream;
use crate::config::{BrokerConnectionConfig, ConnectionKind, SharedBrokerConfig};
use crate::cut_prefix;
use crate::serial::create_serial_frame_reader_writer;

#[cfg(any(feature = "entra-id", feature = "google-auth"))]
use async_compat::CompatExt;

pub(crate) async fn try_server_peer_loop(
    peer_id: PeerId,
    ip_addr: Option<core::net::IpAddr>,
    server_mode: ServerMode,
    broker_writer: Sender<BrokerCommand>,
    stream: AsyncReadWriteBox,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    let res = match server_mode {
        ServerMode::Tcp => {
            info!("Entering TCP peer loop, peer: {peer_id}.");
            server_tcp_peer_loop(peer_id, ip_addr, broker_writer.clone(), stream, broker_config).await
        }
        ServerMode::WebSocket => {
            info!("Entering WebSocket peer loop, peer: {peer_id}.");
            server_ws_peer_loop(peer_id, ip_addr, broker_writer.clone(), stream, broker_config).await
        }
    };
    match res {
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
    ip_addr: Option<core::net::IpAddr>,
    broker_writer: Sender<BrokerCommand>,
    stream: AsyncReadWriteBox,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {

    let (socket_reader, socket_writer) = stream.split();

    let brd = BufReader::new(socket_reader);
    let bwr = BufWriter::new(socket_writer);

    let frame_reader = StreamFrameReader::new(brd).with_peer_id(peer_id);
    let frame_writer = StreamFrameWriter::new(bwr).with_peer_id(peer_id);

    server_peer_loop(peer_id, ip_addr, broker_writer, frame_reader, frame_writer, broker_config).await
}

async fn server_ws_peer_loop(
    peer_id: PeerId,
    ip_addr: Option<core::net::IpAddr>,
    broker_writer: Sender<BrokerCommand>,
    stream: AsyncReadWriteBox,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    let stream = async_tungstenite::accept_async(stream).await?;
    let (socket_sink, socket_stream) = stream.split();
    let frame_reader = WebSocketFrameReader::new(socket_stream).with_peer_id(peer_id);
    let frame_writer = WebSocketFrameWriter::new(socket_sink).with_peer_id(peer_id);

    server_peer_loop(peer_id, ip_addr, broker_writer, frame_reader, frame_writer, broker_config).await
}

const IDLE_WATCHDOG_TIMEOUT_DEFAULT: u64 = 180;

async fn frame_read_timeout<T>(timeout: Duration) -> Result<T, ReceiveFrameError> {
    Timer::after(timeout).await;
    Err(ReceiveFrameError::Timeout(None))
}

async fn frame_write_timeout<T>() -> shvrpc::Result<T> {
    let timeout = Duration::from_secs(10);
    Timer::after(timeout).await;
    Err(format!("frame write timeout after {timeout_str}", timeout_str = timeout.human_format()).into())
}

pub(crate) async fn server_peer_loop(
    peer_id: PeerId,
    ip_addr: Option<core::net::IpAddr>,
    broker_writer: Sender<BrokerCommand>,
    mut frame_reader: impl FrameReader + Send,
    mut frame_writer: impl FrameWriter + Send + 'static,
    broker_config: SharedBrokerConfig
) -> shvrpc::Result<()> {
    macro_rules! peer_log {
        // level + target
        ($level:ident, target: $target:expr, $fmt:expr $(, $args:tt)* ) => {
            $level!(
                target: $target,
                "peer_id({peer_id}): {msg}",
                msg = ::core::format_args!($fmt $(, $args)*)
            );
        };

        // level only
        ($level:ident, $fmt:expr $(, $args:tt)* ) => {
            $level!(
                "peer_id({peer_id}): {msg}",
                msg = ::core::format_args!($fmt $(, $args)*)
            );
        };
    }

    peer_log!(debug, "entering peer loop");

    'session_loop: loop {
        let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();
        let mut nonce = None;
        let (user, options) = 'login_loop: loop {
            let login_phase_timeout = if nonce.is_none() {
                // Kick out clients that do not send initial hello right after establishing the connection and/or sending ResetSession
                Duration::from_secs(5)
            } else {
                Duration::from_secs(IDLE_WATCHDOG_TIMEOUT_DEFAULT)
            };
            let frame = match frame_reader.receive_frame().or(frame_read_timeout(login_phase_timeout)).await {
                Ok(frame) => frame,
                Err(err) => {
                    match &err {
                        ReceiveFrameError::Timeout(Some(meta)) if meta.is_request() => {
                            let mut msg = RpcMessage::prepare_response_from_meta(meta)?;
                            msg.set_error(RpcError::new(shvrpc::rpcmessage::RpcErrorCode::MethodCallTimeout, "Method call timeout"));
                            frame_writer.send_message(msg).or(frame_write_timeout()).await?;
                        }
                        ReceiveFrameError::FrameTooLarge(reason, Some(meta)) if meta.is_request() => {
                            let mut msg = RpcMessage::prepare_response_from_meta(meta)?;
                            msg.set_error(RpcError::new(shvrpc::rpcmessage::RpcErrorCode::InvalidParam, reason));
                            frame_writer.send_message(msg).or(frame_write_timeout()).await?;
                        }
                        _ => { }
                    }
                    return Err(err.into());
                }
            };
            if frame.protocol == Protocol::ResetSession {
                continue 'session_loop;
            }
            let rpcmsg = frame.to_rpcmesage()?;
            let resp_meta = RpcFrame::prepare_response_meta(&frame.meta)?;
            let method = rpcmsg.method().unwrap_or("");
            match method {
                "hello" => {
                    peer_log!(debug, "hello received");
                    let shv2_compat = broker_config.shv2_compatibility;
                    let nonce: &String = nonce.get_or_insert_with(|| if shv2_compat {
                        format!("{}", rand::rng().random_range(0..=2000000000))
                    } else {
                        Alphanumeric.sample_string(&mut rand::rng(), 16)
                    });

                    let result = make_map!{"nonce" => nonce};
                    frame_writer.send_result(resp_meta, result.into()).or(frame_write_timeout()).await?;
                },
                "workflows" => {
                    peer_log!(debug, "workflows received");
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

                    frame_writer.send_result(resp_meta, workflows.into()).or(frame_write_timeout()).await?;
                },
                "login" => {
                    peer_log!(debug, "login received");
                    let params = rpcmsg.param().ok_or("No login params")?.as_map();
                    let user_agent = params.get("options").and_then(|options| options.get("userAgent")).map(RpcValue::as_str).unwrap_or("<no user agent>");
                    peer_log!(info, "User agent: '{user_agent}'");
                    let login = params.get("login").ok_or("Invalid login params")?.as_map();
                    let login_type = login.get("type").map(|v| v.as_str()).unwrap_or("");
                    let password = login.get(if login_type == "TOKEN" {"token"} else {"password"}).ok_or("Password login param is missing")?.as_str();

                    const GOOGLE_AUTH_TOKEN_PREFIX: &str = "oauth2-google:";
                    if login_type == "TOKEN" && let Some(access_token) = password.strip_prefix(GOOGLE_AUTH_TOKEN_PREFIX) {
                        #[cfg(not(feature = "google-auth"))]
                        {
                            let _ = access_token;
                            frame_writer.send_error(resp_meta, "Google login is not supported on this broker.").or(frame_write_timeout()).await?;
                            continue 'login_loop;
                        }
                        #[cfg(feature = "google-auth")]
                        {
                            #[derive(Debug, serde::Serialize, serde::Deserialize)]
                            struct GoogleClaims {
                                iss: String,    // Issuer (should be https://accounts.google.com)
                                aud: String,    // Audience (your Client ID)
                                sub: String,    // Unique Google user ID
                                email: String,  // The verified email you need
                                exp: usize,     // Expiration time
                            }

                            async fn verify_google_token(token: &str, broker_config: SharedBrokerConfig) -> shvrpc::Result<GoogleClaims> {
                                use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

                                // Cache for Google JWT public keys (kid -> DecodingKey)
                                static GOOGLE_KEY_CACHE: std::sync::LazyLock<smol::lock::RwLock<Option<DecodingKey>>> =
                                    std::sync::LazyLock::new(|| smol::lock::RwLock::new(None));

                                // Parse the header to find which key (kid) was used
                                let header = decode_header(token)?;
                                let kid = header.kid.ok_or_else(|| "No kid found in header".to_string())?;

                                // Helper function to fetch key from Google
                                async fn get_google_decoding_key(kid: &str, force_reload: bool) -> shvrpc::Result<DecodingKey> {
                                    let key = GOOGLE_KEY_CACHE.read().await.clone();
                                    if key.is_none() || force_reload {
                                        // Fetch Google's public keys
                                        let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
                                        let response: serde_json::Value = reqwest::get(jwks_url).compat().await?.json().await?;
                                        // Find the specific key matching the 'kid'
                                        let n = response["keys"].as_array()
                                            .and_then(|keys| keys.iter().find(|k| k["kid"] == kid))
                                            .and_then(|k| k["n"].as_str())
                                        .ok_or_else(|| "Key not found".to_string())?;

                                        let e = response["keys"].as_array()
                                            .and_then(|keys| keys.iter().find(|k| k["kid"] == kid))
                                            .and_then(|k| k["e"].as_str())
                                            .ok_or_else(|| "Exponent not found".to_string())?;
                                        // Create a decoding key from RSA components (n, e)
                                        let key = DecodingKey::from_rsa_components(n, e)?;
                                        *GOOGLE_KEY_CACHE.write().await = Some(key);
                                    };
                                    if let Some(key) = GOOGLE_KEY_CACHE.read().await.clone() {
                                        Ok(key)
                                    } else {
                                        Err("Internal error - Google key should be cached already".into())
                                    }
                                }

                                // Set up validation (check audience and issuer)
                                let client_id = broker_config.google_auth.as_ref().map(|c| c.client_id.as_str())
                                    .ok_or_else(|| "No client ID found in configuration".to_string())?;
                                let mut validation = Validation::new(Algorithm::RS256);
                                validation.set_audience(&[client_id]);
                                validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

                                // Try with cached key first
                                let decoding_key = get_google_decoding_key(&kid, false).await?;
                                let token_data = {
                                        // Try to verify with cached key
                                        match decode::<GoogleClaims>(token, &decoding_key, &validation) {
                                            Ok(data) => data,
                                            Err(_) => {
                                                // Cached key failed, fetch new key and retry
                                                let decoding_key = get_google_decoding_key(&kid, true).await?;
                                                // Retry verification with new key
                                                decode::<GoogleClaims>(token, &decoding_key, &validation)?
                                            }
                                        }
                                };
                                Ok(token_data.claims)
                            }
                            match verify_google_token(access_token, broker_config.clone()).await {
                                Ok(claims) => {
                                    let Some(google_auth_config) = &broker_config.google_auth else {
                                        frame_writer.send_error(resp_meta, "Google auth is not configured on this broker.").or(frame_write_timeout()).await?;
                                        continue 'login_loop;
                                    };

                                    let user = claims.email;
                                    let user_mapping = &google_auth_config.user_mapping;

                                    let Some(broker_mapped_groups) = user_mapping.get(&user)
                                        .or_else(|| user_mapping.get("*")) else {
                                            frame_writer.send_error(resp_meta, "No relevant user mapping found.").or(frame_write_timeout()).await?;
                                            continue 'login_loop;
                                        };

                                    let result = make_map!("clientId" => peer_id);
                                    frame_writer.send_result(resp_meta.clone(), result.into()).or(frame_write_timeout()).await?;

                                    let mut mapped_groups = vec![user.clone()];
                                    mapped_groups.extend(broker_mapped_groups.iter().cloned());
                                    broker_writer.send(BrokerCommand::SetOAuth2Groups { peer_id, groups: mapped_groups}).await?;

                                    break 'login_loop (user, params.get("options").cloned());
                                }
                                Err(e) => {
                                    frame_writer.send_error(resp_meta, &format!("Failed to verify Google token: {}", e)).or(frame_write_timeout()).await?;
                                    continue 'login_loop;
                                }
                            }
                        }
                    }

                    if login_type == "TOKEN" || login_type == "AZURE" {
                        #[cfg(not(feature = "entra-id"))]
                        {
                            frame_writer.send_error(resp_meta, "Entra ID login is not supported on this broker.").or(frame_write_timeout()).await?;
                            continue 'login_loop;
                        }
                        #[cfg(feature = "entra-id")]
                        {
                            use std::collections::HashSet;

                            const AZURE_TOKEN_PREFIX: &str = "oauth2-azure:";
                            let access_token = if login_type == "AZURE" {
                                password
                            } else if let Some(access_token) = password.strip_prefix(AZURE_TOKEN_PREFIX) {
                                access_token
                            } else {
                                frame_writer.send_error(resp_meta, "Unsupported token type.").or(frame_write_timeout()).await?;
                                continue 'login_loop;
                            };

                            let Some(azure_config) = &broker_config.azure else {
                                frame_writer.send_error(resp_meta, "Azure is not configured on this broker.").or(frame_write_timeout()).await?;
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
                                .map(|group| group.id)
                                .collect::<HashSet<_>>();

                            let mut mapped_groups = azure_config.group_mapping
                                .iter()
                                .filter_map(|(native_group, shv_groups)| groups_from_azure.contains(native_group).then_some(shv_groups.clone()))
                                .flatten()
                                .collect::<Vec<_>>();


                            if mapped_groups.is_empty() {
                                peer_log!(warn, target: "Azure", "no relevant groups in Azure");
                                frame_writer.send_error(resp_meta, "No relevant Azure groups found.").or(frame_write_timeout()).await?;
                                continue 'login_loop;
                            }

                            peer_log!(debug, target: "Azure", "azure_groups: {mapped_groups:?}");
                            let result = make_map!("clientId" => peer_id);
                            frame_writer.send_result(resp_meta.clone(), result.into()).or(frame_write_timeout()).await?;
                            let user = me_response.mail;
                            mapped_groups.insert(0, user.clone());
                            broker_writer.send(BrokerCommand::SetOAuth2Groups { peer_id, groups: mapped_groups}).await?;
                            break 'login_loop (user, params.get("options").cloned());
                        }
                    }

                    let user = login.get("user").ok_or("User login param is missing")?.as_str().to_string();

                    broker_writer.send(BrokerCommand::CheckAuth {
                        peer_id,
                        ip_addr,
                        sender: peer_writer.clone(),
                        user: user.as_str().to_string(),
                        password: password.to_string(),
                        nonce: nonce.clone(),
                        login_type: login_type.to_string(),
                    }).await?;
                    match peer_reader.recv().await? {
                        BrokerToPeerMessage::AuthResult(result) => {
                            if result {
                                peer_log!(debug, "password OK");
                                let result = make_map!{"clientId" => peer_id};
                                frame_writer.send_result(resp_meta, result.into()).or(frame_write_timeout()).await?;
                                break 'login_loop (user, params.get("options").cloned());
                            } else {
                                peer_log!(warn, "invalid login credentials, user: {user}");
                                frame_writer.send_error(resp_meta, "Invalid login credentials.").or(frame_write_timeout()).await?;
                                continue 'login_loop;
                            }
                        }
                        _ => {
                            panic!("Internal error, PeerEvent::AuthResult expected");
                        }
                    }
                },
                _ => {
                    frame_writer.send_error(resp_meta, "Invalid login message.").or(frame_write_timeout()).await?;
                }
            }
        };

        let options = options.as_ref().map(RpcValue::as_map);

        let device_options = options.and_then(|map| map.get("device"));
        let idle_watchdog_timeout = options
            .and_then(|options| options.get("idleWatchDogTimeOut"))
            .map(RpcValue::as_u64)
            .filter(|idle_timeout| *idle_timeout > 0)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(IDLE_WATCHDOG_TIMEOUT_DEFAULT));

        let device_id = device_options.and_then(|device_options|device_options.get("deviceId")).map(|v| v.as_str().to_string());
        let mount_point = device_options.and_then(|device_options|device_options.get("mountPoint")).map(|v| v.as_str().to_string());
        peer_log!(info, "login success (username: '{user}', deviceId: '{device_id:?}', mountPoint: '{mount_point:?}', idle timeout: {idle_watchdog_timeout:?})");
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
                sender: peer_writer
            }).await?;

        let (frames_tx, mut frames_rx) = futures::channel::mpsc::unbounded();
        let frame_writer_task = smol::spawn(async move {
            while let Some(frame) = frames_rx.next().await {
                if let Err(e) = frame_writer.send_frame(frame).or(frame_write_timeout()).await {
                    peer_log!(error, "RpcFrame send failed: {e}");
                    return Err((e, frame_writer));
                }
            }
            Ok(frame_writer)
        });

        let mut fut_receive_frame = Box::pin(frame_reader.receive_frame().or(frame_read_timeout(idle_watchdog_timeout)).fuse());
        let mut fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
        loop {
            select! {
                frame = fut_receive_frame => {
                    match frame {
                        Ok(frame) => {
                            if frame.protocol == Protocol::ResetSession {
                                // delete peer state
                                broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
                                drop(frames_tx);
                                match frame_writer_task.await {
                                    Ok(writer) => {
                                        frame_writer = writer;
                                        continue 'session_loop;
                                    }
                                    Err(_) => break 'session_loop,
                                }
                            }
                            let mut frame = frame;
                            if frame.is_request() && let Some(req_user_id) = frame.user_id() {
                                let broker_id = broker_config.name.as_ref()
                                    .map(|name| format!(":{name}"))
                                    .unwrap_or_default();
                                let user_id_chain = format!("{req_user_id};{user}{broker_id}");
                                frame.set_user_id(&user_id_chain);
                            }
                            broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame }).await?;
                        }
                        Err(err) => {
                            let meta_rpc_error = match &err {
                                ReceiveFrameError::Timeout(Some(meta)) if meta.is_request() => {
                                    Some((meta, RpcError::new(RpcErrorCode::MethodCallTimeout, "Request receive timeout")))
                                }
                                ReceiveFrameError::Timeout(Some(meta)) if meta.is_response() => {
                                    Some((meta, RpcError::new(RpcErrorCode::MethodCallTimeout, "Response receive timeout")))
                                }
                                ReceiveFrameError::Timeout(None) => {
                                    peer_log!(info, "Peer receive frame idle timeout expired after {idle_watchdog_timeout:?}");
                                    None
                                }
                                ReceiveFrameError::FrameTooLarge(reason, Some(meta)) => {
                                    Some((meta, RpcError::new(RpcErrorCode::MethodCallException, reason)))
                                }
                                _ => {
                                    None
                                }
                            };
                            if let Some((meta, rpc_error)) = meta_rpc_error {
                                if meta.is_request() && let Ok(mut rpc_msg) = RpcMessage::prepare_response_from_meta(meta) {
                                    // Send an error response back to the caller
                                    rpc_msg.set_error(rpc_error);
                                    frames_tx.unbounded_send(rpc_msg.to_frame()?)?;
                                } else if meta.is_response() {
                                    // Forward the error response to the request caller
                                    let mut rpc_msg = RpcMessage::from_meta(meta.clone());
                                    rpc_msg.set_error(rpc_error);
                                    broker_writer.send(BrokerCommand::FrameReceived { peer_id, frame: rpc_msg.to_frame()? }).await?;
                                }
                            } else {
                                peer_log!(debug, "Peer receive frame error: {err}");
                                drop(frames_tx);
                                frame_writer_task.await.ok();
                                break 'session_loop;
                            }
                        }
                    }
                    drop(fut_receive_frame);
                    fut_receive_frame = Box::pin(frame_reader.receive_frame().or(frame_read_timeout(idle_watchdog_timeout)).fuse());
                }
                event = fut_receive_broker_event => match event {
                    Err(e) => {
                        // Broker should always disconnect us via DisconnectByBroker.
                        peer_log!(error, "BrokerToPeer channel closed unexpectedly: {e}");
                        drop(frames_tx);
                        frame_writer_task.await.ok();
                        break 'session_loop;
                    }
                    Ok(event) => {
                        match event {
                            BrokerToPeerMessage::AuthResult(_) => {
                                panic!("AuthResult cannot be received here")
                            }
                            BrokerToPeerMessage::DisconnectByBroker {reason} => {
                                peer_log!(info, "disconnected by broker");
                                if let Some(reason) = reason {
                                    frames_tx.unbounded_send(RpcMessage::new_signal("", "disconnectbybroker").with_param(reason).to_frame().unwrap())?
                                }
                                drop(frames_tx);
                                frame_writer_task.await.ok();
                                Timer::after(Duration::from_secs(1)).await;
                                break 'session_loop;
                            }
                            BrokerToPeerMessage::SendFrame(frame) => {
                                frames_tx.unbounded_send(frame)?
                            }
                        }
                        fut_receive_broker_event = Box::pin(peer_reader.recv()).fuse();
                    }
                }
            }
        }
    }

    peer_log!(info, "peer gone");
    Ok(())
}

fn build_tls_connector(url: &url::Url) -> shvrpc::Result<futures_rustls::TlsConnector> {
    let crypto_provider = Arc::new(futures_rustls::rustls::crypto::aws_lc_rs::default_provider());
    if let Some((_, ca_path)) = url.query_pairs().find(|(k, _)| k == "ca") {
        let ca_certs = load_certs(&ca_path)?;
        let mut root_store = futures_rustls::rustls::RootCertStore::empty();
        root_store.add_parsable_certificates(ca_certs);
        let client_config = TlsClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(futures_rustls::TlsConnector::from(Arc::new(client_config)))
    } else {
        let client_config = TlsClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()?
            .with_platform_verifier()?
            .with_no_client_auth();
        Ok(futures_rustls::TlsConnector::from(Arc::new(client_config)))
    }
}

pub(crate) async fn broker_as_client_peer_loop_with_reconnect(
    peer_id: PeerId,
    config: BrokerConnectionConfig,
    broker_writer: Sender<BrokerCommand>,
) -> shvrpc::Result<()> {
    info!("Spawning broker peer connection loop: {}", config.name);

    let reconnect_interval = config.client.reconnect_interval.unwrap_or_else(|| {
        const DEFAULT_RECONNECT_INTERVAL_SEC: u64 = 10;
        info!("Parent broker connection reconnect interval is not set explicitly, default value {DEFAULT_RECONNECT_INTERVAL_SEC} will be used.");
        std::time::Duration::from_secs(DEFAULT_RECONNECT_INTERVAL_SEC)
    });
    info!("Reconnect interval set to: {reconnect_interval:?}");

    let tls = if config.client.url.scheme() == "ssl" {
        Some((Arc::new(build_tls_connector(&config.client.url)?), futures_rustls::pki_types::ServerName::try_from(config.client.url.host_str().unwrap_or_default())?.to_owned()))
    } else {
        None
    };

    loop {
        info!("Connecting to broker peer id: {peer_id} with url: {}", config.client.url);
        match broker_as_client_peer_loop_from_url(
            peer_id,
            config.clone(),
            broker_writer.clone(),
            tls.clone(),
        ).await {
            Ok(_) => info!("Peer broker loop finished without error"),
            Err(err) => error!("Peer broker loop finished with error: {err}"),
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

async fn broker_as_client_peer_loop_from_url(
    peer_id: PeerId,
    config: BrokerConnectionConfig,
    broker_writer: Sender<BrokerCommand>,
    tls: Option<(Arc<futures_rustls::TlsConnector>, futures_rustls::pki_types::ServerName<'static>)>,
) -> shvrpc::Result<()> {
    let url = &config.client.url;
    let scheme = url.scheme();

    async fn setup_stream_and_run<S>(
        peer_id: PeerId,
        config: BrokerConnectionConfig,
        broker_writer: Sender<BrokerCommand>,
        stream: S,
    ) -> shvrpc::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = stream.split();

        let brd = BufReader::new(reader);
        let bwr = BufWriter::new(writer);

        let frame_reader = StreamFrameReader::new(brd).with_peer_id(peer_id);
        let frame_writer = StreamFrameWriter::new(bwr).with_peer_id(peer_id);

        broker_as_client_peer_loop(
            peer_id,
            login_params_from_client_config(&config.client),
            config.connection_kind,
            false,
            broker_writer,
            frame_reader,
            frame_writer,
        ).await
    }

    match scheme {
        "tcp" => {
            let (host, port) = (url.host_str().unwrap_or_default(), url.port().unwrap_or(3755));
            let address = format!("{host}:{port}");
            info!("Connecting to TCP broker peer: {address}");
            let stream = TcpStream::connect(&address).await?;
            setup_stream_and_run(peer_id, config, broker_writer, stream).await
        }
        "ssl" => {
            let (host, port) = (url.host_str().unwrap_or_default(), url.port().unwrap_or(3756));
            let address = format!("{host}:{port}");
            info!("Connecting to SSL broker peer: {address}");
            let (connector, server_name) = tls
                .ok_or("TLS connector not initialized")?;
            let stream = TcpStream::connect(&address).await?;
            let stream = connector
                .connect(server_name, stream)
                .await?;
            setup_stream_and_run(peer_id, config, broker_writer, stream).await
        }
        "serial" => {
            let port_name = url.path();
            info!("Connecting to serial broker peer: {port_name}");
            let (frame_reader, frame_writer) = create_serial_frame_reader_writer(port_name, peer_id)?;
            broker_as_client_peer_loop(
                peer_id,
                login_params_from_client_config(&config.client),
                config.connection_kind,
                true,
                broker_writer,
                frame_reader,
                frame_writer,
            ).await
        }
        _ => Err(format!("Scheme {scheme} is not supported yet.").into()),
    }
}

pub(crate) fn login_params_from_client_config(client_config: &ClientConfig) -> LoginParams {
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


#[cfg(feature = "can")]
pub(crate) async fn can_interface_task(can_interface_config: crate::brokerimpl::CanInterfaceConfig, broker_sender: Sender<BrokerCommand>, broker_config: SharedBrokerConfig) -> shvrpc::Result<()> {
    let can_iface = &can_interface_config.interface;

    use std::collections::HashMap;
    use futures::channel::mpsc::UnboundedSender;
    use futures::stream::FuturesUnordered;
    use socketcan::CanFdFrame;
    use smol::Task;
    use crate::brokerimpl::next_peer_id;
    use crate::brokerimpl::CanConnectionConfig;

    use shvrpc::canrw::{
        ShvCanFrame,
        AckFrame as ShvCanAckFrame,
        DataFrame as ShvCanDataFrame,
        CanFrameReader,
        CanFrameWriter,
        TerminateFrame as ShvCanTerminateFrame,
    };

    struct PeerChannels {
        writer_ack_tx: UnboundedSender<ShvCanAckFrame>,
        reader_frames_tx: UnboundedSender<ShvCanDataFrame>,
    }
    #[derive(Copy, Clone, PartialEq, Eq, Hash)]
    struct PeerLocalAddr {
        peer_addr: u8,
        local_addr: u8,
    }

    let mut peers_channels = HashMap::<PeerLocalAddr, PeerChannels>::new();
    let mut client_peer_tasks: FuturesUnordered<Task<(PeerId, PeerLocalAddr, shvrpc::Result<()>)>> = FuturesUnordered::new();
    let mut server_peer_tasks: FuturesUnordered<Task<(PeerId, PeerLocalAddr, shvrpc::Result<()>)>> = FuturesUnordered::new();

    let (writer_frames_tx, mut writer_frames_rx) = futures::channel::mpsc::unbounded();
    let (reader_ack_tx, mut reader_ack_rx) = futures::channel::mpsc::unbounded();

    fn run_broker_client_peer_task(
        connection_config: &CanConnectionConfig,
        tasks: &mut FuturesUnordered<Task<(PeerId, PeerLocalAddr, shvrpc::Result<()>)>>,
        channels: &mut HashMap::<PeerLocalAddr, PeerChannels>,
        broker_sender: Sender<BrokerCommand>,
        writer_frames_tx: UnboundedSender<ShvCanDataFrame>,
        reader_ack_tx: UnboundedSender<ShvCanAckFrame>,
    ) {
        let peer_id = next_peer_id();
        let peer_addr = connection_config.peer_address;
        let local_addr = connection_config.local_address;
        info!("Connecting to CAN broker, peer id: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}");
        let (writer_ack_tx, writer_ack_rx) = futures::channel::mpsc::unbounded();
        let (reader_frames_tx, reader_frames_rx) = futures::channel::mpsc::unbounded();
        let peer_local_addr = PeerLocalAddr { peer_addr, local_addr };
        channels.insert(peer_local_addr, PeerChannels { writer_ack_tx, reader_frames_tx });
        let login_params = connection_config.login_params.clone();
        let connection_kind = connection_config.connection_kind.clone();
        tasks.push(smol::spawn(async move {
            let frame_reader = CanFrameReader::new(reader_frames_rx, reader_ack_tx, peer_id, peer_addr);
            let frame_writer = CanFrameWriter::new(writer_frames_tx, writer_ack_rx, peer_id, peer_addr, local_addr);
            let res = broker_as_client_peer_loop(
                peer_id,
                login_params,
                connection_kind,
                true,
                broker_sender,
                frame_reader,
                frame_writer,
            ).await;
            (peer_id, peer_local_addr, res)
        }));
    }

    #[allow(clippy::too_many_arguments)]
    fn run_broker_server_peer_task(
        peer_local_addr: PeerLocalAddr,
        init_frame: ShvCanDataFrame,
        broker_config: SharedBrokerConfig,
        tasks: &mut FuturesUnordered<Task<(PeerId, PeerLocalAddr, shvrpc::Result<()>)>>,
        channels: &mut HashMap::<PeerLocalAddr, PeerChannels>,
        broker_sender: Sender<BrokerCommand>,
        writer_frames_tx: UnboundedSender<ShvCanDataFrame>,
        reader_ack_tx: UnboundedSender<ShvCanAckFrame>,
    ) {
        let peer_id = next_peer_id();
        let PeerLocalAddr { peer_addr, local_addr } = peer_local_addr;
        info!("Starting CAN broker peer task, peer id: {peer_id} peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}");
        let (writer_ack_tx, writer_ack_rx) = futures::channel::mpsc::unbounded();
        let (reader_frames_tx, reader_frames_rx) = futures::channel::mpsc::unbounded();
        reader_frames_tx.unbounded_send(init_frame).ok();
        channels.insert(peer_local_addr, PeerChannels { writer_ack_tx, reader_frames_tx });
        tasks.push(smol::spawn(async move {
            let frame_reader = CanFrameReader::new(reader_frames_rx, reader_ack_tx, peer_id, peer_addr);
            let frame_writer = CanFrameWriter::new(writer_frames_tx, writer_ack_rx, peer_id, peer_addr, local_addr);
            let res = server_peer_loop(peer_id, None, broker_sender, frame_reader, frame_writer, broker_config).await;
            (peer_id, peer_local_addr, res)
        }));
    }

    async fn send_terminate_frame(can_iface: &str, socket: &socketcan::smol::CanFdSocket, peer_local_addr: PeerLocalAddr) -> shvrpc::Result<()> {
        let terminate_frame = ShvCanTerminateFrame::new(peer_local_addr.local_addr, peer_local_addr.peer_addr);
        let fd_frame = match CanFdFrame::try_from(&terminate_frame) {
            Ok(fd_frame) => fd_frame,
            Err(err) => {
                return Err(format!("Cannot convert SHV CAN TerminateFrame to FD frame: {err}, frame: {terminate_frame:?}").into());
            }
        };
        debug!(target: "shvcan", "{can_iface} SEND: {frame}", frame = ShvCanFrame::Terminate(terminate_frame).to_brief_string());
        socket
            .write_frame(&fd_frame)
            .await
            .unwrap_or_else(|e| warn!("Cannot send CAN FD frame: {e}, frame: {fd_frame:?}"));
        Ok(())
    }

    info!("Setting up CAN interface {can_iface}");
    info!("  listen addrs: {listen_addrs}", listen_addrs = can_interface_config
        .listen_addrs
        .iter()
        .map(|a| format!("0x{a:x}"))
        .collect::<Vec<_>>()
        .join(", ")
    );
    info!("  connections: {connections}", connections = can_interface_config
        .connections
        .iter()
        .map(|cfg| format!("0x{local:x}->0x{peer:x}", local = cfg.local_address, peer = cfg.peer_address))
        .collect::<Vec<_>>()
        .join(", ")
    );

    for connection_config in &can_interface_config.connections {
        run_broker_client_peer_task(
            connection_config,
            &mut client_peer_tasks,
            &mut peers_channels,
            broker_sender.clone(),
            writer_frames_tx.clone(),
            reader_ack_tx.clone()
        );
    }

    let (reconnect_tx, mut reconnect_rx) = futures::channel::mpsc::unbounded();

    'init_iface: loop {
        let socket = socketcan::smol::CanFdSocket::open(can_iface)
            .map_err(|err| format!("Cannot open CAN interface {can_iface}: {err}"))?;
        let socket = Arc::new(socket);

        let mut frames = pin!(futures::stream::unfold(socket.clone(), |sock| async move {
            let frame_res = sock.read_frame().await;
            Some((frame_res, sock))
        }));

        let time_broadcast_interval: std::pin::Pin<Box<dyn futures::Stream<Item = ()> + Send>>  = if broker_config.time_broadcast {
            Box::pin(futures::StreamExt::map(Timer::interval(Duration::from_secs(60)), |_| ()))
        } else {
            Box::pin(futures::stream::empty())
        };
        let mut time_broadcast_interval = time_broadcast_interval.fuse();
        let mut time_broadcast_error = false;

        loop {
            use socketcan::id::FdFlags;

            futures::select! {
                maybe_frame = frames.select_next_some() => {
                    match maybe_frame {
                        Ok(frame) => {
                            match frame {
                                socketcan::CanAnyFrame::Fd(fd_frame)  => {
                                    let Ok(shvcan_frame) = ShvCanFrame::try_from(&fd_frame) else {
                                        continue
                                    };

                                    let header = shvcan_frame.header();
                                    let (peer_addr, local_addr) = (header.src(), header.dst());
                                    let peer_local_addr = PeerLocalAddr { peer_addr, local_addr };

                                    if let std::collections::hash_map::Entry::Occupied(entry) = peers_channels.entry(peer_local_addr) {
                                        debug!(target: "shvcan", "{can_iface} RECV: {frame}", frame = shvcan_frame.to_brief_string());
                                        let peer_channels = entry.get();
                                        match shvcan_frame {
                                            ShvCanFrame::Data(data_frame) => {
                                                peer_channels
                                                    .reader_frames_tx
                                                    .unbounded_send(data_frame)
                                                    .unwrap_or_else(|e| warn!("Cannot send a Data frame to peer task 0x{peer_addr:x}->0x{local_addr:x}: {e}"));
                                                }
                                            ShvCanFrame::Ack(ack_frame) => {
                                                peer_channels
                                                    .writer_ack_tx
                                                    .unbounded_send(ack_frame)
                                                    .unwrap_or_else(|e| warn!("Cannot send an ACK frame to peer task 0x{peer_addr:x}->0x{local_addr:x}: {e}"));
                                                }
                                            ShvCanFrame::Terminate(_terminate_frame) => {
                                                entry.remove();
                                            }
                                        }
                                    } else {
                                        let ShvCanFrame::Data(data_frame) = shvcan_frame else {
                                            continue
                                        };
                                        if !can_interface_config.listen_addrs.contains(&local_addr)
                                            || can_interface_config.connections.iter().any(|conn_cfg| conn_cfg.local_address == local_addr && conn_cfg.peer_address == peer_addr)
                                        {
                                            continue
                                        }
                                        debug!(target: "shvcan", "{can_iface} RECV (new server peer): {frame}", frame = ShvCanFrame::Data(data_frame.clone()).to_brief_string());
                                        run_broker_server_peer_task(
                                            PeerLocalAddr { peer_addr, local_addr },
                                            data_frame,
                                            broker_config.clone(),
                                            &mut server_peer_tasks,
                                            &mut peers_channels,
                                            broker_sender.clone(),
                                            writer_frames_tx.clone(),
                                            reader_ack_tx.clone()
                                        );
                                    }
                                }
                                socketcan::CanAnyFrame::Normal(can_normal_frame) => {
                                    // Ignore non-FD frames
                                    debug!("CAN 2.0 frame received on {can_iface}: {can_normal_frame:?}");
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
                _ = time_broadcast_interval.select_next_some() => {
                    static CAN_ID_UTC_TIME: std::sync::LazyLock<socketcan::CanId> = std::sync::LazyLock::new(|| socketcan::CanId::standard(0x04).expect("Time broadcast CAN ID should be valid"));

                    fn to_string<E: std::fmt::Display>(e: E) -> String {
                        e.to_string()
                    }
                    let system_time_ms = match std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(to_string)
                        .and_then(|d| u64::try_from(d.as_millis()).map_err(to_string))
                    {
                        Ok(ms) => {
                            if time_broadcast_error {
                                info!("System time has been fixed, resuming CAN time broadcast on {can_iface}");
                                time_broadcast_error = false;
                            }
                            ms
                        }
                        Err(err) => {
                            if !time_broadcast_error {
                                error!("Invalid system time, CAN time broadcast will not be sent on {can_iface}: {err}");
                                time_broadcast_error = true;
                            }
                            continue
                        }
                    };

                    let Some(frame) = socketcan::CanFdFrame::with_flags(*CAN_ID_UTC_TIME, &system_time_ms.to_be_bytes(), FdFlags::BRS | FdFlags::FDF) else {
                        error!("Cannot create time broadcast CAN frame");
                        continue;
                    };
                    debug!(target: "shvcan", "{can_iface} SEND time broadcast: {frame:?}");
                    socket.write_frame(&frame)
                        .await
                        .unwrap_or_else(|e| warn!("Cannot send time broadcast CAN frame: {e}, frame: {frame:?}"));
                }
                data_frame = writer_frames_rx.select_next_some() => {
                    let fd_frame = match CanFdFrame::try_from(&data_frame) {
                        Ok(fd_frame) => fd_frame,
                        Err(err) => {
                            error!("Cannot convert SHV CAN DataFrame to FD frame: {err}, frame: {data_frame:?}");
                            continue
                        }
                    };
                    debug!(target: "shvcan", "{can_iface} SEND: {frame}", frame = ShvCanFrame::Data(data_frame).to_brief_string());
                    socket
                        .write_frame(&fd_frame)
                        .await
                        .unwrap_or_else(|e| warn!("Cannot send CAN FD frame: {e}, frame: {fd_frame:?}"));
                }
                ack_frame = reader_ack_rx.select_next_some() => {
                    let fd_frame = match CanFdFrame::try_from(&ack_frame) {
                        Ok(fd_frame) => fd_frame,
                        Err(err) => {
                            error!("Cannot convert SHV CAN AckFrame to FD frame: {err}, frame: {ack_frame:?}");
                            continue
                        }
                    };
                    debug!(target: "shvcan", "{can_iface} SEND: {frame}", frame = ShvCanFrame::Ack(ack_frame).to_brief_string());
                    socket
                        .write_frame(&fd_frame)
                        .await
                        .unwrap_or_else(|e| warn!("Cannot send CAN FD frame: {e}, frame: {fd_frame:?}"));
                }
                (peer_id, peer_local_addr, result) = server_peer_tasks.select_next_some() => {
                    let PeerLocalAddr { peer_addr, local_addr } = peer_local_addr;
                    match result {
                        Ok(_) => info!("Broker CAN peer task finished OK, peer ID: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}"),
                        Err(err) => warn!("Broker CAN peer task finished with ERROR, peer ID: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}, err: {err}"),
                    }
                    // Send the Terminate message to the peer if the task has
                    // been terminated from within the broker
                    if peers_channels.remove(&peer_local_addr).is_some()
                        && let Err(err) = send_terminate_frame(can_iface, &socket, peer_local_addr).await {
                            error!("Cannot send Terminate frame: {err}");
                            continue
                    }
                    broker_sender.send(BrokerCommand::PeerGone { peer_id }).await?;
                }
                (peer_id, peer_local_addr, result) = client_peer_tasks.select_next_some() => {
                    let PeerLocalAddr { peer_addr, local_addr } = peer_local_addr;
                    match result {
                        Ok(_) => info!("Broker CAN peer task finished OK, peer ID: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}"),
                        Err(err) => warn!("Broker CAN peer task finished with ERROR, peer ID: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x}, err: {err}"),
                    }
                    // Send the Terminate message to the peer if the task has
                    // been terminated from within the broker
                    if peers_channels.remove(&peer_local_addr).is_some()
                        && let Err(err) = send_terminate_frame(can_iface, &socket, peer_local_addr).await {
                            error!("Cannot send Terminate frame: {err}");
                            continue
                    }
                    broker_sender.send(BrokerCommand::PeerGone { peer_id }).await?;
                    if let Some(connection_cfg) = can_interface_config.connections.iter().find(|cfg| cfg.peer_address == peer_addr && cfg.local_address == local_addr) {
                        let reconnect_interval = connection_cfg.reconnect_interval;
                        info!("Reconnecting to CAN broker, peer id: {peer_id}, peer address: 0x{peer_addr:x}, local address: 0x{local_addr:x} after {reconnect_interval:?}");
                        let reconnect_tx = reconnect_tx.clone();
                        let connection_cfg = connection_cfg.clone();
                        smol::spawn(async move {
                            smol::Timer::after(reconnect_interval).await;
                            reconnect_tx.unbounded_send(connection_cfg).ok();
                        }).detach();
                    }
                }
                connection_cfg = reconnect_rx.select_next_some() => {
                    run_broker_client_peer_task(
                        &connection_cfg,
                        &mut client_peer_tasks,
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

async fn broker_as_client_peer_loop(
    peer_id: PeerId,
    login_params: LoginParams,
    connection_kind: ConnectionKind,
    reset_session: bool,
    broker_writer: Sender<BrokerCommand>,
    mut frame_reader: impl FrameReader + Send,
    mut frame_writer: impl FrameWriter + Send + 'static,
) -> shvrpc::Result<()>
{
    let heartbeat_interval = login_params.heartbeat_interval;
    info!("Heartbeat interval set to: {:?}", &heartbeat_interval);

    let login_timeout = async move {
        const LOGIN_TIMEOUT: u64 = 10;
        let timeout = Duration::from_secs(LOGIN_TIMEOUT);
        Timer::after(timeout).await;
        Err(format!("login timeout after {timeout_str}", timeout_str = timeout.human_format()).into())
    };
    client::login(&mut frame_reader, &mut frame_writer, &login_params, reset_session).or(login_timeout).await?;

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

    let mut frames_stream = pin!(futures::stream::unfold(frame_reader, async |mut reader| {
        let idle_read_timeout = login_params.heartbeat_interval * 3;
        let frame_res = reader
            .receive_frame()
            .or(frame_read_timeout(idle_read_timeout))
            .await;
        Some((frame_res, reader))
    }));

    let mut fut_receive_broker_event = Box::pin(broker_to_peer_receiver.recv()).fuse();
    let make_timeout = || {
        FutureExt::fuse(Box::pin(smol::Timer::after(heartbeat_interval)))
    };

    let (frames_tx, mut frames_rx) = futures::channel::mpsc::unbounded();
    smol::spawn(async move {
        while let Some(frame) = frames_rx.next().await {
            if let Err(e) = frame_writer.send_frame(frame).await {
                log::debug!("frame send failed: {}", e);
                return Err((e, frame_writer));
            }
        }
        Ok(frame_writer)
    }).detach();

    let mut fut_timeout = make_timeout();
    loop {
        select! {
            _ = fut_timeout => {
                // send heartbeat
                let msg = RpcMessage::new_request(".app", METH_PING);
                debug!("sending ping");
                frames_tx.unbounded_send(msg.to_frame()?)?;
                fut_timeout = make_timeout();
            },
            res_frame = frames_stream.select_next_some() => match res_frame {
                Ok(frame) => {
                    if frame.is_error()
                        && let Ok(msg) = frame.to_rpcmesage()
                        && msg.error().is_some_and(|err| err.code == RpcErrorCode::LoginRequired.into())
                    {
                        // With connectionless transport protocols (CAN, serial) the
                        // LoginRequired error means that the session is no longer alive on
                        // the peer side and we need to reset the session on ours.
                        return Err("The peer sent 'Login required' error message".into());
                    }
                    process_broker_client_peer_frame(peer_id, frame, &connection_kind, broker_writer.clone()).await?;
                }
                Err(err) => {
                    let (meta, rpc_error) = match &err {
                        ReceiveFrameError::Timeout(Some(meta)) if meta.is_request() => {
                            (meta, RpcError::new(RpcErrorCode::MethodCallTimeout, "Request receive timeout"))
                        }
                        ReceiveFrameError::Timeout(Some(meta)) if meta.is_response() => {
                            (meta, RpcError::new(RpcErrorCode::MethodCallTimeout, "Response receive timeout"))
                        }
                        ReceiveFrameError::FrameTooLarge(reason, Some(meta)) => {
                            (meta, RpcError::new(RpcErrorCode::MethodCallException, reason))
                        }
                        _ => return Err(format!("Receive frame error: {err}").into()),
                    };
                    if meta.is_request() && let Ok(mut msg) = RpcMessage::prepare_response_from_meta(meta) {
                        // Send the error response back to the caller
                        msg.set_error(rpc_error);
                        frames_tx.unbounded_send(msg.to_frame()?)?;
                    } else if meta.is_response() {
                        // Forward the error response to the request caller
                        let mut msg = RpcMessage::from_meta(meta.clone());
                        msg.set_error(rpc_error);
                        process_broker_client_peer_frame(peer_id, msg.to_frame()?, &connection_kind, broker_writer.clone()).await?;
                    } else {
                        return Err(format!("Receive frame error: {err}").into());
                    }
                }
            },
            event = fut_receive_broker_event => match event {
                Err(e) => {
                    debug!("broker loop has closed peer channel, client ID {peer_id}");
                    return Err(e.into());
                }
                Ok(event) => {
                    match event {
                        BrokerToPeerMessage::AuthResult(_) => {
                            panic!("AuthResult cannot be received here")
                        }
                        BrokerToPeerMessage::DisconnectByBroker {reason} => {
                            info!("Disconnected by parent broker, client ID: {peer_id}, reason: {reason:?}");
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
                            frames_tx.unbounded_send(frame)?;
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
        if let Some(method) = frame.method() && (method == METH_SUBSCRIBE || method == METH_UNSUBSCRIBE) {
            // prepend exported root to subscribed path
            let is_subscribe = method == METH_SUBSCRIBE;
            frame = fix_subscribe_param(frame, shv_root, is_subscribe)?;
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

fn fix_subscribe_param(frame: RpcFrame, exported_root: &str, is_subscribe: bool) -> shvrpc::Result<RpcFrame> {
    let mut msg = frame.to_rpcmesage()?;
    let param = msg.param().unwrap_or_default();
    let mut subpar = SubscriptionParam::from_rpcvalue(param)?;
    let new_path = join_path(exported_root, subpar.ri.path());
    subpar.ri = ShvRI::from_path_method_signal(&new_path, subpar.ri.method(), subpar.ri.signal())?;
    let new_param = if is_subscribe {
        subpar.to_rpcvalue()
    } else {
        RpcValue::from(subpar.ri.to_string())
    };
    msg.set_param(new_param);
    msg.to_frame()
}
