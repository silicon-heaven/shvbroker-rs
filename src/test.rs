use std::path::Path;

use crate::brokerimpl::BrokerImpl;
use crate::sql;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use shvproto::{Map, RpcValue};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::rpcmessage::{PeerId, Response, RpcError, RpcErrorCode, RqId};
use shvrpc::util::join_path;
use smol::channel;
use smol::channel::{Receiver, Sender};
use crate::brokerimpl::{BrokerToPeerMessage, PeerKind, BrokerCommand};
use crate::config::{AccessRule, BrokerConfig, Mount, Password, Role, SharedBrokerConfig, User};
use crate::shvnode::{METH_CHANGE_PASSWORD, METH_LS, METH_SET_VALUE, METH_SUBSCRIBE, METH_UNSUBSCRIBE, METH_VALUE};

struct CallCtx<'a> {
    writer: &'a Sender<BrokerCommand>,
    reader: &'a Receiver<BrokerToPeerMessage>,
    client_id: PeerId,
}
async fn call2(shv_path: &str, method: &str, param: Option<RpcValue>, ctx: &CallCtx<'_>, resp_rq_id: Option<RqId>) -> Result<(RqId, RpcValue), RpcError> {
    let rq = RpcMessage::new_request(shv_path, method, param);
    let rqid = if let Some(resp_rq_id) = resp_rq_id { Some(resp_rq_id) } else { rq.request_id() };
    let frame = RpcFrame::from_rpcmessage(&rq).expect("valid message");
    println!("request: {}", frame.to_rpcmesage().unwrap());
    ctx.writer.send(BrokerCommand::FrameReceived { peer_id: ctx.client_id, frame }).await.unwrap();
    let retval = loop {
        let msg = ctx.reader.recv().await.unwrap();
        let msg = match msg {
            BrokerToPeerMessage::SendFrame(frame) => { frame.to_rpcmesage().unwrap() }
            _ => {
                panic!("unexpected message: {msg:?}");
            }
        };
        if msg.request_id() == rqid {
            match msg.response() {
                Ok(response) => {
                    match response {
                        Response::Success(v) => {
                            break Ok(v.clone());
                        }
                        Response::Delay(_) => {
                            println!("ignoring delay response: {msg}");
                        }
                    }
                }
                Err(e) => {
                    println!("error response: {msg}");
                    break Err(e);
                }
            }
        } else {
            // ignore RPC requests which might be issued after subscribe call
            println!("ignoring message with different request id: {msg}");
        }
    };
    retval.map(|v| (rqid.unwrap_or_default(), v))
}

async fn call(shv_path: &str, method: &str, param: Option<RpcValue>, ctx: &CallCtx<'_>) -> Result<RpcValue, RpcError> {
    let ret = call2(shv_path, method, param, ctx, None).await;
    ret.map(|(_rqid, val)| val )
}

#[test]
fn test_broker_loop_as_user() {
    smol::block_on(test_broker_loop_as_user_async())
}
async fn test_broker_loop_as_user_async() {
    let config = BrokerConfig { use_access_db: true, ..Default::default() };
    let (sql_connection, access_config) = sql::migrate_sqlite_connection(&Path::new(":memory:").to_path_buf(), &config.access).unwrap();
    let config = SharedBrokerConfig::new(config);
    let broker = BrokerImpl::new(config, access_config, Some(sql_connection));
    let broker_sender = broker.command_sender.clone();
    let broker_task = smol::spawn(crate::brokerimpl::broker_loop(broker));

    let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();
    let client_id = 2;

    let call_ctx = CallCtx {
        writer: &broker_sender,
        reader: &peer_reader,
        client_id,
    };

    // login
    let user = "user";
    //let password = "admin";
    broker_sender.send(BrokerCommand::NewPeer {
        peer_id: client_id,
        peer_kind: PeerKind::Device{
            user: user.to_string(),
            device_id: None,
            mount_point: None,
        },
        sender: peer_writer.clone() }).await.unwrap();

    let resp = call(".broker", "ls", Some("access".into()), &call_ctx).await.unwrap();
    assert_eq!(resp, RpcValue::from(true));
    let resp = call(".broker/access/users", "ls", None, &call_ctx).await;
    // viewer cannot list users
    assert!(resp.is_err());

    // test current client info
    let resp = call(".broker/currentClient", "info", None, &call_ctx).await.unwrap();
    let m = resp.as_map();
    assert_eq!(m.get("clientId").unwrap(), &RpcValue::from(2));
    assert_eq!(m.get("mountPoint").unwrap(), &RpcValue::from(""));
    assert_eq!(m.get("userName").unwrap(), &RpcValue::from(user));
    assert_eq!(m.get("subscriptions").unwrap(), &RpcValue::from(shvproto::Map::new()));

    // subscriptions
    let subs_ri = "shv/**:*";
    let subs = SubscriptionParam { ri: ShvRI::try_from(subs_ri).unwrap(), ttl: None };
    {
        // subscribe
        let result = call(".broker/currentClient", METH_SUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await.unwrap();
        assert!(result.as_bool());
        // cannot subscribe the same twice
        let result = call(".broker/currentClient", METH_SUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await.unwrap();
        assert!(!result.as_bool());
        let resp = call(".broker/currentClient", "subscriptions", None, &call_ctx).await.unwrap();
        let subs_map = resp.as_map();
        // let s = format!("{:?}", subs_map);
        assert_eq!(subs_map.len(), 1);
        assert_eq!(subs_map.first_key_value().unwrap().0, subs_ri);
    }
    {
        call(".broker/currentClient", METH_UNSUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await.unwrap();
        let resp = call(".broker/currentClient", "info", None, &call_ctx).await.unwrap();
        let subs = resp.as_map().get("subscriptions").unwrap();
        let subs_map = subs.as_map();
        assert_eq!(subs_map.len(), 0);
    }
    {
        // change password success
        let param: RpcValue = vec![RpcValue::from("user"), "good_password".into()].into();
        let resp = call(".broker/currentClient", METH_CHANGE_PASSWORD, Some(param), &call_ctx).await.unwrap();
        assert_eq!(resp.as_int(), 1);

        // change password wrong password
        let param: RpcValue = vec![RpcValue::from("user"), "better_password".into()].into();
        let resp = call(".broker/currentClient", METH_CHANGE_PASSWORD, Some(param), &call_ctx).await;
        assert!(resp.is_err());
    }

    broker_task.cancel().await;
}

#[test]
fn test_broker_loop_as_admin() {
    smol::block_on(test_broker_loop_as_admin_async())
}
async fn test_broker_loop_as_admin_async() {
    let config = BrokerConfig { use_access_db: true, ..Default::default() };
    let (sql_connection, access_config) = sql::migrate_sqlite_connection(&Path::new(":memory:").to_path_buf(), &config.access).unwrap();
    let config = SharedBrokerConfig::new(config);
    let broker = BrokerImpl::new(config, access_config, Some(sql_connection));
    let broker_sender = broker.command_sender.clone();
    let broker_task = smol::spawn(crate::brokerimpl::broker_loop(broker));

    let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();
    let client_id = 2;

    let call_ctx = CallCtx {
        writer: &broker_sender,
        reader: &peer_reader,
        client_id,
    };

    // login
    let user = "admin";
    //let password = "admin";
    broker_sender.send(BrokerCommand::NewPeer {
        peer_id: client_id,
        peer_kind: PeerKind::Device{
            user: user.to_string(),
            device_id: None,
            mount_point: Some("test/device".to_string()),
        },
        sender: peer_writer.clone() }).await.unwrap();

    /*
    lsmod cannot be received because it is not subscribed
    loop {
        if let BrokerToPeerMessage::SendFrame(frame) = call_ctx.reader.recv().await.unwrap() {
            if frame.method() == Some(SIG_LSMOD) {
                assert_eq!(frame.shv_path(), Some("test"));
                assert_eq!(frame.source(), Some("ls"));
                let msg = frame.to_rpcmesage().unwrap();
                assert_eq!(msg.param().unwrap().as_map(), &Map::from([("device".to_string(), true.into())]));
                break
            }
        }
    }
    */
    let resp = call(".broker", "ls", Some("access".into()), &call_ctx).await.unwrap();
    assert_eq!(resp, RpcValue::from(true));
    let resp = call(".broker/access", "ls", None, &call_ctx).await.unwrap();
    assert!(resp.is_list());
    assert!(resp.as_list().iter().any(|s| s.as_str() == "mounts"));
    let resp = call(".broker/acce", "ls", None, &call_ctx).await;
    assert!(resp.is_err());

    // device should be mounted as 'shv/dev/test'
    let resp = call("test", "ls", Some("device".into()), &call_ctx).await.unwrap();
    assert_eq!(resp, RpcValue::from(true));

    // test current client info
    let resp = call(".broker/currentClient", "info", None, &call_ctx).await.unwrap();
    let m = resp.as_map();
    assert_eq!(m.get("clientId").unwrap(), &RpcValue::from(2));
    assert_eq!(m.get("mountPoint").unwrap(), &RpcValue::from("test/device"));
    assert_eq!(m.get("userName").unwrap(), &RpcValue::from(user));
    assert_eq!(m.get("subscriptions").unwrap(), &RpcValue::from(shvproto::Map::new()));

    let config = BrokerConfig::default();
    let users: Vec<_> = config.access.users.keys().map(|k| k.to_string()).collect();
    let roles: Vec<_> = config.access.roles.keys().map(|k| k.to_string()).collect();
    // access/mounts
    {
        let path = ".broker/access/mounts";
        {
            let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
            let list = resp.as_list();
            assert_eq!(list, RpcValue::from(["test-child-broker","test-device"].to_vec()).as_list());
            let resp = call(&join_path(path, "test-device"), METH_VALUE, None, &call_ctx).await.unwrap();
            let mount1 = Mount::try_from(&resp).unwrap();
            let mount2 = Mount { mount_point: "test/device".to_string(), description: "Testing device mount-point".to_string() };
            assert_eq!(mount1, mount2);
        }
        {
            let mount = Mount{ mount_point: "foo".to_string(), description: "bar".to_string() };
            call(path, METH_SET_VALUE, Some(vec!["baz".into(), mount.to_rpcvalue().unwrap()].into()), &call_ctx).await.unwrap();
            let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
            let list = resp.as_list();
            assert_eq!(list, RpcValue::from(["baz", "test-child-broker","test-device"].to_vec()).as_list());
            let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await.unwrap();
            assert_eq!(mount, Mount::try_from(&resp).unwrap());
        }

        // access/users
        {
            let path = ".broker/access/users";
            {
                let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(users.clone()).as_list());
                let resp = call(&join_path(path, "test"), METH_VALUE, None, &call_ctx).await.unwrap();
                let user1 = User::try_from(&resp).unwrap();
                let user2 = User { password: Password::Plain("test".into()), roles: vec!["tester".into()], deactivated: false };
                assert_eq!(user1, user2);
            }
            {
                let user = User { password: Password::Plain("foo".into()), roles: vec!["bar".into()], deactivated: false };
                call(path, METH_SET_VALUE, Some(vec!["baz".into(), user.to_rpcvalue().unwrap()].into()), &call_ctx).await.unwrap();
                let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
                let list = resp.as_list();
                let mut users = users;
                users.push("baz".to_string());
                users.sort();
                assert_eq!(list, RpcValue::from(users).as_list());
                let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await.unwrap();
                assert_eq!(user, User::try_from(&resp).unwrap());
            }
        }

        // access/roles
        {
            let path = ".broker/access/roles";
            {
                let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(roles.clone()).as_list());
                let resp = call(&join_path(path, "tester"), METH_VALUE, None, &call_ctx).await.unwrap();
                let role1 = Role::try_from(&resp).unwrap();
                let role2 = config.access.roles.get("tester").unwrap();
                assert_eq!(&role1, role2);
            }
            {
                let role = Role { roles: vec!["foo".into()], access: vec![AccessRule{ shv_ri: "bar/**:*".into(), grant: "cfg".into() }], profile: None };
                call(path, METH_SET_VALUE, Some(vec!["baz".into(), role.to_rpcvalue().unwrap()].into()), &call_ctx).await.unwrap();
                let resp = call(path, METH_LS, None, &call_ctx).await.unwrap();
                let list = resp.as_list();
                let mut roles = roles;
                roles.push("baz".to_string());
                roles.sort();
                assert_eq!(list, RpcValue::from(roles).as_list());
                let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await.unwrap();
                assert_eq!(role, Role::try_from(&resp).unwrap());
            }
        }
    }
    broker_task.cancel().await;
}

#[test]
fn test_tunnel_loop() {
    smol::block_on(test_tunnel_loop_async())
}
async fn test_tunnel_loop_async() {
    let mut config = BrokerConfig::default();
    config.tunnelling.enabled = true;
    let config = SharedBrokerConfig::new(config);
    let access = config.access.clone();
    let broker = BrokerImpl::new(config, access, None);
    let broker_sender = broker.command_sender.clone();
    let broker_task = smol::spawn(crate::brokerimpl::broker_loop(broker));

    let (peer_writer, peer_reader) = channel::unbounded::<BrokerToPeerMessage>();
    let client_id = 3;

    let call_ctx = CallCtx {
        writer: &broker_sender,
        reader: &peer_reader,
        client_id,
    };

    // login
    let user = "test";
    //let password = "test";
    broker_sender.send(BrokerCommand::NewPeer {
        peer_id: client_id,
        peer_kind: PeerKind::Client{ user: user.to_string() },
        sender: peer_writer.clone() }).await.unwrap();

    let tunid = call(".app/tunnel", "create", None, &call_ctx).await;
    // host param is missing
    assert!(tunid.is_err());

    let param = Map::from([("host".to_string(), "localhost:54321".into())]);
    let tunid = call(".app/tunnel", "create", Some(param.into()), &call_ctx).await;
    // service not running
    assert_eq!(tunid.err().unwrap().code, RpcErrorCode::MethodCallException.into());

    // echo loop
    const ECHO_LOOP_ADDRESS: &str = "localhost:8888";
    smol::spawn(async move {
        let listener = smol::net::TcpListener::bind(ECHO_LOOP_ADDRESS).await.unwrap();
        println!("Echo server is listening on {}", listener.local_addr().unwrap());

        while let Some(stream) = listener.incoming().next().await {
            match stream {
                Ok(mut socket) => {
                    let addr = socket.peer_addr().unwrap();
                    println!("New connection from: {addr}");

                    smol::spawn(async move {
                        let mut buffer = vec![0; 1024];

                        loop {
                            match socket.read(&mut buffer).await {
                                Ok(0) => {
                                    println!("Connection closed by client: {addr}");
                                    return;
                                }
                                Ok(n) => {
                                    if socket.write_all(&buffer[..n]).await.is_err() {
                                        println!("Failed to send data to: {addr}");
                                        return;
                                    }
                                }
                                Err(e) => {
                                    println!("Error reading from {addr}: {e}");
                                    return;
                                }
                            }
                        }
                    }).detach();
                }
                Err(e) => println!("Connection failed: {e}"),
            }
        }
    }).detach();

    // Wait for the echo loop to initialize
    async fn wait_for_server(address: &str, timeout: std::time::Duration) {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if smol::net::TcpStream::connect(address).await.is_ok() {
                return;
            }
            smol::Timer::after(std::time::Duration::from_millis(200)).await;
        }
        panic!("Could not connect to: {address}");
    }
    wait_for_server(ECHO_LOOP_ADDRESS, std::time::Duration::from_secs(3)).await;

    let param = Map::from([("host".to_string(), ECHO_LOOP_ADDRESS.into())]);
    let tunid = call(".app/tunnel", "create", Some(param.into()), &call_ctx).await.unwrap();
    assert!(tunid.is_string());

    let tunid = tunid.as_str();

    let res = call(".app/tunnel", "ls", None, &call_ctx).await.unwrap();
    assert_eq!(res.as_list(), &[tunid.into()].to_vec());
    let res = call(".app/tunnel", "ls", Some(tunid.into()), &call_ctx).await.unwrap();
    assert!(res.as_bool());

    let data = "hello".as_bytes();
    let (tun_rq_id, res) = call2(&format!(".app/tunnel/{tunid}"), "write", Some(data.into()), &call_ctx, None).await.unwrap();
    assert_eq!(res.as_blob(), data);

    let data = "tunnel".as_bytes();
    let (_, res) = call2(&format!(".app/tunnel/{tunid}"), "write", Some(data.into()), &call_ctx, Some(tun_rq_id)).await.unwrap();
    assert_eq!(res.as_blob(), data);

    let res = call(&format!(".app/tunnel/{tunid}"), "close", None, &call_ctx).await.unwrap();
    assert!(res.as_bool());

    let res = call(".app/tunnel", "ls", None, &call_ctx).await.unwrap();
    assert!(res.as_list().is_empty());

    broker_task.cancel().await;
}
