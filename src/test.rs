use crate::brokerimpl::BrokerImpl;
use async_std::channel::{Receiver, Sender};
use async_std::{channel, task};
use rusqlite::Connection;
use shvproto::{Map, RpcValue};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::rpcmessage::{PeerId, RpcError, RpcErrorCode};
use shvrpc::util::join_path;
use crate::brokerimpl::{BrokerToPeerMessage, PeerKind, BrokerCommand};
use crate::config::{AccessRule, BrokerConfig, Mount, Password, Role, User};
use crate::shvnode::{METH_LS, METH_SET_VALUE, METH_SUBSCRIBE, METH_UNSUBSCRIBE, METH_VALUE};

struct CallCtx<'a> {
    writer: &'a Sender<BrokerCommand>,
    reader: &'a Receiver<BrokerToPeerMessage>,
    client_id: PeerId,
}

async fn call(shv_path: &str, method: &str, param: Option<RpcValue>, ctx: &CallCtx<'_>) -> Result<RpcValue, RpcError> {
    let msg = RpcMessage::new_request(shv_path, method, param);
    let frame = RpcFrame::from_rpcmessage(&msg).expect("valid message");
    println!("request: {}", frame.to_rpcmesage().unwrap());
    ctx.writer.send(BrokerCommand::FrameReceived { peer_id: ctx.client_id, frame }).await.unwrap();
    let retval = loop {
        let msg = ctx.reader.recv().await.unwrap();
        let msg = match msg {
            BrokerToPeerMessage::SendFrame(frame) => { frame.to_rpcmesage().unwrap() }
            BrokerToPeerMessage::SendMessage(message) => { message }
            _ => {
                panic!("unexpected message: {:?}", msg);
            }
        };
        if msg.is_response() {
            println!("response: {msg}");
            break msg.result().cloned()
        } else {
            // ignore RPC requests which might be issued after subscribe call
            println!("ignoring message: {msg}");
            continue;
        }
    };
    retval
}

#[async_std::test]
async fn test_broker_loop() {
    let config = BrokerConfig::default();
    let access = config.access.clone();
    let sql = Connection::open_in_memory().unwrap();
    let broker = BrokerImpl::new(access, Some(sql));
    let broker_sender = broker.command_sender.clone();
    let broker_task = task::spawn(crate::brokerimpl::broker_loop(broker));

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
        peer_kind: PeerKind::Client,
        user: user.to_string(),
        mount_point: Some("test/device".into()),
        device_id: None,
        sender: peer_writer.clone() }).await.unwrap();

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
                let user2 = User { password: Password::Plain("test".into()), roles: vec!["tester".into()] };
                assert_eq!(user1, user2);
            }
            {
                let user = User { password: Password::Plain("foo".into()), roles: vec!["bar".into()] };
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
                let role2 = Role { roles: vec!["client".into()], access: vec![AccessRule{ shv_ri: "test/**:*".into(), grant: "cfg".into() }] };
                assert_eq!(role1, role2);
            }
            {
                let role = Role { roles: vec!["foo".into()], access: vec![AccessRule{ shv_ri: "bar/**:*".into(), grant: "cfg".into() }] };
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

#[async_std::test]
async fn test_tunnel_loop() {
    let config = BrokerConfig::default();
    let access = config.access.clone();
    let broker = BrokerImpl::new(access, None);
    let broker_sender = broker.command_sender.clone();
    let broker_task = task::spawn(crate::brokerimpl::broker_loop(broker));

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
        peer_kind: PeerKind::Client,
        user: user.to_string(),
        mount_point: None,
        device_id: None,
        sender: peer_writer.clone() }).await.unwrap();

    let tunid = call(".app/tunnel", "create", None, &call_ctx).await;
    // host param is missing
    assert!(tunid.is_err());

    let param = Map::from([("host".to_string(), "localhost:54321".into())]);
    let tunid = call(".app/tunnel", "create", Some(param.into()), &call_ctx).await;
    // service not running
    assert_eq!(tunid.err().unwrap().code, RpcErrorCode::MethodCallException);

    // service is running
    // ncat -e /bin/cat -k -l 8888
    let param = Map::from([("host".to_string(), "localhost:8888".into())]);
    let tunid = call(".app/tunnel", "create", Some(param.into()), &call_ctx).await.unwrap();
    assert!(tunid.is_string());

    let tunid = tunid.as_str();

    let res = call(".app/tunnel", "ls", None, &call_ctx).await.unwrap();
    assert_eq!(res.as_list(), &[tunid.into()].to_vec());
    let res = call(".app/tunnel", "ls", Some(tunid.into()), &call_ctx).await.unwrap();
    assert!(res.as_bool());

    let data = "hello".as_bytes();
    let res = call(&format!(".app/tunnel/{tunid}"), "write", Some(data.into()), &call_ctx).await.unwrap();
    assert_eq!(res.as_blob(), data);

    let data = "tunnel".as_bytes();
    let res = call(&format!(".app/tunnel/{tunid}"), "write", Some(data.into()), &call_ctx).await.unwrap();
    assert_eq!(res.as_blob(), data);

    let res = call(&format!(".app/tunnel/{tunid}"), "close", None, &call_ctx).await.unwrap();
    assert!(res.as_bool());

    let res = call(".app/tunnel", "ls", None, &call_ctx).await.unwrap();
    assert!(res.as_list().is_empty());

    broker_task.cancel().await;
}