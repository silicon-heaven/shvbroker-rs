use crate::brokerimpl::BrokerImpl;
use async_std::channel::{Receiver, Sender};
use async_std::{channel, task};
use shvproto::{List, RpcValue};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::rpcmessage::PeerId;
use shvrpc::util::join_path;
use crate::brokerimpl::{BrokerToPeerMessage, PeerKind, BrokerCommand};
use crate::config::{AccessRule, BrokerConfig, Mount, Password, Role, User};
use crate::shvnode::{METH_LS, METH_SET_VALUE, METH_SUBSCRIBE, METH_UNSUBSCRIBE, METH_VALUE};

struct CallCtx<'a> {
    writer: &'a Sender<BrokerCommand>,
    reader: &'a Receiver<BrokerToPeerMessage>,
    client_id: PeerId,
}

async fn call(shv_path: &str, method: &str, param: Option<RpcValue>, ctx: &CallCtx<'_>) -> RpcValue {
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
            match msg.result() {
                Ok(retval) => {
                    break retval.clone();
                }
                Err(err) => {
                    panic!("Rpc error response received: {err} - {}", msg);
                }
            }
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
    let broker = BrokerImpl::new(access, None);
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

    // device should be mounted as 'shv/dev/test'
    let resp = call("test", "ls", Some("device".into()), &call_ctx).await;
    assert_eq!(resp, RpcValue::from(true));

    // test current client info
    let resp = call(".broker/currentClient", "info", None, &call_ctx).await;
    let m = resp.as_map();
    assert_eq!(m.get("clientId").unwrap(), &RpcValue::from(2));
    assert_eq!(m.get("mountPoint").unwrap(), &RpcValue::from("test/device"));
    assert_eq!(m.get("userName").unwrap(), &RpcValue::from(user));
    assert_eq!(m.get("subscriptions").unwrap(), &RpcValue::from(List::new()));

    // subscriptions
    let subs = SubscriptionParam { ri: ShvRI::try_from("shv/**:*").unwrap(), ttl: 0 };
    {
        // subscribe
        let result = call(".broker/currentClient", METH_SUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await;
        assert!(result.as_bool());
        // cannot subscribe the same twice
        let result = call(".broker/currentClient", METH_SUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await;
        assert!(!result.as_bool());
        let resp = call(".broker/currentClient", "info", None, &call_ctx).await;
        let subs = resp.as_map().get("subscriptions").unwrap();
        let subs_list = subs.as_list();
        assert_eq!(subs_list.len(), 1);
    }
    {
        call(".broker/currentClient", METH_UNSUBSCRIBE, Some(subs.to_rpcvalue()), &call_ctx).await;
        let resp = call(".broker/currentClient", "info", None, &call_ctx).await;
        let subs = resp.as_map().get("subscriptions").unwrap();
        let subs_list = subs.as_list();
        assert_eq!(subs_list.len(), 0);
    }

    // access/mounts
    {
        let path = ".broker/access/mounts";
        {
            let resp = call(path, METH_LS, None, &call_ctx).await;
            let list = resp.as_list();
            assert_eq!(list, RpcValue::from(["test-child-broker","test-device"].to_vec()).as_list());
            let resp = call(&join_path(path, "test-device"), METH_VALUE, None, &call_ctx).await;
            let mount1 = Mount::try_from(&resp).unwrap();
            let mount2 = Mount { mount_point: "test/device".to_string(), description: "Testing device mount-point".to_string() };
            assert_eq!(mount1, mount2);
        }
        {
            let mount = Mount{ mount_point: "foo".to_string(), description: "bar".to_string() };
            call(path, METH_SET_VALUE, Some(vec!["baz".into(), mount.to_rpcvalue().unwrap()].into()), &call_ctx).await;
            let resp = call(path, METH_LS, None, &call_ctx).await;
            let list = resp.as_list();
            assert_eq!(list, RpcValue::from(["baz", "test-child-broker","test-device"].to_vec()).as_list());
            let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await;
            assert_eq!(mount, Mount::try_from(&resp).unwrap());
        }

        // access/users
        {
            let path = ".broker/access/users";
            {
                let resp = call(path, METH_LS, None, &call_ctx).await;
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(["admin", "child-broker", "test", "tester", "user"].to_vec()).as_list());
                let resp = call(&join_path(path, "test"), METH_VALUE, None, &call_ctx).await;
                let user1 = User::try_from(&resp).unwrap();
                let user2 = User { password: Password::Plain("test".into()), roles: vec!["tester".into()] };
                assert_eq!(user1, user2);
            }
            {
                let user = User { password: Password::Plain("foo".into()), roles: vec!["bar".into()] };
                call(path, METH_SET_VALUE, Some(vec!["baz".into(), user.to_rpcvalue().unwrap()].into()), &call_ctx).await;
                let resp = call(path, METH_LS, None, &call_ctx).await;
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(["admin", "baz", "child-broker", "test", "tester", "user"].to_vec()).as_list());
                let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await;
                assert_eq!(user, User::try_from(&resp).unwrap());
            }
        }

        // access/roles
        {
            let path = ".broker/access/roles";
            {
                let resp = call(path, METH_LS, None, &call_ctx).await;
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(["browse","child-broker","client","device","ping","su","subscribe","tester"].to_vec()).as_list());
                let resp = call(&join_path(path, "tester"), METH_VALUE, None, &call_ctx).await;
                let role1 = Role::try_from(&resp).unwrap();
                let role2 = Role { roles: vec!["client".into()], access: vec![AccessRule{ shv_ri: "test/**:*".into(), grant: "cfg".into() }] };
                assert_eq!(role1, role2);
            }
            {
                let role = Role { roles: vec!["foo".into()], access: vec![AccessRule{ shv_ri: "bar/**:*".into(), grant: "cfg".into() }] };
                call(path, METH_SET_VALUE, Some(vec!["baz".into(), role.to_rpcvalue().unwrap()].into()), &call_ctx).await;
                let resp = call(path, METH_LS, None, &call_ctx).await;
                let list = resp.as_list();
                assert_eq!(list, RpcValue::from(["baz", "browse","child-broker","client","device","ping","su","subscribe","tester"].to_vec()).as_list());
                let resp = call(&join_path(path, "baz"), METH_VALUE, None, &call_ctx).await;
                assert_eq!(role, Role::try_from(&resp).unwrap());
            }
        }
    }
    broker_task.cancel().await;
}