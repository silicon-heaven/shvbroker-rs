use crate::brokerimpl::BrokerImpl;
use async_std::channel::{Receiver, Sender};
use async_std::{channel, task};
use shvproto::{List, RpcValue};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::rpcmessage::CliId;
use crate::broker::{BrokerToPeerMessage, PeerKind, BrokerCommand};
use crate::config::BrokerConfig;
use crate::node::{METH_SUBSCRIBE, METH_UNSUBSCRIBE};


struct CallCtx<'a> {
    writer: &'a Sender<BrokerCommand>,
    reader: &'a Receiver<BrokerToPeerMessage>,
    client_id: CliId,
}

async fn call(shv_path: &str, method: &str, param: Option<RpcValue>, ctx: &CallCtx<'_>) -> RpcValue {
    let msg = RpcMessage::new_request(shv_path, method, param);
    let frame = RpcFrame::from_rpcmessage(&msg).expect("valid message");
    println!("request: {}", frame.to_rpcmesage().unwrap());
    ctx.writer.send(BrokerCommand::FrameReceived { client_id: ctx.client_id, frame }).await.unwrap();
    let retval = loop {
        let msg = ctx.reader.recv().await.unwrap();
        let msg = match msg {
            BrokerToPeerMessage::SendFrame(frame) => { frame.to_rpcmesage().unwrap() }
            BrokerToPeerMessage::SendMessage(message) => { message }
            _ => {
                panic!("unexpected message: {:?}", msg);
            }
        };
        println!("response: {msg}");
        if msg.is_response() {
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
            continue;
        }
    };
    retval
}

#[test]
fn test_broker() {
    let config = BrokerConfig::default();
    let access = config.access.clone();
    let broker = BrokerImpl::new(access);
    let roles = broker.flatten_roles("child-broker").unwrap();
    assert_eq!(roles, vec!["child-broker", "device", "client", "ping", "subscribe", "browse"]);
}

#[async_std::test]
async fn test_broker_loop() {
    let config = BrokerConfig::default();
    let access = config.access.clone();
    let broker = BrokerImpl::new(access);
    let broker_sender = broker.command_sender.clone();
    let broker_task = task::spawn(crate::broker::broker_loop(broker));

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
    //let nonce = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    //broker_sender.send(BrokerCommand::GetPassword { sender: peer_writer.clone(), user: user.into() }).await.unwrap();
    //match peer_reader.recv().await.unwrap() {
    //    BrokerToPeerMessage::PasswordSha1(password_sha1) => {
    //    }
    //    _ => { panic!("Invalid message type") }
    //}
    broker_sender.send(BrokerCommand::NewPeer { client_id,
        peer_kind: PeerKind::Client,
        user: user.to_string(),
        mount_point: None,
        device_id: Some("test-device".into()),
        sender: peer_writer.clone() }).await.unwrap();
    //let register_device = BrokerCommand::RegisterDevice {
    //    client_id, device_id: Some("test-device".into()),
    //    mount_point: Default::default(),
    //    subscribe_path: Some(SubscribePath::CanSubscribe(".broker/currentClient".into()))
    //};
    //broker_sender.send(register_device).await.unwrap();

    // device should be mounted as 'shv/dev/test'
    let resp = call("shv/test", "ls", Some("device".into()), &call_ctx).await;
    assert_eq!(resp, RpcValue::from(true));

    // test current client info
    let resp = call(".broker/currentClient", "info", None, &call_ctx).await;
    let m = resp.as_map();
    assert_eq!(m.get("clientId").unwrap(), &RpcValue::from(2));
    assert_eq!(m.get("mountPoint").unwrap(), &RpcValue::from("shv/test/device"));
    assert_eq!(m.get("userName").unwrap(), &RpcValue::from(user));
    assert_eq!(m.get("subscriptions").unwrap(), &RpcValue::from(List::new()));

    // subscriptions
    let subs = SubscriptionParam { ri: ShvRI::try_from("shv/**:").unwrap(), ttl: 0 };
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

    broker_task.cancel().await;
}