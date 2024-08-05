use crate::brokerimpl::BrokerImpl;
use async_std::channel::{Receiver, Sender};
use async_std::{channel, task};
use shvproto::{List, RpcValue};
use shvrpc::rpcframe::RpcFrame;
use shvrpc::{RpcMessage, RpcMessageMetaTags};
use shvrpc::rpc::{ShvRI, SubscriptionParam};
use shvrpc::rpcmessage::PeerId;
use crate::broker::{BrokerToPeerMessage, PeerKind, BrokerCommand};
use crate::config::BrokerConfig;
use crate::node::{METH_SUBSCRIBE, METH_UNSUBSCRIBE};


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

    broker_task.cancel().await;
}