use std::process::Command;
use std::sync::Arc;
use assert_cmd::cargo_bin;
use shvrpc::rpcmessage::RpcErrorCode;
use tempfile::NamedTempFile;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{fs, thread, time::Duration};
use shvclient::appnodes::{DotAppNode, DotDeviceNode};
use shvclient::clientnode::SIG_CHNG;
use shvproto::{RpcValue, rpcvalue};
use shvrpc::client::ClientConfig;
use shvrpc::{metamethod, RpcMessage};
use shvrpc::metamethod::{Flags, MetaMethod};
use smol::lock::RwLock;
use shvbroker::config::{BrokerConfig, BrokerConnectionConfig, ConnectionKind, Listen};
use url::Url;
use crate::common::{KillProcessGuard, ShvCallCommand, shv_call, shv_call_many};
use shvbroker::shvnode::{METH_DIR, METH_LS, METH_NAME, METH_PING};

mod common;

#[test]
fn test_broker() -> shvrpc::Result<()> {
    let mut broker_process_guard = KillProcessGuard::new(Command::new(cargo_bin!("shvbroker"))
        .arg("-v").arg("=I")
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(broker_process_guard.is_running());

    let _process_guard_3755 = {
        let config = BrokerConfig {
            listen: vec![Listen { url: Url::parse("tcp://localhost:3756")? }],
            connections: vec![
                BrokerConnectionConfig {
                    name: "test1".to_string(),
                    enabled: true,
                    client: ClientConfig{
                        url: Url::parse("tcp://child-broker@localhost:3755?password=child-broker")?,
                        device_id: Some("test-child-broker".into()),
                        mount: None,
                        heartbeat_interval: duration_str::parse("1m")?,
                        reconnect_interval: None,
                    },
                    connection_kind: ConnectionKind::ToParentBroker {
                        shv_root: "test".to_string(),
                    },
                }
            ],
            ..Default::default()
        };
        let cfg_fn = NamedTempFile::new().expect("Failed to make tempfile for the config");
        fs::write(cfg_fn.as_ref(), &serde_yaml::to_string(&config)?)?;
        let mut process_guard = KillProcessGuard::new(Command::new(cargo_bin!("shvbroker"))
            .arg("--config").arg(cfg_fn.as_ref())
            //.arg("-v").arg("Acc")
            .spawn()?);
        thread::sleep(Duration::from_millis(100));
        assert!(process_guard.is_running());
        process_guard
    };

    pub fn shv_call_parent(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        let rpcmsg = shv_call(path, method, param, None)?;
        rpcmsg
            .response()?
            .success()
            .cloned()
            .ok_or_else(|| format!("Not a success response: {msg}", msg = rpcmsg.to_cpon()).into())
    }
    pub fn shv_call_child(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        let rpcmsg = shv_call(path, method, param, Some(3756))?;
        rpcmsg
            .response()?
            .success()
            .cloned()
            .ok_or_else(|| format!("Not a success response: {msg}", msg = rpcmsg.to_cpon()).into())
    }

    pub fn shv_call_parent_get_response(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcMessage> {
        shv_call(path, method, param, None)
    }

    println!("====== broker =====");
    println!("---broker---: :ls(\".app\")");
    assert_eq!(shv_call_child("", "ls", r#"".app""#)?, RpcValue::from(true));
    //assert_eq!(shv_call_child(".app", "ls", r#""broker""#)?, RpcValue::from(true));
    assert_eq!(shv_call_child(".broker", "ls", r#""client""#)?, RpcValue::from(true));
    {
        println!("---broker---: .app:dir()");
        let expected_methods = [
            MetaMethod::new_static(METH_DIR, Flags::empty(), metamethod::AccessLevel::Browse, "DirParam", "DirResult", &[], ""),
            MetaMethod::new_static(METH_LS, Flags::empty(), metamethod::AccessLevel::Browse, "LsParam", "LsResult", &[], ""),
            MetaMethod::new_static(METH_NAME, Flags::IsGetter, metamethod::AccessLevel::Browse, "", "", &[], ""),
            MetaMethod::new_static(METH_PING, Flags::empty(), metamethod::AccessLevel::Browse, "", "", &[], ""),
        ];
        {
            let methods = shv_call_child(".app", "dir", "")?;
            let methods = methods.as_list();
            'outer: for xmm in expected_methods.iter() {
                for mm in methods.iter() {
                    assert!(mm.is_imap());
                    let name = mm.as_imap().get(&metamethod::DirAttribute::Name.into()).ok_or("Name attribute doesn't exist")?.as_str();
                    if name == xmm.name {
                        continue 'outer;
                    }
                }
                panic!("Method name '{}' is not found", xmm.name);
            }
        }
        println!("---broker---: .app:dir(true)");
        {
            let methods = shv_call_child(".app", "dir", "true")?;
            let methods = methods.as_list();
            'outer: for xmm in expected_methods.iter() {
                for mm in methods.iter() {
                    assert!(mm.is_map());
                    let name = mm.as_map().get("name").ok_or("Name attribute doesn't exist")?.as_str();
                    if name == xmm.name {
                        continue 'outer;
                    }
                }
                panic!("Method name '{}' is not found", xmm.name);
            }
        }
        println!("---broker---: .app:dir(\"ping\")");
        {
            let exists = shv_call_child(".app", "dir", r#""ping""#)?;
            assert!(exists.as_bool());
        }
    }
    println!("---broker---: .app:ping()");
    assert_eq!(shv_call_child(".app", "ping", "")?, RpcValue::null());

    println!("====== device =====");
    run_testing_device(Url::parse("tcp://test:test@localhost:3756").unwrap(), "test/device");
    thread::sleep(Duration::from_millis(200));

    println!("---broker---: test:ls()");
    assert_eq!(shv_call_child("test", "ls", "")?, vec![RpcValue::from("device")].into());
    assert_eq!(shv_call_parent("test/child-broker", "ls", "")?, vec![RpcValue::from(".local"), RpcValue::from("device")].into());
    println!("---broker---: test/device:ls()");
    assert_eq!(shv_call_child("test/device", "ls", "")?, vec![RpcValue::from(".app"), RpcValue::from(".device"), RpcValue::from("state")].into());
    assert_eq!(shv_call_parent("test/child-broker/device", "ls", "")?, vec![RpcValue::from(".app"), RpcValue::from(".device"), RpcValue::from("state")].into());
    println!("---broker---: test/device/.app:ping()");
    assert_eq!(shv_call_child("test/device/.app", "ping", "")?, RpcValue::null());
    assert_eq!(shv_call_parent("test/child-broker/device/.app", "ping", "")?, RpcValue::null());
    println!("---broker---: test/device/number:ls()");
    assert_eq!(shv_call_child("test/device/state/number", "ls", "")?, rpcvalue::List::new().into());
    assert_eq!(shv_call_parent("test/child-broker/device/state/number", "ls", "")?, rpcvalue::List::new().into());
    assert_eq!(shv_call_parent("test/child-broker/device/state/number", "set", "27")?, ().into());
    assert_eq!(shv_call_parent("test/child-broker/device/state/number", "get", "")?, 27.into());
    println!("---broker---: .broker:clients()");
    assert!(!shv_call_child(".broker", "clients", "")?.as_list().is_empty());

    println!("---broker---: .broker:mounts()");
    assert_eq!(shv_call_child(".broker", "mounts", "")?, vec![RpcValue::from("test/device")].into());
    println!("====== subscriptions =====");
    check_subscription("test/device/state/number", "test/**", 3756)?;

    println!("====== child broker =====");
    assert_eq!(shv_call_parent("test", "ls", r#""child-broker""#)?, RpcValue::from(true));
    assert_eq!(shv_call_parent("test/child-broker/device/.app", "name", "")?, RpcValue::from("shvbrokertestingdevice"));
    assert_eq!(shv_call_parent("test/child-broker/device/state/number", "get", "")?, RpcValue::from(123));

    check_subscription_along_property_path("test/child-broker/device/state/number", 3755)?;

    test_child_broker_as_client()?;

    const OVERSIZED_FRAME_SIZE: usize = 60 << 20;
    let resp = shv_call_parent_get_response("test/child-broker/device/state/oversized", "get", &OVERSIZED_FRAME_SIZE.to_string())?;
    assert_eq!(resp.response().unwrap_err().code, RpcErrorCode::MethodCallException.into());

    Ok(())
}

struct State {
    number: AtomicI32,
    text: RwLock<String>,
}

const NUMBER_MOUNT: &str = "state/number";
const TEXT_MOUNT: &str = "state/text";
const OVERSIZED_MOUNT: &str = "state/oversized";

type AppState = Arc<State>;
struct NumberNode {
    state: AppState,
}

shvclient::impl_static_node!{
    NumberNode(&self, request, client_cmd_tx) {
        "get" [IsGetter, Read, "Null", "Int"] => {
            Some(Ok(self.state.number.load(Ordering::SeqCst).into()))
        }
        "set" [IsSetter, Write, "Int", "Null"] (param: i32) => {
            if self.state.number.load(Ordering::SeqCst) != param {
                self.state.number.store(param, Ordering::SeqCst);
                let sigchng = shvclient::shvrpc::RpcMessage::new_signal(NUMBER_MOUNT, SIG_CHNG).with_param(param);
                let _ = client_cmd_tx.send_message(sigchng);
            }
            Some(Ok(().into()))
        }
    }
}

struct TextNode {
    state: AppState,
}

shvclient::impl_static_node!{
    TextNode(&self, request, client_cmd_tx) {
        "get" [IsGetter, Read, "String", "Null"] => {
            let s = &*self.state.text.read().await;
            Some(Ok(s.into()))
        }
        "set" [IsSetter, Write, "Null", "String"] (param: String) => {
            if *self.state.text.read().await != param {
                *self.state.text.write().await = param.clone();
                let sigchng = shvclient::shvrpc::RpcMessage::new_signal(TEXT_MOUNT, SIG_CHNG).with_param(param);
                let _ = client_cmd_tx.send_message(sigchng);
            }
            Some(Ok(().into()))
        }
    }
}

struct OversizedNode;
shvclient::impl_static_node!{
    OversizedNode(&self, _request, _client_cmd_tx) {
        "get" [IsGetter, Read, "String", "Null"] (param: usize) => {
            Some(Ok(std::iter::repeat_n('A', param).collect::<String>().into()))
        }
    }
}
fn run_testing_device(url: Url, mount_point: &str) {

    let client_config = shvclient::shvrpc::client::ClientConfig {
        url,
        mount: Some(mount_point.into()),
        ..Default::default()
    };

    let state = Arc::new(State{ number: 0.into(), text: "".to_string().into() });

    smol::spawn(async move {
        shvclient::Client::new()
            .app(DotAppNode::new("shvbrokertestingdevice"))
            .device(DotDeviceNode::new("shvbrokertestingdevice", "0.1", Some("00000".into())))
            .mount_static(NUMBER_MOUNT, NumberNode {state: state.clone()} )
            .mount_static(TEXT_MOUNT, TextNode {state: state.clone()})
            .mount_static(OVERSIZED_MOUNT, OversizedNode{})
            //.run_with_init(&client_config, init_task)
            .run(&client_config)
            .await
    }).detach();
}

fn check_subscription(property_path: &str, subscribe_path: &str, port: i32) -> shvrpc::Result<()> {
    //let info = shv_call_child(".broker/currentClient", "info", "")?;
    //println!("INFO: {info}");
    let calls: Vec<ShvCallCommand> = vec![
        ShvCallCommand::Call(format!(r#".broker/currentClient:subscribe ["{subscribe_path}:*:chng"]"#)),
        ShvCallCommand::Call(format!(r#"{property_path}:set 42"#)),
        ShvCallCommand::Wait(std::time::Duration::from_millis(1000)),
        ShvCallCommand::Call(format!(r#".broker/currentClient:unsubscribe ["{subscribe_path}:*:chng"]"#)),
        ShvCallCommand::Call(format!(r#"{property_path}:set 123"#)),
    ];
    println!("shv_call_many property: {property_path}, port: {port}");
    for c in calls.iter() { println!("\t{c:?}"); }
    let values = shv_call_many(calls, Some(port))?;
    println!("shv_call_many result:");
    for v in values.iter() { println!("\t{v}"); }
    let expected: Vec<String> = vec![
        "RES true".into(), // response to subscribe
        format!("SIG {property_path}:chng 42"), // SIG chng
        "RES null".into(), // response to SET
        "RES true".into(), // response to unsubscribe
        "RES null".into(), // response to SET
    ];
    for (no, val) in values.iter().enumerate() {
        assert_eq!(&expected[no], val);
    }
    Ok(())
}
fn check_subscription_along_property_path(property_path: &str, port: i32) -> shvrpc::Result<()> {
    let dirs = property_path.split('/').collect::<Vec<_>>();
    for i in 1 .. dirs.len() - 1 {
        let subscribe_path = dirs[.. i].join("/") + "/**";
        check_subscription(property_path, &subscribe_path, port)?
    }
    Ok(())
}
fn test_child_broker_as_client() -> shvrpc::Result<()> {
    let config = BrokerConfig {
        listen: vec![Listen { url: Url::parse("tcp://localhost:3754")? }],
        connections: vec![
            BrokerConnectionConfig {
                name: "test2".to_string(),
                enabled: true,
                client: ClientConfig{
                    url: Url::parse("tcp://localhost:3755?user=test&password=test")?,
                    device_id: None,
                    mount: None,
                    heartbeat_interval: duration_str::parse("1m")?,
                    reconnect_interval: None,
                },
                connection_kind: ConnectionKind::ToChildBroker {
                    shv_root: "test/child-broker/device".to_string(),
                    mount_point: "test/child-device".to_string(),
                },
            }
        ],
        ..Default::default()
    };
    let cfg_fn = NamedTempFile::new().expect("Failed to make tempfile for the config");
    fs::write(cfg_fn.as_ref(), &serde_yaml::to_string(&config)?)?;
    let mut broker_process_guard = KillProcessGuard::new(Command::new(cargo_bin!("shvbroker"))
        .arg("--config").arg(cfg_fn.as_ref())
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(broker_process_guard.is_running());

    pub fn shv_call_3754(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        let rpcmsg = shv_call(path, method, param, Some(3754))?;
        rpcmsg
            .response()?
            .success()
            .cloned()
            .ok_or_else(|| format!("Not a success response: {msg}", msg = rpcmsg.to_cpon()).into())
    }
    assert_eq!(shv_call_3754("test/child-device/.app", "name", "")?, RpcValue::from("shvbrokertestingdevice"));
    check_subscription_along_property_path("test/child-device/state/number", 3754)?;
    Ok(())
}
