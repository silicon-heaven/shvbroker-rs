use std::process::{Command};
use std::{fs, thread, time::Duration};
use shvproto::{RpcValue, rpcvalue};
use shvrpc::client::ClientConfig;
use shvrpc::metamethod;
use shvrpc::metamethod::{Flag, MetaMethod};
use shvbroker::config::{BrokerConfig, BrokerConnectionConfig, ConnectionKind};
use crate::common::{KillProcessGuard, shv_call, shv_call_many};
use shvbroker::shvnode::{METH_DIR, METH_LS, METH_NAME, METH_PING};

mod common;

#[test]
fn test_broker() -> shvrpc::Result<()> {
    let mut broker_process_guard = KillProcessGuard::new(Command::new("target/debug/shvbroker")
        .arg("-v").arg(":I")
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(broker_process_guard.is_running());

    let _process_guard_3756 = {
        let mut config = BrokerConfig::default();
        config.listen.tcp = Some("localhost:3756".into());
        config.connections = vec![
            BrokerConnectionConfig {
                enabled: true,
                client: ClientConfig{
                    url: "tcp://child-broker@localhost:3755?password=child-broker".to_string(),
                    device_id: Some("test-child-broker".into()),
                    mount: None,
                    heartbeat_interval: "1m".to_string(),
                    reconnect_interval: None,
                },
                connection_kind: ConnectionKind::ToParentBroker {
                    shv_root: "test".to_string(),
                },
            }
        ];
        let cfg_fn = "/tmp/test-broker-config3756.yaml";
        fs::write(cfg_fn, &serde_yaml::to_string(&config)?)?;
        let mut process_guard = KillProcessGuard::new(Command::new("target/debug/shvbroker")
            .arg("--config").arg(cfg_fn)
            //.arg("-v").arg("Acc")
            .spawn()?);
        thread::sleep(Duration::from_millis(100));
        assert!(process_guard.is_running());
        process_guard
    };

    pub fn shv_call_parent(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        shv_call(path, method, param, None)
    }
    pub fn shv_call_child(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        shv_call(path, method, param, Some(3756))
    }

    println!("====== broker =====");
    println!("---broker---: :ls(\".app\")");
    assert_eq!(shv_call_child("", "ls", r#"".app""#)?, RpcValue::from(true));
    //assert_eq!(shv_call_child(".app", "ls", r#""broker""#)?, RpcValue::from(true));
    assert_eq!(shv_call_child(".broker", "ls", r#""client""#)?, RpcValue::from(true));
    {
        println!("---broker---: .app:dir()");
        let expected_methods = vec![
            MetaMethod { name: METH_DIR, param: "DirParam", result: "DirResult", ..Default::default() },
            MetaMethod { name: METH_LS, param: "LsParam", result: "LsResult", ..Default::default() },
            MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32,  ..Default::default() },
            MetaMethod { name: METH_PING, ..Default::default() },
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
    let mut device_process_guard = common::KillProcessGuard {
        child: Command::new("shvbrokertestingdevice")
            .arg("--url").arg("tcp://test:test@localhost:3756")
            .arg("--mount").arg("test/device")
            .spawn()?
    };
    thread::sleep(Duration::from_millis(100));
    assert!(device_process_guard.is_running());

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

    Ok(())
}
fn check_subscription(property_path: &str, subscribe_path: &str, port: i32) -> shvrpc::Result<()> {
    //let info = shv_call_child(".broker/currentClient", "info", "")?;
    //println!("INFO: {info}");
    let calls: Vec<String> = vec![
        format!(r#".broker/currentClient:subscribe ["{subscribe_path}:*:chng"]"#),
        format!(r#"{property_path}:set 42"#),
        format!(r#".broker/currentClient:unsubscribe ["{subscribe_path}:*:chng"]"#),
        format!(r#"{property_path}:set 123"#),
    ];
    println!("shv_call_many property: {property_path}, port: {port}");
    for c in calls.iter() { println!("\t{}", c); }
    let values = shv_call_many(calls, Some(port))?;
    println!("shv_call_many result:");
    for v in values.iter() { println!("\t{}", v); }
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
    let mut config = BrokerConfig::default();
    config.listen.tcp = Some("localhost:3754".into());
    config.connections = vec![
        BrokerConnectionConfig {
            enabled: true,
            client: ClientConfig{
                url: "tcp://localhost:3755?user=test&password=test".to_string(),
                device_id: None,
                mount: None,
                heartbeat_interval: "1m".to_string(),
                reconnect_interval: None,
            },
            connection_kind: ConnectionKind::ToChildBroker {
                shv_root: "test/child-broker/device".to_string(),
                mount_point: "test/child-device".to_string(),
            },
        }
    ];
    let cfg_fn = "/tmp/test-broker-config3754.yaml";
    fs::write(cfg_fn, &serde_yaml::to_string(&config)?)?;
    let mut broker_process_guard = KillProcessGuard::new(Command::new("target/debug/shvbroker")
        .arg("--config").arg(cfg_fn)
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(broker_process_guard.is_running());

    pub fn shv_call_3754(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        shv_call(path, method, param, Some(3754))
    }
    assert_eq!(shv_call_3754("test/child-device/.app", "name", "")?, RpcValue::from("shvbrokertestingdevice"));
    check_subscription_along_property_path("test/child-device/state/number", 3754)?;
    Ok(())
}