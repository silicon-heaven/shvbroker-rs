use std::process::{Command};
use std::{thread, time::Duration};
use shvproto::{RpcValue, rpcvalue};
use shvrpc::metamethod;
use shvrpc::metamethod::{Flag, MetaMethod};
use crate::common::{KillProcessGuard, shv_call, shv_call_many, ShvCallOutputFormat};
use shvbroker::shvnode::{METH_DIR, METH_LS, METH_NAME, METH_PING};

mod common;

#[test]
fn test_broker() -> shvrpc::Result<()> {
    let mut broker_process_guard = KillProcessGuard::new(Command::new("target/debug/shvbroker")
        .arg("-v").arg(".:W")
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(broker_process_guard.is_running());

    let mut child_broker_process_guard = KillProcessGuard::new(Command::new("target/debug/shvbroker")
        .arg("--config").arg("tests/child-broker-config.yaml")
        //.arg("-v").arg("Acc")
        .spawn()?);
    thread::sleep(Duration::from_millis(100));
    assert!(child_broker_process_guard.is_running());

    pub fn shv_call_parent(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        shv_call(path, method, param, None)
    }
    pub fn shv_call_child(path: &str, method: &str, param: &str) -> shvrpc::Result<RpcValue> {
        shv_call(path, method, param, Some(3756))
    }

    println!("====== broker =====");
    println!("---broker---: :ls(\".app\")");
    assert_eq!(shv_call_child("", "ls", r#"".app""#)?, RpcValue::from(true));
    assert_eq!(shv_call_child(".app", "ls", r#""broker""#)?, RpcValue::from(true));
    assert_eq!(shv_call_child(".app/broker", "ls", r#""client""#)?, RpcValue::from(true));
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
            let method = shv_call_child(".app", "dir", r#""ping""#)?;
            assert!(method.is_imap());
            let name = method.as_imap().get(&metamethod::DirAttribute::Name.into()).ok_or("Name attribute doesn't exist")?.as_str();
            assert_eq!(name, "ping");
        }
    }
    println!("---broker---: .app:ping()");
    assert_eq!(shv_call_child(".app", "ping", "")?, RpcValue::null());

    println!("====== device =====");
    let mut device_process_guard = common::KillProcessGuard {
        child: Command::new("target/debug/examples/device")
            .arg("--url").arg("tcp://admin:admin@localhost:3756")
            .arg("--mount").arg("test/device")
            .spawn()?
    };
    thread::sleep(Duration::from_millis(100));
    assert!(device_process_guard.is_running());

    println!("---broker---: test:ls()");
    assert_eq!(shv_call_child("test", "ls", "")?, vec![RpcValue::from("device")].into());
    assert_eq!(shv_call_parent("shv/test/child-broker", "ls", "")?, vec![RpcValue::from(".local"), RpcValue::from("device")].into());
    println!("---broker---: test/device:ls()");
    assert_eq!(shv_call_child("test/device", "ls", "")?, vec![RpcValue::from(".app"), RpcValue::from("number")].into());
    assert_eq!(shv_call_parent("shv/test/child-broker/device", "ls", "")?, vec![RpcValue::from(".app"), RpcValue::from("number")].into());
    println!("---broker---: test/device/.app:ping()");
    assert_eq!(shv_call_child("test/device/.app", "ping", "")?, RpcValue::null());
    assert_eq!(shv_call_parent("shv/test/child-broker/device/.app", "ping", "")?, RpcValue::null());
    println!("---broker---: test/device/number:ls()");
    assert_eq!(shv_call_child("test/device/number", "ls", "")?, rpcvalue::List::new().into());
    assert_eq!(shv_call_parent("shv/test/child-broker/device/number", "ls", "")?, rpcvalue::List::new().into());

    println!("---broker---: .app/broker:clients()");
    assert!(!shv_call_child(".app/broker", "clients", "")?.as_list().is_empty());

    println!("---broker---: .app/broker:mounts()");
    assert_eq!(shv_call_child(".app/broker", "mounts", "")?, vec![RpcValue::from("test/device")].into());
    println!("====== subscriptions =====");
    fn check_subscription(property_path: &str, subscribe_path: &str, port: i32) -> shvrpc::Result<()> {
        //let info = shv_call_child(".app/broker/currentClient", "info", "")?;
        //println!("INFO: {info}");
        let calls: Vec<String> = vec![
            format!(r#".app/broker/currentClient:subscribe {{"methods": "chng", "paths": "{subscribe_path}"}}"#),
            format!(r#"{property_path}:set 42"#),
            format!(r#".app/broker/currentClient:unsubscribe {{"methods": "chng", "paths": "{subscribe_path}"}}"#),
            format!(r#"{property_path}:set 123"#),
        ];
        let values = shv_call_many(calls, ShvCallOutputFormat::Simple, Some(port))?;
        for v in values.iter() { println!("\t{}", v); }
        let expected: Vec<String> = vec![
            "RES null".into(), // response to subscribe
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
    check_subscription("test/device/number", "test/**", 3756)?;

    println!("====== child broker =====");
    assert_eq!(shv_call_parent("shv/test", "ls", r#""child-broker""#)?, RpcValue::from(true));
    assert_eq!(shv_call_parent("shv/test/child-broker/device/.app", "name", "")?, RpcValue::from("testdeviceapp"));
    assert_eq!(shv_call_parent("shv/test/child-broker/device/number", "get", "")?, RpcValue::from(123));
    check_subscription("shv/test/child-broker/device/number", "shv/test/**", 3755)?;

    Ok(())
}
