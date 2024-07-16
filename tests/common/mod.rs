use std::process::{Child, Command, Output};
use shvproto::{RpcValue};
use shvrpc::{RpcMessage};

pub struct KillProcessGuard {
    pub child: Child,
}
impl KillProcessGuard {
    pub fn new(child: Child) -> Self {
        KillProcessGuard {
            child,
        }
    }

    pub fn is_running(&mut self) -> bool {
        let status = self.child.try_wait().unwrap();
        //println!("shvbroker is_running status: {:?}", status);
        status.is_none()
    }
}
impl Drop for KillProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _exit_status= self.child.wait();
        //println!("shvbroker exit status: {:?}", exit_status);
    }
}

pub fn rpcmsg_from_output(output: Output) -> shvrpc::Result<RpcMessage> {
    let rv = rpcvalue_from_output(output)?;
    Ok(RpcMessage::from_rpcvalue(rv)?)
}
pub fn rpcvalue_from_output(output: Output) -> shvrpc::Result<RpcValue> {
    let out = bytes_from_output(output)?;
    let cpon = std::str::from_utf8(&out)?;
    Ok(RpcValue::from_cpon(cpon)?)
}
pub fn bytes_from_output(output: Output) -> shvrpc::Result<Vec<u8>> {
    if !output.status.success() {
        let errmsg = std::str::from_utf8(&output.stderr)?;
        return Err(format!("Process exited with error code {:?}, stderr: {}", output.status.code(), errmsg).into());
    }
    Ok(output.stdout)
}
//pub fn text_from_output(output: Output) -> shvrpc::Result<String> {
//    let bytes = bytes_from_output(output)?;
//    Ok(String::from_utf8(bytes)?)
//}
//pub fn string_list_from_output(output: Output) -> shvrpc::Result<Vec<String>> {
//    let bytes = text_from_output(output)?;
//    let mut values = Vec::new();
//    for cpon in bytes.split(|b| b == '\n').filter(|line| !line.is_empty()) {
//        values.push(cpon.trim().to_owned());
//    }
//    Ok(values)
//}
//pub fn value_list_from_output(output: Output) -> shv::Result<Vec<RpcValue>> {
//    let mut values = List::new();
//    let bytes = bytes_from_output(output)?;
//    let mut buff: &[u8] = &bytes;
//    let mut rd = CponReader::new(&mut buff);
//    loop {
//        match rd.read() {
//            Ok(rv) => { values.push(rv) }
//            Err(_) => { break; }
//        }
//    }
//    Ok(values)
//}
pub fn result_from_output(output: Output) -> shvrpc::Result<RpcValue> {
    let msg = rpcmsg_from_output(output)?;
    let result = msg.result()?;
    //println!("cpon: {}, expected: {}", result, expected_value.to_cpon());
    //assert_eq!(result, expected_value);
    Ok(result.clone())
}
//pub enum ShvCallOutputFormat {
//    Cpon,
//    ChainPack,
//    Simple,
//    Value,
//}
//impl ShvCallOutputFormat {
//    fn as_str(&self) -> &'static str {
//        match self {
//            ShvCallOutputFormat::Cpon => { "cpon" }
//            ShvCallOutputFormat::ChainPack => { "chainpack" }
//            ShvCallOutputFormat::Simple => { "simple" }
//            ShvCallOutputFormat::Value => { "value" }
//        }
//    }
//}
const SHVCALL_BINARY: &str = "shvcall";
pub fn shv_call(path: &str, method: &str, param: &str, port: Option<i32>) -> shvrpc::Result<RpcValue> {
    let port = port.unwrap_or(3755);
    println!("shvcall port: {port} {path}:{method} param: {}", param);
    let output = match Command::new(SHVCALL_BINARY)
        .arg("-v").arg(".:T")
        .arg("--url").arg(format!("tcp://admin@localhost:{port}?password=admin"))
        .arg("--path").arg(path)
        .arg("--method").arg(method)
        .arg("--param").arg(param)
        //.arg("--output-format").arg(output_format.as_str())
        .output() {
        Ok(output) => {output}
        Err(e) => {
            panic!("{SHVCALL_BINARY} exec error: {e}");
        }
    };

    result_from_output(output)
}
//pub fn shv_call_many(calls: Vec<String>, output_format: ShvCallOutputFormat, port: Option<i32>) -> shvrpc::Result<Vec<String>> {
//    let port = port.unwrap_or(3755);
//    let mut cmd = Command::new(SHVCALL_BINARY);
//    cmd.stdin(Stdio::piped())
//        .stdout(Stdio::piped())
//        .arg("--url").arg(format!("tcp://admin@localhost:{port}?password=admin"))
//        .arg("--output-format").arg(output_format.as_str())
//        .arg("-v").arg(".:I");
//    let mut child = cmd.spawn()?;
//    let mut stdin = child.stdin.take().expect("shvcall should be running");
//    thread::spawn(move || {
//        for line in calls {
//            stdin.write_all(line.as_bytes()).expect("Failed to write to stdin");
//            stdin.write_all("\n".as_bytes()).expect("Failed to write to stdin");
//        }
//    });
//    let output = child.wait_with_output()?;
//    string_list_from_output(output)
//}