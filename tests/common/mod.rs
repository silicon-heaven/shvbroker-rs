use std::io::Write;
use std::process::{Child, Command, Output, Stdio};
use std::sync::LazyLock;
use std::thread;
use std::time::Duration;
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
    let rv = RpcValue::from_cpon(cpon)?;
    //println!("cpon: {}, rpc vla: {}", cpon, rv.to_cpon());
    Ok(rv)
}
pub fn bytes_from_output(output: Output) -> shvrpc::Result<Vec<u8>> {
    if !output.status.success() {
        let errmsg = std::str::from_utf8(&output.stderr)?;
        return Err(format!("Process exited with error code {:?}, stderr: {}", output.status.code(), errmsg).into());
    }
    Ok(output.stdout)
}
pub fn text_from_output(output: Output) -> shvrpc::Result<String> {
    bytes_from_output(output)
        .and_then(|bytes| String::from_utf8(bytes).map_err(Into::into))
}
pub fn string_list_from_output(output: Output) -> shvrpc::Result<Vec<String>> {
    text_from_output(output)
        .map(|text| text
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(|cpon| cpon.trim().to_owned())
            .collect::<Vec<_>>()
        )
}

static SHVCALL_BINARY: LazyLock<String> = LazyLock::new(|| {
    let shvcall_package = cargo_run_bin::metadata::get_binary_packages()
        .unwrap()
        .iter()
        .find(|p| p.package == "shvcall")
        .unwrap()
        .to_owned();
    cargo_run_bin::binary::install(shvcall_package).unwrap()
});

pub fn shv_call(path: &str, method: &str, param: &str, port: Option<i32>) -> shvrpc::Result<RpcMessage> {
    let port = port.unwrap_or(3755);
    println!("shvcall port: {port} {path}:{method} param: {param}");
    let shvcall_binary = &*SHVCALL_BINARY;
    let mut cmd = Command::new(shvcall_binary);
    cmd
        .arg("-v").arg(".:T")
        .arg("--url").arg(format!("tcp://localhost:{port}?user=admin&password=admin"))
        .arg("--method").arg(format!("{path}:{method}"));
    if !param.is_empty() {
        cmd.arg("--param-file").arg("-");
    };
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut chld = cmd.spawn().unwrap();
    let mut stdin = chld.stdin.take().unwrap();
    stdin.write_all(param.as_bytes()).unwrap();
    drop(stdin);

    //.arg("--output-format").arg(output_format.as_str())
    chld.wait_with_output()
        .map(rpcmsg_from_output)
        .unwrap_or_else(|e| panic!("{shvcall_binary} exec error: {e}"))

}

#[derive(Debug)]
pub(crate) enum ShvCallCommand {
    Call(String),
    Wait(Duration),
}

pub fn shv_call_many(commands: Vec<ShvCallCommand>, port: Option<i32>) -> shvrpc::Result<Vec<String>> {
    let port = port.unwrap_or(3755);
    let mut cmd = Command::new(&*SHVCALL_BINARY);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--url").arg(format!("tcp://localhost:{port}?user=test&password=test"))
        .arg("--output-format").arg("simple")
        .arg("-v").arg(".:I");
    //println!("shvcall --url 'tcp://localhost:{port}?user=admin&password=admin' --output-format simple -v .:I");
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().expect("shvcall should be running");
    thread::spawn(move || {
        for command in commands {
            match command {
                ShvCallCommand::Call(call) => {
                    stdin.write_all(call.as_bytes()).expect("Failed to write to stdin");
                    stdin.write_all("\n".as_bytes()).expect("Failed to write to stdin");
                },
                ShvCallCommand::Wait(duration) => {
                    std::thread::sleep(duration);
                },
            }
        }
    });
    let output = child.wait_with_output()?;
    string_list_from_output(output)
}
