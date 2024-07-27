use std::collections::{BTreeMap, HashSet};
use std::format;
use log::warn;
use shvrpc::metamethod::{Flag, MetaMethod};
use shvrpc::{metamethod, RpcMessage, RpcMessageMetaTags};
use shvproto::{RpcValue, rpcvalue};
use shvrpc::metamethod::AccessLevel;
use shvrpc::rpcframe::RpcFrame;
use shvrpc::rpcmessage::{RpcError, RpcErrorCode};

pub const DOT_LOCAL_GRANT: &str = "dot-local";
pub const DOT_LOCAL_DIR: &str = ".local";
pub const DOT_LOCAL_HACK: &str = "dot-local-hack";
pub const DIR_APP: &str = ".app";
pub const DIR_APP_DEVICE: &str = ".app/device";

pub enum DirParam {
    Brief,
    Full,
    BriefMethod(String),
}
impl From<Option<&RpcValue>> for DirParam {
    fn from(value: Option<&RpcValue>) -> Self {
        match value {
            Some(rpcval) => {
                if rpcval.is_string() {
                    DirParam::BriefMethod(rpcval.as_str().into())
                } else if rpcval.as_bool() {
                    DirParam::Full
                } else {
                    DirParam::Brief
                }
            }
            None => {
                DirParam::Brief
            }
        }
    }
}

fn dir<'a>(methods: impl Iterator<Item=&'a MetaMethod>, param: DirParam) -> RpcValue {
    let mut result = RpcValue::null();
    let mut lst = rpcvalue::List::new();
    for mm in methods {
        match param {
            DirParam::Brief => {
                lst.push(mm.to_rpcvalue(metamethod::DirFormat::IMap));
            }
            DirParam::Full => {
                lst.push(mm.to_rpcvalue(metamethod::DirFormat::Map));
            }
            DirParam::BriefMethod(ref method_name) => {
                if mm.name == method_name {
                    result = mm.to_rpcvalue(metamethod::DirFormat::IMap);
                    break;
                }
            }
        }
    }
    if result.is_null() {
        lst.into()
    } else {
        result
    }
}

pub enum LsParam {
    List,
    Exists(String),
}
impl From<Option<&RpcValue>> for LsParam {
    fn from(value: Option<&RpcValue>) -> Self {
        match value {
            Some(rpcval) => {
                if rpcval.is_string() {
                    LsParam::Exists(rpcval.as_str().into())
                } else {
                    LsParam::List
                }
            }
            None => {
                LsParam::List
            }
        }
    }
}


pub fn process_local_dir_ls<V>(mounts: &BTreeMap<String, V>, frame: &RpcFrame) -> Option<Result<RpcValue, RpcError>> {
    let method = frame.method().unwrap_or_default();
    if !(method == METH_DIR || method == METH_LS) {
        return None
    }
    let shv_path = frame.shv_path().unwrap_or_default();
    let mut children_on_path = children_on_path(mounts, shv_path);
    if let Some(children_on_path) = children_on_path.as_mut() {
        if frame.meta.get(DOT_LOCAL_HACK).is_some() {
            children_on_path.insert(0, DOT_LOCAL_DIR.into());
        }
    }
    let mount = find_longest_prefix(mounts, shv_path);
    let is_mount_point = mount.is_some();
    let is_leaf = match &children_on_path {
        None => { is_mount_point }
        Some(dirs) => { dirs.is_empty() }
    };
    if children_on_path.is_none() && !is_mount_point {
        // path doesn't exist
        return Some(Err(RpcError::new(RpcErrorCode::MethodNotFound, format!("Invalid shv path: {}", shv_path))))
    }
    if method == METH_DIR && !is_mount_point {
        // dir in the middle of the tree must be resolved locally
        if let Ok(rpcmsg) = frame.to_rpcmesage() {
            let dir = dir(DIR_LS_METHODS.iter(), rpcmsg.param().into());
            return Some(Ok(dir))
        } else {
            return Some(Err(RpcError::new(RpcErrorCode::InvalidRequest, "Cannot convert RPC frame to Rpc message")))
        }
    }
    if method == METH_LS && !is_leaf {
        // ls on not-leaf node must be resolved locally
        if let Ok(rpcmsg) = frame.to_rpcmesage() {
            let ls = ls_children_to_result(children_on_path, rpcmsg.param().into());
            return Some(ls)
        } else {
            return Some(Err(RpcError::new(RpcErrorCode::InvalidRequest, "Cannot convert RPC frame to Rpc message")))
        }
    }
    None
}
fn ls_children_to_result(children: Option<Vec<String>>, param: LsParam) -> Result<RpcValue, RpcError> {
    match param {
        LsParam::List => {
            match children {
                None => {
                    Err(RpcError::new(RpcErrorCode::MethodCallException, "Invalid shv path"))
                }
                Some(dirs) => {
                    let res: rpcvalue::List = dirs.iter().map(RpcValue::from).collect();
                    Ok(res.into())
                }
            }
        }
        LsParam::Exists(path) => {
            match children {
                None => {
                    Ok(false.into())
                }
                Some(children) => {
                    Ok(children.contains(&path).into())
                }
            }
        }
    }
}
pub fn children_on_path<V>(mounts: &BTreeMap<String, V>, path: &str) -> Option<Vec<String>> {
    let mut dirs: Vec<String> = Vec::new();
    let mut unique_dirs: HashSet<String> = HashSet::new();
    let mut dir_exists = false;
    for (key, _) in mounts.range(path.to_string()..) {
        if key.starts_with(path) {
            if path.is_empty() || (key.len() > path.len() && key.as_bytes()[path.len()] == (b'/')) {
                dir_exists = true;
                let dir_rest_start = if path.is_empty() { 0 } else { path.len() + 1 };
                let mut updirs = key[dir_rest_start..].split('/');
                if let Some(dir) = updirs.next() {
                    if !unique_dirs.contains(dir) {
                        dirs.push(dir.to_string());
                        unique_dirs.insert(dir.to_string());
                    }
                }
            }
        } else {
            break;
        }
    }
    if dir_exists {
        Some(dirs)
    } else {
        None
    }
}
pub fn find_longest_prefix<'a, V>(map: &BTreeMap<String, V>, shv_path: &'a str) -> Option<(&'a str, &'a str)> {
    let mut path = shv_path;
    let mut rest = "";
    loop {
        if map.contains_key(path) {
            return Some((path, rest))
        }
        if path.is_empty() {
            break;
        }
        if let Some(slash_ix) = path.rfind('/') {
            path = &shv_path[..slash_ix];
            rest = &shv_path[(slash_ix + 1)..];
        } else {
            path = "";
            rest = shv_path;
        };
    }
    None
}

pub struct ShvNode {
    pub methods: Vec<&'static MetaMethod>,
}
impl ShvNode {
    pub fn is_request_granted(&self, rq: &RpcFrame) -> Option<&'static MetaMethod> {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            if let Some(rq_access) = rq.access_level() {
                let method = rq.method().unwrap_or_default();
                for mm in &self.methods {
                    if mm.name == method {
                        return if rq_access >= mm.access as i32 { Some(*mm) } else { None }
                    }
                }
            }
        }
        None
    }
    pub fn process_dir(methods: &[&'static MetaMethod], rq: &RpcMessage) -> Result<RpcValue, RpcError> {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            let resp = dir(methods.iter().copied(), rq.param().into());
            Ok(resp)
        } else {
            let errmsg = format!("Unknown method '{}:{}()', invalid path.", rq.shv_path().unwrap_or_default(), rq.method().unwrap_or_default());
            warn!("{}", &errmsg);
            Err(RpcError::new(RpcErrorCode::MethodNotFound, errmsg))
        }
    }
    pub fn process_ls(rq: &RpcMessage) -> Result<RpcValue, RpcError> {
        let shv_path = rq.shv_path().unwrap_or_default();
        if shv_path.is_empty() {
            match LsParam::from(rq.param()) {
                LsParam::List => {
                    Ok(rpcvalue::List::new().into())
                }
                LsParam::Exists(_path) => {
                    Ok(false.into())
                }
            }
        } else {
            let errmsg = format!("Unknown method '{}:{}()', invalid path.", rq.shv_path().unwrap_or_default(), rq.method().unwrap_or(""));
            warn!("{}", &errmsg);
            Err(RpcError::new(RpcErrorCode::MethodNotFound, errmsg))
        }
    }
}

pub const METH_DIR: &str = "dir";
pub const METH_LS: &str = "ls";
pub const METH_GET: &str = "get";
pub const METH_SET: &str = "set";
pub const SIG_CHNG: &str = "chng";
pub const METH_SHV_VERSION_MAJOR: &str = "shvVersionMajor";
pub const METH_SHV_VERSION_MINOR: &str = "shvVersionMinor";
pub const METH_NAME: &str = "name";
pub const METH_PING: &str = "ping";
pub const METH_VERSION: &str = "version";
pub const METH_SERIAL_NUMBER: &str = "serialNumber";

pub const META_METHOD_DIR: MetaMethod = MetaMethod { name: METH_DIR, flags: Flag::None as u32, access: AccessLevel::Browse, param: "DirParam", result: "DirResult", description: "" };
pub const META_METHOD_LS: MetaMethod = MetaMethod { name: METH_LS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "LsParam", result: "LsResult", description: "" };

pub const DIR_LS_METHODS: [MetaMethod; 2] = [
    MetaMethod { name: METH_DIR, flags: Flag::None as u32, access: AccessLevel::Browse, param: "DirParam", result: "DirResult", description: "" },
    MetaMethod { name: METH_LS, flags: Flag::None as u32, access: AccessLevel::Browse, param: "LsParam", result: "LsResult", description: "" },
];
/*
pub const PROPERTY_METHODS: [MetaMethod; 3] = [
    MetaMethod { name: METH_GET, flags: Flag::IsGetter as u32, access: Access::Browse, param: "", result: "", description: "" },
    MetaMethod { name: METH_SET, flags: Flag::IsSetter as u32, access: Access::Browse, param: "", result: "", description: "" },
    MetaMethod { name: SIG_CHNG, flags: Flag::IsSignal as u32, access: Access::Browse, param: "", result: "", description: "" },
];
const DEVICE_METHODS: [MetaMethod; 3] = [
    MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32, access: Access::Browse, param: "", result: "", description: "" },
    MetaMethod { name: METH_VERSION, flags: Flag::IsGetter as u32, access: Access::Browse, param: "", result: "", description: "" },
    MetaMethod { name: METH_SERIAL_NUMBER, flags: Flag::IsGetter as u32, access: Access::Browse, param: "", result: "", description: "" },
];
 */
pub struct AppNode {
    pub app_name: &'static str,
    pub shv_version_major: i32,
    pub shv_version_minor: i32,
}
impl Default for AppNode {
    fn default() -> Self {
        AppNode {
            app_name: "",
            shv_version_major: 3,
            shv_version_minor: 0,
        }
    }
}

const META_METH_APP_SHV_VERSION_MAJOR: MetaMethod = MetaMethod { name: METH_SHV_VERSION_MAJOR, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };
const META_METH_APP_SHV_VERSION_MINOR: MetaMethod = MetaMethod { name: METH_SHV_VERSION_MINOR, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };
const META_METH_APP_NAME: MetaMethod = MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };
const META_METH_APP_PING: MetaMethod = MetaMethod { name: METH_PING, flags: Flag::None as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };

impl AppNode {
    pub fn new_shvnode() -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_APP_SHV_VERSION_MAJOR,
            &META_METH_APP_SHV_VERSION_MINOR,
            &META_METH_APP_NAME,
            &META_METH_APP_PING,
        ] }
    }
}

const META_METH_VERSION: MetaMethod = MetaMethod { name: METH_VERSION, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };
const META_METH_NAME: MetaMethod = MetaMethod { name: METH_NAME, flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };
const META_METH_SERIAL_NUMBER: MetaMethod = MetaMethod { name: "serialNumber", flags: Flag::IsGetter as u32, access: AccessLevel::Browse, param: "", result: "", description: "" };

pub struct AppDeviceNode {
    pub device_name: &'static str,
    pub version: &'static str,
    pub serial_number: Option<String>,
}

impl AppDeviceNode {
    pub fn new_shvnode(&self) -> ShvNode {
        ShvNode { methods: vec![
            &META_METHOD_DIR,
            &META_METHOD_LS,
            &META_METH_NAME,
            &META_METH_VERSION,
            &META_METH_SERIAL_NUMBER,
        ] }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_mounts() {
        let mut mounts = BTreeMap::new();
        mounts.insert("a".into(), ());
        mounts.insert("a/1".into(), ());
        mounts.insert("b/2/C".into(), ());
        mounts.insert("b/2/D".into(), ());
        mounts.insert("b/3/E".into(), ());
        mounts.insert("a/xyz".into(), ());
        mounts.insert("a/1xyz".into(), ());
        assert_eq!(super::children_on_path(&mounts, ""), Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(super::children_on_path(&mounts, "a"), Some(vec!["1".to_string(), "1xyz".to_string(), "xyz".to_string()]));
        assert_eq!(super::children_on_path(&mounts, "a/x"), None);
        assert_eq!(super::children_on_path(&mounts, "a/1"), None);
        assert_eq!(super::children_on_path(&mounts, "b/2"), Some(vec!["C".to_string(), "D".to_string()]));
    }
}
