use std::collections::{BTreeMap};
use std::fs;
use serde::{Serialize, Deserialize};
use shvproto::RpcValue;
use shvrpc::client::ClientConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BrokerConfig {
    pub listen: Listen,
    #[serde(default)]
    pub use_access_db: bool,
    #[serde(default)]
    pub shv2_compatibility: bool,
    #[serde(default)]
    pub data_directory: Option<String>,
    #[serde(default)]
    pub connections: Vec<BrokerConnectionConfig>,
    #[serde(default)]
    pub access: AccessConfig,
    #[serde(default)]
    pub tunnelling: TunnellingConfig,
    #[serde(default)]
    pub azure: Option<AzureConfig>,
}
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct AzureConfig {
    #[serde(default)]
    pub group_mapping: BTreeMap<String, Vec<String>>,
    pub client_id: String,
}
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct TunnellingConfig {
    #[serde(default)]
    pub enabled:bool,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ConnectionKind {
    ToParentBroker {shv_root: String},
    ToChildBroker {shv_root: String, mount_point: String},
}
impl Default for ConnectionKind {
    fn default() -> Self {
        ConnectionKind::ToParentBroker { shv_root: "".to_string() }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrokerConnectionConfig {
    #[serde(default)]
    pub enabled:bool,
    #[serde(default)]
    pub connection_kind: ConnectionKind,
    pub client: ClientConfig,
}
type DeviceId = String;
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AccessConfig {
    pub users: BTreeMap<String, User>,
    pub roles: BTreeMap<String, Role>,
    pub mounts: BTreeMap<DeviceId, Mount>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Listen {
    #[serde(default)]
    pub tcp: Option<String>,
    #[serde(default)]
    pub ssl: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(PartialEq)]
pub struct User {
    pub password: Password,
    pub roles: Vec<String>,
}
impl User {
    pub(crate) fn to_rpcvalue(&self) -> Result<RpcValue, String> {
        let cpon = serde_json::to_string(self).map_err(|e| e.to_string())?;
        RpcValue::from_cpon(&cpon).map_err(|e| e.to_string())
    }
    fn from_v2(user: UserV2) -> Result<Self, String> {
        Ok(Self {
            password: Password::from_v2(user.password)?,
            roles: user.roles
        })
    }
}
impl TryFrom<&RpcValue> for User {
    type Error = String;
    fn try_from(value: &RpcValue) -> Result<Self, Self::Error> {
        let cpon = value.to_cpon();
        match serde_json::from_str(&cpon) {
            Ok(user) => { Ok(user) }
            Err(e) => {
                match UserV2::try_from(cpon.as_str()) {
                    Ok(user) => { User::from_v2(user) }
                    Err(_) => { Err(e.to_string()) }
                }
            }
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(PartialEq)]
pub enum Password {
    Plain(String),
    Sha1(String),
}
impl Password {
    fn from_v2(password: PasswordV2) -> Result<Self, String> {
        let format = password.format.to_lowercase();
        match format.as_str()  {
            "plain" => { Ok(Password::Plain(password.password)) }
            "sha1" => { Ok(Password::Sha1(password.password)) }
            s => { Err(format!("Invalid password format {s}")) }
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserV2 {
    pub password: PasswordV2,
    pub roles: Vec<String>,
}
impl TryFrom<&str> for UserV2 {
    type Error = String;
    fn try_from(cpon: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(cpon).map_err(|e| e.to_string())
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordV2 {
    format: String,
    password: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(PartialEq)]
pub struct Role {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
}
impl Role {
    pub(crate) fn to_rpcvalue(&self) -> Result<RpcValue, String> {
        let cpon = serde_json::to_string(self).map_err(|e| e.to_string())?;
        RpcValue::from_cpon(&cpon).map_err(|e| e.to_string())
    }
}
impl TryFrom<&RpcValue> for Role {
    type Error = String;
    fn try_from(value: &RpcValue) -> Result<Self, Self::Error> {
        let cpon = value.to_cpon();
        serde_json::from_str(&cpon).map_err(|e| e.to_string())
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(PartialEq)]
pub struct AccessRule {
    #[serde(rename = "shvRI")]
    pub shv_ri: String,
    pub grant: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Mount {
    #[serde(rename = "mountPoint")]
    pub mount_point: String,
    #[serde(default)]
    pub description: String,
}

impl Mount {
    pub(crate) fn to_rpcvalue(&self) -> Result<RpcValue, String> {
        let cpon = serde_json::to_string(self).map_err(|e| e.to_string())?;
        RpcValue::from_cpon(&cpon).map_err(|e| e.to_string())
    }
}
impl TryFrom<&RpcValue> for Mount {
    type Error = String;
    fn try_from(value: &RpcValue) -> Result<Self, Self::Error> {
        let cpon = value.to_cpon();
        serde_json::from_str(&cpon).map_err(|e| e.to_string())
    }
}
impl AccessConfig {
    pub fn from_file(file_name: &str) -> shvrpc::Result<Self> {
        let content = fs::read_to_string(file_name)?;
        Ok(serde_yaml::from_str(&content)?)
    }
}
impl BrokerConfig {
    pub fn from_file(file_name: &str) -> shvrpc::Result<Self> {
        let content = fs::read_to_string(file_name)?;
        Ok(serde_yaml::from_str(&content)?)
    }
}
impl Default for BrokerConfig {
    fn default() -> Self {
        let child_broker_config = BrokerConnectionConfig {
            connection_kind: ConnectionKind::ToChildBroker { shv_root: "".to_string(), mount_point: "".to_string() },
            ..BrokerConnectionConfig::default()
        };
        Self {
            listen: Listen { tcp: Some("localhost:3755".to_string()), ssl: None },
            use_access_db: false,
            shv2_compatibility: false,
            data_directory: None,
            connections: vec![
                BrokerConnectionConfig::default(),
                child_broker_config,
            ],
            access: AccessConfig {
                users: BTreeMap::from([
                    ("admin".to_string(), User { password: Password::Plain("admin".into()), roles: vec!["su".to_string()] }),
                    ("user".to_string(), User { password: Password::Plain("user".into()), roles: vec!["client".to_string()] }),
                    ("test".to_string(), User { password: Password::Plain("test".into()), roles: vec!["tester".to_string()] }),
                    ("viewer".to_string(), User { password: Password::Plain("viewer".into()), roles: ["subscribe", "browse"].iter().map(|s| s.to_string()).collect() }),
                    ("child-broker".to_string(), User { password: Password::Plain("child-broker".into()), roles: vec!["child-broker".to_string()] }),
                    ("tester".to_string(), User { password: Password::Sha1("ab4d8d2a5f480a137067da17100271cd176607a1".into()), roles: vec!["tester".to_string()] }),
                ]),
                roles: BTreeMap::from([
                    ("su".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: "**:*".into(), grant: "su,dot-local".to_string() },
                        ],
                    }),
                    ("client".to_string(), Role { roles: vec!["ping".to_string(), "subscribe".to_string(), "browse".to_string()], access: vec![] }),
                    ("device".to_string(), Role { roles: vec!["client".to_string()], access: vec![] }),
                    ("child-broker".to_string(), Role { roles: vec!["device".to_string()], access: vec![] }),
                    ("tester".to_string(), Role {
                        roles: vec!["client".to_string()],
                        access: vec![
                            AccessRule { shv_ri: ".app/tunnel:create".into(), grant: "wr".to_string() },
                            AccessRule { shv_ri: ".app/tunnel:ls".into(), grant: "su".to_string() },
                            AccessRule { shv_ri: ".app/tunnel:dir".into(), grant: "su".to_string() },
                            AccessRule { shv_ri: "test/**:*".into(), grant: "cfg".to_string() },
                        ],
                    }),
                    ("ping".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: ".app:ping".into(), grant: "wr".to_string() },
                        ],
                    }),
                    ("subscribe".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: ".broker/currentClient:subscribe".into(), grant: "wr".to_string() },
                            AccessRule { shv_ri: ".broker/currentClient:unsubscribe".into(), grant: "wr".to_string() },
                        ],
                    }),
                    ("browse".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: "**:*".into(), grant: "bws".to_string() },
                        ],
                    }),
                ]),
                mounts: BTreeMap::from([
                    ("test-device".into(), Mount{ mount_point: "test/device".to_string(), description: "Testing device mount-point".to_string() }),
                    ("test-child-broker".into(), Mount{ mount_point: "test/child-broker".to_string(), description: "Testing child broker mount-point".to_string() }),
                ]),
            },
            tunnelling: Default::default(),
            azure: Default::default(),
        }
    }
}
