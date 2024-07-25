use std::collections::{BTreeMap};
use std::fs;
use serde::{Serialize, Deserialize};
use shvrpc::client::ClientConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BrokerConfig {
    pub listen: Listen,
    #[serde(default)]
    pub use_access_db: bool,
    #[serde(default)]
    pub data_directory: Option<String>,
    #[serde(default)]
    pub parent_broker: ParentBrokerConfig,
    #[serde(default)]
    pub access: AccessControl,
}
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParentBrokerConfig {
    #[serde(default)]
    pub enabled:bool,
    pub client: ClientConfig,
    pub exported_root: String,
}
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AccessControl {
    pub users: BTreeMap<String, User>,
    pub roles: BTreeMap<String, Role>,
    pub mounts: BTreeMap<String, Mount>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Listen {
    #[serde(default)]
    pub tcp: Option<String>,
    #[serde(default)]
    pub ssl: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub password: Password,
    pub roles: Vec<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Password {
    Plain(String),
    Sha1(String),
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Role {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessRule {
    #[serde(rename = "shvRI")]
    pub shv_ri: String,
    pub grant: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mount {
    #[serde(rename = "mountPoint")]
    pub mount_point: String,
    #[serde(default)]
    pub description: String,
}
impl AccessControl {
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
        Self {
            listen: Listen { tcp: Some("localhost:3755".to_string()), ssl: None },
            use_access_db: false,
            data_directory: None,
            parent_broker: Default::default(),
            access: AccessControl {
                users: BTreeMap::from([
                    ("admin".to_string(), User { password: Password::Plain("admin".into()), roles: vec!["su".to_string()] }),
                    ("user".to_string(), User { password: Password::Plain("user".into()), roles: vec!["client".to_string()] }),
                    ("test".to_string(), User { password: Password::Plain("test".into()), roles: vec!["tester".to_string()] }),
                    ("child-broker".to_string(), User { password: Password::Plain("child-broker".into()), roles: vec!["child-broker".to_string()] }),
                    ("tester".to_string(), User { password: Password::Sha1("ab4d8d2a5f480a137067da17100271cd176607a1".into()), roles: vec!["tester".to_string()] }),
                ]),
                roles: BTreeMap::from([
                    ("su".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: "**::".into(), grant: "su,dot-local".to_string() },
                        ],
                    }),
                    ("client".to_string(), Role { roles: vec!["ping".to_string(), "subscribe".to_string(), "browse".to_string()], access: vec![] }),
                    ("device".to_string(), Role { roles: vec!["client".to_string()], access: vec![] }),
                    //("parent-broker".to_string(), Role { roles: vec![],
                    //    access: vec![
                    //        AccessRule { paths: ".app/**".to_string(), methods: "".to_string(), grant: "rd".to_string() },
                    //        AccessRule { paths: ".broker/currentClient".to_string(), methods: "*subscribe".to_string(), grant: "wr".to_string() },
                    //        AccessRule { paths: ".broker/currentClient".to_string(), methods: "subscriptions".to_string(), grant: "rd".to_string() },
                    //    ]
                    //}),
                    ("child-broker".to_string(), Role { roles: vec!["device".to_string()], access: vec![] }),
                    ("tester".to_string(), Role {
                        roles: vec!["client".to_string()],
                        access: vec![
                            AccessRule { shv_ri: "test/**::".into(), grant: "cfg".to_string() },
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
                            AccessRule { shv_ri: "::".into(), grant: "bws".to_string() },
                        ],
                    }),
                ]),
                mounts: BTreeMap::from([
                    ("test-device".into(), Mount{ mount_point: "shv/test/device".to_string(), description: "Testing device mount-point".to_string() }),
                    ("test-child-broker".into(), Mount{ mount_point: "shv/test/child-broker".to_string(), description: "Testing child broker mount-point".to_string() }),
                ]),
            },
        }
    }
}
