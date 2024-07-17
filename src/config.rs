use std::collections::HashMap;
use std::fs;
use std::path::Path;
use log::info;
use serde::{Serialize, Deserialize};
use shvrpc::client::ClientConfig;

#[derive(Serialize, Deserialize, Debug)]
pub struct BrokerConfig {
    pub listen: Listen,
    #[serde(default)]
    pub editable_access: bool,
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
    pub users: HashMap<String, User>,
    pub roles: HashMap<String, Role>,
    pub mounts: HashMap<String, Mount>,
}
#[derive(Serialize, Deserialize, Debug)]
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
    pub paths: String,
    #[serde(default)]
    pub signal: String,
    #[serde(default)]
    pub source: String,
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
    pub fn from_file_or_default(file_name: &str, create_if_not_exist: bool) -> shvrpc::Result<Self> {
        let file_path = Path::new(file_name);
        if file_path.exists() {
            info!("Loading config file {file_name}");
            return match Self::from_file(file_name) {
                Ok(cfg) => {
                    Ok(cfg)
                }
                Err(err) => {
                    Err(format!("Cannot read config file: {file_name} - {err}").into())
                }
            }
        } else if !create_if_not_exist {
            return Err(format!("Cannot find config file: {file_name}").into())
        }
        let config = Default::default();
        if create_if_not_exist {
            if let Some(config_dir) = file_path.parent() {
                fs::create_dir_all(config_dir)?;
            }
            info!("Creating default config file: {file_name}");
            fs::write(file_path, serde_yaml::to_string(&config)?)?;
        }
        Ok(config)
    }
}
impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            listen: Listen { tcp: Some("localhost:3755".to_string()), ssl: None },
            editable_access: false,
            data_directory: None,
            parent_broker: Default::default(),
            access: AccessControl {
                users: HashMap::from([
                    ("admin".to_string(), User { password: Password::Plain("admin".into()), roles: vec!["su".to_string()] }),
                    ("user".to_string(), User { password: Password::Plain("user".into()), roles: vec!["client".to_string()] }),
                    ("test".to_string(), User { password: Password::Plain("test".into()), roles: vec!["tester".to_string()] }),
                    ("child-broker".to_string(), User { password: Password::Plain("child-broker".into()), roles: vec!["child-broker".to_string()] }),
                    ("tester".to_string(), User { password: Password::Sha1("ab4d8d2a5f480a137067da17100271cd176607a1".into()), roles: vec!["tester".to_string()] }),
                ]),
                roles: HashMap::from([
                    ("su".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { paths: "**".to_string(), signal: "".to_string(), source: "".to_string(), grant: "su,dot-local".to_string() },
                        ],
                    }),
                    ("client".to_string(), Role { roles: vec!["ping".to_string(), "subscribe".to_string(), "browse".to_string()], access: vec![] }),
                    ("device".to_string(), Role { roles: vec!["client".to_string()], access: vec![] }),
                    //("parent-broker".to_string(), Role { roles: vec![],
                    //    access: vec![
                    //        AccessRule { paths: ".app/**".to_string(), methods: "".to_string(), grant: "rd".to_string() },
                    //        AccessRule { paths: ".app/broker/currentClient".to_string(), methods: "*subscribe".to_string(), grant: "wr".to_string() },
                    //        AccessRule { paths: ".app/broker/currentClient".to_string(), methods: "subscriptions".to_string(), grant: "rd".to_string() },
                    //    ]
                    //}),
                    ("child-broker".to_string(), Role { roles: vec!["device".to_string()], access: vec![] }),
                    ("tester".to_string(), Role {
                        roles: vec!["client".to_string()],
                        access: vec![
                            AccessRule { paths: "test/**".to_string(), signal: "".to_string(), source: "".to_string(), grant: "cfg".to_string() },
                        ],
                    }),
                    ("ping".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { paths: ".app".to_string(), signal: "ping".to_string(), source: "".to_string(), grant: "wr".to_string() },
                        ],
                    }),
                    ("subscribe".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { paths: ".app/broker/currentClient".to_string(), signal: "subscribe".to_string(), source: "".to_string(), grant: "wr".to_string() },
                            AccessRule { paths: ".app/broker/currentClient".to_string(), signal: "unsubscribe".to_string(), source: "".to_string(), grant: "wr".to_string() },
                        ],
                    }),
                    ("browse".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { paths: "**".to_string(), signal: "".to_string(), source: "".to_string(), grant: "bws".to_string() },
                        ],
                    }),
                ]),
                mounts: HashMap::from([
                    ("test-device".into(), Mount{ mount_point: "shv/test/device".to_string(), description: "Testing device mount-point".to_string() }),
                    ("test-child-broker".into(), Mount{ mount_point: "shv/test/child-broker".to_string(), description: "Testing child broker mount-point".to_string() }),
                ]),
            },
        }
    }
}
