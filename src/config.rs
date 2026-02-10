use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::sync::Arc;
use crate::{brokerimpl::ParsedAccessRule, sql::{TBL_ALLOWED_IPS, TBL_MOUNTS, TBL_ROLES, TBL_USERS}};
use log::error;
use serde::{Serialize, Deserialize};
use shvproto::RpcValue;
use shvrpc::client::ClientConfig;
use smol::lock::RwLock;
use url::Url;

pub type SharedBrokerConfig = Arc<BrokerConfig>;
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BrokerConfig {
    #[serde(default)]
    pub name: Option<String>,
    pub listen: Vec<Listen>,
    #[serde(default)]
    pub use_access_db: bool,
    #[serde(default)]
    pub shv2_compatibility: bool,
    #[serde(default)]
    pub time_broadcast: bool,
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
    pub group_mapping: Vec<(String, Vec<String>)>,
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct TunnellingConfig {
    #[serde(default)]
    pub enabled:bool,
    #[serde(default)]
    pub tsub_support: bool,
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
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub connection_kind: ConnectionKind,
    pub client: ClientConfig,
}

type DeviceId = String;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AccessConfig {
    users: BTreeMap<String, User>,
    roles: BTreeMap<String, Role>,
    mounts: BTreeMap<DeviceId, Mount>,
    #[serde(default)]
    allowed_ips: BTreeMap<String, Vec<ipnet::IpNet>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Listen {
    pub url: Url,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct User {
    pub password: Password,
    pub roles: Vec<String>,
    #[serde(default)]
    pub deactivated: bool,
}

impl User {
    pub(crate) fn to_rpcvalue(&self) -> Result<RpcValue, String> {
        let cpon = serde_json::to_string(self).map_err(|e| e.to_string())?;
        RpcValue::from_cpon(&cpon).map_err(|e| e.to_string())
    }
    fn from_v2(user: UserV2) -> Result<Self, String> {
        Ok(Self {
            password: Password::from_v2(user.password)?,
            roles: user.roles,
            deactivated: false,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum ProfileValue {
    String(String),
    Int(i64),
    Bool(bool),
    Map(BTreeMap<String, ProfileValue>),
    List(Vec<ProfileValue>),
    #[default]
    Null,
}

impl ProfileValue {
    pub fn merge(&mut self, other: ProfileValue) {
        match (self, other) {
            (ProfileValue::Map(lhs_map), ProfileValue::Map(rhs_map)) => {
                for (key, rhs_val) in rhs_map {
                    match lhs_map.get_mut(&key) {
                        Some(lhs_val) => lhs_val.merge(rhs_val),
                        None => {
                            lhs_map.insert(key, rhs_val);
                        }
                    }
                }
            }
            (ProfileValue::List(lhs_list), ProfileValue::List(rhs_list)) => {
                lhs_list.extend_from_slice(&rhs_list);
            }
            // Ignore all other cases, values that are merged into self do not override self.
            _ => ()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Role {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub profile: Option<ProfileValue>,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

enum UpdateSqlOperation<'a> {
    Insert { table: &'a str, id: &'a str, json: String },
    Update { table: &'a str, id: &'a str, json: String },
    Delete { table: &'a str, id: &'a str },
}

pub(crate) fn parse_role_access_rules(role: &Role) -> shvrpc::Result<Vec<ParsedAccessRule>> {
    role.access
        .iter()
        .map(ParsedAccessRule::try_from)
        .collect::<Result<Vec<_>,_>>()
}

impl AccessConfig {
    pub fn new(
        users: BTreeMap<String, User>,
        roles: BTreeMap<String, Role>,
        mounts: BTreeMap<DeviceId, Mount>,
        allowed_ips: BTreeMap<String, Vec<ipnet::IpNet>>,
    ) -> Self {
        AccessConfig { users, roles, mounts, allowed_ips }
    }

    pub fn from_file(file_name: &str) -> shvrpc::Result<Self> {
        let content = fs::read_to_string(file_name)?;
        Ok(serde_yaml::from_str(&content)?)
    }

    pub(crate) fn users(&self) -> &BTreeMap<String, User> {
        &self.users
    }

    pub(crate) fn access_user(&self, id: &str) -> Option<&crate::config::User> {
        self.users.get(id)
    }

    async fn update_sql(&self, oper: Vec<UpdateSqlOperation<'_>>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
        let query = oper.into_iter().fold(String::new(), |mut acc, oper| {
            match oper {
                UpdateSqlOperation::Insert { table, id, json } => {
                    acc += &format!("INSERT INTO {table} (id, def) VALUES ('{id}', '{json}');");
                }
                UpdateSqlOperation::Update { table, id, json } => {
                    acc += &format!("UPDATE {table} SET def = '{json}' WHERE id = '{id}';");
                }
                UpdateSqlOperation::Delete { table, id } => {
                    acc += &format!("DELETE FROM {table} WHERE id = '{id}';");
                }
            };
            acc
        });

        sql_connection.conn(move |sql_connection| {
            sql_connection.execute(&query, ())
        }).await
            .map(|v| RpcValue::from(v as i64))
            .map_err(|err| shvrpc::rpcmessage::RpcError::new(shvrpc::rpcmessage::RpcErrorCode::MethodCallException, err.to_string()).into())
    }

    pub(crate) async fn set_access_user(&mut self, id: &str, user: Option<crate::config::User>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
        let sqlop = if let Some(user) = user {
            let json = serde_json::to_string(&user).unwrap_or_else(|e| {
                error!("Generate SQL self.ent error: {e}");
                "".to_string()
            });
            let sql = if self.users.contains_key(id) {
                vec![UpdateSqlOperation::Update { table: TBL_USERS,  id, json }]
            } else {
                vec![UpdateSqlOperation::Insert { table: TBL_USERS, id, json }]
            };
            self.users.insert(id.to_string(), user);
            sql
        } else {
            self.users.remove(id);
            let mut res = vec![UpdateSqlOperation::Delete { table: TBL_USERS, id }];
            if self.allowed_ips.remove(id).is_some() {
                res.push(UpdateSqlOperation::Delete { table: TBL_USERS, id })
            }
            res
        };
        self.update_sql(sqlop, sql_connection).await
    }

    pub(crate) fn mounts(&self) -> &BTreeMap<String, Mount> {
        &self.mounts
    }

    pub(crate) fn access_mount(&self, id: &str) -> Option<&crate::config::Mount> {
        self.mounts.get(id)
    }

    pub(crate) async fn set_access_mount(&mut self, id: &str, mount: Option<crate::config::Mount>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
        let sqlop = if let Some(mount) = mount {
            let json = serde_json::to_string(&mount).unwrap_or_else(|e| {
                error!("Generate SQL self.ent error: {e}");
                "".to_string()
            });
            let sql = if self.mounts.contains_key(id) {
                UpdateSqlOperation::Update {table: TBL_MOUNTS, id, json }
            } else {
                UpdateSqlOperation::Insert {table: TBL_MOUNTS, id, json }
            };
            self.mounts.insert(id.to_string(), mount);
            sql
        } else {
            self.mounts.remove(id);
            UpdateSqlOperation::Delete {table: TBL_MOUNTS, id }
        };
        self.update_sql(vec![sqlop], sql_connection).await
    }

    pub(crate) fn allowed_ips(&self) -> &BTreeMap<String, Vec<ipnet::IpNet>> {
        &self.allowed_ips
    }

    pub(crate) fn access_allowed_ips(&self, id: &str) -> Option<&Vec<ipnet::IpNet>> {
        self.allowed_ips.get(id)
    }

    pub(crate) async fn set_allowed_ips(&mut self, id: &str, allowed_ips: Option<Vec<ipnet::IpNet>>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
        let sqlop = if let Some(allowed_ips) = allowed_ips {
            let json = serde_json::to_string(&allowed_ips).unwrap_or_else(|e| {
                error!("Generate SQL self.ent error: {e}");
                "".to_string()
            });
            let sql = if self.allowed_ips.contains_key(id) {
                UpdateSqlOperation::Update {table: TBL_ALLOWED_IPS, id, json }
            } else {
                UpdateSqlOperation::Insert {table: TBL_ALLOWED_IPS, id, json }
            };
            self.allowed_ips.insert(id.to_string(), allowed_ips);
            sql
        } else {
            self.allowed_ips.remove(id);
            UpdateSqlOperation::Delete {table: TBL_ALLOWED_IPS, id }
        };
        self.update_sql(vec![sqlop], sql_connection).await
    }

    pub(crate) fn roles(&self) -> &BTreeMap<String, Role> {
        &self.roles
    }

    pub(crate) fn access_role(&self, id: &str) -> Option<&crate::config::Role> {
        self.roles.get(id)
    }

    pub(crate) async fn set_access_role(&mut self, role_name: &str, role: Option<Role>, role_access_rules: &RwLock<HashMap<String, Vec<ParsedAccessRule>>>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
        let sqlop = if let Some(role) = role {
            let parsed_access_rules = parse_role_access_rules(&role)?;
            let json = serde_json::to_string(&role).expect("JSON should be generated");
            let sql = if self.roles.contains_key(role_name) {
                UpdateSqlOperation::Update { table: TBL_ROLES, id: role_name, json }
            } else {
                UpdateSqlOperation::Insert { table: TBL_ROLES, id: role_name, json }
            };
            self.roles.insert(role_name.to_string(), role);
            role_access_rules.write().await.insert(role_name.to_string(), parsed_access_rules);
            sql
        } else {
            self.roles.remove(role_name);
            UpdateSqlOperation::Delete { table: TBL_ROLES, id: role_name }
        };
        self.update_sql(vec![sqlop], sql_connection).await
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
        let child_tcp_broker_config = BrokerConnectionConfig {
            name: "TCP-to-child-broker".to_string(),
            connection_kind: ConnectionKind::ToChildBroker { shv_root: "".to_string(), mount_point: "".to_string() },
            ..BrokerConnectionConfig::default()
        };
        let child_serial_broker_config = BrokerConnectionConfig {
            name: "serial-to-child-broker".to_string(),
            enabled: false,
            connection_kind: ConnectionKind::ToChildBroker { shv_root: "".to_string(), mount_point: "test/serial-brc".to_string() },
            client: ClientConfig {
                url: Url::parse("serial:/dev/ttyACM0?user=test").expect("Serial default URL must be valid"),
                ..ClientConfig::default()
            },
        };
        let child_can_broker_config = BrokerConnectionConfig {
            name: "CAN-to-child-broker".to_string(),
            enabled: false,
            connection_kind: ConnectionKind::ToChildBroker { shv_root: "".to_string(), mount_point: "test/serial-brc".to_string() },
            client: ClientConfig {
                url: Url::parse("can:vcan0?local_address=1&peer_address=2&user=test").expect("CAN default URL must be valid"),
                ..ClientConfig::default()
            },
        };
        Self {
            name: Some("foo".into()),
            listen: vec![Listen { url: Url::parse("tcp://localhost:3755").expect("TCP default URL should be valid") }],
            use_access_db: false,
            shv2_compatibility: false,
            time_broadcast: false,
            data_directory: None,
            connections: vec![
                BrokerConnectionConfig {
                    name: "TCP-to-parent-broker".to_string(),
                    ..BrokerConnectionConfig::default()
                },
                child_tcp_broker_config,
                child_serial_broker_config,
                child_can_broker_config,
            ],
            access: AccessConfig {
                users: BTreeMap::from([
                    ("admin".to_string(), User { password: Password::Plain("admin".into()), roles: vec!["su".to_string()], deactivated: false }),
                    ("user".to_string(), User { password: Password::Plain("user".into()), roles: vec!["client".to_string()], deactivated: false }),
                    ("test".to_string(), User { password: Password::Plain("test".into()), roles: vec!["tester".to_string()], deactivated: false }),
                    ("viewer".to_string(), User { password: Password::Plain("viewer".into()), roles: ["subscribe", "browse"].iter().map(|s| s.to_string()).collect(), deactivated: false }),
                    ("child-broker".to_string(), User { password: Password::Plain("child-broker".into()), roles: vec!["child-broker".to_string()], deactivated: false }),
                    ("tester".to_string(), User { password: Password::Sha1("ab4d8d2a5f480a137067da17100271cd176607a1".into()), roles: vec!["tester".to_string()], deactivated: false }),
                ]),
                roles: BTreeMap::from([
                    ("su".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: "**:*".into(), grant: "su,dot_local".to_string() },
                        ],
                        profile: None,
                    }),
                    ("client".to_string(), Role {
                        roles: vec!["ping".to_string(), "subscribe".to_string(), "browse".to_string()],
                        access: vec![
                            AccessRule { shv_ri: ".broker/currentClient:*".into(), grant: "wr".to_string() },
                        ],
                        profile: None,
                    }),
                    ("device".to_string(), Role {
                        roles: vec!["client".to_string()],
                        access: vec![],
                        profile: None,
                    }),
                    ("child-broker".to_string(), Role {
                        roles: vec!["device".to_string()],
                        access: vec![],
                        profile: None,
                    }),
                    ("tester".to_string(), Role {
                        roles: vec!["client".to_string()],
                        access: vec![
                            AccessRule { shv_ri: ".app/tunnel:create".into(), grant: "wr".to_string() },
                            AccessRule { shv_ri: ".app/tunnel:ls".into(), grant: "su".to_string() },
                            AccessRule { shv_ri: ".app/tunnel:dir".into(), grant: "su".to_string() },
                            AccessRule { shv_ri: "test/**:*".into(), grant: "cfg".to_string() },
                        ],
                        profile: None,
                    }),
                    ("ping".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: ".app:ping".into(), grant: "wr".to_string() },
                        ],
                        profile: None,
                    }),
                    ("subscribe".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: ".broker/currentClient:subscribe".into(), grant: "wr".to_string() },
                            AccessRule { shv_ri: ".broker/currentClient:unsubscribe".into(), grant: "wr".to_string() },
                        ],
                        profile: None,
                    }),
                    ("browse".to_string(), Role {
                        roles: vec![],
                        access: vec![
                            AccessRule { shv_ri: "**:*".into(), grant: "bws".to_string() },
                        ],
                        profile: None,
                    }),
                ]),
                mounts: BTreeMap::from([
                    ("test-device".into(), Mount{ mount_point: "test/device".to_string(), description: "Testing device mount-point".to_string() }),
                    ("test-child-broker".into(), Mount{ mount_point: "test/child-broker".to_string(), description: "Testing child broker mount-point".to_string() }),
                ]),
                allowed_ips: Default::default(),
            },
            tunnelling: Default::default(),
            azure: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    mod profile_value {
        use super::super::*;

        fn map(entries: impl IntoIterator<Item = (&'static str, ProfileValue)>) -> ProfileValue {
            ProfileValue::Map(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        }

        #[test]
        fn merge_simple() {
            let mut a = ProfileValue::Int(10);
            a.merge(ProfileValue::Int(20));
            assert_eq!(a, ProfileValue::Int(10));
        }

        #[test]
        fn merge_null_does_not_replace() {
            let mut a = ProfileValue::String("Hello".into());
            a.merge(ProfileValue::Null);
            assert_eq!(a, ProfileValue::String("Hello".into()));
        }

        #[test]
        fn merge_map_adds_new_keys() {
            let mut a = map([
                ("name", ProfileValue::String("Alice".into())),
            ]);

            let b = map([
                ("age", ProfileValue::Int(30)),
            ]);

            a.merge(b);

            assert_eq!(
                a,
                map([
                    ("name", ProfileValue::String("Alice".into())),
                    ("age", ProfileValue::Int(30)),
                ])
            );
        }

        #[test]
        fn merge_map_does_not_replace_non_map_values() {
            let mut a = map([
                ("name", ProfileValue::String("Alice".into())),
            ]);

            let b = map([
                ("name", ProfileValue::String("Bob".into())),
            ]);

            a.merge(b);

            assert_eq!(
                a,
                map([("name", ProfileValue::String("Alice".into()))])
            );
        }

        #[test]
        fn merge_map_merges_recursively() {
            let mut a = map([
                ("settings", map([
                                 ("dark_mode", ProfileValue::Bool(false)),
                                 ("volume", ProfileValue::Int(5)),
                ])),
            ]);

            let b = map([
                ("settings", map([
                                 ("volume", ProfileValue::Int(10)),
                                 ("notifications", ProfileValue::Bool(true)),
                ])),
            ]);

            a.merge(b);

            assert_eq!(
                a,
                map([(
                        "settings",
                        map([
                            ("dark_mode", ProfileValue::Bool(false)),
                            ("volume", ProfileValue::Int(5)),
                            ("notifications", ProfileValue::Bool(true)),
                        ])
                )])
            );
        }

        #[test]
        fn merge_non_map_not_replaced_by_map() {
            let mut a = ProfileValue::Int(5);
            let b = map([("key", ProfileValue::Bool(true))]);
            a.merge(b.clone());
            assert_eq!(a, ProfileValue::Int(5));
        }

        #[test]
        fn merge_map_with_null_value() {
            let mut a = map([
                ("theme", ProfileValue::String("light".into())),
            ]);

            let b = map([
                ("theme", ProfileValue::Null),
            ]);

            a.merge(b);

            assert_eq!(
                a,
                map([("theme", ProfileValue::String("light".into()))])
            );
        }

        #[test]
        fn merge_list_concats() {
            let mut a = ProfileValue::List(vec![ProfileValue::Int(1)]);
            let b = ProfileValue::List(vec![ProfileValue::Int(2), ProfileValue::Int(3)]);
            a.merge(b.clone());
            assert_eq!(a, ProfileValue::List(vec![ProfileValue::Int(1), ProfileValue::Int(2), ProfileValue::Int(3)]));
        }

        #[test]
        fn merge_null_into_null_remains_null() {
            let mut a = ProfileValue::Null;
            a.merge(ProfileValue::Null);
            assert_eq!(a, ProfileValue::Null);
        }
    }
}
