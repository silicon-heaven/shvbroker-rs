use clap::Parser;
use rusqlite::{params, Connection, OpenFlags, Result};
use serde::Serialize;
use shvbroker::config::{AccessRule, Mount, Password, ProfileValue, Role, User};
use std::collections::BTreeMap;
use serde::Deserialize;
use shvbroker::config::{BrokerConfig, BrokerConnectionConfig, ConnectionKind, Listen, AzureConfig as BrokerAzureConfig};
use shvproto::RpcValue;
use shvrpc::client::ClientConfig;
use url::Url;
use std::path::Path;
use std::time::Duration;

fn load_users(conn: &Connection) -> Result<BTreeMap<String, User>> {
    let mut stmt = conn.prepare("SELECT name, password, passwordFormat, roles FROM acl_users")?;
    let mut rows = stmt.query([])?;

    let mut users = BTreeMap::new();

    while let Some(row) = rows.next()? {
        let name: String = row.get("name")?;
        let password: String = row.get("password")?;
        let password_format: Option<String> = row.get("passwordFormat")?;
        let roles_str: Option<String> = row.get("roles")?;

        let password = match password_format.as_deref() {
            Some("SHA1") => Password::Sha1(password),
            _ => Password::Plain(password),
        };

        let roles = roles_str
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        users.insert(name, User { password, roles });
    }

    Ok(users)
}

fn load_mounts(conn: &Connection) -> Result<BTreeMap<String, Mount>> {
    let mut stmt = conn.prepare("SELECT deviceId, mountPoint, description FROM acl_mounts")?;
    let mut rows = stmt.query([])?;

    let mut mounts = BTreeMap::new();

    while let Some(row) = rows.next()? {
        let device_id: String = row.get("deviceId")?;
        let mount_point: String = row.get("mountPoint")?;
        let description: String = row.get("description")?;

        mounts.insert(device_id, Mount { mount_point, description });
    }

    Ok(mounts)
}

fn load_roles(conn: &Connection) -> Result<BTreeMap<String, Role>> {
    // --- Load roles from acl_roles table ---
    let mut stmt = conn.prepare("SELECT name, roles, profile FROM acl_roles")?;
    let mut roles = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let roles_str: String = row.get(1)?;
        let profile_str: Option<String> = row.get(2).ok();

        // Parse roles (comma-separated)
        let role_list: Vec<String> = roles_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Parse profile JSON if not empty
        let profile = if let Some(s) = profile_str {
            if !s.trim().is_empty() {
                match serde_json::from_str::<ProfileValue>(&s) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("Failed to parse profile JSON for {name}: {e}");
                        Some(ProfileValue::Null)
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok((name, Role {
            roles: role_list,
            access: vec![],
            profile,
        }))
    })?
    .collect::<Result<BTreeMap<String, Role>, _>>()?;

    // --- Load access rules from acl_access table ---
    let mut stmt = conn.prepare(
        "SELECT role, path, method, accessRole, ruleNumber
         FROM acl_access
         ORDER BY role, ruleNumber ASC",
    )?;

    let access_rows = stmt.query_map([], |row| {
        let role: String = row.get(0)?;
        let path = row.get(1).map(|s: Option<String>| s.unwrap_or_default().trim().to_string())?;
        let method = row.get(2).map(|s: Option<String>| s.unwrap_or_default().trim().to_string())?;
        let grant: String = row.get(3)?;

        let shv_ri = format!("{}:{}", if path.is_empty() { "**" } else { &path }, if method.is_empty() { "*" } else { &method });
        let access_rule = AccessRule { shv_ri, grant };

        if let Err(err) = shvbroker::brokerimpl::ParsedAccessRule::try_from(&access_rule) {
            panic!("Cannot parse AccessRule from acl_access table, row: {row:?} error: {err}");
        }

        Ok((role, access_rule))
    })?;

    for row in access_rows {
        let (role_name, access_rule) = row?;
        if let Some(role) = roles.get_mut(&role_name) {
            role.access.push(access_rule);
        } else {
            // If acl_access has entry for undefined role, we can log it
            eprintln!("Warning: acl_access refers to undefined role '{role_name}'");
        }
    }

    Ok(roles)
}

// Inserts a map into a table as (id, def) pairs where `def` is serialized JSON.
fn insert_map<T: Serialize>(
    conn: &mut Connection,
    table: &str,
    map: &BTreeMap<String, T>,
) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare(&format!("INSERT OR REPLACE INTO {table} (id, def) VALUES (?1, ?2)"))?;
        for (key, value) in map {
            let json = serde_json::to_string(value)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            stmt.execute(params![key, json])?;
        }
    }
    tx.commit()
}

// Ensures that the output database has the necessary tables created.
fn init_output_schema(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, def TEXT NOT NULL)",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mounts (id TEXT PRIMARY KEY, def TEXT NOT NULL)",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, def TEXT NOT NULL)",
        [],
    )?;
    Ok(())
}

// Legacy config format:
//
//{
//         "server": {
//                 "port": 3755,
//                 "websocket": {
//                         "port": 3777,
//                 }
//         },
//         "sqlconfig": {
//                 "enabled": true,
//                 "database": "/opt/shv/var/shvbroker/shvbroker.cfg.db"
//         },
//         "masters": {
//                 "enabled": true,
//                 "connections": {
//                         "broker1": {
//                                 "enabled": true,
//                                 "exportedShvPath": "shv",
//                                 "login": {
//                                         "user": "user",
//                                         "password": "passwd",
//                                         "type": "sha1" //"plain"
//                                 },
//                                 "server": {
// 					                       "host": "ssl://10.0.0.1:1234",
// 					                       "peerVerify": false
//                                 },
//                                 "device": {
//                                         "id": "broker",
//                                         //"mountPoint": "test/broker1",
//                                         //"idFile": "some-id.txt"
//                                 },
//                                 "rpc": {
//                                         //"protocolType": "chainpack",
//                                         //"reconnectInterval": 10,
//                                         //"heartbeatInterval": 60,
//                                 },
//                         },
//                 }
//         }
//         "ldap": {
//                 "hostname": "ldaps://localhost:1234",
//                 "searchBaseDN": "dn1=val1,dn2=val2,dn3=val3",
//                 "searchAttrs": [""attr1", "attr2"],
//                 "groupMapping": [
//                       ["def2", "grp1"],
//                       ["def2", "grp2"]
//                 ],
//                 "username": "user",
//                 "password": "passwd"
//         },
//         "azure": {
//                 "groupMapping": [
//                     ["xyz-123-abc", "group1"],
//                     ["xyz-123-abc", "group2"],
//                     ["xyz-123-abc", "group3"]
//                 ],
//                 "clientId": "xyz-123-abc",
//                 "authorizeUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
//                 "tokenUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
//                 "scopes": "scope.x"
//         }
// }

#[derive(Debug, Deserialize)]
pub struct LegacyBrokerConfig {
    #[serde(default)]
    pub app: AppConfig,
    pub server: Option<ServerConfig>,
    pub sqlconfig: Option<SqlConfig>,
    pub masters: Option<MastersConfig>,
    pub ldap: Option<LdapConfig>,
    pub azure: Option<AzureConfig>,
}

fn default_broker_id() -> String {
    "broker.local".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self { broker_id: default_broker_id() }
    }
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    #[serde(rename = "brokerId", default = "default_broker_id")]
    pub broker_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: Option<u16>,
    #[serde(rename = "sslPort")]
    pub ssl_port: Option<u16>,
    pub websocket: Option<WebsocketConfig>,
    pub ssl: Option<SslConfig>,
}

#[derive(Debug, Deserialize)]
pub struct WebsocketConfig {
    pub port: Option<u16>,
    #[serde(rename = "sslport")]
    pub ssl_port: Option<u16>,
}

fn default_ssl_key() -> String {
    "server.key".into()
}

fn default_ssl_cert() -> String {
    "server.crt".into()
}

#[derive(Debug, Deserialize)]
pub struct SslConfig {
    #[serde(default = "default_ssl_key")]
    pub key: String,
    #[serde(default = "default_ssl_cert")]
    pub cert: String,
}

#[derive(Clone,Debug, Deserialize)]
pub struct SqlConfig {
    #[serde(default)]
    pub enabled: bool,
    pub database: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MastersConfig {
    #[serde(default)]
    pub enabled: bool,
    pub connections: BTreeMap<String, MasterConnection>,
}

#[derive(Debug, Deserialize)]
pub struct MasterConnection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "exportedShvPath")]
    pub exported_shv_path: Option<String>,
    pub login: Option<LoginConfig>,
    pub server: Option<MasterServerConfig>,
    pub device: Option<DeviceConfig>,
    pub rpc: Option<RpcConfig>,
}

#[derive(Debug, Deserialize)]
pub struct LoginConfig {
    pub user: String,
    pub password: String,
    #[serde(rename = "type")]
    pub password_type: Option<String>, // "sha1" or "plain"
}

#[derive(Debug, Deserialize)]
pub struct MasterServerConfig {
    pub host: String,
    #[serde(rename = "peerVerify")]
    pub peer_verify: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceConfig {
    pub id: Option<String>,
    #[serde(rename = "mountPoint")]
    pub mount_point: Option<String>,
    #[serde(rename = "idFile")]
    pub id_file: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    #[serde(rename = "protocolType")]
    pub protocol_type: Option<String>,
    #[serde(rename = "reconnectInterval")]
    pub reconnect_interval: Option<u64>,
    #[serde(rename = "heartbeatInterval")]
    pub heartbeat_interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LdapConfig {
    pub hostname: String,
    #[serde(rename = "searchBaseDN")]
    pub search_base_dn: String,
    #[serde(rename = "searchAttrs")]
    pub search_attrs: Option<Vec<String>>,
    #[serde(rename = "groupMapping")]
    pub group_mapping: Option<Vec<[String; 2]>>,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AzureConfig {
    #[serde(rename = "groupMapping")]
    pub group_mapping: Option<Vec<[String; 2]>>,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "authorizeUrl")]
    pub authorize_url: String,
    #[serde(rename = "tokenUrl")]
    pub token_url: String,
    pub scopes: Option<String>,
}

impl From<LegacyBrokerConfig> for BrokerConfig {
    fn from(cfg: LegacyBrokerConfig) -> Self {
        let mut listen = Vec::new();

        if let Some(server) = &cfg.server {
            if let Some(port) = server.port
                && let Ok(url) = Url::parse(&format!("tcp://127.0.0.1:{port}")) {
                    listen.push(Listen { url });
            }

            if let Some(ssl_port) = server.ssl_port
                && let Ok(mut url) = Url::parse(&format!("ssl://0.0.0.0:{ssl_port}"))
                    && let Some(ssl) = &server.ssl {
                        url.query_pairs_mut()
                            .append_pair("cert", &ssl.cert)
                            .append_pair("key", &ssl.key);
                        listen.push(Listen { url });
            }

            if let Some(ws) = &server.websocket {
                if let Some(port) = ws.port
                    && let Ok(url) = Url::parse(&format!("ws://127.0.0.1:{port}")) {
                        listen.push(Listen { url });
                }

                if let Some(ssl_port) = ws.ssl_port
                    && let Ok(mut url) = Url::parse(&format!("wss://0.0.0.0:{ssl_port}"))
                        && let Some(ssl) = &server.ssl {
                            url.query_pairs_mut()
                                .append_pair("cert", &ssl.cert)
                                .append_pair("key", &ssl.key);
                            listen.push(Listen { url });
                }
            }
        }

        let mut connections = Vec::new();

        if let Some(masters_cfg) = cfg.masters && masters_cfg.enabled {
            for (name, mconn) in masters_cfg.connections {
                let connection_kind = ConnectionKind::ToParentBroker {
                    shv_root: "".into(),
                };

                let base_host = mconn
                    .server
                    .as_ref()
                    .map(|s| s.host.clone())
                    .unwrap_or_else(|| "tcp://127.0.0.1".to_string());

                // Ensure the base_host has a scheme
                let normalized_host = if base_host.contains("://") {
                    base_host
                } else {
                    format!("tcp://{}", base_host)
                };

                let mut url = Url::parse(&normalized_host)
                    .unwrap_or_else(|_| Url::parse("tcp://127.0.0.1").unwrap());

                // Inject user and password
                if let Some(login) = &mconn.login {
                    // Set user as part of the authority
                    if url.set_username(&login.user).is_err() {
                        eprintln!("Cannot set username {user} for URL {url}", user = login.user);
                    }
                    // Add password as query parameter
                    url.query_pairs_mut()
                        .append_pair("password", &login.password);
                }

                // heartbeat/reconnect intervals
                let heartbeat_interval = mconn
                    .rpc
                    .as_ref()
                    .and_then(|r| r.heartbeat_interval)
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| Duration::from_secs(60));

                let reconnect_interval = mconn
                    .rpc
                    .as_ref()
                    .and_then(|r| r.reconnect_interval)
                    .map(Duration::from_secs);

                let client = ClientConfig {
                    url,
                    device_id: mconn.device.as_ref().and_then(|d| d.id.clone()),
                    mount: mconn.device.as_ref().and_then(|d| d.mount_point.clone()),
                    heartbeat_interval,
                    reconnect_interval,
                };

                connections.push(BrokerConnectionConfig {
                    name,
                    enabled: mconn.enabled,
                    connection_kind,
                    client,
                });
            }
        }

        let azure = cfg.azure.map(|az| {
            let group_mapping = az
                .group_mapping
                .unwrap_or_default()
                .into_iter()
                .map(|[native_group, shv_group]| (native_group, vec![shv_group]))
                .collect::<Vec<_>>();

            BrokerAzureConfig {
                group_mapping,
                client_id: az.client_id,
                authorize_url: az.authorize_url,
                token_url: az.token_url,
                scopes: az
                    .scopes
                    .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
                    .unwrap_or_default(),
            }
        });

        let data_directory = cfg.sqlconfig.as_ref().and_then(|sql| {
            sql.database
                .as_ref()
                .and_then(|db| Path::new(db).parent())
                .map(|p| p.to_string_lossy().to_string())
        });

        BrokerConfig {
            name: Some(cfg.app.broker_id),
            listen,
            use_access_db: cfg.sqlconfig.as_ref().is_some_and(|s| s.enabled),
            shv2_compatibility: false,
            time_broadcast: false,
            data_directory,
            connections,
            access: shvbroker::config::AccessConfig::default(),
            tunnelling: shvbroker::config::TunnellingConfig::default(),
            azure,
        }
    }
}

// Command-line arguments for the database converter.
#[derive(clap::Parser, Debug)]
#[command(
    name = "migrate_legacy_data",
    about = "A tool for converting legacy C++ shvbroker config file and access database to the format used by shvbroker-rs"
)]
struct Args {
    /// Path to the legacy config file
    #[arg(long)]
    legacy_config: String,

    /// Path to the converted config file
    #[arg(long)]
    result_config: Option<String>,
}

fn main() -> shvrpc::Result<()> {
    let args = Args::parse();

    let legacy_config_cpon = std::fs::read_to_string(&args.legacy_config)?;
    let legacy_config: LegacyBrokerConfig = shvproto::from_rpcvalue(&RpcValue::from_cpon(legacy_config_cpon)?)?;

    let legacy_sql_config = legacy_config.sqlconfig.clone();
    let mut broker_config: BrokerConfig = legacy_config.into();

    let config_dir = Path::new(&args.legacy_config).parent().unwrap_or_else(|| Path::new("."));
    let result_config = args.result_config.map_or_else(|| Path::new(config_dir).join("shvbroker.yml"), |path| path.into());

    println!("Migrating config file from: {from} to: {to}", from = args.legacy_config, to = result_config.to_str().unwrap_or_default());
    std::fs::write(result_config, serde_yaml::to_string(&broker_config)?)?;

    if broker_config.use_access_db {
        // Determine the data directory from the config directory if it wasn't specified as an absolute path.
        let data_dir = Path::new(&broker_config.data_directory.unwrap_or_default()).to_owned();
        let data_dir = if data_dir.is_relative() {
            config_dir.join(data_dir)
        } else {
            data_dir
        };
        println!("data dir: {data_dir:?}");
        broker_config.data_directory = Some(data_dir.to_string_lossy().into());

        let legacy_db_file_name = if let Some(legacy_sql_config) = legacy_sql_config
            && let Some(db) = legacy_sql_config.database {
                Path::new(&db)
                    .file_name()
                    .map_or_else(|| Path::new("shvbroker.cfg.db"), |file_name| Path::new(file_name))
                    .to_owned()
            } else {
                Path::new("shvbroker.cfg.db").to_owned()
        };
        let legacy_db_path = data_dir.join(legacy_db_file_name);
        let new_db_path = data_dir.join("shvbroker.sqlite");

        println!("Migrating the access database from: {from} to: {to}",
            from = legacy_db_path.to_string_lossy(),
            to = new_db_path.to_string_lossy()
        );

        let input_conn = Connection::open_with_flags(legacy_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut output_conn = Connection::open(new_db_path)?;

        let users = load_users(&input_conn)?;
        let mounts = load_mounts(&input_conn)?;
        let roles = load_roles(&input_conn)?;

        init_output_schema(&output_conn)?;
        insert_map(&mut output_conn, "users", &users)?;
        insert_map(&mut output_conn, "mounts", &mounts)?;
        insert_map(&mut output_conn, "roles", &roles)?;
    }

    Ok(())
}

