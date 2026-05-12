use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

use log::{debug, info};
use async_sqlite::{ClientBuilder, Client};
use shvproto::RpcValue;

use crate::{brokerimpl::LastLogin, config::{AccessConfig, Policies, UpdateSqlOperation}};

pub const TBL_MOUNTS: &str = "mounts";
pub const TBL_USERS: &str = "users";
pub const TBL_ROLES: &str = "roles";
pub const TBL_POLICIES: &str = "policies";
pub const TBL_LAST_LOGIN: &str = "last_login";

pub async fn migrate_sqlite_connection(sql_config_file: &PathBuf, access: &AccessConfig, policies: &Policies) -> shvrpc::Result<(Client, AccessConfig, Policies, LastLogin)> {
    info!("Opening SQLite access db file: {}", sql_config_file.to_str().expect("Valid path"));
    let sql_connection = if sql_config_file == ":memory:" {
        // In memoty database is the default.
        ClientBuilder::new().open().await?
    } else {
        if let Some(path) = sql_config_file.parent() {
            fs::create_dir_all(path)?;
        }
        let db_file_exists = Path::new(&sql_config_file).exists();
        if !db_file_exists {
            info!("Creating new db file: {}", sql_config_file.to_str().expect("Valid path"));
        }

        let sql_connection = ClientBuilder::new()
            .path(sql_config_file)
            .open()
            .await?;

        sql_connection.conn_and_then(|sql_connection| {
            if sql_connection.is_readonly(sql_connection.db_name(0)?.as_str())? {
                return shvrpc::Result::Err("Couldn't open SQLite database as read-write".into());
            }
            Ok(())
        }).await?;

        sql_connection
    };
    let (access_config, policies, last_login) = load_access_sqlite(&sql_connection, access, policies, &LastLogin::default()).await?;

    Ok((sql_connection, access_config, policies, last_login))
}

async fn ensure_table_exists<TableElementType: serde::Serialize + Send + 'static>(sql_conn: &Client, tbl_name: &'static str, default_items: BTreeMap<String, TableElementType>) -> shvrpc::Result<()> {
    sql_conn.conn_and_then(move |sql_conn| {
        let result = sql_conn.query_row(&format!(r#"
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                AND name = '{tbl_name}';
            "#), [], |_| Ok(()));

        if result.is_ok() {
            return Ok(());
        }

        sql_conn.execute(&format!(r#"
                CREATE TABLE {tbl_name} (
                    id character varying PRIMARY KEY,
                    def character varying
                );
            "#), [])?;

        let query = format!(r#"INSERT INTO {tbl_name} (id, def) VALUES (?1, ?2);"#);
        let mut stmt = sql_conn.prepare(&query)?;
        for (id, def) in default_items {
            debug!("Inserting {id} into {tbl_name}");
            stmt.execute((id, serde_json::to_string(&def)?))?;
        }
        Ok(())
    }).await
}

pub(crate) async fn update_sql(oper: Vec<UpdateSqlOperation<'_>>, sql_connection: &async_sqlite::Client) -> shvrpc::Result<RpcValue> {
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

async fn load_access_sqlite(sql_conn: &Client, default_access: &AccessConfig, default_policies: &Policies, default_last_login: &LastLogin) -> shvrpc::Result<(AccessConfig, Policies, LastLogin)> {
    async fn load_table<TableElementType: serde::Serialize + for <'a> serde::Deserialize<'a> + 'static + Send>(sql_conn: &Client, table_name: &'static str, default_items: BTreeMap<String, TableElementType>) -> shvrpc::Result<BTreeMap<String, TableElementType>> {
        ensure_table_exists(sql_conn, table_name, default_items)
            .await
            .map_err(|err| err.to_string())?;
        sql_conn.conn_and_then(move |sql_conn| {

            let mut stmt = sql_conn.prepare(&format!("SELECT id, def FROM {table_name}"))?;
            let rows = stmt.query([])?;
            let first_two_columns = rows.mapped(|row| {
                let id: String = row.get(0)?;
                let def: String = row.get(1)?;
                Ok((id, def))
            }).collect::<Result<Vec<_>,_>>()?;

            let parsed_rows = first_two_columns
                .into_iter()
                .map(|(id, def)| serde_json::from_str(&def).map(|parsed| (id, parsed)))
                .collect::<Result<BTreeMap<_,_>,_>>()?;

            Ok(parsed_rows)
        }).await
    }

    let access = AccessConfig::new(
        load_table(sql_conn, TBL_USERS, default_access.users().clone()).await?,
        load_table(sql_conn, TBL_ROLES, default_access.roles().clone()).await?,
        load_table(sql_conn, TBL_MOUNTS, default_access.mounts().clone()).await?,
    );

    let policies = Policies::new(load_table(sql_conn, TBL_POLICIES, default_policies.get().clone()).await?);

    let last_login = load_table(sql_conn, TBL_LAST_LOGIN, default_last_login.get().iter().map(|(key, val)| (key.clone(), val.to_iso_string())).collect()).await?
        .into_iter()
        .filter_map(|(key, val): (String, String)|{
            let date_time = shvproto::DateTime::from_iso_str(&val).inspect_err(|err| log::error!("Couldn't parse last_login datetime string: {err}")).ok();
            date_time.map(|date_time| (key, date_time))
        }).collect();

    Ok((access, policies, LastLogin::new(last_login)))
}
