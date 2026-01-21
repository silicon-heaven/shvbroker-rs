use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

use log::{debug, info};
use async_sqlite::{ClientBuilder, Client};

use crate::config::AccessConfig;

pub const TBL_MOUNTS: &str = "mounts";
pub const TBL_USERS: &str = "users";
pub const TBL_ROLES: &str = "roles";
pub const TBL_ALLOWED_IPS: &str = "allowed_ips";

pub async fn migrate_sqlite_connection(sql_config_file: &PathBuf, access: &AccessConfig) -> shvrpc::Result<(Client, AccessConfig)> {
    info!("Opening SQLite access db file: {}", sql_config_file.to_str().expect("Valid path"));
    let (sql_connection, db_is_empty) = if sql_config_file == ":memory:" {
        // In memoty database is the default.
        (ClientBuilder::new().open().await?, true)
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

        (sql_connection, !db_file_exists)
    };
    let access_config = init_access_db(&sql_connection, db_is_empty, access).await?;

    Ok((sql_connection, access_config))
}

async fn init_access_db(sql_connection: &Client, db_is_empty: bool, access: &AccessConfig) -> shvrpc::Result<AccessConfig> {
    let access_config = if db_is_empty {
        create_access_sqlite(sql_connection, access).await?;
        access.clone()
    } else {
        load_access_sqlite(sql_connection).await?
    };
    Ok(access_config)
}

async fn create_access_sqlite(sql_conn: &Client, access: &AccessConfig) -> shvrpc::Result<()> {
    async fn save_table<TableElementType: serde::Serialize + Send + 'static>(sql_conn: &Client, tbl_name: &'static str, items: BTreeMap<String, TableElementType>) -> shvrpc::Result<()> {
        sql_conn.conn_and_then(move |sql_conn| {
            sql_conn.execute(&format!(r#"
                CREATE TABLE {tbl_name} (
                    id character varying PRIMARY KEY,
                    def character varying
                );
            "#), [])?;
            let query = format!(r#"INSERT INTO {tbl_name} (id, def) VALUES (?1, ?2);"#);
            let mut stmt = sql_conn.prepare(&query)?;
            for (id, def) in items {
                debug!("Inserting {id} into {tbl_name}");
                stmt.execute((id, serde_json::to_string(&def)?))?;
            }
            Ok(())
        }).await
    }

    info!("Creating SQLite access db");
    save_table(sql_conn, TBL_MOUNTS, access.mounts.clone()).await?;
    save_table(sql_conn, TBL_USERS, access.users.clone()).await?;
    save_table(sql_conn, TBL_ROLES, access.roles.clone()).await?;
    save_table(sql_conn, TBL_ALLOWED_IPS, access.allowed_ips.clone()).await?;

    Ok(())
}

async fn load_access_sqlite(sql_conn: &Client) -> shvrpc::Result<AccessConfig> {
    async fn load_table<TableElementType: for <'a> serde::Deserialize<'a> + 'static + Send>(sql_conn: &Client, table_name: &'static str) -> shvrpc::Result<BTreeMap<String, TableElementType>> {
        sql_conn.conn_and_then(move |sql_conn| {
            sql_conn.execute(&format!(r#"
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id character varying PRIMARY KEY,
                    def character varying
                );
            "#), [])
                .map_err(|err| err.to_string())?;

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

    Ok(AccessConfig {
        users: load_table(sql_conn, TBL_USERS).await?,
        roles: load_table(sql_conn, TBL_ROLES).await?,
        mounts: load_table(sql_conn, TBL_MOUNTS).await?,
        allowed_ips: load_table(sql_conn, TBL_ALLOWED_IPS).await?,
    })
}
