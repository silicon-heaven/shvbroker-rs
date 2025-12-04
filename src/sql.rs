use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

use log::{debug, info};
use rusqlite::Connection;

use crate::config::AccessConfig;

const TBL_MOUNTS: &str = "mounts";
const TBL_USERS: &str = "users";
const TBL_ROLES: &str = "roles";

pub fn migrate_sqlite_connection(sql_config_file: &PathBuf, access: &AccessConfig) -> shvrpc::Result<(Connection, AccessConfig)> {
    info!("Opening SQLite access db file: {}", sql_config_file.to_str().expect("Valid path"));
    let (sql_connection, db_is_empty) = if sql_config_file == ":memory:" {
        (Connection::open_in_memory()?, true)
    } else {
        if let Some(path) = sql_config_file.parent() {
            fs::create_dir_all(path)?;
        }
        let db_file_exists = Path::new(&sql_config_file).exists();
        if !db_file_exists {
            info!("Creating new db file: {}", sql_config_file.to_str().expect("Valid path"));
        }
        let sql_connection = Connection::open(sql_config_file)?;

        if sql_connection.is_readonly(sql_connection.db_name(0)?.as_str())? {
            return Err("Couldn't open SQLite database as read-write".into());
        }

        (sql_connection, !db_file_exists)
    };
    let access_config = init_access_db(&sql_connection, db_is_empty, access)?;

    Ok((sql_connection, access_config))
}

fn init_access_db(sql_connection: &Connection, db_is_empty: bool, access: &AccessConfig) -> shvrpc::Result<AccessConfig> {
    let access_config = if db_is_empty {
        create_access_sqlite(sql_connection, access)?;
        access.clone()
    } else {
        load_access_sqlite(sql_connection)?
    };
    Ok(access_config)
}

fn create_access_sqlite(sql_conn: &Connection, access: &AccessConfig) -> shvrpc::Result<()> {
    fn save_table<TableElementType: serde::Serialize>(sql_conn: &rusqlite::Connection, tbl_name: &str, items: &BTreeMap<String, TableElementType>) -> shvrpc::Result<()> {
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
            stmt.execute((id, serde_json::to_string(def)?))?;
        }
        Ok(())
    }

    info!("Creating SQLite access db");
    save_table(sql_conn, TBL_MOUNTS, &access.mounts)?;
    save_table(sql_conn, TBL_USERS, &access.users)?;
    save_table(sql_conn, TBL_ROLES, &access.roles)?;

    Ok(())
}

fn load_access_sqlite(sql_conn: &Connection) -> shvrpc::Result<AccessConfig> {
    fn load_table<TableElementType: for <'a> serde::Deserialize<'a>>(sql_conn: &Connection, table_name: &str) -> shvrpc::Result<BTreeMap<String, TableElementType>> {
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
    }

    Ok(AccessConfig {
        users: load_table(sql_conn, TBL_USERS)?,
        roles: load_table(sql_conn, TBL_ROLES)?,
        mounts: load_table(sql_conn, TBL_MOUNTS)?,
    })
}
