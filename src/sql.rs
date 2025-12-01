use std::{fs, path::{Path, PathBuf}};

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
    info!("Creating SQLite access db");
    for tbl_name in [TBL_MOUNTS, TBL_USERS, TBL_ROLES] {
        sql_conn.execute(&format!(r#"
            CREATE TABLE {tbl_name} (
                id character varying PRIMARY KEY,
                def character varying
            );
        "#), [])?;
    }
    for (id, def) in &access.mounts {
        debug!("Inserting mount: {id}");
        sql_conn.execute(&format!(r#"
            INSERT INTO {TBL_MOUNTS} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    for (id, def) in &access.users {
        debug!("Inserting user: {id}");
        sql_conn.execute(&format!(r#"
            INSERT INTO {TBL_USERS} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    for (id, def) in &access.roles {
        debug!("Inserting role: {id}");
        sql_conn.execute(&format!(r#"
            INSERT INTO {TBL_ROLES} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    Ok(())
}

fn load_access_sqlite(sql_conn: &Connection) -> shvrpc::Result<AccessConfig> {
    let mut access = AccessConfig {
        users: Default::default(),
        roles: Default::default(),
        mounts: Default::default(),
    };

    let mut stmt = sql_conn.prepare(&format!("SELECT id, def FROM {TBL_USERS}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.users.insert(id, user);
    }

    let mut stmt = sql_conn.prepare(&format!("SELECT id, def FROM {TBL_ROLES}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.roles.insert(id, user);
    }

    let mut stmt = sql_conn.prepare(&format!("SELECT id, def FROM {TBL_MOUNTS}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.mounts.insert(id, user);
    }

    Ok(access)
}
