use clap::Parser;
use rusqlite::{params, Connection, OpenFlags, Result};
use serde::Serialize;
use shvbroker::config::{AccessRule, Mount, Password, ProfileValue, Role, User};
use std::collections::BTreeMap;

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
        let access_role: String = row.get(3)?;

        let shv_ri = format!("{}:{}:*", if path.is_empty() { "**" } else { &path }, if method.is_empty() { "*" } else { &method });
        let grant = access_role.replace("dot_local", "dot-local");

        Ok((role, AccessRule { shv_ri, grant }))
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

// Command-line arguments for the database converter.
#[derive(clap::Parser, Debug)]
#[command(
    name = "db-convert",
    about = "A tool for converting legacy C++ shvbroker access databases to the Rust format"
)]
struct Args {
    /// Input SQLite database path
    #[arg(long)]
    input: String,

    /// Output SQLite database path
    #[arg(long)]
    output: String,
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

fn main() -> Result<()> {
    let args = Args::parse();
    let input_conn = Connection::open_with_flags(&args.input, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut output_conn = Connection::open(&args.output)?;

    let users = load_users(&input_conn)?;
    let mounts = load_mounts(&input_conn)?;
    let roles = load_roles(&input_conn)?;

    init_output_schema(&output_conn)?;
    insert_map(&mut output_conn, "users", &users)?;
    insert_map(&mut output_conn, "mounts", &mounts)?;
    insert_map(&mut output_conn, "roles", &roles)?;

    // println!("{:#?}", users);
    // println!("{:#?}", mounts);
    // println!("{:#?}", roles);

    Ok(())
}

