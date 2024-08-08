use std::fs;
use std::path::Path;
use async_std::task;
use log::*;
use simple_logger::SimpleLogger;
use shvrpc::util::{join_path, parse_log_verbosity};
use clap::{Args, Command, FromArgMatches, Parser};
use rusqlite::Connection;
use shvbroker::config::{AccessConfig, BrokerConfig};

#[derive(Parser, Debug)]
struct CliOpts {
    /// Config file path
    #[arg(short, long)]
    config: Option<String>,
    /// Create default config file if one specified by --config is not found
    #[arg(long)]
    create_config: bool,
    /// Write current config to file
    #[arg(long)]
    write_config: Option<String>,
    /// RW directory location, where access database will bee stored
    #[arg(short, long)]
    data_directory: Option<String>,
    /// Allow writing to access database
    #[arg(short, long)]
    use_config_db: bool,
    /// Verbose mode (module, .)
    #[arg(short = 'v', long = "verbose")]
    verbose: Option<String>,
}

pub(crate) fn main() -> shvrpc::Result<()> {
    let cli = Command::new("CLI");//.arg(arg!(-b - -built).action(clap::ArgAction::SetTrue));
    let cli = CliOpts::augment_args(cli);
    let cli_matches = cli.get_matches();
    let cli_use_access_db_set = cli_matches.try_get_one::<bool>("use_access_db").is_ok();
    let cli_opts = CliOpts::from_arg_matches(&cli_matches).map_err(|err| err.exit()).unwrap();

    let mut logger = SimpleLogger::new();
    logger = logger.with_level(LevelFilter::Info);
    if let Some(module_names) = cli_opts.verbose {
        for (module, level) in parse_log_verbosity(&module_names, module_path!()) {
            logger = logger.with_module_level(module, level);
        }
    }
    logger.init().unwrap();

    info!("=====================================================");
    info!("{} starting", module_path!());
    info!("=====================================================");
    //trace!("trace message");
    //debug!("debug message");
    //info!("info message");
    //warn!("warn message");
    //error!("error message");
    //log!(target: "RpcMsg", Level::Debug, "RPC message");
    //log!(target: "Access", Level::Debug, "Access control message");

    let config = if let Some(config_file) = &cli_opts.config {
        info!("Loading config file {config_file}");
        match BrokerConfig::from_file(config_file) {
            Ok(config) => {config}
            Err(err) => {
                if cli_opts.create_config {
                    if let Some(config_dir) = Path::new(config_file).parent() {
                        fs::create_dir_all(config_dir)?;
                    }
                    info!("Creating default config file: {config_file}");
                    let config = BrokerConfig::default();
                    fs::write(config_file, serde_yaml::to_string(&config)?)?;
                    config
                } else {
                    return Err(err);
                }
            }
        }
    } else {
        info!("Using default config");
        BrokerConfig::default()
    };
    let data_dir = cli_opts.data_directory.or(config.data_directory.clone()).unwrap_or("/tmp/shvbroker/data".to_owned());
    let use_config_db = (cli_use_access_db_set && cli_opts.use_config_db) || config.use_access_db;
    let access = if use_config_db {
        let config_file = join_path(&data_dir, "shvbroker.sqlite");
        if Path::new(&config_file).exists() {
            load_access_sqlite(&config_file)?
        } else {
            create_access_sqlite(&config_file, &config.access)?;
            config.access.clone()
        }
    } else {
        config.access.clone()
    };
    if let Some(file) = cli_opts.write_config {
        write_config_to_file(&file, &config, &access)?;
    }
    task::block_on(shvbroker::brokerimpl::accept_loop(config, access))
}

fn write_config_to_file(file: &str, config: &BrokerConfig, access: &AccessConfig) -> shvrpc::Result<()> {
    info!("Writing config to file: {file}");
    if let Some(path) = Path::new(file).parent() {
        fs::create_dir_all(path)?;
    }
    let mut config = config.clone();
    config.access = access.clone();
    fs::write(file, &serde_yaml::to_string(&config)?)?;
    Ok(())
}

const TBL_MOUNTS: &str = "mounts";
const TBL_USERS: &str = "users";
const TBL_ROLES: &str = "roles";
fn create_access_sqlite(file_path: &str, access: &AccessConfig) -> shvrpc::Result<()> {
    info!("Creating SQLite access tables: {file_path}");
    if let Some(path) = Path::new(file_path).parent() {
        fs::create_dir_all(path)?;
    }
    let conn = Connection::open(file_path)?;
    for tbl_name in [TBL_MOUNTS, TBL_USERS, TBL_ROLES] {
        conn.execute(&format!(r#"
            CREATE TABLE {tbl_name} (
                id character varying PRIMARY KEY,
                def character varying
            );
        "#), [])?;
    }
    for (id, def) in &access.mounts {
        debug!("Inserting mount: {id}");
        conn.execute(&format!(r#"
            INSERT INTO {TBL_MOUNTS} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    for (id, def) in &access.users {
        debug!("Inserting user: {id}");
        conn.execute(&format!(r#"
            INSERT INTO {TBL_USERS} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    for (id, def) in &access.roles {
        debug!("Inserting role: {id}");
        conn.execute(&format!(r#"
            INSERT INTO {TBL_ROLES} (id, def) VALUES (?1, ?2);
        "#), (&id, serde_json::to_string(&def)?))?;
    }
    Ok(())
}

fn load_access_sqlite(file_path: &String) -> shvrpc::Result<AccessConfig> {
    info!("Loading SQLite access tables: {file_path}");
    let conn = Connection::open(file_path)?;

    let mut access = AccessConfig {
        users: Default::default(),
        roles: Default::default(),
        mounts: Default::default(),
    };

    let mut stmt = conn.prepare(&format!("SELECT id, def FROM {TBL_USERS}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.users.insert(id, user);
    }

    let mut stmt = conn.prepare(&format!("SELECT id, def FROM {TBL_ROLES}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.roles.insert(id, user);
    }

    let mut stmt = conn.prepare(&format!("SELECT id, def FROM {TBL_MOUNTS}"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let def: String = row.get(1)?;
        let user = serde_json::from_str(&def)?;
        access.mounts.insert(id, user);
    }

    Ok(access)
}

