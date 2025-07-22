use std::fs;
use std::path::Path;
use log::*;
use simple_logger::SimpleLogger;
use shvrpc::util::parse_log_verbosity;
use clap::{Args, Command, FromArgMatches, Parser};
use rusqlite::Connection;
use shvbroker::{brokerimpl::BrokerImpl, config::{AccessConfig, BrokerConfig, SharedBrokerConfig}};

#[derive(Parser, Debug)]
struct CliOpts {
    /// Print application version and exit
    #[arg(long)]
    version: bool,
    /// Config file path
    #[arg(short, long)]
    config: Option<String>,
    /// Print current config to stdout
    #[arg(long)]
    print_config: bool,
    /// RW directory location, where access database will bee stored
    #[arg(short, long)]
    data_directory: Option<String>,
    /// Allow writing to access database
    #[arg(short = 'b', long)]
    use_access_db: bool,
    /// Enable broker tunneling feature
    #[arg(long)]
    tunneling: bool,
    /// SHV2 compatibility mode
    #[arg(long = "shv2")]
    shv2_compatibility: bool,
    /// Verbose mode (module, .)
    #[arg(short = 'v', long = "verbose")]
    verbose: Option<String>,
}

pub(crate) fn main() -> shvrpc::Result<()> {
    const SMOL_THREADS: &str = "SMOL_THREADS";
    if std::env::var(SMOL_THREADS).is_err_and(|e| matches!(e, std::env::VarError::NotPresent)) {
        if let Ok(num_threads) = std::thread::available_parallelism() {
            unsafe {
                std::env::set_var(SMOL_THREADS, num_threads.to_string());
            }
        }
    }
    let cli = Command::new("CLI");//.arg(arg!(-b - -built).action(clap::ArgAction::SetTrue));
    let cli = CliOpts::augment_args(cli);
    let cli_matches = cli.get_matches();
    let cli_use_access_db_set = cli_matches.try_get_one::<bool>("use_access_db").is_ok();
    let cli_tunneling_set = cli_matches.try_get_one::<bool>("tunneling").is_ok();
    let cli_shv2_set = cli_matches.try_get_one::<bool>("shv2_compatibility").is_ok();
    let cli_opts = CliOpts::from_arg_matches(&cli_matches).map_err(|err| err.exit()).unwrap();

    if cli_opts.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());   
    }

    let mut logger = SimpleLogger::new();
    logger = logger.with_level(LevelFilter::Info);
    if let Some(module_names) = cli_opts.verbose {
        for (module, level) in parse_log_verbosity(&module_names, module_path!()) {
            if let Some(module) = module {
                logger = logger.with_module_level(module, level);
            } else {
                logger = logger.with_level(level);
            }
        }
    }
    logger.init().unwrap();

    info!("=====================================================");
    info!("{} ver. {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    info!("=====================================================");
    //trace!("trace message");
    //debug!("debug message");
    //info!("info message");
    //warn!("warn message");
    //error!("error message");
    //log!(target: "RpcMsg", Level::Debug, "RPC message");
    //log!(target: "Access", Level::Debug, "Access control message");

    let mut config = if let Some(config_file) = &cli_opts.config {
        info!("Loading config file {config_file}");
        match BrokerConfig::from_file(config_file) {
            Ok(config) => {config}
            Err(err) => {
                return Err(err);
            }
        }
    } else {
        info!("Using default config");
        BrokerConfig::default()
    };
    if cli_tunneling_set {
        config.tunnelling.enabled = cli_opts.tunneling;
    }
    if config.tunnelling.enabled {
        info!("Tunneling enabled");
    }
    if cli_shv2_set {
        config.shv2_compatibility = cli_opts.shv2_compatibility;
    }
    if config.shv2_compatibility {
        info!("Running in SHV2 compatibility mode");
    }
    let data_dir = cli_opts.data_directory.or(config.data_directory.clone()).unwrap_or("/tmp/shvbroker/data".to_owned());
    let use_access_db = (cli_use_access_db_set && cli_opts.use_access_db) || config.use_access_db;
    let (access, sql_connection) = if use_access_db {
        let config_file = Path::new(&data_dir).join("shvbroker.sqlite");
        if let Some(path) = config_file.parent() {
            fs::create_dir_all(path)?;
        }
        let create_db = !Path::new(&config_file).exists();
        let sql_connection = Connection::open(&config_file)?;
        let config = if create_db {
            info!("Creating SQLite access db: {}", config_file.to_str().expect("Invalid path"));
            create_access_sqlite(&sql_connection, &config.access)?;
            config.access.clone()
        } else {
            info!("Loading SQLite access db: {}", config_file.to_str().expect("Invalid path"));
            load_access_sqlite(&sql_connection)?
        };
        (config, Some(sql_connection))
    } else {
        (config.access.clone(), None)
    };
    if cli_opts.print_config {
        print_config(&config, &access)?;
        return Ok(());
    }
    info!("-----------------------------------------------------");
    let broker_impl = BrokerImpl::new(SharedBrokerConfig::new(config), access, sql_connection);
    smol::block_on(shvbroker::brokerimpl::run_broker(broker_impl))
}

fn print_config(config: &BrokerConfig, access: &AccessConfig) -> shvrpc::Result<()> {
    // info!("Writing config to file: {file}");
    // if let Some(path) = Path::new(file).parent() {
    //     fs::create_dir_all(path)?;
    // }
    let mut config = config.clone();
    config.access = access.clone();
    println!("{}", &serde_yaml::to_string(&config)?);
    Ok(())
}

const TBL_MOUNTS: &str = "mounts";
const TBL_USERS: &str = "users";
const TBL_ROLES: &str = "roles";
fn create_access_sqlite(sql_conn: &Connection, access: &AccessConfig) -> shvrpc::Result<()> {

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
