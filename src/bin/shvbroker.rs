use std::{fs};
use std::path::Path;
use async_std::task;
use log::*;
use simple_logger::SimpleLogger;
use shvrpc::util::{join_path, parse_log_verbosity};
use clap::{Parser};
use rusqlite::Connection;
use shvbroker::config::AccessControl;

#[derive(Parser, Debug)]
struct CliOpts {
    /// Config file path
    #[arg(long)]
    config: Option<String>,
    /// Create default config file if one specified by --config is not found
    #[arg(short, long)]
    create_default_config: bool,
    /// RW directory location, where access database will bee stored
    #[arg(short, long)]
    data_directory: Option<String>,
    /// Allow write to access database
    #[arg(short, long)]
    editable_access: Option<bool>,
    /// Verbose mode (module, .)
    #[arg(short = 'v', long = "verbose")]
    verbose: Option<String>,
}

pub(crate) fn main() -> shvrpc::Result<()> {
    let cli_opts = CliOpts::parse();

    let mut logger = SimpleLogger::new();
    logger = logger.with_level(LevelFilter::Info);
    if let Some(module_names) = cli_opts.verbose {
        for (module, level) in parse_log_verbosity(&module_names, module_path!()) {
            logger = logger.with_module_level(module, level);
        }
    }
    logger.init().unwrap();

    log::info!("=====================================================");
    log::info!("{} starting", std::module_path!());
    log::info!("=====================================================");
    //trace!("trace message");
    //debug!("debug message");
    //info!("info message");
    //warn!("warn message");
    //error!("error message");
    log!(target: "RpcMsg", Level::Debug, "RPC message");
    log!(target: "Access", Level::Debug, "Access control message");

    let config = if let Some(config_file) = &cli_opts.config {
        shvbroker::config::BrokerConfig::from_file_or_default(config_file, cli_opts.create_default_config)?
    } else {
        Default::default()
    };
    let data_dir = cli_opts.data_directory.or(config.data_directory).unwrap_or("/tmp/shvbroker/data".to_owned());
    let editable_access = cli_opts.editable_access.or(Some(config.editable_access)).unwrap_or(false);
    if editable_access {
        let access_file = join_path(&data_dir, "access.sqlite");
        if !Path::new(&access_file).exists() {
            create_access_sqlite(&access_file, &config.access)?;
        }
    }
    let (access, create_editable_access_file) = 'access: {
        //let mut create_editable_access_file = false;
        if editable_access {
            let file_name = join_path(&data_dir, "access.yaml");
            if Path::new(&file_name).exists() {
                info!("Loading access file {file_name}");
                match AccessControl::from_file(&file_name) {
                    Ok(acc) => {
                        break 'access (acc, false);
                    }
                    Err(err) => {
                        error!("Cannot read access file: {file_name} - {err}");
                    }
                }
            } else {
                create_editable_access_file = true;
            }
        }
        break 'access (config.access.clone(), create_editable_access_file);
    };
    if create_editable_access_file {
        let data_dir = &config.data_directory.clone().unwrap_or("/tmp/shvbroker/data".into());
        fs::create_dir_all(data_dir)?;
        let access_file = join_path(data_dir, "access.yaml");
        info!("Creating access file {access_file}");
        fs::write(access_file, serde_yaml::to_string(&access)?)?;
    }
    task::block_on(shvbroker::broker::accept_loop(config, access))
}

const TBL_MOUNTS: &str = "mounts";
const TBL_USERS: &str = "users";
const TBL_ROLES: &str = "roles";
const TBL_ACCESS: &str = "access";
fn create_access_sqlite(file_path: &str, access: &AccessControl) -> shvrpc::Result<()> {
    let conn = Connection::open(file_path)?;
    info!("Creating SQLite access tables: {file_path}");
    conn.execute(&format!(r#"
        CREATE TABLE IF NOT EXISTS {TBL_MOUNTS} (
            deviceId character varying PRIMARY KEY,
            mountPoint character varying,
            description character varying
        );
    "#), ())?;
    conn.execute(&format!(r#"
        CREATE TABLE IF NOT EXISTS {TBL_USERS} (
            name character varying PRIMARY KEY,
            password character varying,
            passwordType character varying,
            roles character varying
        );
    "#), ())?;
    conn.execute(&format!(r#"
        CREATE TABLE IF NOT EXISTS {TBL_ROLES} (
            name character varying PRIMARY KEY,
            roles character varying,
            profile character varying
        );
    "#), ())?;
    conn.execute(&format!(r#"
        CREATE TABLE IF NOT EXISTS {TBL_ACCESS} (
            role character varying,
            paths character varying,
            signal character varying,
            source character varying,
            accessGrant character varying,
            PRIMARY KEY (role, paths, signal, source)
        );
    "#), ())?;
    Ok(())
}


