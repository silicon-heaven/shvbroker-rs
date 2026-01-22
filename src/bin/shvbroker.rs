use std::{path::Path, sync::Arc};
use log::*;
use simple_logger::SimpleLogger;
use shvrpc::util::parse_log_verbosity;
use clap::{Parser};
use shvbroker::{brokerimpl::BrokerImpl, config::{AccessConfig, BrokerConfig, SharedBrokerConfig}, sql::{self}};

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
    /// Runtime data directory, for storing the access database
    #[arg(short, long)]
    data_directory: Option<String>,
    /// Enable saving runtime data to an SQL database
    #[arg(short = 'b', long)]
    use_access_db: bool,
    /// Disable saving runtime data to an SQL database, takes precedence over --use-access-db
    #[arg(long)]
    no_use_access_db: bool,
    /// Enable broker tunneling feature
    #[arg(long)]
    tunneling: bool,
    /// Disable broker tunneling feature, takes precedence over --tunneling
    #[arg(long)]
    no_tunneling: bool,
    /// SHV2 compatibility mode
    #[arg(long = "shv2")]
    shv2_compatibility: bool,
    /// Disable SHV2 compatibility mode, takes precedence over --shv2
    #[arg(long = "no-shv2")]
    no_shv2_compatibility: bool,
    /// Specify log level for modules, `.` is the default log level (.=<verbosity>,<module>=<verbosity>,...),
    /// E: error, W: warn, I: info, D: debug, O: off
    #[arg(short = 'v', long = "verbose")]
    verbose: Option<String>,
}

pub(crate) fn main() -> shvrpc::Result<()> {
    const SMOL_THREADS: &str = "SMOL_THREADS";
    if std::env::var(SMOL_THREADS).is_err_and(|e| matches!(e, std::env::VarError::NotPresent))
        && let Ok(num_threads) = std::thread::available_parallelism() {
        unsafe {
            std::env::set_var(SMOL_THREADS, num_threads.to_string());
        }
    }

    let cli_opts = CliOpts::parse();

    if cli_opts.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let mut logger = SimpleLogger::new().with_level(LevelFilter::Info);
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
    if cli_opts.data_directory.is_some() {
        config.data_directory = cli_opts.data_directory;
    }
    config.shv2_compatibility |= cli_opts.shv2_compatibility;
    config.shv2_compatibility &= !cli_opts.no_shv2_compatibility;
    config.tunnelling.enabled |= cli_opts.tunneling;
    config.tunnelling.enabled &= !cli_opts.no_tunneling;
    config.use_access_db |= cli_opts.use_access_db;
    config.use_access_db &= !cli_opts.no_use_access_db;

    if config.shv2_compatibility {
        info!("Running in SHV2 compatibility mode");
    }
    let (access, sql_connection) = if config.use_access_db {
        let data_dir = config.data_directory.clone().unwrap_or("/tmp/shvbroker/data".to_owned());
        info!("Data directory: {}", data_dir);
        let sql_config_file = Path::new(&data_dir).join("shvbroker.sqlite");
        let (sql_connection, access_config) = smol::block_on( sql::migrate_sqlite_connection(&sql_config_file, &config.access))?;
        (access_config, Some(sql_connection))
    } else {
        (config.access.clone(), None)
    };
    if cli_opts.print_config {
        print_config(&config, &access)?;
        return Ok(());
    }
    info!("-----------------------------------------------------");
    let (command_sender, command_receiver) = smol::channel::unbounded();
    let broker_impl = Arc::new(BrokerImpl::new(SharedBrokerConfig::new(config), access, command_sender, sql_connection));
    smol::block_on(shvbroker::brokerimpl::run_broker(broker_impl, command_receiver))
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
