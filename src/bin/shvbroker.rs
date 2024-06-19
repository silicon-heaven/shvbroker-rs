use std::{fs};
use std::path::Path;
use async_std::task;
use log::*;
use simple_logger::SimpleLogger;
use shvrpc::util::{join_path, parse_log_verbosity};
use clap::{Parser};
use shvbroker::config::AccessControl;

#[derive(Parser, Debug)]
struct CliOpts {
    /// Config file path
    #[arg(long)]
    config: Option<String>,
    /// Create default config file if one specified by --config is not found
    #[arg(short, long)]
    create_default_config: bool,
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
    log!(target: "Acc", Level::Debug, "Access control message");

    let config = if let Some(config_file) = &cli_opts.config {
        shvbroker::config::BrokerConfig::from_file_or_default(config_file, cli_opts.create_default_config)?
    } else {
        Default::default()
    };
    let (access, create_editable_access_file) = 'access: {
        let mut create_editable_access_file = false;
        if let Some(data_dir) = &config.data_directory {
            if config.editable_access {
                let file_name = join_path(data_dir, "access.yaml");
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


