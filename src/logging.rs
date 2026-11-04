use std::sync::{Arc, RwLock};
use flexi_logger::{AdaptiveFormat, FlexiLoggerError, LevelFilter, LogSpecification, Logger, LoggerHandle};
use flexi_logger::DeferredNow;
use flexi_logger::filter::{LogLineFilter, LogLineWriter};
use shvrpc::util::parse_log_verbosity;

pub fn log_specification_from_verbosity(verbosity: Option<&str>) -> LogSpecification {
    let mut log_specification = LogSpecification::builder();
    log_specification.default(LevelFilter::Info);
    if let Some(verbosity) = verbosity {
        for (module, level) in parse_log_verbosity(verbosity, env!("CARGO_PKG_NAME")) {
            if let Some(module) = module {
                log_specification.module(module, level);
            } else {
                log_specification.default(level);
            }
        }
    }
    log_specification.build()
}

pub fn start_logger(
    log_specification: impl Into<LogSpecification>,
) -> Result<(LoggerHandle, Arc<RwLock<LogSpecification>>), FlexiLoggerError> {
    let log_specification = Arc::new(RwLock::new(log_specification.into()));
    let logger_handle = Logger::with(LogSpecification::trace())
        .filter(Box::new(TopicLogFilter {
            log_specification: log_specification.clone(),
        }))
        .set_palette("196;208;6;27;8".to_owned())
        .log_to_stderr()
        .adaptive_format_for_stderr(AdaptiveFormat::Custom(
            flexi_logger::detailed_format,
            detailed_format_color_level,
        ))
        .start()?;
    Ok((logger_handle, log_specification))
}

struct TopicLogFilter {
    log_specification: Arc<RwLock<LogSpecification>>,
}

impl LogLineFilter for TopicLogFilter {
    fn write(
        &self,
        now: &mut DeferredNow,
        record: &log::Record,
        log_line_writer: &dyn LogLineWriter,
    ) -> std::io::Result<()> {
        let log_specification = self.log_specification
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !should_write_log(
            record.level(),
            record.target(),
            record.module_path(),
            &log_specification,
        ) {
            return Ok(());
        }

        log_line_writer.write(now, record)
    }
}

fn should_write_log(
    level: log::Level,
    target: &str,
    module_path: Option<&str>,
    log_specification: &LogSpecification,
) -> bool {
    let has_target_filter = log_specification
        .module_filters()
        .iter()
        .filter_map(|module_filter| module_filter.module_name.as_deref())
        .any(|module_name| target.starts_with(module_name));

    if module_path == Some(target) || has_target_filter {
        return log_specification.enabled(level, target);
    }

    level <= log::LevelFilter::Warn
}

fn detailed_format_color_level(
    writer: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
) -> std::io::Result<()> {
    let module_path = record.module_path().unwrap_or("<unnamed>");
    write!(
        writer,
        "{} {} [{}:{}]",
        now.format(flexi_logger::TS_DASHES_BLANK_COLONS_DOT_BLANK),
        flexi_logger::style(record.level()).paint(record.level().to_string()),
        module_path,
        record.line().unwrap_or(0),
    )?;
    if record.target() != module_path {
        write!(writer, "({})", record.target())?;
    }
    write!(writer, " {}", record.args())
}

#[cfg(test)]
mod tests {
    use super::should_write_log;
    use flexi_logger::{LevelFilter, LogSpecification};
    use log::Level;

    #[test]
    fn info_without_topic_keeps_info_default() {
        let log_specification = LogSpecification::info();

        assert!(should_write_log(
            Level::Info,
            "shvbroker::config",
            Some("shvbroker::config"),
            &log_specification,
        ));
        assert!(!should_write_log(
            Level::Debug,
            "shvbroker::config",
            Some("shvbroker::config"),
            &log_specification,
        ));
    }

    #[test]
    fn topic_logs_use_warn_default_independent_of_global_level() {
        let permissive_log_specification = LogSpecification::trace();
        let restrictive_log_specification = LogSpecification::error();

        for level in [Level::Info, Level::Debug, Level::Trace] {
            assert!(!should_write_log(
                level,
                "Access",
                Some("shvbroker::config"),
                &permissive_log_specification,
            ));
        }
        for level in [Level::Warn, Level::Error] {
            assert!(should_write_log(
                level,
                "Access",
                Some("shvbroker::config"),
                &restrictive_log_specification,
            ));
        }
    }

    #[test]
    fn explicit_topic_verbosity_overrides_warn_default() {
        let mut builder = LogSpecification::builder();
        builder.default(LevelFilter::Info);
        builder.module("Access", LevelFilter::Debug);
        let log_specification = builder.build();

        for level in [Level::Info, Level::Debug] {
            assert!(should_write_log(
                level,
                "Access",
                Some("shvbroker::config"),
                &log_specification,
            ));
        }
        assert!(!should_write_log(
            Level::Trace,
            "Access",
            Some("shvbroker::config"),
            &log_specification,
        ));
    }

}
