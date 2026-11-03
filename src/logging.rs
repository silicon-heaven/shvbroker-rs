use flexi_logger::{AdaptiveFormat, FlexiLoggerError, LogSpecification, Logger, LoggerHandle};

pub fn start_logger(
    log_specification: impl Into<LogSpecification>,
) -> Result<LoggerHandle, FlexiLoggerError> {
    Logger::with(log_specification)
        .set_palette("196;208;6;27;8".to_owned())
        .log_to_stderr()
        .adaptive_format_for_stderr(AdaptiveFormat::Custom(
            flexi_logger::detailed_format,
            detailed_format_color_level,
        ))
        .start()
}

fn detailed_format_color_level(
    writer: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
) -> std::io::Result<()> {
    write!(
        writer,
        "[{}] {} [{}] {}:{}: ",
        now.format(flexi_logger::TS_DASHES_BLANK_COLONS_DOT_BLANK),
        flexi_logger::style(record.level()).paint(record.level().to_string()),
        record.module_path().unwrap_or("<unnamed>"),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
    )?;
    write!(writer, "{}", record.args())
}
