use env_logger::Builder;
use log::Level;
use std::io::Write;

// Custom pretty env logger

/// Initializes the global logger with a pretty env logger.
///
/// This should be called early in the execution of a Rust program, and the
/// global logger may only be initialized once. Future initialization attempts
/// will return an error.
///
/// # Panics
///
/// This function fails to set the global logger if one has already been set.
pub fn init() {
    try_init().unwrap();
}

/// Initializes the global logger with a pretty env logger.
///
/// This should be called early in the execution of a Rust program, and the
/// global logger may only be initialized once. Future initialization attempts
/// will return an error.
///
/// # Errors
///
/// This function fails to set the global logger if one has already been set.
pub fn try_init() -> Result<(), log::SetLoggerError> {
    try_init_custom_env("RUST_LOG")
}

/// Initialized the global logger with a pretty env logger, with a custom variable name.
///
/// This should be called early in the execution of a Rust program, and the
/// global logger may only be initialized once. Future initialization attempts
/// will return an error.
///
/// # Errors
///
/// This function fails to set the global logger if one has already been set.
pub fn try_init_custom_env(environment_variable_name: &str) -> Result<(), log::SetLoggerError> {
    let mut builder = formatted_builder();

    if let Ok(s) = ::std::env::var(environment_variable_name) {
        builder.parse_filters(&s);
    }

    builder.try_init()
}

// INFO levels will be be just normal text
pub fn formatted_builder() -> Builder {
    let mut builder = Builder::new();

    builder.format(|f, record| {
        if record.level() == Level::Info {
            writeln!(f, " > {}", record.args())
        } else {
            let label = match record.level() {
                Level::Trace => "TRACE",
                Level::Debug => "DEBUG",
                Level::Info => "INFO ",
                Level::Warn => "WARN ",
                Level::Error => "ERROR",
            };
            writeln!(f, " {} > {}", label, record.args())
        }
    });

    builder
}
