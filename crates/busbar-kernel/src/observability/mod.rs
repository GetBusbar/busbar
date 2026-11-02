// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

pub const HOTPATH_LEVEL: tracing::Level = tracing::Level::DEBUG;

pub mod arrival;

fn log_levels() -> (
    tracing_subscriber::filter::LevelFilter,
    tracing_subscriber::filter::LevelFilter,
) {
    let stderr = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);

    let otlp = stderr.max(tracing::Level::DEBUG);
    (
        tracing_subscriber::filter::LevelFilter::from_level(stderr),
        tracing_subscriber::filter::LevelFilter::from_level(otlp),
    )
}

pub fn init_log_bridge() -> Result<(), tracing_log::log::SetLoggerError> {
    tracing_log::LogTracer::init()
}

pub fn init_logging(
    stdout_reserved: bool,
) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    use tracing_subscriber::fmt::writer::BoxMakeWriter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;
    let (stderr_filter, otlp_filter) = log_levels();
    let make_writer = if stdout_reserved {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(make_writer)
        .with_target(false)
        .with_filter(stderr_filter);
    let subscriber = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(crate::export::traces::layer(otlp_filter));
    tracing::subscriber::set_global_default(subscriber)
}

#[cfg(test)]
#[path = "../tests/observability_tests.rs"]
mod tests;
