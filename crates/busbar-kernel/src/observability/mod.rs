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

/// Whether any subscriber layer may record at [`HOTPATH_LEVEL`]: the one global max-level load
/// every disabled `debug!` already performs. Gate debug-only work (clock reads, field values) on it.
#[inline]
#[must_use]
pub fn hotpath_enabled() -> bool {
    tracing::level_filters::LevelFilter::current() >= HOTPATH_LEVEL
}

pub mod arrival;

pub mod request;

/// The `RUST_LOG` value could not be read as a log filter. Boot refuses it rather than falling back
/// to a default level: a filter the operator wrote and busbar silently ignored is a debugging
/// session lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustLogError {
    value: String,
    why: String,
}

impl std::fmt::Display for RustLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RUST_LOG={:?} is not a log filter: {}. Use a level (off, error, warn, info, debug, \
             trace) or comma-separated target=level directives, e.g. RUST_LOG=busbar=debug,hyper=warn",
            self.value, self.why
        )
    }
}

impl std::error::Error for RustLogError {}

/// Why the stderr/stdout subscriber was not installed.
#[derive(Debug)]
pub enum LoggingError {
    /// `RUST_LOG` is not a filter ([`RustLogError`]).
    RustLog(RustLogError),
    /// A global subscriber was already installed.
    AlreadyInitialized(tracing::subscriber::SetGlobalDefaultError),
}

impl std::fmt::Display for LoggingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RustLog(e) => e.fmt(f),
            Self::AlreadyInitialized(e) => write!(f, "tracing subscriber already initialized: {e}"),
        }
    }
}

impl std::error::Error for LoggingError {}

/// The console filter `RUST_LOG` names.
///
/// * unset, empty or blank: `info`, as every release before.
/// * one bare level word (`debug`, `WARN`, `3`, `off`): that level for every target, exactly the
///   1.5.x reading (which also took `Level` digits `1`..`5`); `off`/`0` are now honoured too.
/// * comma-separated directives (`busbar=debug,hyper=warn`, `warn,busbar::request=debug`): a
///   per-target filter. A bare level among them sets the level of every target no directive
///   names; with none, that level is `info`, so naming one target never silences the rest.
///
/// Anything else is an error, never a fallback. A bare word that is not a level is refused rather
/// than read as "this target at trace" (the `tracing-subscriber` reading), because a misspelt level
/// (`RUST_LOG=debgu`) would otherwise silently turn every other target off.
///
/// The filter is a [`Targets`](tracing_subscriber::filter::Targets): a static per-target table, so
/// each callsite's interest is decided once and cached (no per-event matching, no span or field
/// directives, no regex).
pub fn console_filter(
    raw: Option<&str>,
) -> Result<tracing_subscriber::filter::Targets, RustLogError> {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    let err = |why: String| RustLogError {
        value: raw.unwrap_or_default().to_string(),
        why,
    };
    let raw = raw.map(str::trim).unwrap_or_default();
    if raw.is_empty() {
        return Ok(Targets::new().with_default(LevelFilter::INFO));
    }
    let mut default: Option<LevelFilter> = None;
    let mut targets = Targets::new();
    for part in raw.split(',').map(str::trim) {
        if part.is_empty() {
            return Err(err("it has an empty directive".to_string()));
        }
        match part.split_once('=') {
            None => {
                let level = part.parse::<LevelFilter>().map_err(|_| {
                    err(format!(
                        "`{part}` is not a level (to name a target, write `{part}=<level>`)"
                    ))
                })?;
                if default.replace(level).is_some() {
                    return Err(err("it names more than one default level".to_string()));
                }
            }
            Some((target, level)) => {
                let (target, level) = (target.trim(), level.trim());
                if target.is_empty() || target.contains(['[', ']', '{', '}', '=', ' ']) {
                    return Err(err(format!(
                        "`{part}` does not name a target (span and field directives are not \
                         supported)"
                    )));
                }
                let level = match level.parse::<LevelFilter>() {
                    Ok(parsed) if !level.is_empty() => parsed,
                    _ => return Err(err(format!("`{level}` in `{part}` is not a level"))),
                };
                targets = targets.with_target(target, level);
            }
        }
    }
    Ok(targets.with_default(default.unwrap_or(LevelFilter::INFO)))
}

/// Validate `RUST_LOG` before the server does any work, so a bad value stops boot at once.
pub fn check_rust_log() -> Result<(), RustLogError> {
    console_filter(std::env::var("RUST_LOG").ok().as_deref()).map(|_| ())
}

fn log_levels_from(
    raw: Option<&str>,
) -> Result<
    (
        tracing_subscriber::filter::Targets,
        tracing_subscriber::filter::LevelFilter,
    ),
    RustLogError,
> {
    let console = console_filter(raw)?;
    // The console's most verbose level: what OTLP must at least match.
    let stderr =
        tracing_subscriber::layer::Filter::<tracing_subscriber::Registry>::max_level_hint(&console)
            .unwrap_or(tracing_subscriber::filter::LevelFilter::TRACE);
    let otlp = stderr.max(tracing_subscriber::filter::LevelFilter::DEBUG);
    Ok((console, otlp))
}

fn log_levels() -> Result<
    (
        tracing_subscriber::filter::Targets,
        tracing_subscriber::filter::LevelFilter,
    ),
    RustLogError,
> {
    log_levels_from(std::env::var("RUST_LOG").ok().as_deref())
}

pub fn init_log_bridge() -> Result<(), tracing_log::log::SetLoggerError> {
    tracing_log::LogTracer::init()
}

/// Install the process's one subscriber: a stderr `fmt` layer filtered by `RUST_LOG`, and the OTLP
/// export layer. Logs ALWAYS go to stderr, as in 1.5.5, so stdout is never written by logging and
/// stays free for a plane serving its protocol on stdout (`--mcp-stdio`).
pub fn init_logging() -> Result<(), LoggingError> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;
    let (stderr_filter, otlp_filter) = log_levels().map_err(LoggingError::RustLog)?;
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_filter(stderr_filter);
    let subscriber = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(crate::export::traces::layer(otlp_filter));
    tracing::subscriber::set_global_default(subscriber).map_err(LoggingError::AlreadyInitialized)
}

#[cfg(test)]
#[path = "../tests/observability_tests.rs"]
mod tests;
