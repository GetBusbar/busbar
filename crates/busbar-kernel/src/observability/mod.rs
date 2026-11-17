// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn percent_decode(s: &str) -> String {
    String::from_utf8(busbar_contract::net::percent_decoded_bytes(s))
        .unwrap_or_else(|_| s.to_owned())
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

/// One log event that carries plugin text (IF §12.16 round 34, PLUGIN-ERROR-CODES §2.6). `message` is core's own
/// words. The plugin's text is a plain `&str` field `text` (never `message`, never `%` or `?`), so the stock `fmt`
/// formatter writes it with `{:?}`: one quoted value with `"`, `\`, `\n`, `\r`, `\t` and other controls escaped,
/// which cannot open a new field or line. On a text line `text` is the joined `"{code}: {text}"`; `plugin_diag`
/// is a second plain field, present only with a code. `kind` and `instance` name the instance in operator
/// vocabulary. No custom formatter is installed: this path is the whole rule.
pub fn plugin_text(
    level: tracing::Level,
    kind: &str,
    instance: &str,
    message: &str,
    text: &crate::plugin_text::PluginText,
) {
    let joined = text.to_string();
    let joined = joined.as_str();
    let diag = text.code.map(|code| code.to_string());
    macro_rules! emit {
        ($level:ident) => {
            match diag.as_deref() {
                Some(plugin_diag) => {
                    tracing::$level!(kind, instance, plugin_diag, text = joined, "{message}")
                }
                None => tracing::$level!(kind, instance, text = joined, "{message}"),
            }
        };
    }
    match level {
        tracing::Level::ERROR => emit!(error),
        tracing::Level::WARN => emit!(warn),
        tracing::Level::INFO => emit!(info),
        tracing::Level::DEBUG => emit!(debug),
        _ => emit!(trace),
    }
}

#[cfg(test)]
mod plugin_text_tests {
    use crate::plugin_text::{PluginCode, PluginText};
    use std::sync::{Arc, Mutex, PoisonError};

    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn captured(f: impl FnOnce()) -> String {
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_target(false)
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = lines
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).expect("utf-8 log")
    }

    const SENT: &str = "  BUSBAR-6013 bad\tthing\nx\x1b[2K";

    /// PLUGIN-ERROR-CODES T1b: one line; `plugin_diag` and the joined `text` in the stock formatter's Debug
    /// spelling; core's own message unchanged.
    #[test]
    fn plugin_text_escaped_on_text_lines() {
        let t = PluginText::new(
            Some(PluginCode {
                plugin: "acme-store",
                number: 3,
            }),
            SENT,
        );
        let out = captured(|| {
            super::plugin_text(tracing::Level::WARN, "store", "main", "open refused", &t);
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("open refused"), "{out}");
        assert!(
            out.contains(r#"plugin_diag="BUSBAR-acme-store-0003""#),
            "{out}"
        );
        assert!(
            out.contains(r#"text="BUSBAR-acme-store-0003:   BUSBAR-6013 bad\tthing\nx\u{1b}[2K""#),
            "{out}"
        );
        assert!(out.contains(r#"kind="store""#), "{out}");
        assert!(out.contains(r#"instance="main""#), "{out}");
    }

    /// T1b/T2: a no-code text that imitates a field writes no `plugin_diag` field outside the quoted value, and a
    /// quote or backslash it sends is escaped.
    #[test]
    fn a_no_code_text_cannot_forge_a_field() {
        let t = PluginText::new(None, "x plugin_diag=\"BUSBAR-4013\" \\ end");
        let out = captured(|| {
            super::plugin_text(tracing::Level::ERROR, "auth", "sso", "verify failed", &t);
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        let quoted = r#"text="x plugin_diag=\"BUSBAR-4013\" \\ end""#;
        assert!(out.contains(quoted), "{out}");
        let outside = out.replacen(quoted, "", 1);
        assert!(!outside.contains("plugin_diag"), "{out}");
    }
}

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
/// stays free for a plane serving its protocol on stdout (`--stdio`).
pub fn init_logging() -> Result<crate::export::traces::TracePublisher, LoggingError> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;
    let (stderr_filter, otlp_filter) = log_levels().map_err(LoggingError::RustLog)?;
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_filter(stderr_filter);
    let (export_layer, publisher) = crate::export::traces::dormant(otlp_filter);
    let subscriber = tracing_subscriber::registry()
        .with(export_layer)
        .with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(LoggingError::AlreadyInitialized)?;
    Ok(publisher)
}

#[cfg(test)]
#[path = "../tests/observability_tests.rs"]
mod tests;
