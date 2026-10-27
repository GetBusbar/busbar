// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observability beyond Prometheus `/metrics`: the process-wide `tracing` subscriber
//! ([`init_logging`]) and the one-spot hot-path level policy.
//!
//! Spans leave the process as `traces` RECORDS (K9a S7, `crate::export::traces`), which an export
//! sink subscribed to the stream is handed like any other stream (K9e-2).

/// Percent-decode a URL component to its raw UTF-8 string, leaving any byte that is not a valid
/// `%XX` escape (or invalid UTF-8) untouched so a credential is never silently corrupted. Also used
/// by the protocol catch-all to decode path-model segments (axum's `Path` extractor decoded them
/// before the collapse; the raw-path dispatch must match).
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
    String::from_utf8_lossy(&out).into_owned()
}

/// THE TRACING SEAM — the one-spot level policy for every per-request span/event.
///
/// Every per-request span or event MUST be bound to a level, and that level MUST be set in exactly
/// one place. This constant is that one place: every hot-path `#[tracing::instrument]`
/// and every per-request `tracing::debug!`/`trace!` call references `HOTPATH_LEVEL` (or the literal
/// it is set to) rather than picking its own level ad hoc, so raising or lowering the hot-path
/// verbosity for the WHOLE request path is a one-line change here, and `scripts/tracing-lint.sh`
/// fails CI on any `#[instrument]` that skips the reference and hand-picks a level instead (a
/// "rogue trace").
///
/// Deliberately `DEBUG`, not the `tracing::Level::TRACE` variant: `log_levels()` below is the other
/// half of the one-spot policy — it floors the OTLP export filter at DEBUG specifically so an
/// operator who points the trace-export endpoint at a collector gets every request-path span
/// (this crate's own `named`/`adhoc` ingress spans among them) WITHOUT also having to
/// set `RUST_LOG=debug` and flood stderr with every debug line in the process (see the doc comment
/// on `log_levels`). If `HOTPATH_LEVEL` were `TRACE` instead, that OTLP floor would need to move to
/// TRACE too — losing the "OTLP get the hot path, stderr stays at its own level" split the two-filter
/// design exists for. Both stay OFF at the default `RUST_LOG=info` filter either way: `DEBUG` is
/// less verbose than `TRACE`, so nothing about the "off by default" contract changes with this
/// choice.
// A′ (ABI-purity P4): the hot-path tracing floor relocated DOWN to busbar-substrate so a plane crate
// can name it via the ABI (`busbar_kernel::observability::HOTPATH_LEVEL`). A pure
// compile-time `const` (no registry, no dual-compile concern). Re-exported here so `crate::
// observability::HOTPATH_LEVEL` and every in-core reference stay unchanged and byte-identical.
pub const HOTPATH_LEVEL: tracing::Level = tracing::Level::DEBUG;

/// The arrival spans a plane's claims state (status row 173), one callsite per name.
pub mod arrival;

/// The stderr and OTLP level filters, which are deliberately NOT the same.
///
/// stderr takes `RUST_LOG` (a bare level word, e.g. `debug`), default `info`. Full `EnvFilter`
/// directive syntax (`busbar=debug,hyper=warn`) would require the `env-filter` feature.
///
/// OTLP floors at DEBUG (== `HOTPATH_LEVEL` above), because every request-path span (including this
/// crate's own `named`/`adhoc` ingress spans) is emitted at debug so it costs nothing on the stderr path
/// at the default level. Exporting at the stderr level meant an operator who configured a collector
/// received no request trace at all — only the one span that happens to default to INFO, orphaned
/// from the parent that was never created. The two must be independent: turning traces on must not
/// require `RUST_LOG=debug`, which would flood stderr with every debug line in the process.
///
/// Both are attached PER LAYER. A bare `LevelFilter` added to the registry itself is a GLOBAL
/// filter that gates callsite enablement for every layer, so an OTLP-specific filter underneath one
/// is inert.
fn log_levels() -> (
    tracing_subscriber::filter::LevelFilter,
    tracing_subscriber::filter::LevelFilter,
) {
    let stderr = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    // `Level`'s ordering is by verbosity, so this is "DEBUG, or more verbose if asked for".
    let otlp = stderr.max(tracing::Level::DEBUG);
    (
        tracing_subscriber::filter::LevelFilter::from_level(stderr),
        tracing_subscriber::filter::LevelFilter::from_level(otlp),
    )
}

/// Make `tracing-log`'s `LogTracer` this process's `log` logger, so a `log` record becomes a
/// `tracing` event. Called FIRST in the composition root, before any compiled-in plugin's door runs:
/// a compiled-in plugin shares this image's `log` logger slot, and its door's call capture installs
/// the same `LogTracer` best-effort on first use (`BUSBAR-1.6.0.md` decision #85, "the plugin image
/// installs it, and so does the host"), so the host must take the slot first or find it taken. Open
/// to every level: the capture keeps everything and the subscribers filter. An error means another
/// `log` logger already holds the slot.
pub fn init_log_bridge() -> Result<(), tracing_log::log::SetLoggerError> {
    tracing_log::LogTracer::init()
}

/// Install the process-wide `tracing` subscriber once at startup: always a stderr `fmt` layer
/// (level from `RUST_LOG`, default `info`) so spans/warnings are visible out of the box, plus the
/// `traces` record producer ([`crate::export::traces`]) under the span floor (see [`log_levels`]).
/// The `log` bridge is [`init_log_bridge`]'s, installed earlier, so this installs the subscriber
/// alone; an error means a global subscriber is already installed.
///
/// `stdout_reserved`: set by a caller whose transport uses this process's own stdout as its wire
/// channel — the framed protocol on stdout forbids any byte that is not one of its own messages —
/// so every log line moves to stderr instead, which is where such a transport's spec sends a
/// server's diagnostics anyway. The listener modes keep stdout, unchanged.
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
