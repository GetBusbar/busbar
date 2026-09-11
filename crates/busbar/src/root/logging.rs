// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process's logging: the subscriber install and the two level filters.
//!
//! MOVED HERE, not written here. This is the retiring engine's `observability` module minus the
//! sink guard (which went to the egress unit), minus `percent_decode` (whose reader is still on the
//! request path) and now minus THE WHOLE OTLP HALF. It is here because it is BOOT, by definition
//! and by measurement: a process installs its logging exactly once, and a library crate that
//! installs a process-global subscriber is a library that cannot be linked twice.
//!
//! WHAT LEFT, AND WHY IT IS NOT HERE ANY MORE. `build_otlp`, the retained `SdkTracerProvider`, the
//! credential split and `shutdown_tracing` were an EXPORT SINK wearing a logging module's name: a
//! `hyper_rustls` connector, an `opentelemetry_otlp::SpanExporter`, a BATCH processor with its own
//! queue and its own drop rule, and a flush this process could not see the end of. The sink is now
//! `busbar-export-otlp` and the pipeline is `units_export::traces` — one queue, one declared bound,
//! one gate and one maintenance tick on the same shutdown broadcast as every other background task.
//! What is left of OTLP HERE is one argument: a layer the composer built and this function attaches.
//! This module names no exporter, no provider, no collector and no credential.
//!
//! THE TWO FILTERS ARE NOT THE SAME FILTER, and that is the design rather than an oversight. stderr
//! takes `RUST_LOG`, default `info`. THE TRACE EXPORT FLOORS AT DEBUG, because every request-path
//! span is emitted at debug so it costs nothing on the stderr path at the default level; exporting
//! at the stderr level meant an operator who configured a collector received no request trace at
//! all. Both are attached PER LAYER — a bare `LevelFilter` on the registry is a GLOBAL filter that
//! gates callsite enablement for every layer, so a trace-specific filter underneath one is inert.

use crate::root::units_export::traces::TraceLayer;

/// The stderr and trace-export level filters, which are deliberately NOT the same.
///
/// stderr takes `RUST_LOG` (a bare level word, e.g. `debug`), default `info`. Full `EnvFilter`
/// directive syntax (`busbar=debug,hyper=warn`) would require the `env-filter` feature.
///
/// The export floors at DEBUG (== `busbar_substrate::observability::HOTPATH_LEVEL`, the one-spot
/// hot-path tracing seam), because every request-path span (`forward`, `gemini_ingress`,
/// `bedrock_converse`, `named`, `adhoc`) is emitted at debug so it costs nothing on the stderr path
/// at the default level. Exporting at the stderr level meant an operator who configured a collector
/// received no request trace at all — only the one span that happens to default to INFO, orphaned
/// from the parent that was never created. The two must be independent: turning traces on must not
/// require `RUST_LOG=debug`, which would flood stderr with every debug line in the process.
///
/// Both are attached PER LAYER. A bare `LevelFilter` added to the registry itself is a GLOBAL
/// filter that gates callsite enablement for every layer, so a trace-specific filter underneath one
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
    let traces = stderr.max(tracing::Level::DEBUG);
    (
        tracing_subscriber::filter::LevelFilter::from_level(stderr),
        tracing_subscriber::filter::LevelFilter::from_level(traces),
    )
}

/// Install the process-wide `tracing` subscriber once at startup: always a stderr `fmt` layer
/// (level from `RUST_LOG`, default `info`) so spans and warnings are visible out of the box, plus
/// the span-export layer the composer built when an `otlp` export instance is configured.
///
/// `traces` is that layer, ALREADY COMPOSED — its sink, its gate, its queue and its wire were built
/// by `units_export::traces::install` before this was called, because a layer cannot be added to a
/// subscriber that already exists. `None` ⇒ no `otlp` instance, or an endpoint the SSRF guard
/// refused; either way nothing was composed and nothing is attached. `Option<Layer>` is itself a
/// `Layer`, so the absent case composes cleanly.
///
/// `stdout_reserved`: the MCP STDIO SERVE MODE's one logging requirement. In `--mcp-stdio` the
/// process's stdout IS the protocol channel — `STDIO.STDOUT-ONLY-MCP` forbids anything on it that
/// is not a JSON-RPC message — so every log line moves to stderr, which is where the transport
/// spec sends a server's diagnostics anyway. The listener modes keep stdout, unchanged.
///
/// A REPEATED CALL INSTALLS NOTHING AND MUTATES NOTHING. There is no deferred global side effect
/// left to get wrong: the tracer provider that used to be installed only after `try_init` succeeded
/// does not exist any more, because there is no provider.
pub fn init_logging(traces: Option<TraceLayer>, stdout_reserved: bool) {
    use tracing_subscriber::fmt::writer::BoxMakeWriter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::Layer as _;
    let (stderr_filter, traces_filter) = log_levels();
    let make_writer = if stdout_reserved {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(make_writer)
        .with_target(false)
        .with_filter(stderr_filter);

    // The MASKED endpoint, read off the layer before it is moved into the subscriber. This module
    // never holds the raw one and could not log it if it tried.
    let endpoint = traces.as_ref().map(|t| t.endpoint().to_string());
    let traces_layer = traces.map(|t| t.with_filter(traces_filter));

    if tracing_subscriber::registry()
        .with(fmt_layer)
        .with(traces_layer)
        .try_init()
        .is_err()
    {
        eprintln!("busbar: tracing subscriber already initialized");
        return;
    }
    if let Some(endpoint) = endpoint {
        tracing::info!(endpoint, "OTLP tracing enabled");
    }
}

#[cfg(test)]
#[path = "tests/logging.rs"]
mod tests;
