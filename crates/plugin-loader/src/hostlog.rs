// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host side of the plugin log bridge.
//!
//! A plugin cdylib statically links its own `tracing-core`, so its dispatcher is not this process's
//! and nothing joins them: every `tracing::warn!` inside a loaded plugin was discarded, including
//! auth-oidc's on a failed token signature verification. The loader hands each plugin a callback
//! through the optional `busbar_set_log_sink` symbol; this module is what that callback does.
//!
//! Its own file rather than more lines in `lib.rs`, which the structure lint caps at 2500.

use std::ffi::c_void;

/// A stable, per-DISTINCT-NAME `ctx` pointer for the plugin log sink.
///
/// One allocation per unique plugin name for the life of the process, not one per load — the same
/// bound, and for the same reason, as `intern_name` in the parent module. See the call site in
/// `wire_up_raw` for why a per-load `Box::into_raw` here is unbounded rather than "one per plugin".
///
/// A separate map from `intern_name`'s rather than a reuse of it: that one returns a `&'static str`,
/// and the sink needs a pointer it can deref as a `*const String` without carrying a length
/// alongside it through the C signature.
///
/// A leaked `String` (not a `&str`) so [`host_log_sink`] can keep reading it as `*const String`,
/// which needs no length alongside the pointer.
pub(crate) fn intern_log_ctx(name: &str) -> *mut c_void {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CTXS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    let map = CTXS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(&addr) = guard.get(name) {
        return addr as *mut c_void;
    }
    let leaked: &'static String = Box::leak(Box::new(name.to_string()));
    let addr = leaked as *const String as usize;
    guard.insert(name.to_string(), addr);
    addr as *mut c_void
}

/// The host's maximum enabled `tracing` level, as a [`busbar_plugin::cold::log_level`] constant.
///
/// Handed to the plugin so it can filter on ITS side of the FFI boundary. Without it a plugin's
/// dispatcher claims interest in everything, and every `trace!`/`debug!` in the plugin's dependency
/// tree renders a string and crosses the sink call on the REQUEST PATH just to be dropped here.
pub(crate) fn host_max_level() -> u32 {
    use busbar_plugin::cold::log_level;
    match tracing::level_filters::LevelFilter::current() {
        tracing::level_filters::LevelFilter::OFF => log_level::OFF,
        tracing::level_filters::LevelFilter::ERROR => log_level::ERROR,
        tracing::level_filters::LevelFilter::WARN => log_level::WARN,
        tracing::level_filters::LevelFilter::INFO => log_level::INFO,
        tracing::level_filters::LevelFilter::DEBUG => log_level::DEBUG,
        _ => log_level::TRACE,
    }
}

/// The sink handed to every plugin that exports `busbar_set_log_sink`, re-emitting the plugin's
/// record through THIS process's `tracing` subscriber so it lands wherever the operator's logs go.
///
/// `extern "C"`, NOT `"C-unwind"`: this is host code called from a differently-compiled object, and
/// letting a panic unwind across that boundary is undefined behaviour. Everything is therefore
/// wrapped in `catch_unwind`, and a panic here is swallowed — losing one log line is not a reason to
/// take down a gateway.
///
/// # Safety
/// Called by a plugin with the `ctx` this loader supplied and a UTF-8 `msg` of `msg_len` bytes,
/// borrowed for the call. Nothing here retains either pointer.
pub(crate) unsafe extern "C" fn host_log_sink(
    ctx: *mut c_void,
    level: u32,
    msg: *const u8,
    msg_len: usize,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if msg.is_null() || msg_len == 0 {
            return;
        }
        // Bound what a single record can cost: a plugin handing over a huge length must not make the
        // host allocate it, mirroring MAX_PLUGIN_RESPONSE_LEN's reasoning on the reply path.
        const MAX_LOG_LEN: usize = 64 * 1024;
        let len = msg_len.min(MAX_LOG_LEN);
        let bytes = unsafe { std::slice::from_raw_parts(msg, len) };
        // LOSSY, never a hard error: a plugin that hands over malformed UTF-8 has a bug, but that is
        // itself worth seeing rather than a reason to drop the record.
        let text = String::from_utf8_lossy(bytes);
        let name: &str = if ctx.is_null() {
            "<unknown>"
        } else {
            unsafe { &*(ctx as *const String) }
        };
        #[cfg(test)]
        log_tap::record(name, level, &text);
        match level {
            busbar_plugin::cold::log_level::ERROR => {
                tracing::error!(plugin = %name, "{text}")
            }
            busbar_plugin::cold::log_level::WARN => tracing::warn!(plugin = %name, "{text}"),
            busbar_plugin::cold::log_level::DEBUG => tracing::debug!(plugin = %name, "{text}"),
            busbar_plugin::cold::log_level::TRACE => tracing::trace!(plugin = %name, "{text}"),
            // INFO, and anything a newer plugin invents: clamped to info rather than dropped. Losing
            // a record because its level is unrecognized would be the worst possible failure mode for
            // a channel that exists to stop losing records.
            _ => tracing::info!(plugin = %name, "{text}"),
        }
    }));
}

/// Test-visible tap on the records crossing the bridge.
///
/// The end-to-end assertion cannot go through `tracing` itself: interest is cached PER CALLSITE and
/// GLOBALLY, and this binary's other tests load plugins with no subscriber installed, so the sink's
/// callsite gets cached as uninteresting and a thread-local capturing subscriber then never sees the
/// event. That is a property of the test harness, not of the bridge — instrumenting the loader
/// showed the sink being invoked correctly on every load — so the record is tapped here instead,
/// where the assertion is deterministic and tests exactly what matters: that the plugin's message
/// crossed the ABI and arrived attributed to the right plugin.
#[cfg(test)]
pub(crate) mod log_tap {
    use std::sync::Mutex;

    pub(crate) static RECORDS: Mutex<Vec<(String, u32, String)>> = Mutex::new(Vec::new());

    /// Called from `host_log_sink` for every record that crosses the ABI. Inside the module rather
    /// than beside it so clippy's `items_after_test_module` stays satisfied.
    pub(crate) fn record(name: &str, level: u32, text: &str) {
        RECORDS.lock().unwrap_or_else(|e| e.into_inner()).push((
            name.to_string(),
            level,
            text.to_string(),
        ));
    }
}
