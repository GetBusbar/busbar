// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::{extract::OriginalUri, http::StatusCode, response::Response};

use crate::state::App;

/// Render the pool scope of a blocking limit for the client-facing rejection: a pool-qualified
/// limit caps only that pool's traffic, and saying so tells the caller the actionable part -
/// other pools may still serve them.
fn pool_scope_suffix(pool: &Option<String>) -> String {
    match pool {
        Some(p) => format!(", pool '{p}'"),
        None => String::new(),
    }
}

/// THE LIMIT REFUSAL a blocked admission is answered with: its status, its kind word,
/// its message (naming the group, metric and window, never the key), and its Retry-After seconds
/// (a rolling window's; `total` never rolls). One spelling, read by every door that admits.
#[must_use]
pub fn limit_refusal(
    blocked: &crate::governance::LimitBlocked,
) -> (StatusCode, &'static str, String, Option<u64>) {
    use crate::governance::LimitBlocked;
    match blocked {
        LimitBlocked::Limit {
            group,
            metric: "concurrent",
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            format!(
                "Too many concurrent requests (group '{group}' is at its in-flight \
                     limit). Please retry shortly."
            ),
            None,
        ),
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            // The quota status is 429 on every dialect (accepted difference C-22); the plane
            // that words the refusal states its own.
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            format!(
                "You have exceeded your current quota (group '{group}' budget per {}{} \
                     exhausted). Please check your plan and billing details.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),
        // EVERY OTHER METRIC IS A RATE LIMIT: `requests`, `tokens`, and a cap on any meter class
        // the operator configured (`tokens_<class>`), each a 429 naming the metric word as
        // configured — never the quota status, so no metric inherits `budget`'s answer. The
        // metric is an opaque word here: the kernel names no plane's meter class (audit K4 #2;
        // BUSBAR-1.6.0.md l.166, "Nothing in the kernel parses or understands ... a plane concept").
        LimitBlocked::Limit {
            group,
            metric,
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            format!(
                "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                     after the indicated time.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),
        // A FROZEN group (`enabled: false`) is an administrative freeze, not a quota: the
        // vendor-plausible shape is a permission denial.
        LimitBlocked::Disabled(group) => (
            StatusCode::FORBIDDEN,
            busbar_contract::protocol::KIND_PERMISSION,
            format!(
                "Your API key does not currently have access to this resource (group \
                     '{group}' is disabled)."
            ),
            None,
        ),
        // FAIL-CLOSED: a key bound to a group this node's config does not know is not
        // admitted; the message names the missing bucket so the operator can fix it.
        LimitBlocked::MissingGroup(group) => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            format!(
                "Your quota configuration is incomplete (group '{group}' is not \
                     configured). Please contact your administrator."
            ),
            None,
        ),
    }
}

/// Map a client-supplied model/name string to a BOUNDED `pool` metric label (metrics.rs).
/// Returns the string verbatim ONLY when it names a configured pool (`app.pools`) or a configured
/// by-model lane (`app.by_model`) — i.e. a value drawn from the finite, operator-controlled label
/// space. For anything else (an unknown model, a governance-rejected request whose model was never
/// resolved, a provider-mismatched ad-hoc model) it returns the fixed sentinel `"unresolved"`.
///
/// Without this, every `finish`/webhook call on a 404 / governance-rejection path stamped the raw
/// attacker-controlled model as the `pool` label, letting a single valid credential mint an
/// unbounded number of Prometheus time series (one per distinct model string) — a low-effort
/// memory-exhaustion DoS that also bloats every `/metrics` scrape and leaks the attacker-chosen
/// string into the request-log webhook. The label space is now bounded BY CONSTRUCTION:
/// |configured pools| + |configured by-model lanes| + 1.
pub fn pool_label<'a>(app: &Arc<App>, model: &'a str) -> &'a str {
    let v = app.engine_tables_view();
    if v.pools().iter().any(|(n, _)| *n == model) || v.model_index(model).is_some() {
        model
    } else {
        crate::proxy::POOL_LABEL_UNRESOLVED
    }
}

// THE PLANE-NEUTRAL JSON-RPC ENVELOPE READER, shared by every JSON-RPC-fronted mounted plane. It
// lives under `ingress/` because that is the shared owner `structure-lint`'s plane ledger already
// names for the ingress concern: "one plane-neutral admission in ingress/, with the plane supplying
// its wire reader". This is the envelope half of that.
pub mod jsonrpc;

/// THE NEUTRAL ARRIVAL SEAM — the `ArrivalHost` ABI a dialect calls to reach the core request
/// pipeline. The kernel keeps no side-table of arrivals (status row 82, D2). Absorbed from
/// busbar-substrate (W4.b P2).
pub mod arrival;
/// THE NEUTRAL INBOUND BYTE-DUPLEX TRANSPORT — the byte half of a single full-duplex channel.
/// Absorbed from busbar-substrate (W4.b P2).
pub mod byte_duplex;
/// THE NEUTRAL FULL-DUPLEX WS INGRESS ACCEPTOR, armed under `runtime`. Absorbed from busbar-substrate.
#[cfg(feature = "runtime")]
pub mod duplex_ws;

/// THE ONE JSON-RPC INGRESS SEQUENCE. Read its header: it carries the thirteen-step measurement
/// that says which four steps are a protocol's and which nine are core's.
pub mod protocol;

// The error-shaping boundary: the ONE place a resolved ingress becomes a native error envelope.
pub mod native;

/// The protocol catch-all.
pub mod dispatch;
/// THE PLANE INGRESS BOUNDARY: one request-observability layer over every mounted plane's door, and
/// the [`observe::Counted`] marker a plane's handler sets on a response it has already labelled.
pub mod observe;
// `protocol_dispatch` is the axum catch-all fallback the core router mounts and nothing outside core
// names, so it stays crate-private — keeping the confidential `CallerToken` it takes off the public
// seam. (The universal resolved-op ingress it used to hold — `operation_resolved`/`operation_ingress`
// — RELOCATED into the plane that owns it; core reaches it only through the neutral body-arrival seam.)
pub(crate) use dispatch::protocol_dispatch;
/// Minimal percent-decoding for a single path segment (no external dependency). Decodes `%XX`
/// escapes as UTF-8; on any malformed escape it leaves the bytes as-is.
///
/// No longer on the request path: axum percent-decodes `Path` params before the handler runs, so
/// a path-model dialect's arrival handler uses the already-decoded segment directly (decoding twice
/// corrupts ids whose first decode yields a literal `%XX`). Retained as a `#[cfg(test)]` helper
/// documenting the decode semantics and guarding against accidental reintroduction of a
/// double-decode.
#[cfg(any(test, feature = "test-support"))]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
