// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOSTLESS UPSTREAM-COUNT EMITS, in the neutral substrate.
//!
//! `upstream_attempt_on` / `upstream_failure_on` are the two `(pool, lane)`-labelled counters every
//! plane's synchronous client leg emits for the upstream calls busbar itself originates. They take
//! NO `App` — both labels are operator-configured (a registration id and a transport/binding word off
//! a closed axis), never caller-supplied, so the series count stays bounded without an engine handle.
//! That makes the emit itself a pure `metrics` write, which is why it lives here: a plane names it
//! (`busbar_substrate::telemetry::upstream_attempt_on`) without reaching into `busbar-core`, and
//! core's `crate::telemetry` re-exports both so its own `App`-holding wrappers call them unchanged.

/// `busbar_upstream_attempts_total` — labels: pool (bounded), lane.
pub const UPSTREAM_ATTEMPTS_TOTAL: &str = "busbar_upstream_attempts_total";
/// `busbar_upstream_failures_total` — labels: pool (bounded), lane, disposition.
pub const UPSTREAM_FAILURES_TOTAL: &str = "busbar_upstream_failures_total";

/// `busbar_upstream_attempts_total` for one dispatch attempt on `(pool label, lane label)`.
///
/// BOTH LABELS ARE OPERATOR-CONFIGURED and therefore bounded: the pool label is a registration name
/// out of the operator's config and the lane label is a transport/binding word off a closed axis.
/// Neither is caller-supplied, so a client-supplied value here could never mint a time series per
/// distinct string.
pub fn upstream_attempt_on(pool_label: &str, lane_label: &str) {
    metrics::counter!(
        UPSTREAM_ATTEMPTS_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned()
    )
    .increment(1);
}

/// `busbar_upstream_failures_total` for one classified failure on `(pool label, lane label)`.
///
/// THE EMIT for this family, on EVERY plane — see [`upstream_attempt_on`] for why there is no `&App`
/// and why both labels are bounded. `disposition` is the model plane's own vocabulary (the
/// `DISPOSITION_*` values in [`crate::proxy`]) and no plane gets one of its own.
pub fn upstream_failure_on(pool_label: &str, lane_label: &str, disposition: &'static str) {
    metrics::counter!(
        UPSTREAM_FAILURES_TOTAL,
        "pool" => pool_label.to_owned(),
        "lane" => lane_label.to_owned(),
        "disposition" => disposition
    )
    .increment(1);
}

/// THE HTTP STATUS → OUTCOME LABEL, in the neutral substrate. A pure `u16 → &'static str` fold over a
/// CLOSED set of outcome words (`ok`, `exhausted`, `client_error`, `error`) — no `App`, no state — so
/// every plane names it (`busbar_substrate::telemetry::outcome_of`) for its own request-completion
/// label without reaching into `busbar-core`, and core's `crate::telemetry` re-exports it so its own
/// call sites are unchanged. `503` is called out as `exhausted` (a pool ran dry) distinctly from the
/// rest of the `5xx`/other band, exactly as before.
pub fn outcome_of(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        503 => "exhausted",
        400..=499 => "client_error",
        _ => "error",
    }
}
