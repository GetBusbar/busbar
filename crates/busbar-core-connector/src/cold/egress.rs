// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS MODULES' COLD TEXT: a failed or capped
//! name lookup's sentence, a proxy's refusal of a CONNECT, a crossing refused for want of the host
//! clock, and the rate-limited BUSBAR-5051 / BUSBAR-5047 lines and audit records of a refused dial
//! or a TLS verification failure (`egress_audit`). Each is built only when a dial is refused or
//! fails, out of line.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_kernel::diagnostics as diag;
use foldhash::{HashMap, HashMapExt as _};

/// A failed system lookup, answered with its sentence.
#[cold]
pub(crate) fn lookup_failed(e: &std::io::Error) -> String {
    e.to_string()
}

/// A lookup refused at the in-flight cap `cap`, answered with its sentence.
#[cold]
pub(crate) fn lookups_in_flight(cap: usize) -> String {
    format!("name lookup: {cap} lookups already in flight")
}

/// The proxy refused the tunnel to `addr`; the refusal quotes its status `line`.
#[cold]
pub(crate) fn proxy_refused_connect(addr: &str, line: &[u8]) -> String {
    format!(
        "proxy refused CONNECT {addr}: {}",
        String::from_utf8_lossy(line)
    )
}

/// A crossing refused for want of the host clock a request head deadline needs.
#[cold]
pub(crate) fn no_host_clock() -> crate::framer::Crossed {
    crate::framer::Crossed {
        outcome: Outcome::Failed,
        error: Some(b"request head deadline requires the host clock".to_vec()),
    }
}

/// The audit action of a refused dial.
const AUDIT_DIAL_REFUSED: &str = "egress.dial_refused";
/// The audit action of an outbound TLS verification failure.
const AUDIT_TLS_FAILED: &str = "egress.tls_verification_failed";

/// How often one (host, reason) pair writes a line and a record.
const EVERY: Duration = Duration::from_secs(60);
/// The most (host, reason) pairs the limiter remembers; past it the oldest are forgotten.
const REMEMBERED: usize = 4096;

static LAST: Mutex<Option<HashMap<(String, String), Instant>>> = Mutex::new(None);

/// Whether the limiter lets a line for `(host, why)` through now: judged by the op's one clock
/// reading, `now` (the op's memo: the clock is read here only if the op has not read it yet).
#[cold]
pub(crate) fn due(host: &str, why: &str, now: &mut Option<Instant>) -> bool {
    let now = crate::compose::clock(now);
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = last.get_or_insert_with(HashMap::new);
    let key = (host.to_owned(), why.to_owned());
    if map
        .get(&key)
        .is_some_and(|at| now.duration_since(*at) < EVERY)
    {
        return false;
    }
    if map.len() >= REMEMBERED {
        map.retain(|_, at| now.duration_since(*at) < EVERY);
        if map.len() >= REMEMBERED {
            map.clear();
        }
    }
    map.insert(key, now);
    true
}

/// A REFUSED DIAL of `host` (as a record may name it): one BUSBAR-5051 line and one audit record,
/// rate-limited per host and reason by the op's clock memo `now`.
#[cold]
pub(crate) fn dial_refused(
    host: &str,
    class: Option<u32>,
    why: &str,
    owner: Option<(u64, u32)>,
    now: &mut Option<Instant>,
) {
    if !due(host, why, now) {
        return;
    }
    let owner_text =
        owner.map_or_else(|| "-".to_owned(), |(i, n)| format!("instance {i} need {n}"));
    tracing::warn!(
        diag = %diag::EGRESS_DIAL_REFUSED.banner(),
        host = %host,
        reason = why,
        class = class.map_or(-1, i64::from),
        owner = %owner_text,
        "outbound dial to {host} refused: {why}"
    );
    busbar_kernel::audit_ring::AUDIT.record_by(
        AUDIT_DIAL_REFUSED,
        &format!("dest:{host}:{why}"),
        busbar_kernel::audit_ring::OUTCOME_REJECTED,
        "system",
    );
}

/// A TLS VERIFICATION FAILURE on a dial of `host` (as a record may name it): one BUSBAR-5047 line
/// and one audit record naming the matched `advanced.tls.destinations` entries and the operator
/// anchors in force, rate-limited by the op's clock memo `now`.
#[cold]
pub(crate) fn tls_failed(host: &str, why: &str, now: &mut Option<Instant>) {
    if !due(host, "tls", now) {
        return;
    }
    let (matched, anchors) = crate::egress_audit::store()
        .load_full()
        .map(|s| (s.matched(host), s.fingerprints_for(host)))
        .unwrap_or_default();
    let matched = if matched.is_empty() {
        "-".to_owned()
    } else {
        matched.join(",")
    };
    let anchors = if anchors.is_empty() {
        "roots".to_owned()
    } else {
        anchors.join(",")
    };
    busbar_kernel::diag_warn!(
        diag::EGRESS_TLS_VERIFICATION_FAILED,
        host = %host,
        matched = %matched,
        anchors = %anchors,
        reason = %why,
        "outbound TLS to {host} failed verification: {why}"
    );
    busbar_kernel::audit_ring::AUDIT.record_by(
        AUDIT_TLS_FAILED,
        &format!("dest:{host}:matched={matched}:anchors={anchors}"),
        busbar_kernel::audit_ring::OUTCOME_REJECTED,
        "system",
    );
}
