// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY OUTBOUND REFUSAL AND TLS FAILURE, EXPLAINED AND AUDITED.
//!
//! A refused dial (the destination guard, the plaintext rule, the trust store) is one coded
//! BUSBAR-5051 line and one `egress.dial_refused` audit record; a TLS verification failure is one
//! BUSBAR-5047 line and one `egress.tls_verification_failed` audit record carrying the dialled host,
//! the `advanced.tls.destinations` entries that matched and the fingerprints of the operator
//! anchors in force. Lines are rate-limited per (host, reason) so a retry storm writes one line a
//! minute; audit records are written for every refusal the limiter lets through, never with
//! certificate bodies or credentials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use busbar_kernel::diagnostics as diag;

use crate::tls::store::TrustStore;

/// The audit action of a refused dial.
pub const AUDIT_DIAL_REFUSED: &str = "egress.dial_refused";
/// The audit action of an outbound TLS verification failure.
pub const AUDIT_TLS_FAILED: &str = "egress.tls_verification_failed";

/// How often one (host, reason) pair writes a line and a record.
const EVERY: Duration = Duration::from_secs(60);
/// The most (host, reason) pairs the limiter remembers; past it the oldest are forgotten.
const REMEMBERED: usize = 4096;

static STORE: OnceLock<ArcSwapOption<TrustStore>> = OnceLock::new();
static LAST: Mutex<Option<HashMap<(String, String), Instant>>> = Mutex::new(None);

fn store() -> &'static ArcSwapOption<TrustStore> {
    STORE.get_or_init(ArcSwapOption::empty)
}

/// Install the process's trust store for the failure records (the connector selects with its own).
pub fn install_store(s: Arc<TrustStore>) {
    store().store(Some(s));
}

/// Whether the limiter lets a line for `(host, why)` through now.
fn due(host: &str, why: &str) -> bool {
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = last.get_or_insert_with(HashMap::new);
    let now = Instant::now();
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

/// The host of a dial target, without userinfo, port or brackets: what a record may name.
fn shown(target: &str) -> String {
    let t = target.split_once("://").map_or(target, |(_, r)| r);
    let t = t.rsplit_once('@').map_or(t, |(_, h)| h);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    t.chars().take(256).collect()
}

/// The verdict name a `dest.judge` verdict number reads as.
#[must_use]
pub fn verdict_name(v: u64) -> &'static str {
    use busbar_contract::abi::host::service::{
        DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST, DEST_OBFUSCATED,
        DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE,
    };
    match v {
        DEST_SCHEME => "scheme",
        DEST_NO_HOST => "no-host",
        DEST_METADATA => "metadata",
        DEST_OBFUSCATED => "obfuscated",
        DEST_INTERNAL => "internal",
        DEST_PLAINTEXT => "plaintext",
        DEST_UNRESOLVABLE => "unresolvable",
        DEST_NO_ADDRESSES => "no-addresses",
        _ => "refused",
    }
}

/// A REFUSED DIAL: one BUSBAR-5051 line and one audit record, rate-limited per host and reason.
/// `class` is the need's egress class when known; `owner` names the instance and need.
pub fn dial_refused(target: &str, class: Option<u32>, why: &str, owner: Option<(u64, u32)>) {
    let host = shown(target);
    if !due(&host, why) {
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

/// A TLS VERIFICATION FAILURE on a dial of `target`: one BUSBAR-5047 line and one audit record
/// naming the matched `advanced.tls.destinations` entries and the operator anchors in force.
pub fn tls_failed(target: &str, why: &str) {
    let host = shown(target);
    if !due(&host, "tls") {
        return;
    }
    let (matched, anchors) = store()
        .load_full()
        .map(|s| (s.matched(&host), s.fingerprints_for(&host)))
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

/// Whether a TLS error is a verification failure (certificate or pin), not a transport error.
#[must_use]
pub fn is_verification(e: &rustls::Error) -> bool {
    matches!(
        e,
        rustls::Error::InvalidCertificate(_)
            | rustls::Error::NoCertificatesPresented
            | rustls::Error::General(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_host_never_its_userinfo_and_is_rate_limited() {
        assert_eq!(
            shown("https://user:pw@db.internal:5432/x"),
            "db.internal:5432"
        );
        assert!(due("rate.test", "internal"));
        assert!(
            !due("rate.test", "internal"),
            "a second line within a minute is held"
        );
        assert!(
            due("rate.test", "plaintext"),
            "another reason is its own line"
        );
    }
}
