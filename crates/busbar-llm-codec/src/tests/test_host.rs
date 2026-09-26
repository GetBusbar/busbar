// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS CRATE'S TEST HOST (#83a SD-3): the host services a shipped binary's composition root arms
//! behind the contract seams, armed for this crate's own test binary by the test itself — so the
//! codec's tests prove the codec's own seam and never reach the host crate. Test-only by
//! construction (`#[cfg(test)]` at its one `mod` line).
//!
//! - ENTROPY: the OS CSPRNG, the same source the host arms.
//! - WALL CLOCK: the system clock in whole seconds, as the host reads it.
//! - TRANSLATE CAP: none armed — the contract's documented 32 MiB default applies, which is the
//!   host's own default for an unconfigured limit.
//! - USAGE-TAP COUNT: a per-thread record of every `(protocol, reason)` fault the codec reports,
//!   first-seen per thread, which [`tap_faults`] reads back. What the host does with a report (the
//!   `busbar_billing_tap_decode_fail_total` series and the warn-once set) is pinned in the host's suite.
//! - CLASSIFICATION: [`classified`] reads the class the host's classifier places a raw upstream error
//!   in off the shared fixture `testing/plane-copies/upstream-classes.json`, which the host's suite
//!   holds its classifier to.

use busbar_contract::codec::CodecError;
use busbar_contract::upstream::{CanonicalSignal, RawUpstreamError, StatusClass};
use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    /// Every usage-tap fault this thread reported, `(protocol, reason) -> count`.
    static TAP_FAULTS: RefCell<BTreeMap<(String, &'static str), u64>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn record_tap_fault(protocol: &str, reason: &'static str) -> bool {
    TAP_FAULTS.with(|t| {
        let mut t = t.borrow_mut();
        let n = t.entry((protocol.to_string(), reason)).or_insert(0);
        *n += 1;
        *n == 1
    })
}

fn report_decode_failure(protocol: &str, _error: &CodecError) {
    record_tap_fault(protocol, "decode");
}

fn os_entropy(out: &mut [u8]) -> bool {
    getrandom::fill(out).is_ok()
}

fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Arm the test host's services behind the contract seams, ONCE per process — the counterpart of
/// the composition root arming the host's own. `Once`-guarded.
pub fn ensure_test_protocols_registered() {
    static ARM: std::sync::Once = std::sync::Once::new();
    ARM.call_once(|| {
        busbar_contract::codec::install_entropy_source(os_entropy);
        busbar_contract::codec::install_wall_clock(system_clock);
        busbar_contract::codec::install_usage_tap_fault_latch(record_tap_fault);
        busbar_contract::codec::install_usage_tap_fault_reporter(report_decode_failure);
    });
}

/// The usage-tap faults THIS thread reported while running `f`, `(protocol, reason) -> count`.
pub fn tap_faults(f: impl FnOnce()) -> BTreeMap<(String, &'static str), u64> {
    ensure_test_protocols_registered();
    TAP_FAULTS.with(|t| t.borrow_mut().clear());
    f();
    TAP_FAULTS.with(|t| t.borrow().clone())
}

/// The class the host's classifier places `raw` in with an EMPTY operator `error_map`, read off the
/// shared fixture. A raw shape the fixture does not list fails the test that produced it: a dialect
/// whose error reader starts producing a new shape must add it there, where the host's suite checks
/// it too.
pub fn classified(raw: &RawUpstreamError) -> CanonicalSignal {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/upstream-classes.json"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
            .expect("fixture is JSON");
    let row = doc["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| {
            r["http_status"] == u64::from(raw.http_status)
                && r["provider_code"].as_str() == raw.provider_code.as_deref()
                && r["structured_type"].as_str() == raw.structured_type.as_deref()
                && r["retry_after_secs"].as_u64() == raw.retry_after_secs
        })
        .unwrap_or_else(|| panic!("{raw:?} is not in testing/plane-copies/upstream-classes.json"));
    CanonicalSignal {
        class: StatusClass::parse(row["class"].as_str().expect("class")).expect("a class token"),
        provider_signal: raw.provider_code.clone(),
        retry_after: raw.retry_after_secs,
    }
}
