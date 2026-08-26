// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane/auditlog.rs`.

use super::*;
use crate::audit::{digest, frame_prelude, Framing};

/// THE BYTE-IDENTITY GATE: the plane's pre-framed suffix, appended RAW after the host prelude
/// framed with `digests_scope = false`, reproduces the legacy [`AuditEntry`] digest byte-for-byte.
/// A perturbation of the suffix, the prelude framing, or the `digests_scope` flag would fail this.
fn assert_roundtrip(seq: u64, prev_hash: &str, ts: u64, act: &str, res: &str, out: &str, pr: &str) {
    // The seam's digest input: frame_prelude(PipeSeparated, prev_hash, None=no scope, seq) ⧺ suffix.
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&audit_suffix(ts, act, res, out, pr));
    let via_seam = busbar_api::sha256_hex(&input);

    // The legacy digest: the AuditEntry's own `digest_fields` through the ONE canonicaliser.
    let entry = AuditEntry {
        seq,
        ts,
        action: act.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        recorded_here: true,
    };
    let legacy = digest(&entry);
    assert_eq!(
        via_seam, legacy,
        "seam digest (digests_scope=false) must byte-equal the legacy AuditEntry digest"
    );
}

#[test]
fn suffix_plus_scopeless_prelude_equals_legacy_audit_digest() {
    // Genesis (empty prev_hash) — the leading `|` before `seq` the empty prev_hash produces is
    // load-bearing; and a linked record.
    assert_roundtrip(
        1,
        "",
        1_700_000_000,
        "hook.register",
        "hook:compress",
        "applied",
        "admin",
    );
    assert_roundtrip(
        2,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        1_700_000_060,
        "hook.delete",
        "hook:compress",
        "applied",
        "admin",
    );
}

/// THE CONVERSION GATE: a converted site's record, appended through the SEAM, carries the SAME hash
/// the legacy admin ring computes for the same fields at the same chain position — genesis AND the
/// inter-record link. Feeds a fixed `ts` on both sides (the seam suffix built directly, the legacy
/// `AuditEntry` filled directly) so the comparison isolates the digest, not the clock.
#[test]
fn a_converted_sites_seam_record_matches_the_legacy_ring_hash() {
    let h = AuditTestHarness::over(std::sync::Arc::new(busbar_store_memory::MemoryStore::new()));
    let (ts, act, res, out, pr) = (
        1_700_000_123u64,
        "hook.register",
        "hook:x",
        "applied",
        "admin",
    );

    // Append through the seam (the converted-site path) and read the link each append sealed.
    let (seq1, prev1, hash1) = h.emit_full(ADMIN_LOG, audit_suffix(ts, act, res, out, pr));
    let (seq2, prev2, hash2) = h.emit_full(
        ADMIN_LOG,
        audit_suffix(ts + 60, "hook.delete", res, out, pr),
    );

    // The legacy ring's records for the SAME fields at the SAME chain positions.
    let mk = |seq, ts, action: &str, prev: String| AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: res.to_string(),
        outcome: out.to_string(),
        principal: pr.to_string(),
        prev_hash: prev,
        hash: String::new(),
        recorded_here: true,
    };
    assert_eq!((seq1, prev1.as_str()), (1, ""), "genesis position");
    assert_eq!(hash1, digest(&mk(1, ts, act, String::new())));
    assert_eq!((seq2, prev2), (2, hash1.clone()), "record 2 links record 1");
    assert_eq!(hash2, digest(&mk(2, ts + 60, "hook.delete", hash1)));
}
