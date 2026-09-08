// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHAIN-CLEAVE CONTRACT — `sha256_hex(frame_prelude(..) ⧺ suffix)` byte-equals the legacy
//! single-[`Digest`] output.
//!
//! The two halves of a chained digest can be computed in two places: a host frames the PRELUDE (the
//! previous hash, the scope if the stream digests it, the sequence) and a plane hands back an
//! already-framed content SUFFIX, which the host appends RAW. That split is only sound if the
//! concatenation is byte-identical to feeding every field through one canonicaliser — and the whole
//! point of the split is that the two are computed by different code, so nothing else in the tree
//! notices when they stop agreeing.
//!
//! Both framings are checked, because the pipe-separated one carries a landmine the length-prefixed
//! one does not: a genesis record's previous hash is EMPTY, and pushing it first is what flips
//! `started` and buys the leading vertical bar before the sequence. A prelude that skipped an empty
//! previous hash would produce `1|...` where every deployed store holds `|1|...`, and every chain
//! written before this crate existed would fail to verify at its next boot.
//!
//! The fixed record set below is the vector. If a framing byte moves, these hashes stop matching.

use crate::legacy::chain::{
    digest, frame_prelude, sha256_hex, ChainLabels, ChainedRecord, Digest, Framing,
};
use crate::legacy::entry::AuditEntry;

/// The admin entry's own digested fields, AFTER the prelude — the suffix a plane would hand back.
/// Framed pipe-separated exactly as [`AuditEntry::digest_fields`] frames them, and carrying the
/// leading separator the prelude's trailing field owes.
fn admin_suffix(ts: u64, action: &str, resource: &str, outcome: &str, principal: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for field in [
        ts.to_string(),
        action.to_string(),
        resource.to_string(),
        outcome.to_string(),
        principal.to_string(),
    ] {
        out.push(b'|');
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// One admin record, both ways: prelude ⧺ suffix, and the one canonicaliser.
fn assert_admin_cleaves(
    seq: u64,
    prev_hash: &str,
    ts: u64,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) {
    // The admin chain does NOT digest its scope, so the prelude is prev_hash then seq.
    let mut input = frame_prelude(Framing::PipeSeparated, prev_hash, None, seq);
    input.extend_from_slice(&admin_suffix(ts, action, resource, outcome, principal));
    let cleaved = sha256_hex(&input);

    let entry = AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: principal.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        recorded_here: true,
    };
    let whole = digest(&entry);

    assert_eq!(
        cleaved, whole,
        "the cleaved digest (prelude ⧺ suffix) must byte-equal the single-Digest output for \
         seq {seq}, prev_hash {prev_hash:?}"
    );
}

#[test]
fn pipe_separated_prelude_plus_suffix_equals_the_whole_digest() {
    // GENESIS: the empty previous hash is the landmine. The leading vertical bar it produces before
    // the sequence is load-bearing and is what every deployed store was written with.
    assert_admin_cleaves(
        1,
        "",
        1_700_000_000,
        "hook.register",
        "hook:compress",
        "applied",
        "admin",
    );
    // LINKED: an ordinary record, previous hash present.
    assert_admin_cleaves(
        2,
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        1_700_000_060,
        "hook.delete",
        "hook:compress",
        "applied",
        "admin",
    );
    // A rejected mutation, and a principal that is not the default one.
    assert_admin_cleaves(
        3,
        "0000000000000000000000000000000000000000000000000000000000000001",
        1_700_000_120,
        "config.apply",
        "config:deploy",
        "rejected",
        "operator@example.test",
    );
}

// ── THE SCOPE-DIGESTING, LENGTH-PREFIXED HALF ────────────────────────────────────────────────────
//
// The other framing, and the other prelude shape: a stream that DOES digest its scope. A throwaway
// record type declared here and nowhere else, so the contract is proved against the mechanism rather
// than against one record type's habits.

/// A record whose digest is the framed prelude followed by an opaque suffix fed RAW — the shape a
/// plane reaches the host with.
struct Cleaved {
    tenant: String,
    seq: u64,
    content: Vec<u8>,
    prev_hash: String,
    hash: String,
}

struct CleavedInput {
    content: Vec<u8>,
}

impl ChainedRecord for Cleaved {
    type Input = CleavedInput;
    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the cleaved test chain",
        scope: "tenant",
    };
    // Unused for framing: `digest_fields` frames the prelude itself and appends the suffix RAW.
    const FRAMING: Framing = Framing::LengthPrefixed;
    fn scope_of(&self) -> &str {
        &self.tenant
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }
    fn link(scope: &str, seq: u64, prev_hash: String, input: CleavedInput) -> Self {
        Cleaved {
            tenant: scope.to_string(),
            seq,
            content: input.content,
            prev_hash,
            hash: String::new(),
        }
    }
    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }
    fn digest_fields(&self, d: &mut Digest) {
        d.raw(&frame_prelude(
            Framing::LengthPrefixed,
            &self.prev_hash,
            Some(&self.tenant),
            self.seq,
        ));
        d.raw(&self.content);
    }
}

/// The same record's digest, built WITHOUT the cleave: one canonicaliser, prelude fields fed as
/// fields, then the suffix appended raw. This is the "whole" side of the contract for a stream that
/// digests its scope.
fn whole_digest(tenant: &str, seq: u64, prev_hash: &str, content: &[u8]) -> String {
    let mut d = Digest::new(Framing::LengthPrefixed);
    d.text(prev_hash).text(tenant).num(seq).raw(content);
    d.finish()
}

#[test]
fn length_prefixed_scope_digesting_prelude_plus_suffix_equals_the_whole_digest() {
    for (tenant, seq, prev_hash, content) in [
        ("acme", 1u64, "", &b"the-opaque-suffix"[..]),
        (
            "acme",
            2,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            &b""[..],
        ),
        // A suffix containing the pipe byte: the length-prefixed framing must not care, and the
        // cleave must not either.
        ("other|tenant", 7, "abc", &b"a|b|c"[..]),
    ] {
        let record = crate::legacy::chain::seal::<Cleaved>(
            tenant,
            seq,
            prev_hash.to_string(),
            CleavedInput {
                content: content.to_vec(),
            },
        );
        assert_eq!(
            record.hash,
            whole_digest(tenant, seq, prev_hash, content),
            "the cleaved digest must byte-equal the single-Digest output for {tenant}/{seq}"
        );
        assert_eq!(
            digest(&record),
            record.hash,
            "recomputing the record's own digest must reproduce the sealed hash"
        );
    }
}

/// `raw` appends VERBATIM: no length prefix and no separator of its own, in either framing. That is
/// the property the cleave rests on — a `raw` that framed its argument would silently double-frame
/// every plane's suffix.
#[test]
fn raw_appends_verbatim_in_both_framings() {
    for framing in [Framing::LengthPrefixed, Framing::PipeSeparated] {
        let mut d = Digest::new(framing);
        d.raw(b"abc");
        d.raw(b"def");
        assert_eq!(
            d.bytes(),
            b"abcdef",
            "raw must append verbatim in {framing:?}, adding neither a length prefix nor a separator"
        );
    }
}

/// The genesis landmine, stated as its own assertion so a failure names the cause rather than a
/// hash mismatch: an EMPTY previous hash still flips `started`, so the sequence is preceded by a
/// vertical bar.
#[test]
fn an_empty_genesis_prev_hash_still_owes_the_leading_separator() {
    assert_eq!(
        frame_prelude(Framing::PipeSeparated, "", None, 1),
        b"|1".to_vec(),
        "a genesis pipe-separated prelude is `|1`, not `1` — every deployed store holds the bar"
    );
    assert_eq!(
        frame_prelude(Framing::PipeSeparated, "deadbeef", None, 2),
        b"deadbeef|2".to_vec(),
    );
    assert_eq!(
        frame_prelude(Framing::PipeSeparated, "", Some("log"), 1),
        b"|log|1".to_vec(),
        "a scope-digesting stream puts the scope between the previous hash and the sequence"
    );
}
