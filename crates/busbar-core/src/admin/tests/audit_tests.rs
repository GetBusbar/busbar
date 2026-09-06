// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/audit.rs`.

use super::*;

#[test]
fn export_load_roundtrip_resumes_chain() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");
    let exported = log.export();
    assert_eq!(exported.len(), 2);

    // Restore into a fresh log (a fresh boot): chain intact, sequence resumes AFTER max seq.
    let restored = AuditLog::new();
    restored.load(exported);
    assert!(restored.verify(), "restored chain must verify");
    restored.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
    let all = restored.list(10);
    assert_eq!(all.len(), 3);
    assert!(
        all[0].seq > all[1].seq,
        "post-restore entries continue the sequence"
    );
    assert!(
        restored.verify(),
        "chain still verifies across the restore boundary"
    );
}

#[test]
fn record_and_list_newest_first() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    let entries = log.list(10);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].action, "hook.delete", "newest first");
    assert!(entries[0].seq > entries[1].seq, "monotonic seq");
}

#[test]
fn hash_chain_links_and_verifies() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    log.record_by("hook.register", "hook:b", OUTCOME_REJECTED, "admin");
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    assert!(log.verify(), "an untouched chain verifies");

    // Each entry (oldest→newest) links to its predecessor's hash.
    let q = log.entries.lock().unwrap();
    assert_eq!(q[0].prev_hash, "", "first entry has no predecessor");
    assert_eq!(q[1].prev_hash, q[0].hash);
    assert_eq!(q[2].prev_hash, q[1].hash);
    drop(q);

    // Tamper: mutate a recorded field in place → verification fails.
    {
        let mut q = log.entries.lock().unwrap();
        q[1].resource = "hook:evil".to_string();
    }
    assert!(!log.verify(), "a tampered entry breaks the chain");
}

/// THE FORGERY THE PIPE JOIN ADMITS, PERFORMED ON THIS RING, AND REFUSED. A caller hands `record_by`
/// a resource containing the separator; under the legacy framing the resulting entry's digest is
/// exactly the digest of a DIFFERENT entry — one whose outcome and whose attribution have both been
/// rewritten — so `verify` passes the lie. Under the framing this build seals every new record with,
/// the substitution is a `DigestMismatch`.
///
/// RED BEFORE GREEN, on the chain that actually serves the read surface: relabel the recorded entry
/// as the legacy scheme and the forged fields verify; leave it as sealed and they do not.
#[test]
fn a_caller_supplied_separator_cannot_move_a_recorded_outcome_or_attribution() {
    let log = AuditLog::new();
    // What actually happened: `hook:x` was REJECTED, and the attribution is the odd-looking (but
    // entirely permitted) principal `applied|mallory`.
    log.record_by(
        "hook.register",
        "hook:x",
        OUTCOME_REJECTED,
        "applied|mallory",
    );

    // The LIE the same bytes can be read as under the pipe join: `hook:x|rejected` was APPLIED by
    // `mallory`. Same seq, same ts, same prev_hash — only the field boundaries move.
    let forge = |e: &AuditEntry| AuditEntry {
        resource: "hook:x|rejected".to_string(),
        outcome: "applied".to_string(),
        principal: "mallory".to_string(),
        ..e.clone()
    };

    let sealed = log.export().remove(0);
    assert_eq!(
        sealed.digest_scheme,
        crate::plane::auditlog::DIGEST_SCHEME_LEN_PREFIXED,
        "`record_by` must seal under the injective framing"
    );

    // THE DEFECT: under the legacy framing the forged record recomputes to the SAME digest, so a
    // chain carrying it verifies and the rewritten outcome and attribution are indistinguishable
    // from what happened.
    let legacy = AuditEntry {
        digest_scheme: crate::plane::auditlog::DIGEST_SCHEME_LEGACY_PIPE,
        hash: String::new(),
        ..sealed.clone()
    };
    let legacy_hash = crate::audit::digest(&legacy);
    let legacy_forged = AuditEntry {
        hash: legacy_hash.clone(),
        ..forge(&legacy)
    };
    assert_eq!(
        crate::audit::digest(&legacy_forged),
        legacy_hash,
        "the pipe join is the defect: the forged record must recompute to the sealed digest"
    );
    assert!(
        crate::audit::verify_window(std::slice::from_ref(&legacy_forged)).is_ok(),
        "and the verifier must pass it — that is what makes it a forgery and not a corruption"
    );

    // THE FIX: the record this build actually sealed. The same substitution is caught.
    let forged = forge(&sealed);
    assert_ne!(
        crate::audit::digest(&forged),
        sealed.hash,
        "scheme 2 must not admit the substitution"
    );
    assert!(
        matches!(
            crate::audit::verify_window(std::slice::from_ref(&forged))
                .unwrap_err()
                .kind,
            crate::audit::ChainBreakKind::DigestMismatch { .. }
        ),
        "the forged record must be reported as EDITED"
    );
}

/// A PERSISTED 1.5.5 CHAIN STILL VERIFIES, and a chain that spans the upgrade verifies too. The
/// entries a store already holds were sealed under the pipe join and cannot be re-sealed; a build
/// that could not read them would report every deployment's own history as tampered at the next boot.
#[test]
fn a_legacy_chain_verifies_and_so_does_one_that_crosses_the_upgrade() {
    let legacy = crate::plane::auditlog::DIGEST_SCHEME_LEGACY_PIPE;
    let mk = |seq: u64, scheme: u8, prev: String| {
        let mut e = AuditEntry {
            seq,
            ts: 1_700_000_000 + seq,
            action: "hook.register".to_string(),
            resource: "hook:a".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "admin".to_string(),
            prev_hash: prev,
            hash: String::new(),
            digest_scheme: scheme,
            recorded_here: false,
        };
        e.hash = crate::audit::digest(&e);
        e
    };

    // What 1.5.5 wrote, on its own: every record pipe-joined.
    let a = mk(1, legacy, String::new());
    let b = mk(2, legacy, a.hash.clone());
    let persisted = vec![a, b];
    assert!(
        crate::audit::verify_chain(&persisted).is_ok(),
        "a chain written entirely by 1.5.5 must still verify"
    );

    // The same store, appended to by this build: ONE sequence, two framings, checked entry by entry
    // against the framing that sealed each.
    let log = AuditLog::new();
    log.load(persisted);
    log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
    assert!(
        log.verify(),
        "a chain spanning the framing upgrade must verify"
    );
    let all = log.list(10);
    assert_eq!(all.len(), 3);
    assert_eq!(
        all[0].digest_scheme,
        crate::plane::auditlog::DIGEST_SCHEME_LEN_PREFIXED,
        "the entry this build appended is scheme 2"
    );
    assert_eq!(all[2].digest_scheme, legacy, "the restored head is legacy");
}

/// THE WIRE, BOTH WAYS. `digest_scheme` is present on a record this build sealed — an external
/// re-implementation of the digest has to read it — and ABSENT on a legacy one, so a 1.5.5 record read
/// out of a store re-serialises to the same eight fields it arrived as rather than gaining a field
/// its writer never wrote.
#[test]
fn the_scheme_is_on_the_wire_for_a_new_entry_and_off_it_for_a_legacy_one() {
    let log = AuditLog::new();
    log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
    let sealed = log.export().remove(0);

    let json = serde_json::to_value(&sealed).expect("serialize");
    assert_eq!(
        json.get("digest_scheme")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "GET /audit must carry the scheme on an entry this release sealed"
    );

    let legacy = AuditEntry {
        digest_scheme: crate::plane::auditlog::DIGEST_SCHEME_LEGACY_PIPE,
        ..sealed
    };
    let legacy_json = serde_json::to_value(&legacy).expect("serialize");
    assert!(
        legacy_json.get("digest_scheme").is_none(),
        "a pre-1.6.0 record must re-serialise without a scheme field"
    );
    assert_eq!(
        legacy_json.as_object().map(serde_json::Map::len),
        Some(8),
        "the legacy record's wire shape is the eight fields it has always been"
    );

    // And a legacy body coming BACK in — with no scheme field at all — is read as the framing that
    // really sealed it, not as this build's.
    let back: AuditEntry = serde_json::from_value(legacy_json).expect("deserialize");
    assert_eq!(
        back.digest_scheme,
        crate::plane::auditlog::DIGEST_SCHEME_LEGACY_PIPE
    );
}
