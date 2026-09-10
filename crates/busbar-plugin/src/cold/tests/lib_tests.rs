// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-abi/src/lib.rs`.

use super::*;
use busbar_api::{AuditRecord, ScopeRef, SecretErrorKind as LegacySecretErrorKind, VirtualKey};

/// The five status codes are pairwise DISTINCT integers. The loader's discrimination (esp. the
/// revocation-denylist fallback) keys on these being different: an undecodable-variant signal
/// ([`STATUS_UNSUPPORTED`]) must never collide with a caught panic ([`STATUS_PANIC`]) or a backend
/// failure ([`STATUS_ERR`]) or a caller-protocol violation ([`STATUS_PROTOCOL`]).
#[test]
fn status_codes_are_pairwise_distinct() {
    let all = [
        STATUS_OK,
        STATUS_ERR,
        STATUS_PROTOCOL,
        STATUS_UNSUPPORTED,
        STATUS_PANIC,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "status codes must be pairwise distinct");
        }
    }
    // The two forward-compat codes are the specific values the loader/SDK agree on.
    assert_eq!(STATUS_UNSUPPORTED, 2);
    assert_eq!(STATUS_PANIC, 3);
}

/// The response cap is exactly 256 MiB, not some other magnitude a mutated `*`/`+`/`/` in its
/// definition could silently produce (e.g. `256 * 1024 + 1024` is ~262 KiB, `256 * 1024 / 1024`
/// is 256 bytes — both would pass a loose "it's some positive number" check but leave the loader
/// either OOM-vulnerable or unable to carry a real payload).
#[test]
fn max_plugin_response_len_is_exactly_256_mebibytes() {
    assert_eq!(MAX_PLUGIN_RESPONSE_LEN, 268_435_456);
    assert_eq!(MAX_PLUGIN_RESPONSE_LEN, 256 * 1024 * 1024);
}

/// Every kind has a NUL-TERMINATED sibling whose bytes are exactly the plain `&str` plus one
/// trailing NUL, and every one of them is a legal C string. `busbar_plugin_kind()` returns a
/// bare `*const u8` with NO length, and the loader does `CStr::from_ptr` on it — so the ONLY
/// safe thing a hand-written export may return is the pointer to one of THESE. The plain
/// `kind::*` `&str`s are NOT NUL-terminated; returning `kind::EXPORT.as_ptr()` compiles and is
/// an unbounded out-of-bounds read. This test is the mechanical proof the safe siblings exist,
/// stay in lockstep with the strings, and are C-legal.
#[test]
fn every_kind_has_a_nul_terminated_sibling_that_is_a_legal_c_string() {
    let pairs: [(&str, &[u8]); 5] = [
        (kind::STORE, kind::STORE_NUL),
        (kind::SECRET, kind::SECRET_NUL),
        (kind::AUTH, kind::AUTH_NUL),
        (kind::HOOK, kind::HOOK_NUL),
        (kind::EXPORT, kind::EXPORT_NUL),
    ];
    for (s, nul) in pairs {
        assert_eq!(
            nul.len(),
            s.len() + 1,
            "{s}: the NUL sibling is the string plus exactly one terminator"
        );
        assert_eq!(&nul[..s.len()], s.as_bytes(), "{s}: bytes must match");
        let c = std::ffi::CStr::from_bytes_with_nul(nul)
            .unwrap_or_else(|e| panic!("{s}: not a legal C string: {e}"));
        assert_eq!(
            c.to_str().expect("ASCII"),
            s,
            "{s}: CStr round-trips to the plain form (this is exactly what the loader does)"
        );
    }
}

fn sample_audit() -> AuditRecord {
    AuditRecord {
        seq: 7,
        ts: 123,
        action: "plugin.install".into(),
        resource: "plugin:x".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: "abc".into(),
        hash: "def".into(),
    }
}

fn sample_key() -> VirtualKey {
    VirtualKey {
        id: "vk_1".into(),
        generation_hash: "deadbeef".into(),
        name: "test".into(),
        allowed_scopes: Some(vec![ScopeRef::pool("p1")]),
        enabled: true,
        created_at: 42,
        group: Some("growth".into()),
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn sample_credential_secret() -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: "cred_1".into(),
            key_id: "vk_1".into(),
            kind: "sigv4".into(),
            slot: 0,
            public_id: "AKIA_TEST".into(),
            secret_form: busbar_api::SecretForm::Recoverable,
            created_at: 42,
            updated_at: 42,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 1,
        },
        secret: "v1:plain:s3cr3t".into(),
    }
}

/// The request/response enums round-trip through JSON unchanged — the wire is stable and the
/// variant is self-describing (no separate op-code needed).
#[test]
fn request_response_json_roundtrip() {
    let reqs = vec![
        StoreRequest::PutKey(sample_key()),
        StoreRequest::GetKey("vk_1".into()),
        StoreRequest::ListKeys,
        StoreRequest::DeleteKey("vk_1".into()),
        StoreRequest::GetUsage {
            bucket_id: "vk_1".into(),
            window_start: 100,
        },
        StoreRequest::PutUsage {
            bucket_id: "vk_1".into(),
            window_start: 100,
            ledger: busbar_api::UsageLedger {
                requests: 1,
                billable_requests: 1,
                models: vec![busbar_api::ModelTokens {
                    model: "gpt-5".into(),
                    usage_units: std::collections::BTreeMap::from([
                        (busbar_api::UNIT_INPUT.to_string(), 7u64),
                        (busbar_api::UNIT_OUTPUT.to_string(), 3),
                        (busbar_api::UNIT_CACHE_READ.to_string(), 1),
                    ]),
                }],
            },
        },
        StoreRequest::AddUsage {
            bucket_id: "group:growth".into(),
            window_start: 100,
            delta: busbar_api::UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![busbar_api::ModelTokensDelta {
                    model: "gpt-5".into(),
                    usage_units: std::collections::BTreeMap::from([
                        (busbar_api::UNIT_INPUT.to_string(), 7i64),
                        (busbar_api::UNIT_OUTPUT.to_string(), -3),
                    ]),
                }],
            },
        },
        StoreRequest::ListMetering(9),
        StoreRequest::PurgeWindowsBefore(100),
        StoreRequest::PurgeMeteringBefore("2026-07-30".into()),
        StoreRequest::PutCredential(sample_credential_secret()),
        StoreRequest::PutKeyWithCredential {
            key: sample_key(),
            secret: sample_credential_secret(),
        },
        StoreRequest::ListCredentials("vk_1".into()),
        StoreRequest::LookupCredentialSecret {
            kind: "sigv4".into(),
            public_id: "AKIA_TEST".into(),
        },
        StoreRequest::RevokeCredential {
            id: "cred_1".into(),
            reason: "rotated".into(),
        },
        StoreRequest::ListCredentialsSince(0),
        StoreRequest::ScrubKey("vk_1".into()),
        StoreRequest::ListKeysSince(0),
        StoreRequest::AppendAudit(sample_audit()),
        StoreRequest::ListAudit,
        StoreRequest::ListAuditTail(500),
    ];
    for r in reqs {
        let j = serde_json::to_vec(&r).unwrap();
        let back: StoreRequest = serde_json::from_slice(&j).unwrap();
        // Re-serialize and compare bytes (the enums aren't PartialEq, but their JSON is stable).
        assert_eq!(serde_json::to_vec(&back).unwrap(), j);
    }

    // The audit response variant round-trips too.
    let ar = StoreResponse::Audit(vec![sample_audit()]);
    let j = serde_json::to_vec(&ar).unwrap();
    match serde_json::from_slice::<StoreResponse>(&j).unwrap() {
        StoreResponse::Audit(v) => assert_eq!(v, vec![sample_audit()]),
        _ => panic!("wrong variant"),
    }

    let key = sample_key();
    let resp = StoreResponse::Key(Some(key.clone()));
    let j = serde_json::to_vec(&resp).unwrap();
    let back: StoreResponse = serde_json::from_slice(&j).unwrap();
    match back {
        StoreResponse::Key(Some(k)) => assert!(k == key),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn abi_version_is_four() {
    // Bumped 1 -> 2 for the credentials generalization, 2 -> 3 for the Store genericization (the 14
    // protocol-named Store verbs collapsed to 8 neutral kind-tagged verbs), then 3 -> 4 for the
    // plane record-type relocation (the four durable record structs moved out of `busbar-api` into
    // the plane crates, so a 1.6-built plugin can no longer link against 1.7 — see ABI_VERSION's
    // doc). A mismatched plugin is refused at the handshake, and the loader's supported-ABI floor is
    // [4,4], so a stale 1.6 store artifact is refused at load.
    assert_eq!(ABI_VERSION, 4);
}

/// The auth payload schema is at v2 (1.5.2 login primitives). Pinned so the SDK/loader floor and
/// the wire additions can't silently drift apart.
#[test]
fn auth_abi_version_is_two() {
    assert_eq!(AUTH_ABI_VERSION, 2);
}

// ── the secret kind's wire error taxonomy, re-homed ─────────────────────────────────────────────
//
// `SecretErrorKind` used to be declared in the retiring 1.5.5 plugin-contract crate, named ON the
// frozen `SecretResponse` wire. That crate is being deleted, so the enum moves into the crate that
// owns the wire. The move is a NAMESPACING change and nothing else, and these two cells are what
// proves that rather than asserting it: the first pins the five wire tokens against literal JSON,
// the second serialises EVERY variant through BOTH spellings — the legacy one, imported here as
// `LegacySecretErrorKind`, and the re-homed one — and requires the bytes to be equal.
// `SECRET_ABI_VERSION` therefore does not move.

/// Every variant's wire token, against a literal. These five strings are what an installed
/// third-party `kind: secret` plugin emits today; a rename here is a signed-wire break.
#[test]
fn secret_error_kind_wire_tokens_are_the_frozen_five() {
    let pairs = [
        (SecretErrorKind::NotFound, "\"not_found\""),
        (SecretErrorKind::Unavailable, "\"unavailable\""),
        (SecretErrorKind::Denied, "\"denied\""),
        (SecretErrorKind::Invalid, "\"invalid\""),
        (SecretErrorKind::Internal, "\"internal\""),
    ];
    for (variant, token) in pairs {
        assert_eq!(
            serde_json::to_string(&variant).expect("wire enum serialises"),
            token,
            "the frozen secret wire token for {variant:?}"
        );
        assert_eq!(
            serde_json::from_str::<SecretErrorKind>(token).expect("wire enum deserialises"),
            variant,
            "the frozen secret wire token for {variant:?} round-trips"
        );
    }
}

/// BYTE-IDENTITY, both directions, for the whole `SecretResponse::Error` envelope as well as the
/// bare kind: the re-homed enum and the legacy enum it replaces serialise to the SAME BYTES, and
/// each decodes the other's bytes. This is the cell that licenses deleting the legacy copy without
/// bumping `SECRET_ABI_VERSION`.
#[test]
fn secret_error_kind_is_byte_identical_to_the_legacy_enum_it_replaces() {
    let before = [
        LegacySecretErrorKind::NotFound,
        LegacySecretErrorKind::Unavailable,
        LegacySecretErrorKind::Denied,
        LegacySecretErrorKind::Invalid,
        LegacySecretErrorKind::Internal,
    ];
    let after = [
        SecretErrorKind::NotFound,
        SecretErrorKind::Unavailable,
        SecretErrorKind::Denied,
        SecretErrorKind::Invalid,
        SecretErrorKind::Internal,
    ];
    assert_eq!(before.len(), after.len(), "same variant count, same order");
    for (old, new) in before.iter().zip(after.iter()) {
        let old_bytes = serde_json::to_vec(old).expect("legacy enum serialises");
        let new_bytes = serde_json::to_vec(new).expect("cold enum serialises");
        assert_eq!(
            old_bytes, new_bytes,
            "the re-homed {new:?} must serialise to the bytes the legacy {old:?} does"
        );
        // Each side decodes the other's bytes, so a plugin built against either spelling talks to
        // an engine built against the other.
        serde_json::from_slice::<SecretErrorKind>(&old_bytes)
            .expect("the cold enum decodes the legacy enum's bytes");
        serde_json::from_slice::<LegacySecretErrorKind>(&new_bytes)
            .expect("the legacy enum decodes the cold enum's bytes");

        // And the whole envelope the wire actually carries, not just the tag.
        let envelope = serde_json::to_string(&SecretResponse::Error {
            kind: *new,
            message: "m".to_string(),
        })
        .expect("envelope serialises");
        assert_eq!(
            envelope,
            format!(
                "{{\"Error\":{{\"kind\":{},\"message\":\"m\"}}}}",
                String::from_utf8(old_bytes).expect("token is utf-8")
            ),
            "the frozen SecretResponse::Error envelope"
        );
    }
}
