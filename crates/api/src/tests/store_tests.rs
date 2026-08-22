// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/store.rs`.

use super::*;

fn sample_key() -> VirtualKey {
    VirtualKey {
        id: "vk_1".to_string(),
        generation_hash: "deadbeefdeadbeef".to_string(),
        name: "test".to_string(),
        allowed_scopes: Some(vec![ScopeRef::pool("p")]),
        enabled: true,
        created_at: 42,
        group: Some("growth".to_string()),
        labels: std::collections::BTreeMap::from([("team".to_string(), "growth".to_string())]),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn sample_credential() -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: "cred_1".to_string(),
            key_id: "vk_1".to_string(),
            kind: "sigv4".to_string(),
            slot: 0,
            public_id: "AKIA_TEST".to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 42,
            updated_at: 42,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 1,
        },
        secret: "v1:plain:s3cr3t-signing-key".to_string(),
    }
}

/// Pool-grant semantics on the runtime encoding: omitted (`None`) = ALL pools; an explicit
/// list is exhaustive; an explicit EMPTY list is NO pools (never "all"). Exercised through
/// `scope_allowed("pool", ...)`, the generalized replacement for the old `pool_allowed` - this
/// is the "zero behavior change for pool-only configs" property the generalization promises.
#[test]
fn scope_allowed_pool_kind_c6_semantics() {
    let mut k = sample_key();
    k.allowed_scopes = None;
    assert!(k.scope_allowed("pool", "anything"), "omitted = all scopes");
    k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(k.scope_allowed("pool", "fast"));
    assert!(!k.scope_allowed("pool", "cold"));
    k.allowed_scopes = Some(Vec::new());
    assert!(
        !k.scope_allowed("pool", "fast"),
        "an explicit [] is the EMPTY set - no scopes, never all"
    );
}

/// CROSS-KIND `scope_allowed` is FAIL-CLOSED, and that is frozen.
///
/// A key whose `allowed_scopes` names only `pool` entries grants NOTHING for any OTHER kind. This
/// matters because 1.6.0 adds `mcp_server` and `agent`: under the fail-OPEN reading
/// (an unlisted kind is "unconstrained") every already-issued pool-scoped key would silently
/// become a WILDCARD over the new kind on upgrade — a privilege escalation delivered by a
/// version bump.
///
/// Only an OMITTED (`None`) list is ever a wildcard. An explicit list — even one that mentions no
/// entry of the queried kind at all — is exhaustive ACROSS ALL KINDS.
#[test]
fn scope_allowed_cross_kind_is_fail_closed() {
    let mut k = sample_key();

    // A pool-only grant denies every future kind, by value AND by kind.
    k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(k.scope_allowed("pool", "fast"));
    for future_kind in ["mcp_server", "agent", "some_kind_not_invented_yet"] {
        assert!(
            !k.scope_allowed(future_kind, "fast"),
            "a pool-only grant must grant NOTHING for the future kind '{future_kind}' — the unlisted-kind case is FAIL-CLOSED and frozen"
        );
        assert!(!k.scope_allowed(future_kind, "anything-else"));
    }

    // The ONLY wildcard is an omitted list, and it spans every kind (unchanged).
    k.allowed_scopes = None;
    assert!(k.scope_allowed("pool", "fast"));
    assert!(k.scope_allowed("mcp_server", "filesystem"));
    assert!(k.scope_allowed("agent", "planner"));

    // A grant naming ONLY a future kind likewise denies pools — the rule is symmetric, so it
    // cannot be read as "pool is special".
    k.allowed_scopes = Some(vec![ScopeRef {
        kind: "mcp_server".to_string(),
        value: "filesystem".to_string(),
    }]);
    assert!(k.scope_allowed("mcp_server", "filesystem"));
    assert!(
        !k.scope_allowed("pool", "filesystem"),
        "the fail-closed rule is symmetric across kinds"
    );
}

/// A DIFFERENT kind never matches a `pool`-kind grant, and vice versa - `ScopeRef` is
/// kind-agnostic and `scope_allowed` is a strict `(kind, value)` membership test, not a bare
/// value match: kind stays a plain string, never privileging "pool".
#[test]
fn scope_allowed_is_kind_specific() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(k.scope_allowed("pool", "fast"));
    assert!(
        !k.scope_allowed("mcp_server", "fast"),
        "same value, different kind: must not match"
    );
}

/// THE contract test: a config using only `allowed_pools` (bare strings, no `kind` wrapper)
/// produces a BYTE-IDENTICAL wire shape before and after the `ScopeRef` generalization - the
/// entire point of the wire-compat design. The in-memory representation is
/// `allowed_scopes: Vec<ScopeRef>`, but the JSON on the wire is still the plain
/// `"allowed_pools":["fast","slow"]` array of bare strings a pre-generalization admin API
/// client already knows how to read and write.
#[test]
fn allowed_pools_wire_shape_is_byte_identical_to_pre_generalization() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")]);
    let json = serde_json::to_string(&k).unwrap();
    assert!(
        json.contains(r#""allowed_pools":["fast","slow"]"#),
        "wire field must be the bare-string array under the `allowed_pools` name, no `kind` \
         wrapper anywhere: {json}"
    );
    assert!(
        !json.contains("kind"),
        "no ScopeRef {{kind, value}} shape may leak onto the wire: {json}"
    );

    // The pre-generalization wire shape a real (already-deployed) admin API client sends -
    // must deserialize into the exact ScopeRef list this test set up.
    let legacy_wire = r#"{"id":"vk_1","generation_hash":"h","name":"n","allowed_pools":["fast","slow"],"enabled":true,"created_at":1}"#;
    let back: VirtualKey = serde_json::from_str(legacy_wire).unwrap();
    assert_eq!(
        back.allowed_scopes,
        Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")])
    );

    // Round-trip: serialize → deserialize → identical scopes (and the None/empty cases,
    // which must ALSO stay wire-identical).
    let round: VirtualKey = serde_json::from_str(&json).unwrap();
    assert_eq!(round.allowed_scopes, k.allowed_scopes);

    let mut none_grant = sample_key();
    none_grant.allowed_scopes = None;
    let json_none = serde_json::to_string(&none_grant).unwrap();
    assert!(
        json_none.contains(r#""allowed_pools":null"#),
        "omitted grant serializes as bare `null`, same as before: {json_none}"
    );

    let mut empty_grant = sample_key();
    empty_grant.allowed_scopes = Some(Vec::new());
    let json_empty = serde_json::to_string(&empty_grant).unwrap();
    assert!(
        json_empty.contains(r#""allowed_pools":[]"#),
        "explicit-empty grant serializes as a bare `[]`, same as before: {json_empty}"
    );
}

/// The 1.6.0 attribution/provenance fields (`idp_subject`, `binding_mode`, `minted_by`) survive a
/// store wire round-trip, are OMITTED from the wire when `None` (so an app/service token carries no
/// empty attribution keys), and a legacy wire row with none of them deserializes to `None` — the
/// additive, backward-compatible pattern the trailing-Option fields exist to guarantee.
#[test]
fn attribution_fields_round_trip_and_are_backward_compatible() {
    // Absent by default: a key that set none of the three must not emit the keys at all.
    let bare = sample_key();
    let json_bare = serde_json::to_string(&bare).unwrap();
    assert!(
        !json_bare.contains("idp_subject")
            && !json_bare.contains("binding_mode")
            && !json_bare.contains("minted_by"),
        "None attribution fields are skipped on the wire: {json_bare}"
    );

    // A personal (user-bound) token records the IdP subject for attribution.
    let mut personal = sample_key();
    personal.idp_subject = Some("okta|matthew".to_string());
    personal.binding_mode = Some("user-bound".to_string());
    let rt: VirtualKey = serde_json::from_str(&serde_json::to_string(&personal).unwrap()).unwrap();
    assert_eq!(rt.idp_subject.as_deref(), Some("okta|matthew"));
    assert_eq!(rt.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(rt.minted_by, None);

    // An app/service token records provenance (minted_by) and outlives its minter.
    let mut app = sample_key();
    app.binding_mode = Some("time-bound".to_string());
    app.minted_by = Some("vk_admin".to_string());
    let rt: VirtualKey = serde_json::from_str(&serde_json::to_string(&app).unwrap()).unwrap();
    assert_eq!(rt.minted_by.as_deref(), Some("vk_admin"));
    assert_eq!(rt.binding_mode.as_deref(), Some("time-bound"));
    assert_eq!(rt.idp_subject, None);

    // A legacy wire row predating these fields deserializes with all three None.
    let legacy = r#"{"id":"vk_1","generation_hash":"h","name":"n","allowed_pools":null,"enabled":true,"created_at":1}"#;
    let back: VirtualKey = serde_json::from_str(legacy).unwrap();
    assert_eq!(back.idp_subject, None);
    assert_eq!(back.binding_mode, None);
    assert_eq!(back.minted_by, None);
}

/// Scope KINDS survive a store wire round-trip (1.6.0).
///
/// Before the kind-partitioned wire fields existed, `allowed_scopes_wire` serialized every
/// entry's bare `value` under `allowed_pools` and deserialized every one back as
/// `kind: "pool"` - so an `mcp_server` grant silently became a POOL grant on any store
/// round-trip: a loss of the MCP grant AND an escalation into pool access. Each kind now has
/// its OWN named wire field (`allowed_pools` / `allowed_mcp_servers` / `allowed_mcp_tools`),
/// partitioned on write and reassembled on read.
#[test]
fn scope_kinds_survive_store_round_trip() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![
        ScopeRef::pool("fast"),
        ScopeRef {
            kind: "mcp_server".into(),
            value: "filesystem".into(),
        },
        ScopeRef {
            kind: "mcp_tool".into(),
            value: "filesystem_read_file".into(),
        },
    ]);
    let json = serde_json::to_string(&k).expect("serialize");
    let rt: VirtualKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        rt.allowed_scopes, k.allowed_scopes,
        "scope kinds must survive a store round-trip intact: {json}"
    );

    // The escalation guard: an MCP grant must NEVER come back as a pool grant.
    assert!(!rt.scope_allowed("pool", "filesystem"));
    assert!(!rt.scope_allowed("pool", "filesystem_read_file"));
    assert!(rt.scope_allowed("mcp_server", "filesystem"));
    assert!(rt.scope_allowed("mcp_tool", "filesystem_read_file"));
    assert!(rt.scope_allowed("pool", "fast"));
}

/// A scope kind with no registered wire field is a HARD serialize error - never silently
/// remapped into `allowed_pools` (the pre-P0 behavior) and never silently dropped. When 1.6.0
/// adds `agent`, this is the test that forces it to get its own named wire field before an
/// `agent` grant can be persisted at all.
#[test]
fn unknown_scope_kind_is_a_hard_serialize_error() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![ScopeRef {
        kind: "agent".to_string(),
        value: "planner".to_string(),
    }]);
    let err = serde_json::to_string(&k);
    assert!(
        err.is_err(),
        "an unregistered scope kind must fail serialization, got: {err:?}"
    );
}

/// The MCP wire fields are ADDITIVE: absent from a pool-only key's wire shape (so the
/// pre-1.6.0 byte-identity contract holds), and readable when present. An explicit-empty
/// `allowed_pools: []` beside an MCP field stays the EMPTY pool set - never "all".
#[test]
fn mcp_scope_wire_fields_are_additive() {
    // Pool-only and None grants must not grow mcp fields on the wire.
    let pool_only = sample_key();
    let v = serde_json::to_value(&pool_only).unwrap();
    assert!(v.get("allowed_mcp_servers").is_none(), "{v}");
    assert!(v.get("allowed_mcp_tools").is_none(), "{v}");

    // A wire body carrying the new fields reassembles into kind-tagged scopes.
    let wire = r#"{"id":"vk_9","generation_hash":"h","name":"n","allowed_pools":[],"allowed_mcp_servers":["filesystem"],"allowed_mcp_tools":["filesystem_read_file"],"enabled":true,"created_at":1}"#;
    let k: VirtualKey = serde_json::from_str(wire).unwrap();
    assert_eq!(
        k.allowed_scopes,
        Some(vec![
            ScopeRef {
                kind: "mcp_server".into(),
                value: "filesystem".into()
            },
            ScopeRef {
                kind: "mcp_tool".into(),
                value: "filesystem_read_file".into()
            },
        ])
    );
    assert!(
        !k.scope_allowed("pool", "filesystem"),
        "empty pool set stays empty"
    );

    // MCP-only grant round-trips with an explicit-empty `allowed_pools` (an explicit list was
    // set, so the pool set must stay the EMPTY set on the wire, never absent/null = "all").
    let json = serde_json::to_string(&k).unwrap();
    let rt: VirtualKey = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.allowed_scopes, k.allowed_scopes);
    assert!(!rt.scope_allowed("pool", "anything"));
}

/// The redacting `Debug` - the guard for the structured-logging surface, since
/// `tracing` records fields via `Debug`/`Display`, never serde - must NEVER emit the secret-
/// equivalent `generation_hash` / `secret_access_key`. Any place a record reaches a log must
/// show presence only.
#[test]
fn debug_redacts_secret_equivalents() {
    let key = sample_key();
    let key_dbg = format!("{key:?}");
    assert!(
        !key_dbg.contains("deadbeefdeadbeef"),
        "VirtualKey Debug leaked generation_hash: {key_dbg}"
    );
    assert!(key_dbg.contains("<redacted; present>"));

    let cred = sample_credential();
    let cred_dbg = format!("{cred:?}");
    assert!(
        !cred_dbg.contains("s3cr3t-signing-key"),
        "CredentialSecret Debug leaked the secret: {cred_dbg}"
    );
    // The AccessKeyId (public_id) is NOT secret and stays visible for diagnosability, via the
    // embedded CredentialMeta's ordinary (derived) Debug.
    assert!(cred_dbg.contains("AKIA_TEST"));
}

/// The `Serialize`/`Deserialize` on `VirtualKey` is a load-bearing PERSISTENCE contract (a
/// valkey-shaped store round-trips it as JSON): it MUST stay faithful, so it is emphatically NOT
/// redacted. This pins that contract so a well-meaning "redact the Serialize too" change (which
/// would silently corrupt every valkey-persisted key) fails loudly here instead. The
/// logging-surface leak is closed by the redacting `Debug` above, not by lossy serialization.
/// `CredentialSecret` deliberately has NO `Serialize` at all (see its doc) — persisting the raw
/// `secret` string is a backend-owned concern, not this crate's, so there is no equivalent
/// round-trip test for it here.
#[test]
fn serialize_roundtrip_is_faithful_for_persistence() {
    let key = sample_key();
    let json = serde_json::to_string(&key).unwrap();
    assert!(
        json.contains("deadbeefdeadbeef"),
        "persistence must keep generation_hash"
    );
    let back: VirtualKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);

    // CredentialSecret DOES round-trip faithfully too — it crosses the plugin ABI wire and is
    // what a backend persists, so its Serialize/Deserialize is load-bearing (see the type doc);
    // the leak surface it must NOT have is Debug (covered by the redaction test above), not
    // serde.
    let cred = sample_credential();
    let json = serde_json::to_string(&cred).unwrap();
    assert!(
        json.contains("s3cr3t-signing-key"),
        "persistence must keep the secret material"
    );
    let back: CredentialSecret = serde_json::from_str(&json).unwrap();
    assert_eq!(cred, back);
}

/// The minimal pure-auth JSON round-trips, and the optional fields default: a row with no
/// `allowed_pools` / `group` / `labels` / `expires_at` / `deleted_at` / `revision` deserializes
/// to all-pools / no-group / no labels / never-expires / live / revision-0. Guards the
/// valkey-style JSON persistence for the 1.5.0 pure-auth key shape, including the fields added by
/// the credentials-generalization redesign.
#[test]
fn virtual_key_minimal_json_defaults_optionals() {
    let minimal = r#"{"id":"vk_1","generation_hash":"h","name":"n","enabled":true,"created_at":1}"#;
    let k: VirtualKey = serde_json::from_str(minimal).unwrap();
    assert_eq!(k.allowed_scopes, None, "absent grant = all pools");
    assert_eq!(k.group, None);
    assert!(k.labels.is_empty());
    assert_eq!(k.expires_at, None);
    assert_eq!(k.deleted_at, None);
    assert_eq!(k.revision, 0);
}

/// `CredentialMeta::is_live` is the exact predicate the SigV4 admit path consults (in addition
/// to the KEY-level `enabled`/denylist checks, which are unaffected by per-credential
/// revocation): not revoked, and not expired as of `now`.
#[test]
fn credential_meta_is_live_checks_revocation_and_expiry() {
    let mut m = sample_credential().meta;
    assert!(m.is_live(100), "fresh credential, no expiry: live");
    m.expires_at = Some(200);
    assert!(m.is_live(100), "before expiry: live");
    assert!(!m.is_live(200), "at expiry: not live");
    assert!(!m.is_live(300), "past expiry: not live");
    m.expires_at = None;
    m.revoked_at = Some(50);
    assert!(
        !m.is_live(100),
        "revoked (even with no expiry set): not live"
    );
}

/// The ledger's additive delta application: model rows materialize on first sight, tiers
/// accumulate independently, and negative deltas floor every counter at 0.
#[test]
fn usage_ledger_applies_deltas_and_floors_at_zero() {
    let mut l = UsageLedger::default();
    l.apply_delta(&UsageDelta {
        requests: 2,
        billable_requests: 2,
        models: vec![ModelTokensDelta {
            model: "gpt-5".to_string(),
            tokens: TierTokensDelta {
                input: 100,
                output: 50,
                cache_read: 10,
                cache_write: 5,
            },
        }],
    });
    assert_eq!(l.requests, 2);
    let t = l.tokens_for("gpt-5").unwrap();
    assert_eq!(
        (t.input, t.output, t.cache_read, t.cache_write),
        (100, 50, 10, 5)
    );
    assert_eq!(l.total_tokens(), 165);

    // A second model materializes its own row; the first is untouched.
    l.apply_delta(&UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "haiku".to_string(),
            tokens: TierTokensDelta {
                input: 7,
                output: 3,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    });
    assert_eq!(l.models.len(), 2);
    assert_eq!(l.tokens_for("gpt-5").unwrap().input, 100);

    // Over-refund floors at 0, never negative.
    l.apply_delta(&UsageDelta {
        requests: -10,
        billable_requests: -10,
        models: vec![ModelTokensDelta {
            model: "haiku".to_string(),
            tokens: TierTokensDelta {
                input: -1000,
                output: -1,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    });
    assert_eq!(l.requests, 0);
    let h = l.tokens_for("haiku").unwrap();
    assert_eq!((h.input, h.output), (0, 2));
}

/// The default trait `add_usage` (read-modify-write fallback) accumulates through
/// get_usage/put_usage, so a store double implementing only those two is fleet-usable
/// (single-writer).
#[test]
fn default_add_usage_accumulates_via_get_put() {
    use std::sync::Mutex;
    #[derive(Default)]
    struct Double(Mutex<std::collections::HashMap<(String, u64), UsageLedger>>);
    impl Store for Double {
        fn put_key(&self, _: &VirtualKey) -> StoreResult<()> {
            Ok(())
        }
        fn get_key(&self, _: &str) -> StoreResult<Option<VirtualKey>> {
            Ok(None)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            Ok(Vec::new())
        }
        fn delete_key(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        fn get_usage(&self, b: &str, w: u64) -> StoreResult<UsageLedger> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(b.to_string(), w))
                .cloned()
                .unwrap_or_default())
        }
        fn put_usage(&self, b: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
            self.0.lock().unwrap().insert((b.to_string(), w), l.clone());
            Ok(())
        }
        fn add_metering(&self, _: &MeteringDelta) -> StoreResult<()> {
            Ok(())
        }
        fn list_metering(&self, _: u64) -> StoreResult<Vec<MeteringRow>> {
            Ok(Vec::new())
        }
    }
    let s = Double::default();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            tokens: TierTokensDelta {
                input: 5,
                output: 5,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    s.add_usage("bucket", 0, &d).unwrap();
    s.add_usage("bucket", 0, &d).unwrap();
    let l = s.get_usage("bucket", 0).unwrap();
    assert_eq!(l.requests, 2);
    assert_eq!(l.tokens_for("m").unwrap().input, 10);
}

#[test]
fn virtual_key_is_live_reflects_deleted_at() {
    let mut k = sample_key();
    assert!(k.is_live(), "deleted_at: None must be live");
    k.deleted_at = Some(99);
    assert!(!k.is_live(), "deleted_at: Some(_) must not be live");
}

#[test]
fn credential_secret_plaintext_extracts_v1_plain_only() {
    let mut c = sample_credential();
    assert_eq!(c.plaintext(), Some("s3cr3t-signing-key"));
    c.secret = "v1:aead:opaque-ciphertext".to_string();
    assert_eq!(
        c.plaintext(),
        None,
        "a non-plain scheme must never be treated as plaintext"
    );
    c.secret = String::new();
    assert_eq!(c.plaintext(), None);
}

#[test]
fn tier_tokens_is_zero_requires_every_field_zero() {
    assert!(TierTokens::default().is_zero());
    assert!(!TierTokens {
        input: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokens {
        output: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokens {
        cache_read: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokens {
        cache_write: 1,
        ..Default::default()
    }
    .is_zero());
}

#[test]
fn tier_tokens_delta_is_zero_requires_every_field_zero() {
    assert!(TierTokensDelta::default().is_zero());
    assert!(!TierTokensDelta {
        input: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokensDelta {
        output: -1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokensDelta {
        cache_read: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!TierTokensDelta {
        cache_write: 1,
        ..Default::default()
    }
    .is_zero());
}

#[test]
fn usage_delta_is_zero_requires_requests_billable_and_every_model_zero() {
    assert!(UsageDelta::default().is_zero());
    assert!(!UsageDelta {
        requests: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!UsageDelta {
        billable_requests: 1,
        ..Default::default()
    }
    .is_zero());
    assert!(!UsageDelta {
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            tokens: TierTokensDelta {
                input: 1,
                ..Default::default()
            },
        }],
        ..Default::default()
    }
    .is_zero());
}

#[test]
fn store_error_display_wraps_the_inner_message() {
    let e = StoreError("disk full".to_string());
    assert_eq!(e.to_string(), "store error: disk full");
}

struct AuditDouble(Vec<AuditRecord>, Vec<VirtualKey>);
impl Store for AuditDouble {
    fn put_key(&self, _: &VirtualKey) -> StoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        Ok(self.1.clone())
    }
    fn delete_key(&self, _: &str) -> StoreResult<()> {
        Ok(())
    }
    fn get_usage(&self, _: &str, _: u64) -> StoreResult<UsageLedger> {
        Ok(UsageLedger::default())
    }
    fn put_usage(&self, _: &str, _: u64, _: &UsageLedger) -> StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _: &MeteringDelta) -> StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        Ok(self.0.clone())
    }
}

fn audit_record(seq: u64) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 0,
        action: "test.action".to_string(),
        resource: "test:res".to_string(),
        outcome: "applied".to_string(),
        principal: "vk_1".to_string(),
        prev_hash: String::new(),
        hash: String::new(),
    }
}

/// The DEFAULTED `list_keys_since` fallback: `revision > since`, exclusive of `since` itself
/// (a row whose revision EQUALS `since` was already seen by that watermark and must not
/// re-appear, or a poller loops on the same row forever).
#[test]
fn default_list_keys_since_excludes_the_watermark_itself() {
    let mut a = sample_key();
    a.id = "vk_a".to_string();
    a.revision = 5;
    let mut b = sample_key();
    b.id = "vk_b".to_string();
    b.revision = 6;
    let s = AuditDouble(Vec::new(), vec![a, b]);
    let since5: Vec<_> = s.list_keys_since(5).unwrap();
    assert_eq!(
        since5.len(),
        1,
        "revision == since must be EXCLUDED, not included"
    );
    assert_eq!(since5[0].id, "vk_b");
    assert_eq!(s.list_keys_since(4).unwrap().len(), 2);
    assert_eq!(s.list_keys_since(6).unwrap().len(), 0);
}

/// The DEFAULTED `list_audit_tail` fallback: keep only the last `limit` records (drain the
/// HEAD, `all.len() - limit` of them), never off-by-one on the boundary.
#[test]
fn default_list_audit_tail_keeps_exactly_the_last_limit_records() {
    let records: Vec<_> = (1..=5).map(audit_record).collect();
    let s = AuditDouble(records, Vec::new());
    // Exactly at the cap: nothing trimmed.
    let exact = s.list_audit_tail(5).unwrap();
    assert_eq!(exact.len(), 5);
    // Under the cap: keep the tail-most `limit` records (drop the oldest, i.e. lowest seq).
    let tail = s.list_audit_tail(3).unwrap();
    assert_eq!(tail.len(), 3);
    assert_eq!(
        tail.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![3, 4, 5],
        "must keep the NEWEST records, dropping the oldest from the head"
    );
    // limit above the total count: everything is kept, no panic on the subtraction.
    assert_eq!(s.list_audit_tail(100).unwrap().len(), 5);
}

/// THE NEUTRAL PLANE-VERB DEFAULTS ARE BACKWARD-COMPATIBLE AND SILENT, and both halves matter.
///
/// A store plugin is a SIGNED ARTIFACT, and a backend that keeps no durable plane state overrides
/// none of the eight neutral kind-tagged verbs. If those verbs had no default, such a backend would
/// fail to compile against the contract; if they defaulted to an ERROR, every task submission on it
/// would fail at runtime. So they default to "accepted, and nothing kept" — the RAM default's
/// documented behaviour — and the engine learns whether a deployment actually has durability by
/// READING A RECORD BACK, never by trusting the write's return value. This test pins that, because a
/// future change of the defaults to something louder would silently break every such backend.
#[test]
fn the_plane_record_verbs_default_to_accepting_and_keeping_nothing() {
    /// A backend that keeps no durable plane state: it implements the six REQUIRED methods and
    /// nothing else. That it compiles at all is half the assertion.
    struct PreTaskBackend;
    impl Store for PreTaskBackend {
        fn put_key(&self, _: &VirtualKey) -> StoreResult<()> {
            Ok(())
        }
        fn get_key(&self, _: &str) -> StoreResult<Option<VirtualKey>> {
            Ok(None)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            Ok(Vec::new())
        }
        fn delete_key(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        fn get_usage(&self, _: &str, _: u64) -> StoreResult<UsageLedger> {
            Ok(UsageLedger::default())
        }
        fn put_usage(&self, _: &str, _: u64, _: &UsageLedger) -> StoreResult<()> {
            Ok(())
        }
        fn add_metering(&self, _: &MeteringDelta) -> StoreResult<()> {
            Ok(())
        }
        fn list_metering(&self, _: u64) -> StoreResult<Vec<MeteringRow>> {
            Ok(Vec::new())
        }
    }

    let s = PreTaskBackend;
    let task = TaskRow {
        task_id: "t-1".to_string(),
        context_id: "ctx-1".to_string(),
        principal: "key-1".to_string(),
        direction: "inbound".to_string(),
        state: "working".to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 3,
        push_callback: String::new(),
        created_at: 10,
        updated_at: 11,
    };
    let event = TaskEventRow {
        task_id: "t-1".to_string(),
        seq: 1,
        ts: 10,
        kind: "task.submitted".to_string(),
        context_id: "ctx-1".to_string(),
        principal: "key-1".to_string(),
        agent_id: String::new(),
        state: "submitted".to_string(),
        request_id: "req-1".to_string(),
        prev_hash: String::new(),
        hash: "deadbeef".to_string(),
    };

    // The writes are ACCEPTED — a legacy backend must not fail a task submission.
    assert!(s
        .upsert_plane_record(&PlaneRecord {
            kind: "task".into(),
            id: task.task_id.clone(),
            parent: None,
            seq: 0,
            ts: task.updated_at,
            disposition: PlaneDisposition::Active,
            body: serde_json::to_vec(&task).unwrap(),
        })
        .is_ok());
    assert!(s
        .append_plane_record(&PlaneRecord {
            kind: "task_event".into(),
            id: event.task_id.clone(),
            parent: Some(event.task_id.clone()),
            seq: event.seq,
            ts: event.ts,
            disposition: PlaneDisposition::Active,
            body: serde_json::to_vec(&event).unwrap(),
        })
        .is_ok());
    // And nothing is kept. This is the assertion the durability layer is built on: the only honest
    // way to know a deployment is durable is to read back, and here the read-back is empty.
    assert_eq!(s.get_plane_record("task", "t-1").unwrap(), None);
    assert!(s
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .is_empty());
    assert!(s
        .list_plane_records("task_event", &PlaneSelector::Parent("t-1".into()))
        .unwrap()
        .is_empty());
    assert_eq!(s.purge_plane_records_before("task", u64::MAX).unwrap(), 0);
}

/// The task rows round-trip through serde unchanged. They cross a plugin ABI, so a field whose
/// serialized name drifts is a field a backend silently stops persisting.
#[test]
fn task_rows_round_trip_through_the_store_seam_encoding() {
    let task = TaskRow {
        task_id: "t-1".to_string(),
        context_id: "ctx-1".to_string(),
        principal: "key-1".to_string(),
        direction: "outbound".to_string(),
        state: "auth-required".to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 7,
        push_callback: "https://caller.example/cb".to_string(),
        created_at: 10,
        updated_at: 20,
    };
    let json = serde_json::to_string(&task).unwrap();
    assert_eq!(serde_json::from_str::<TaskRow>(&json).unwrap(), task);
    // The wire names are the field names, spelled out here so a rename is a visible diff rather
    // than a silent data loss on the next deploy of an older backend.
    for field in [
        "task_id",
        "context_id",
        "principal",
        "direction",
        "state",
        "agent_id",
        "artifact_cursor",
        "push_callback",
        "created_at",
        "updated_at",
    ] {
        assert!(
            json.contains(field),
            "`{field}` must be on the wire: {json}"
        );
    }
}
