// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/records.rs` — the money-path durable record shapes.

use super::*;

/// A name-keyed reserved-four unit map (test helper) — the M1b replacement for the old
fn units<T: Copy + Default + PartialEq>(
    input: T,
    output: T,
    cache_read: T,
    cache_write: T,
) -> std::collections::BTreeMap<String, T> {
    let mut m = std::collections::BTreeMap::new();
    for (k, v) in [
        (UNIT_INPUT, input),
        (UNIT_OUTPUT, output),
        (UNIT_CACHE_READ, cache_read),
        (UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != T::default() {
            m.insert(k.to_string(), v);
        }
    }
    m
}

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
            kind: "customsig".to_string(),
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
#[test]
fn scope_allowed_cross_kind_is_fail_closed() {
    let mut k = sample_key();

    k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(k.scope_allowed("pool", "fast"));
    for future_kind in ["grid_server", "agent", "some_kind_not_invented_yet"] {
        assert!(
            !k.scope_allowed(future_kind, "fast"),
            "a pool-only grant must grant NOTHING for the future kind '{future_kind}' — the unlisted-kind case is FAIL-CLOSED and frozen"
        );
        assert!(!k.scope_allowed(future_kind, "anything-else"));
    }

    k.allowed_scopes = None;
    assert!(k.scope_allowed("pool", "fast"));
    assert!(k.scope_allowed("grid_server", "filesystem"));
    assert!(k.scope_allowed("agent", "planner"));

    k.allowed_scopes = Some(vec![ScopeRef {
        kind: "grid_server".to_string(),
        value: "filesystem".to_string(),
    }]);
    assert!(k.scope_allowed("grid_server", "filesystem"));
    assert!(
        !k.scope_allowed("pool", "filesystem"),
        "the fail-closed rule is symmetric across kinds"
    );
}

/// A DIFFERENT kind never matches a `pool`-kind grant, and vice versa - `ScopeRef` is
#[test]
fn scope_allowed_is_kind_specific() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![ScopeRef::pool("fast")]);
    assert!(k.scope_allowed("pool", "fast"));
    assert!(
        !k.scope_allowed("grid_server", "fast"),
        "same value, different kind: must not match"
    );
}

/// THE contract test: a config using only `allowed_pools` (bare strings, no `kind` wrapper)
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

    let legacy_wire = r#"{"id":"vk_1","generation_hash":"h","name":"n","allowed_pools":["fast","slow"],"enabled":true,"created_at":1}"#;
    let back: VirtualKey = serde_json::from_str(legacy_wire).unwrap();
    assert_eq!(
        back.allowed_scopes,
        Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")])
    );

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
#[test]
fn attribution_fields_round_trip_and_are_backward_compatible() {
    let bare = sample_key();
    let json_bare = serde_json::to_string(&bare).unwrap();
    assert!(
        !json_bare.contains("idp_subject")
            && !json_bare.contains("binding_mode")
            && !json_bare.contains("minted_by"),
        "None attribution fields are skipped on the wire: {json_bare}"
    );

    let mut personal = sample_key();
    personal.idp_subject = Some("okta|matthew".to_string());
    personal.binding_mode = Some("user-bound".to_string());
    let rt: VirtualKey = serde_json::from_str(&serde_json::to_string(&personal).unwrap()).unwrap();
    assert_eq!(rt.idp_subject.as_deref(), Some("okta|matthew"));
    assert_eq!(rt.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(rt.minted_by, None);

    let mut app = sample_key();
    app.binding_mode = Some("time-bound".to_string());
    app.minted_by = Some("vk_admin".to_string());
    let rt: VirtualKey = serde_json::from_str(&serde_json::to_string(&app).unwrap()).unwrap();
    assert_eq!(rt.minted_by.as_deref(), Some("vk_admin"));
    assert_eq!(rt.binding_mode.as_deref(), Some("time-bound"));
    assert_eq!(rt.idp_subject, None);

    let legacy = r#"{"id":"vk_1","generation_hash":"h","name":"n","allowed_pools":null,"enabled":true,"created_at":1}"#;
    let back: VirtualKey = serde_json::from_str(legacy).unwrap();
    assert_eq!(back.idp_subject, None);
    assert_eq!(back.binding_mode, None);
    assert_eq!(back.minted_by, None);
}

/// Scope KINDS survive a store wire round-trip (1.6.0).
#[test]
fn scope_kinds_survive_store_round_trip() {
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![
        ScopeRef::pool("fast"),
        ScopeRef {
            kind: "grid_server".into(),
            value: "filesystem".into(),
        },
        ScopeRef {
            kind: "grid_tool".into(),
            value: "filesystem_read_file".into(),
        },
    ]);
    let json = serde_json::to_string(&k).expect("serialize");
    let rt: VirtualKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        rt.allowed_scopes, k.allowed_scopes,
        "scope kinds must survive a store round-trip intact: {json}"
    );

    assert!(!rt.scope_allowed("pool", "filesystem"));
    assert!(!rt.scope_allowed("pool", "filesystem_read_file"));
    assert!(rt.scope_allowed("grid_server", "filesystem"));
    assert!(rt.scope_allowed("grid_tool", "filesystem_read_file"));
    assert!(rt.scope_allowed("pool", "fast"));
}

/// Any scope kind round-trips VERBATIM under its own `allowed_{kind}s` field (1.6.0
#[test]
fn unregistered_scope_kind_round_trips_verbatim_under_its_own_field() {
    let kind = "sdk_scopekinds_never_registered";
    let mut k = sample_key();
    k.allowed_scopes = Some(vec![ScopeRef {
        kind: kind.to_string(),
        value: "planner".to_string(),
    }]);
    let v = serde_json::to_value(&k).expect("an unregistered kind must serialize");
    assert_eq!(
        v["allowed_sdk_scopekinds_never_registereds"],
        serde_json::json!(["planner"]),
        "{v}"
    );
    assert_eq!(
        v["allowed_pools"],
        serde_json::json!([]),
        "never remapped into allowed_pools: {v}"
    );
    let rt: VirtualKey = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(rt.allowed_scopes, k.allowed_scopes, "{v}");
    assert!(!rt.scope_allowed("pool", "planner"));
    assert!(rt.scope_allowed(kind, "planner"));

    assert_eq!(serde_json::to_value(&rt).unwrap(), v);
}

/// The GRID wire fields are ADDITIVE: absent from a pool-only key's wire shape (so the
#[test]
fn grid_scope_wire_fields_are_additive() {
    let pool_only = sample_key();
    let v = serde_json::to_value(&pool_only).unwrap();
    assert!(v.get("allowed_grid_servers").is_none(), "{v}");
    assert!(v.get("allowed_grid_tools").is_none(), "{v}");

    let wire = r#"{"id":"vk_9","generation_hash":"h","name":"n","allowed_pools":[],"allowed_grid_servers":["filesystem"],"allowed_grid_tools":["filesystem_read_file"],"enabled":true,"created_at":1}"#;
    let k: VirtualKey = serde_json::from_str(wire).unwrap();
    assert_eq!(
        k.allowed_scopes,
        Some(vec![
            ScopeRef {
                kind: "grid_server".into(),
                value: "filesystem".into()
            },
            ScopeRef {
                kind: "grid_tool".into(),
                value: "filesystem_read_file".into()
            },
        ])
    );
    assert!(
        !k.scope_allowed("pool", "filesystem"),
        "empty pool set stays empty"
    );

    let json = serde_json::to_string(&k).unwrap();
    let rt: VirtualKey = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.allowed_scopes, k.allowed_scopes);
    assert!(!rt.scope_allowed("pool", "anything"));
}

/// The redacting `Debug` - the guard for the structured-logging surface, since
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

    assert!(cred_dbg.contains("AKIA_TEST"));
}

/// The `Serialize`/`Deserialize` on `VirtualKey` is a load-bearing PERSISTENCE contract (a
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

/// `CredentialMeta::is_live` is the exact predicate the signed-request admit path consults (in
#[test]
fn credential_meta_is_live_checks_revocation_and_expiry() {
    let mut m = sample_credential().meta.clone();
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
#[test]
fn usage_ledger_applies_deltas_and_floors_at_zero() {
    let mut l = UsageLedger::default();
    l.checked_apply_delta(&UsageDelta {
        requests: 2,
        billable_requests: 2,
        models: vec![ModelTokensDelta {
            scale: 0,
            model: "gpt-5".to_string(),
            usage_units: units(100, 50, 10, 5),
        }],
    })
    .unwrap();
    assert_eq!(l.requests, 2);
    let m = &l.models[0];
    assert_eq!(
        (
            m.tier(UNIT_INPUT),
            m.tier(UNIT_OUTPUT),
            m.tier(UNIT_CACHE_READ),
            m.tier(UNIT_CACHE_WRITE)
        ),
        (100_000_000, 50_000_000, 10_000_000, 5_000_000)
    );
    assert_eq!(l.total_tokens(), 165_000_000);

    l.checked_apply_delta(&UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 0,
            model: "haiku".to_string(),
            usage_units: units(7, 3, 0, 0),
        }],
    })
    .unwrap();
    assert_eq!(l.models.len(), 2);
    assert_eq!(l.total_input(), 107_000_000);

    l.checked_apply_delta(&UsageDelta {
        requests: -10,
        billable_requests: -10,
        models: vec![ModelTokensDelta {
            scale: 0,
            model: "haiku".to_string(),
            usage_units: units(-1000, -1, 0, 0),
        }],
    })
    .unwrap();
    assert_eq!(l.requests, 0);
    let h = l.models.iter().find(|m| m.model == "haiku").unwrap();
    assert_eq!((h.tier(UNIT_INPUT), h.tier(UNIT_OUTPUT)), (0, 2_000_000));
}

/// Transitional traits cannot manufacture atomicity from independent operations.
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
fn model_tokens_is_zero_requires_every_unit_zero() {
    assert!(ModelTokens::default().is_zero());
    for u in RESERVED_UNITS {
        let m = ModelTokens {
            scale: 0,
            model: "m".into(),
            usage_units: std::collections::BTreeMap::from([(u.to_string(), 1i128)]),
        };
        assert!(!m.is_zero(), "a nonzero {u} tier is not zero");
    }

    let m = ModelTokens {
        scale: 0,
        model: "m".into(),
        usage_units: std::collections::BTreeMap::from([("audio".to_string(), 1i128)]),
    };
    assert!(!m.is_zero());
}

#[test]
fn model_tokens_delta_is_zero_requires_every_unit_zero() {
    assert!(ModelTokensDelta::default().is_zero());
    let d = ModelTokensDelta {
        scale: 0,
        model: "m".into(),
        usage_units: units(1, 0, 0, 0),
    };
    assert!(!d.is_zero());
    let d = ModelTokensDelta {
        scale: 0,
        model: "m".into(),
        usage_units: units(0, -1, 0, 0),
    };
    assert!(!d.is_zero());
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
            scale: 0,
            model: "m".to_string(),
            usage_units: units(1, 0, 0, 0),
        }],
        ..Default::default()
    }
    .is_zero());
}

#[test]
fn store_error_display_wraps_the_inner_message() {
    let e = RecordStoreError("disk full".to_string());
    assert_eq!(e.to_string(), "store error: disk full");
}

#[test]
fn plane_record_envelope_round_trips_through_the_store_seam_encoding() {
    let record = PlaneRecord {
        kind: "task".into(),
        id: "t-1".into(),
        parent: Some("t-1".into()),
        seq: 7,
        ts: 20,
        disposition: PlaneDisposition::Terminal,

        body: br#"{"anything":"the plane put here","seq":7}"#.to_vec(),
    };
    let json = serde_json::to_string(&record).unwrap();
    assert_eq!(serde_json::from_str::<PlaneRecord>(&json).unwrap(), record);

    for field in ["kind", "id", "parent", "seq", "ts", "disposition", "body"] {
        assert!(
            json.contains(field),
            "`{field}` must be on the wire: {json}"
        );
    }
}

/// An all-empty `ModelTokens` serializes to just `{"model":…}` (skip-if-empty), and an old row with
#[test]
fn model_tokens_usage_units_is_the_sole_representation() {
    let reserved = ModelTokens {
        scale: 0,
        model: "gpt-x".into(),
        usage_units: units(10, 20, 0, 0),
    };
    let json = serde_json::to_string(&reserved).unwrap();
    assert!(json.contains("usage_units") && json.contains("\"input\":10"));

    let rt: ModelTokens = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, reserved);

    let empty = ModelTokens {
        scale: 0,
        model: "z".into(),
        usage_units: std::collections::BTreeMap::new(),
    };
    let ej = serde_json::to_string(&empty).unwrap();
    assert!(!ej.contains("usage_units"), "empty map is skipped: {ej}");

    let mut mixed = reserved.clone();
    mixed.usage_units.insert("classifications".into(), 3);
    let rt2: ModelTokens = serde_json::from_str(&serde_json::to_string(&mixed).unwrap()).unwrap();
    assert_eq!(rt2, mixed);
}

/// Checked application folds every signed unit delta and floors ordinary refunds at zero.
#[test]
fn checked_model_delta_folds_usage_units_flooring_at_zero() {
    let mut ledger = UsageLedger::default();
    let mut d1 = ModelTokensDelta {
        scale: 0,
        model: "m".into(),
        usage_units: units(0, 0, 0, 0),
    };
    d1.usage_units.insert("search".into(), 5);
    ledger
        .checked_apply_delta(&UsageDelta {
            models: vec![d1],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ledger.models[0].usage_units.get("search"), Some(&5_000_000));

    let mut d2 = ModelTokensDelta {
        scale: 0,
        model: "m".into(),
        usage_units: std::collections::BTreeMap::new(),
    };
    d2.usage_units.insert("search".into(), -9);
    ledger
        .checked_apply_delta(&UsageDelta {
            models: vec![d2],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(ledger.models[0].usage_units.get("search"), Some(&0));
}

#[test]
fn retention_codes_round_trip_and_age_is_the_default() {
    assert_eq!(Retention::default(), Retention::Age);
    for r in [Retention::Age, Retention::TerminalOnly] {
        assert_eq!(Retention::from_code(r.code()), Some(r));
    }
    assert_eq!(Retention::Age.code(), 0);
    assert_eq!(Retention::TerminalOnly.code(), 1);
    assert_eq!(Retention::from_code(2), None);
}
