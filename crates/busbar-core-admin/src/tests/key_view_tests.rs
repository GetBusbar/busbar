// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 4.2: the key view's full field set, the ETag over the stored row, the
//! `expired` state and the `GET /keys` filters.

use super::*;
use busbar_contract::records::{CredentialMeta, ScopeRef, SecretForm};

fn key_1_5_5() -> VirtualKey {
    VirtualKey {
        id: "vk_a".into(),
        generation_hash: "binding:vk_a:g".into(),
        name: "ci".into(),
        allowed_scopes: Some(vec![ScopeRef::pool("fast")]),
        enabled: true,
        created_at: 1_700_000_000,
        group: Some("growth".into()),
        labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        ..Default::default()
    }
}

/// The 1.5.5 ETag basis, written out by hand: the bytes 1.5.5 hashed.
fn key_1_5_5_etag() -> String {
    let body = json!({
        "id": "vk_a",
        "name": "ci",
        "allowed_pools": ["fast"],
        "group": "growth",
        "enabled": true,
        "created_at": 1_700_000_000u64,
        "labels": {"team": "growth"},
    });
    busbar_contract::sha256_hex(body.to_string().as_bytes())[..16].to_string()
}

#[test]
fn key_etag_unchanged_for_1_5_5_key() {
    assert_eq!(key_etag(&key_1_5_5()), key_1_5_5_etag());
    let mut migrated = key_1_5_5();
    migrated.migrated_from = Some("1.5.5".into());
    assert_eq!(
        key_etag(&migrated),
        key_1_5_5_etag(),
        "the import stamps `origin` once; it never moves the ETag a client holds"
    );
}

#[test]
fn key_etag_basis_is_stored_row() {
    let k = key_1_5_5();
    let before = key_etag(&k);
    // The view's own `etag` is the stored-row hash and is not an input to it.
    let view = key_meta(&k);
    assert_eq!(view["etag"], json!(before));
    assert_eq!(key_etag(&k), before);
    // Derived and foreign fields are never hashed: they are not in the basis at all.
    let basis = etag_basis(&k);
    for derived in ["etag", "state", "revocation", "credentials", "last_used_at"] {
        assert!(basis.get(derived).is_none(), "{derived} must not be hashed");
    }
    // A rename moves it, and so does a rotation.
    let mut renamed = k.clone();
    renamed.name = "ci-2".into();
    assert_ne!(key_etag(&renamed), before);
    let mut rotated = k.clone();
    rotated.rotation_count = 1;
    rotated.rotated_at = Some(1_700_000_100);
    assert_ne!(key_etag(&rotated), before);
}

#[test]
fn key_view_full_fields() {
    let mut k = key_1_5_5();
    k.expires_at = Some(1_800_000_000);
    k.minted_by = Some("admin-1".into());
    k.idp_provider = Some("corp-sso".into());
    k.idp_subject = Some("alice".into());
    k.binding_mode = Some("user-bound".into());
    k.rotated_at = Some(1_700_000_100);
    k.rotation_count = 2;
    k.migrated_from = Some("1.5.5".into());
    let v = key_meta(&k);
    assert_eq!(v["expires_at"], json!(1_800_000_000u64));
    assert_eq!(v["minted_by"], json!("admin-1"));
    assert_eq!(v["minted_via"], json!("corp-sso"));
    assert_eq!(v["idp_subject"], json!("alice"));
    assert_eq!(v["binding_mode"], json!("user-bound"));
    assert_eq!(v["deleted_at"], Value::Null);
    assert_eq!(
        v["rotation"],
        json!({"generation": "3", "rotated_at": 1_700_000_100u64, "count": "2"})
    );
    assert_eq!(v["origin"], json!({"migrated_from": "1.5.5"}));
    assert!(v["etag"].is_string());

    // A fresh key carries every nullable member as null and the zero rotation.
    let fresh = key_meta(&key_1_5_5());
    for nullable in [
        "expires_at",
        "deleted_at",
        "minted_by",
        "minted_via",
        "idp_subject",
        "binding_mode",
    ] {
        assert_eq!(fresh[nullable], Value::Null, "{nullable}");
    }
    assert_eq!(
        fresh["rotation"],
        json!({"generation": "1", "rotated_at": null, "count": "0"})
    );
    assert_eq!(fresh["origin"], json!("created"));
}

#[test]
fn expired_state() {
    let mut k = key_1_5_5();
    k.expires_at = Some(1_000);
    assert_eq!(disposition(&k, false, 999), "active");
    assert_eq!(disposition(&k, false, 1_000), "expired");
    k.enabled = false;
    assert_eq!(disposition(&k, false, 2_000), "expired");
    assert_eq!(disposition(&k, true, 2_000), "revoked");
    k.deleted_at = Some(1_500);
    assert_eq!(disposition(&k, true, 2_000), "tombstoned");
    assert_eq!(disposition(&key_1_5_5(), false, u64::MAX), "active");
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
        .collect()
}

fn admits(filter: &[(&str, &str)], k: &VirtualKey, state: &str) -> bool {
    KeyFilter::parse(&pairs(filter))
        .unwrap()
        .admits(k, state, false)
}

#[test]
fn key_filters() {
    let mut k = key_1_5_5();
    k.expires_at = Some(5_000);
    k.idp_provider = Some("corp-sso".into());
    k.labels.insert("env".into(), "prod".into());

    assert!(admits(&[], &k, "active"));
    assert!(admits(&[("state", "active")], &k, "active"));
    assert!(!admits(&[("state", "revoked")], &k, "active"));
    // `label` repeats and ANDs.
    assert!(admits(
        &[("label", "team:growth"), ("label", "env:prod")],
        &k,
        "active"
    ));
    assert!(!admits(
        &[("label", "team:growth"), ("label", "env:dev")],
        &k,
        "active"
    ));
    assert!(admits(&[("expires_before", "5001")], &k, "active"));
    assert!(!admits(&[("expires_before", "5000")], &k, "active"));
    assert!(!admits(&[("expires_before", "9")], &key_1_5_5(), "active"));
    assert!(admits(&[("grant", "pool:fast")], &k, "active"));
    assert!(!admits(&[("grant", "pool:slow")], &k, "active"));
    assert!(admits(&[("minted_via", "corp-sso")], &k, "active"));
    assert!(!admits(&[("minted_via", "other")], &k, "active"));
    assert!(admits(&[("admin", "false")], &k, "active"));
    assert!(!admits(&[("admin", "true")], &k, "active"));

    // A tombstoned key is listed only on request.
    let mut gone = key_1_5_5();
    gone.deleted_at = Some(9);
    assert!(!admits(&[], &gone, "tombstoned"));
    assert!(admits(&[("state", "tombstoned")], &gone, "tombstoned"));
    assert!(KeyFilter::parse(&pairs(&[]))
        .unwrap()
        .admits(&gone, "tombstoned", true));

    for bad in [
        ("state", "gone"),
        ("label", "no-colon"),
        ("expires_before", "soon"),
        ("grant", "pool"),
        ("admin", "maybe"),
    ] {
        assert!(KeyFilter::parse(&pairs(&[bad])).is_err(), "{bad:?}");
    }
}

#[test]
fn credentials_never_carry_secret() {
    let meta = CredentialMeta {
        id: "cred_1".into(),
        key_id: "vk_a".into(),
        kind: "sigv4".into(),
        slot: 1,
        public_id: "AKIATEST".into(),
        secret_form: SecretForm::Recoverable,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_050,
        expires_at: None,
        revoked_at: None,
        revoke_reason: None,
        revision: 4,
    };
    let entry = credential_json(&meta);
    let mut names: Vec<_> = entry.as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(names, ["created_at", "kind", "public_id", "slot"]);
    assert_eq!(entry["public_id"], json!("AKIATEST"));
}
