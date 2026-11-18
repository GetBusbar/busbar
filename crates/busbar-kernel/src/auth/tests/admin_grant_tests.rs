// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API r5 section 2 (MR2): an admin credential is a virtual key with an `admin` grant, the
//! admin chain's `keys` position admits it, and its verbs are judged per verb.

use super::*;
use busbar_contract::authz::Scope;
use busbar_contract::records::{AdminGrant, VirtualKey};

fn verb_rung(name: &str) -> Option<Scope> {
    match name {
        "post_config_apply" | "post_keys" => Some(Scope::Full),
        "get_keys" | "get_whoami" => Some(Scope::ReadOnly),
        _ => None,
    }
}

fn admin_key(scope: &str, verbs: &[&str]) -> VirtualKey {
    VirtualKey {
        id: "vk_admin".into(),
        name: "console".into(),
        enabled: true,
        allowed_scopes: Some(Vec::new()),
        admin: Some(AdminGrant {
            scope: scope.into(),
            verbs: verbs.iter().map(|v| v.to_string()).collect(),
        }),
        ..VirtualKey::default()
    }
}

fn door_of(key: VirtualKey) -> AdminDoor {
    let principal = Principal::from_id(format!("key:{}", key.id));
    admin_door_from_bindings(
        &crate::config::RoleBindings::new(),
        &Operator::new("operator-provider"),
        "operator:local",
        ChainVerdict::Identified {
            module: crate::config::KEYS_MODULE.into(),
            principal,
            resolved: Some(std::sync::Arc::new(key)),
            signed_authority: None,
        },
        None,
        verb_rung,
    )
}

#[test]
fn admin_key_cannot_use_data_plane() {
    let key = admin_key("full", &[]);
    assert_eq!(key.allowed_scopes, Some(Vec::new()));
    assert!(
        !key.scope_allowed("pool", "fast"),
        "an admin key holds no pool"
    );
    assert!(!key.scope_allowed("agent", "any"), "nor any other kind");
}

#[test]
fn data_key_cannot_use_admin() {
    let data = VirtualKey {
        id: "vk_data".into(),
        enabled: true,
        ..VirtualKey::default()
    };
    let door = door_of(data);
    assert!(!admin_door_admits(&door, "GET", "/api/v1/admin/keys"));
    assert!(!admin_door_admits(&door, "POST", "/api/v1/admin/keys"));
}

#[test]
fn read_only_admin_key_verbs() {
    let door = door_of(admin_key("read-only", &[]));
    assert!(matches!(door, AdminDoor::Identified(..)), "{door:?}");
    assert!(admin_door_admits(&door, "GET", "/api/v1/admin/keys"));
    assert!(
        !admin_door_admits(&door, "POST", "/api/v1/admin/keys"),
        "a read-only ceiling never reaches a mutation"
    );
}

#[test]
fn empty_verbs_means_scope_ceiling() {
    let full = door_of(admin_key("full", &[]));
    assert!(admin_door_admits(&full, "GET", "/api/v1/admin/keys"));
    assert!(admin_door_admits(&full, "POST", "/api/v1/admin/keys"));
    let read = door_of(admin_key("read-only", &[]));
    assert!(!admin_door_admits(
        &read,
        "POST",
        "/api/v1/admin/config/apply"
    ));
}

#[test]
fn named_verbs_are_exactly_the_verbs_held_within_the_ceiling() {
    let door = door_of(admin_key(
        "read-only",
        &["get_keys", "post_keys", "no_such_verb"],
    ));
    let AdminDoor::Listed(_, _, list) = door else {
        panic!("named verbs list the door, got {door:?}");
    };
    assert!(list.admits(Some("get_keys"), Scope::ReadOnly));
    assert!(
        !list.admits(Some("post_keys"), Scope::Full),
        "above the ceiling"
    );
    assert!(
        !list.admits(Some("no_such_verb"), Scope::ReadOnly),
        "not in the table"
    );
}

#[test]
fn every_identified_admin_principal_may_read_whoami() {
    let door = door_of(admin_key("full", &["post_keys"]));
    let AdminDoor::Listed(_, _, list) = door else {
        panic!("listed, got {door:?}");
    };
    assert!(list.admits(Some(WHOAMI_VERB), Scope::ReadOnly));
}

#[test]
fn admin_auth_absent_defaults_to_tokens_and_keys() {
    let names = crate::config::auth::default_admin_auth_names();
    assert_eq!(names.last().map(String::as_str), Some("keys"));
    assert!(
        names.iter().all(|n| !n.trim().is_empty()),
        "never the empty word: {names:?}"
    );
    let absent: crate::config::auth::AuthDeployCfg =
        busbar_contract::json::parse_str("{}").unwrap();
    assert_eq!(absent.admin_auth, names);
}

#[test]
fn explicit_admin_auth_not_extended() {
    let explicit: crate::config::auth::AuthDeployCfg =
        busbar_contract::json::parse_str(r#"{"admin_auth":["only-this"]}"#).unwrap();
    assert_eq!(explicit.admin_auth, vec!["only-this".to_string()]);
}

#[tokio::test]
async fn expired_admin_key_reason() {
    use crate::governance::{signing::TokenSigner, GovState, NewKeySpec};
    let gov = GovState::new_with_core(
        crate::real_store::core().await,
        None,
        Some(TokenSigner::from_secret_bytes(&[9; 32], "test")),
    )
    .await
    .expect("governance");
    let spec = || NewKeySpec {
        name: "console".into(),
        allowed_pools: Some(Vec::new()),
        admin: Some(AdminGrant {
            scope: "full".into(),
            verbs: Vec::new(),
        }),
        ..NewKeySpec::default()
    };
    let (key, token) = gov
        .mint_signed_async(spec(), 2000, 1000)
        .await
        .expect("mint");
    let token = token.expose(&crate::seal::lend()).to_string();
    let live = gov.verify_token(&token, 1500, None).expect("live");
    assert!(live.admin.is_some(), "the grant rides the stored key");
    assert_eq!(gov.token_refusal(&token, 3000, None), "credential_expired");
    assert_eq!(
        gov.token_refusal("bbk_not-a-token", 1500, None),
        "credential_invalid"
    );
    gov.update_key_outcome_async(&key.id, Some(false), None)
        .await
        .expect("disable");
    assert_eq!(gov.token_refusal(&token, 1500, None), "credential_revoked");
}
