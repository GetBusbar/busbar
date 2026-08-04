// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 4 (token-exchange) guards: deterministic idempotent mint, refresh-invalidates-old, the
//! HMAC-is-a-mint-time-selector-not-the-credential property, identity-from-principal-not-body, and a
//! FAKE `SelfServeKeys` proving the endpoint is key-scheme agnostic.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::super::self_keys::{
    issue_key, resolve_exchange, DeterministicEd25519Keys, ExchangeError, IssuedKey,
    SelfGroupProvisioner, SelfServeKeys,
};
use super::super::{ChainVerdict, Principal};
use crate::config::groups::{provision_child, GroupCfg};
use crate::config::{RoleBindingCfg, RoleBindings};
use crate::governance::{GovState, MemoryStore};

const SEED: [u8; 32] = [7u8; 32];

/// A fake [`SelfGroupProvisioner`] over an in-memory group registry, seeded with the TEAM (parent)
/// carrying a `child_default`. `ensure_leaf` mirrors production: build the leaf via the real
/// `provision_child` (so the child_default → leaf-limits logic is the SAME code the admin path uses),
/// idempotent on the leaf name. Lets the GovState-only test harness assert the group is provisioned.
struct FakeProvisioner {
    registry: std::sync::Mutex<BTreeMap<String, GroupCfg>>,
}

impl FakeProvisioner {
    /// Seed a registry with `team` carrying the given `child_default` YAML body (a `GroupCfg`).
    fn with_team(team: &str, group_yaml: &str) -> Self {
        let cfg: GroupCfg = serde_yaml::from_str(group_yaml).expect("team group cfg parses");
        let mut reg = BTreeMap::new();
        reg.insert(team.to_string(), cfg);
        Self {
            registry: std::sync::Mutex::new(reg),
        }
    }

    fn snapshot(&self) -> BTreeMap<String, GroupCfg> {
        self.registry.lock().unwrap().clone()
    }
}

#[async_trait]
impl SelfGroupProvisioner for FakeProvisioner {
    async fn ensure_leaf(&self, leaf: &str, parent: &str) -> Result<(), String> {
        let mut reg = self.registry.lock().unwrap();
        if reg.contains_key(leaf) {
            return Ok(()); // idempotent: already provisioned, never reset
        }
        let cfg = provision_child(&reg, parent);
        reg.insert(leaf.to_string(), cfg);
        Ok(())
    }
}

/// A no-op provisioner for the tests that only exercise key-row behavior (idempotency, refresh,
/// token verification) and do not assert on the group tree.
struct NoopProvisioner;
#[async_trait]
impl SelfGroupProvisioner for NoopProvisioner {
    async fn ensure_leaf(&self, _leaf: &str, _parent: &str) -> Result<(), String> {
        Ok(())
    }
}

fn gov() -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            Arc::new(MemoryStore::new()),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &SEED,
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("gov constructs"),
    )
}

fn principal(id: &str, roles: &[&str]) -> Principal {
    Principal {
        id: id.to_string(),
        name: Some("Sam".into()),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        ttl_secs: None,
    }
}

/// role_bindings with `<module>.<role>` → group `team`, all pools.
fn bindings(module: &str, role: &str, group: Option<&str>) -> RoleBindings {
    let mut inner = BTreeMap::new();
    inner.insert(
        role.to_string(),
        RoleBindingCfg {
            allowed_pools: None,
            group: group.map(str::to_string),
            admin_scope: None,
        },
    );
    let mut outer: RoleBindings = BTreeMap::new();
    outer.insert(module.to_string(), inner);
    outer
}

fn identified(module: &str, p: Principal) -> ChainVerdict {
    ChainVerdict::Identified {
        module: module.to_string(),
        principal: p,
        resolved: None,
    }
}

fn self_rows(gov: &GovState, sub: &str) -> Vec<crate::governance::VirtualKey> {
    let group = format!("user:{sub}");
    gov.all_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(&group))
        .collect()
}

// ── deterministic idempotent mint ────────────────────────────────────────────────────────────────

#[test]
fn first_call_provisions_second_call_reuses_one_row() {
    let gov = gov();
    let (b1, t1) = gov.issue_self("sam", None, 5000, 1000).unwrap();
    let (b2, t2) = gov.issue_self("sam", None, 6000, 2000).unwrap();
    // ONE binding row for the principal, reused: same id, same group.
    assert_eq!(
        b1.id, b2.id,
        "deterministic id: re-login reuses the same subject"
    );
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "exactly one binding row after two logins"
    );
    // Both tokens verify (the second just carries a fresher exp).
    assert!(gov.verify_token(&t1, 1000).is_some());
    assert!(gov.verify_token(&t2, 2000).is_some());
}

/// THE 1.5.2 TOKEN-EXCHANGE FIX (red-before-green). A self-serve exchange must produce a USABLE key:
/// the `user:<sub>` budget group is auto-provisioned as a leaf under the resolved TEAM, stamped from
/// the team's `child_default`, so enforcement resolves the chain instead of failing closed with 429
/// MissingGroup. Idempotent: a second exchange reuses the one leaf and the one key row.
///
/// RED before the fix: the mint seam bound the key to `user:<sub>` but never created that group, so
/// `reg.get("user:sam")` is absent (panic) and a cost model built from the registry can't resolve the
/// key's chain — exactly the live `429 group 'user:<sub>' is not configured` the demo hit.
#[tokio::test]
async fn exchange_provisions_user_leaf_from_child_default_and_key_is_usable() {
    let gov = gov();
    // The team the role binds to, carrying a child_default the per-user leaf inherits.
    let prov = Arc::new(FakeProvisioner::with_team(
        "team",
        "child_default:\n  limits:\n    - { budget: 500, per: month }\n",
    ));
    let keys = DeterministicEd25519Keys::new(gov.clone(), "team".into(), None, prov.clone());

    // First exchange: mints the key AND auto-provisions the user:sam budget bucket.
    let issued = issue_key(
        &keys,
        &principal("sam", &["eng"]),
        Duration::from_secs(3600),
        false,
    )
    .await
    .expect("first exchange issues a key");
    assert_eq!(issued.group, "user:sam");

    // The GROUP now exists, parented under the team, with the team's child_default limits copied in.
    let reg = prov.snapshot();
    let leaf = reg
        .get("user:sam")
        .expect("user:sam leaf auto-provisioned on first exchange (the fix)");
    assert_eq!(
        leaf.parent.as_deref(),
        Some("team"),
        "leaf parented under the team"
    );
    assert_eq!(
        leaf.limits,
        reg["team"].child_default.as_ref().unwrap().limits,
        "leaf limits stamped from the team's child_default"
    );
    assert!(
        !leaf.limits.is_empty(),
        "child_default limits actually copied onto the leaf"
    );

    // ENFORCEMENT resolves it: a cost model built from the registry finds the key's chain, NOT
    // MissingGroup — the exact difference between a usable key and the live 429.
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &reg);
    assert!(cost.group_named("user:sam").is_some());
    let binding = gov
        .lookup_by_sub(&issued.key_id)
        .expect("minted binding row");
    assert!(
        cost.chain_for(&binding).is_ok(),
        "the self key resolves its enforcement chain (not MissingGroup)"
    );

    // Idempotent: a second exchange reuses the one leaf and the one key row (no sprawl, no reset).
    let issued2 = issue_key(
        &keys,
        &principal("sam", &["eng"]),
        Duration::from_secs(3600),
        false,
    )
    .await
    .expect("second exchange reuses");
    assert_eq!(issued2.key_id, issued.key_id, "same deterministic key row");
    assert_eq!(
        prov.snapshot().len(),
        2,
        "team + exactly one user leaf (no duplicate)"
    );
    assert_eq!(self_rows(&gov, "sam").len(), 1, "exactly one key binding");
}

#[test]
fn cap_not_tripped_n_logins_one_row() {
    let gov = gov();
    for i in 0..25u64 {
        gov.issue_self("sam", None, 100_000, 1000 + i).unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "N logins must never sprawl past the one idempotent binding row"
    );
}

#[test]
fn refresh_invalidates_old_token() {
    let gov = gov();
    let (_b, old) = gov.issue_self("sam", None, 100_000, 1000).unwrap();
    assert!(
        gov.verify_token(&old, 1000).is_some(),
        "old token valid before refresh"
    );

    let (_b2, fresh) = gov.refresh_self("sam", None, 100_000, 2000).unwrap();
    // Old token now fails (its binding was tombstoned / rotated away).
    assert!(
        gov.verify_token(&old, 2000).is_none(),
        "refresh must invalidate the prior token"
    );
    // The new token verifies, and there is still exactly one live self row.
    assert!(
        gov.verify_token(&fresh, 2000).is_some(),
        "fresh token valid"
    );
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "still one live self key after refresh"
    );
}

// ── the crypto guard: HMAC is a mint-time id SELECTOR, NEVER the credential ───────────────────────

#[test]
fn hmac_sig_token_rejected_bad_signature() {
    use hmac::{Hmac, KeyInit, Mac};
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &SEED,
        crate::governance::signing::DEFAULT_KID,
    );
    let verifier =
        crate::governance::signing::TokenVerifier::single(signer.kid(), signer.verifying_key());
    // A legit token: reuse its payload segment, then FORGE the signature as a literal HMAC over the
    // subject — the "Model B literal-HMAC credential" a naive reading might build. It must be
    // rejected: the credential is an ed25519 signature, not an HMAC.
    let tok = signer.mint("vk_deadbeef", 5000, Some("0"));
    let body = tok.strip_prefix("bbk_").unwrap();
    let (payload_b64, _sig_b64) = body.split_once('.').unwrap();
    // 64-byte HMAC (SHA-512) so it PARSES as a signature and reaches the (failing) crypto check,
    // proving rejection is BadSignature, not merely Malformed length.
    let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(&SEED).unwrap();
    mac.update(b"user:vk_deadbeef#0");
    let forged_sig = mac.finalize().into_bytes();
    use base64::Engine;
    let forged = format!(
        "bbk_{}.{}",
        payload_b64,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(forged_sig)
    );
    let err = verifier.verify(&forged, 1000).unwrap_err();
    assert_eq!(
        err,
        crate::governance::signing::VerifyError::BadSignature,
        "an HMAC in the signature slot is a forgery, rejected BadSignature"
    );
}

#[test]
fn issued_token_verifies_through_the_unchanged_path() {
    // The whole point of Model B: `issue_self` returns a STANDARD busbar token that the ordinary
    // verify path accepts — no verify-side change.
    let gov = gov();
    let (binding, token) = gov.issue_self("sam", None, 5000, 1000).unwrap();
    let resolved = gov
        .verify_token(&token, 1000)
        .expect("standard token verifies");
    assert_eq!(resolved.id, binding.id);
    assert_eq!(resolved.group.as_deref(), Some("user:sam"));
}

/// Re-login after an admin NARROWS the group's `allowed_pools` must take effect: the single reused
/// binding is re-persisted with the freshly-resolved pools, not left with the stale set. RED before
/// the fix: `issue_self`'s reuse branch returned the existing binding verbatim, keeping the OLD pools
/// forever.
#[test]
fn re_login_updates_allowed_pools_when_they_change() {
    use busbar_api::ScopeRef;
    let gov = gov();
    let (b1, _t1) = gov
        .issue_self("sam", Some(vec!["poolA".into()]), 5000, 1000)
        .unwrap();
    assert_eq!(b1.allowed_scopes, Some(vec![ScopeRef::pool("poolA")]));
    // Admin changed the group's pools; the dev logs in again (same sub).
    let (b2, _t2) = gov
        .issue_self("sam", Some(vec!["poolB".into()]), 6000, 2000)
        .unwrap();
    assert_eq!(
        b2.id, b1.id,
        "still exactly ONE binding (same deterministic id)"
    );
    assert_eq!(
        b2.allowed_scopes,
        Some(vec![ScopeRef::pool("poolB")]),
        "a changed allowed_pools must take effect on re-login, not keep the stale set"
    );
}

/// N concurrent `issue_self` for ONE sub yield exactly ONE binding row (the deterministic id makes
/// `put_key` idempotent; the self-mint lock also serializes the check→write so an issue/refresh
/// interleaving can't strand a second enabled binding).
#[test]
fn concurrent_issue_self_yields_one_binding() {
    let gov = gov(); // Arc<GovState>
    let mut handles = vec![];
    for i in 0..8u64 {
        let g = gov.clone();
        handles.push(std::thread::spawn(move || {
            g.issue_self("sam", Some(vec!["p".into()]), 5000, 1000 + i)
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "concurrent self-logins for one sub must leave exactly one binding"
    );
}

// ── resolve_exchange: identity source + refusal matrix ────────────────────────────────────────────

#[test]
fn identity_from_principal_not_body() {
    // resolve_exchange takes ONLY the verdict — there is no body parameter through which a caller
    // could assert a different identity. The subject it resolves is exactly the verified principal.
    let rb = bindings("oidc", "eng", Some("team"));
    let v = identified("oidc", principal("sam", &["eng"]));
    let (p, team, _pools) = resolve_exchange(&v, &rb).expect("bound principal admitted");
    assert_eq!(
        p.id, "sam",
        "self-scope comes from the verified principal, never a body"
    );
    assert_eq!(
        team, "team",
        "the bound team is threaded out for provisioning"
    );
}

#[test]
fn rejects_static_key_400() {
    let rb = bindings("oidc", "eng", Some("team"));
    // A static busbar key was presented → the engine resolved a VirtualKey.
    let key = Arc::new(crate::governance::VirtualKey {
        id: "vk_static".into(),
        generation_hash: "binding:vk_static:0".into(),
        name: "k".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    });
    let v = ChainVerdict::Identified {
        module: "oidc".into(),
        principal: principal("sam", &["eng"]),
        resolved: Some(key),
    };
    assert_eq!(
        resolve_exchange(&v, &rb).unwrap_err(),
        ExchangeError::StaticKeyPresented
    );
}

#[test]
fn open_and_denied_are_unauthorized() {
    let rb = bindings("oidc", "eng", Some("team"));
    assert_eq!(
        resolve_exchange(&ChainVerdict::Open, &rb).unwrap_err(),
        ExchangeError::Unauthorized
    );
    assert_eq!(
        resolve_exchange(&ChainVerdict::Denied, &rb).unwrap_err(),
        ExchangeError::Unauthorized
    );
}

#[test]
fn unbound_role_is_403() {
    // Identified but no role bound under the identifying module.
    let rb = bindings("oidc", "eng", Some("team"));
    let v = identified("oidc", principal("sam", &["other"]));
    assert_eq!(
        resolve_exchange(&v, &rb).unwrap_err(),
        ExchangeError::Unbound
    );
}

#[test]
fn bound_role_without_group_is_403() {
    // A self key must charge through a group; a binding without one is refused.
    let rb = bindings("oidc", "eng", None);
    let v = identified("oidc", principal("sam", &["eng"]));
    assert_eq!(
        resolve_exchange(&v, &rb).unwrap_err(),
        ExchangeError::Unbound
    );
}

#[test]
fn later_role_group_used_when_earlier_role_bound_but_groupless() {
    // CODEAUDIT ROUND-2 FIX 1: resolve_exchange must scan ALL of the principal's granting bindings
    // in the module for the first one that carries a group — not just take the FIRST role that has
    // any binding at all and then fail if THAT one happens to be groupless. Here role "A" binds but
    // has no group; role "B" binds AND carries a group. Before the fix this 403'd with Unbound even
    // though a later granting role clearly admits the principal under group "x".
    //
    // CODEAUDIT ROUND-3 FIX 1: the POOLS must be the C6 UNION across ALL granting bindings (role A's
    // "pool-a" AND role B's "pool-b"), matching `synthesize_principal_key` — not just the pools of
    // the single binding the group happened to come from (role B alone, "pool-b" only). RED before
    // the fix: only `pool-b` came back, silently narrowing a self-serve key's pools below what the
    // SAME identity gets on the data plane through `synthesize_principal_key`.
    let mut inner = BTreeMap::new();
    inner.insert(
        "A".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-a".to_string()]),
            group: None,
            admin_scope: None,
        },
    );
    inner.insert(
        "B".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-b".to_string()]),
            group: Some("x".to_string()),
            admin_scope: None,
        },
    );
    let mut rb: RoleBindings = BTreeMap::new();
    rb.insert("oidc".to_string(), inner);

    let v = identified("oidc", principal("sam", &["A", "B"]));
    let (_p, team, pools) = resolve_exchange(&v, &rb)
        .expect("a later granting role's group must admit the principal, not Unbound");
    assert_eq!(team, "x", "resolves to role B's group, not Unbound");
    let pools = pools.expect("neither granting binding omits allowed_pools");
    assert_eq!(
        pools.len(),
        2,
        "pools must be the union across ALL granting bindings: {pools:?}"
    );
    assert!(
        pools.contains(&"pool-a".to_string()),
        "role A's pool must be in the union: {pools:?}"
    );
    assert!(
        pools.contains(&"pool-b".to_string()),
        "role B's pool must be in the union: {pools:?}"
    );
}

#[test]
fn omitted_pools_on_any_granting_binding_widens_union_to_all_pools() {
    // C6: an OMITTED `allowed_pools` on ANY granting binding is the widest grant (ALL pools) and
    // must win the union even when another granting binding lists an explicit, narrower set — the
    // SAME rule `synthesize_principal_key` applies. Role A omits `allowed_pools` (all pools); role B
    // (which carries the group) lists only "pool-b". The resolved pools must be `None` (all), not
    // `Some(["pool-b"])`.
    let mut inner = BTreeMap::new();
    inner.insert(
        "A".to_string(),
        RoleBindingCfg {
            allowed_pools: None,
            group: None,
            admin_scope: None,
        },
    );
    inner.insert(
        "B".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-b".to_string()]),
            group: Some("x".to_string()),
            admin_scope: None,
        },
    );
    let mut rb: RoleBindings = BTreeMap::new();
    rb.insert("oidc".to_string(), inner);

    let v = identified("oidc", principal("sam", &["A", "B"]));
    let (_p, team, pools) = resolve_exchange(&v, &rb).expect("both roles grant");
    assert_eq!(team, "x");
    assert_eq!(
        pools, None,
        "an omitted allowed_pools on ANY granting binding widens the union to ALL pools"
    );
}

#[test]
fn sub_sanitization_refused() {
    let rb = bindings("oidc", "eng", Some("team"));
    // Refused: '/' separator, a LEADING reserved bucket/real-key prefix, empty, and control chars.
    // NOTE an INTERNAL ':' (e.g. `oidc:alice`) is NOT here — it is legitimate (module-namespaced).
    for bad in ["a/b", "vk_evil", "group:x", "user:x", "", "a\tb", "a\nb"] {
        let v = identified("oidc", principal(bad, &["eng"]));
        assert_eq!(
            resolve_exchange(&v, &rb).unwrap_err(),
            ExchangeError::BadSubject,
            "unsafe subject {bad:?} must be refused"
        );
    }
    // Admitted: a plain sub and a module-namespaced sub (internal ':').
    for ok in ["sam", "oidc:alice", "github:torvalds"] {
        let v = identified("oidc", principal(ok, &["eng"]));
        assert!(
            resolve_exchange(&v, &rb).is_ok(),
            "legitimate subject {ok:?} must be admitted"
        );
    }
}

// ── end-to-end through the real seam ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn resolve_then_issue_via_real_seam() {
    let gov = gov();
    let rb = bindings("oidc", "eng", Some("team"));
    let v = identified("oidc", principal("sam", &["eng"]));
    let (p, team, pools) = resolve_exchange(&v, &rb).unwrap();
    let keys = DeterministicEd25519Keys::new(gov.clone(), team, pools, Arc::new(NoopProvisioner));
    let issued = issue_key(&keys, p, Duration::from_secs(3600), false)
        .await
        .unwrap();
    assert!(issued.secret.starts_with("bbk_"));
    assert_eq!(issued.group, "user:sam");
    // The token the seam handed back verifies through the ordinary path.
    let now = crate::store::now();
    assert!(gov.verify_token(&issued.secret, now).is_some());
}

/// A real OIDC/GitHub/LDAP plugin sets `principal.id = "oidc:<sub>"` (module-namespaced). Such an id
/// is LEGITIMATE and verified — it must mint a key, grouped under `user:oidc:<sub>` (the internal ':'
/// cannot escape the `user:` namespace because the group is ALWAYS `user:` + the whole sub). RED
/// before the fix: `sanitize_self_sub` rejected ANY ':' → 403 BadSubject, so token-exchange with a
/// real OIDC JWT never issued a key.
#[tokio::test]
async fn module_namespaced_sub_is_admitted_and_grouped_under_user() {
    let gov = gov();
    let rb = bindings("oidc", "eng", Some("team"));
    let v = identified("oidc", principal("oidc:alice", &["eng"]));
    let (p, team, pools) =
        resolve_exchange(&v, &rb).expect("a module-namespaced subject is legitimate + verified");
    let keys = DeterministicEd25519Keys::new(gov.clone(), team, pools, Arc::new(NoopProvisioner));
    let issued = issue_key(&keys, p, Duration::from_secs(3600), false)
        .await
        .unwrap();
    assert_eq!(
        issued.group, "user:oidc:alice",
        "the whole sub lives inside the user: namespace"
    );
    assert!(gov
        .verify_token(&issued.secret, crate::store::now())
        .is_some());
}

// ── the endpoint is key-scheme agnostic ──────────────────────────────────────────────────────────

/// A FAKE scheme that issues an opaque string — proving `issue_key`/the handler depend ONLY on the
/// `SelfServeKeys` trait, never on ed25519/epoch/envelope internals.
struct FakeKeys;
#[async_trait]
impl SelfServeKeys for FakeKeys {
    async fn issue(&self, principal: &Principal, _ttl: Duration) -> Result<IssuedKey, String> {
        Ok(IssuedKey {
            secret: format!("fake-scheme-token:{}", principal.id),
            key_id: "fake".into(),
            group: format!("user:{}", principal.id),
            exp: 9999,
        })
    }
    async fn refresh(&self, principal: &Principal, ttl: Duration) -> Result<IssuedKey, String> {
        self.issue(principal, ttl).await
    }
}

#[tokio::test]
async fn endpoint_is_scheme_agnostic_over_the_trait() {
    let rb = bindings("oidc", "eng", Some("team"));
    let v = identified("oidc", principal("sam", &["eng"]));
    let (p, _team, _pools) = resolve_exchange(&v, &rb).unwrap();
    let issued = issue_key(&FakeKeys, p, Duration::from_secs(60), false)
        .await
        .unwrap();
    assert_eq!(issued.secret, "fake-scheme-token:sam");
    // Refresh path also rides the same trait object.
    let refreshed = issue_key(&FakeKeys, p, Duration::from_secs(60), true)
        .await
        .unwrap();
    assert_eq!(refreshed.secret, "fake-scheme-token:sam");
}
