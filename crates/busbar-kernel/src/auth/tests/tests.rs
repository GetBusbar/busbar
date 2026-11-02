use super::*;
use busbar_contract::records::ScopeRef;

fn binding(
    allowed_pools: Option<&[&str]>,
    group: Option<&str>,
    admin_scope: Option<&str>,
) -> crate::config::RoleBindingCfg {
    crate::config::RoleBindingCfg {
        allowed_pools: allowed_pools.map(|ps| ps.iter().map(|p| p.to_string()).collect()),
        group: group.map(str::to_string),
        admin_scope: admin_scope.map(str::to_string),
        verbs: None,
        plane_grants: Default::default(),
    }
}

fn bindings_for(
    module: &str,
    roles: &[(&str, crate::config::RoleBindingCfg)],
) -> crate::config::RoleBindings {
    let mut table = std::collections::BTreeMap::new();
    for (role, b) in roles {
        table.insert(role.to_string(), b.clone());
    }
    let mut rb = crate::config::RoleBindings::new();
    rb.insert(module.to_string(), table);
    rb
}

fn chain_cfg(modules: &[&str]) -> crate::config::AuthCfg {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.chain = modules
        .iter()
        .map(|m| crate::config::AuthChainEntry::bare(*m))
        .collect();
    cfg
}

fn grp_principal(id: &str, roles: &[&str]) -> Principal {
    let mut p = Principal::from_id(id);
    p.roles = roles.iter().map(|r| r.to_string()).collect();
    p
}

#[test]
fn admin_scope_resolution() {
    use busbar_contract::authz::{Grants, Scope};
    let rb = bindings_for(
        "test-groups-module",
        &[
            ("viewers", binding(None, None, Some("read-only"))),
            ("admins", binding(None, None, Some("full"))),
            ("no-admin", binding(None, None, None)),
        ],
    );
    let module = Some("test-groups-module");
    let operator = Operator::new("operator-provider");
    let operator_id = "operator:local";

    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, None, None),
        Grants::of(Scope::Full)
    );

    assert_eq!(
        admin_scope_from_bindings(
            &rb,
            &operator,
            operator_id,
            Some("operator-provider"),
            Some(&Principal::from_id(operator_id))
        ),
        Grants::of(Scope::Full)
    );

    assert_eq!(
        admin_scope_from_bindings(
            &rb,
            &operator,
            operator_id,
            module,
            Some(&Principal::from_id(operator_id))
        ),
        Grants::default()
    );

    let p = grp_principal("test:alice", &["viewers", "admins"]);
    assert!(
        admin_scope_from_bindings(&rb, &operator, operator_id, module, Some(&p))
            .allows(Scope::Full)
    );
    let p = grp_principal("test:alice", &["viewers"]);
    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, module, Some(&p)),
        Grants::of(Scope::ReadOnly)
    );

    let p = grp_principal("test:alice", &["strangers"]);
    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, module, Some(&p)),
        Grants::default()
    );

    let p = grp_principal("test:alice", &["no-admin"]);
    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, module, Some(&p)),
        Grants::default()
    );

    let stranger = Principal::from_id("test:bob");
    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, module, Some(&stranger)),
        Grants::default()
    );
}

#[test]
fn admin_scope_bindings_are_module_scoped() {
    use busbar_contract::authz::{Grants, Scope};
    let rb = bindings_for(
        "other-module",
        &[("admins", binding(None, None, Some("full")))],
    );
    let operator = Operator::new("operator-provider");
    let operator_id = "operator:local";
    let p = grp_principal("test:alice", &["admins"]);
    assert!(
        admin_scope_from_bindings(
            &rb,
            &operator,
            operator_id,
            Some("test-groups-module"),
            Some(&p)
        ) == Grants::default(),
        "a role asserted by module A must not ride module B's binding"
    );

    assert_eq!(
        admin_scope_from_bindings(&rb, &operator, operator_id, Some("other-module"), Some(&p)),
        Grants::of(Scope::Full)
    );

    assert_eq!(
        admin_scope_from_bindings(
            &rb,
            &operator,
            operator_id,
            Some("unbound-module"),
            Some(&p)
        ),
        Grants::default()
    );
}

#[test]
fn test_constant_time_eq_same() {
    assert!(AuthMiddleware::constant_time_eq("secret", "secret"));
}

#[test]
fn test_constant_time_eq_different_length() {
    assert!(!AuthMiddleware::constant_time_eq("short", "longer"));
}

#[test]
fn test_constant_time_eq_one_char_diff() {
    assert!(!AuthMiddleware::constant_time_eq("secret1", "secret2"));
}

#[test]
fn test_extract_bearer_token_valid() {
    let token = AuthMiddleware::extract_bearer_token("Bearer mytoken123");
    assert_eq!(token, Some("mytoken123".to_string()));
}

#[test]
fn test_extract_bearer_token_case_insensitive() {
    let token = AuthMiddleware::extract_bearer_token("BEARER mytoken123");
    assert_eq!(token, Some("mytoken123".to_string()));
}

#[test]
fn test_extract_bearer_token_no_bearer() {
    let token = AuthMiddleware::extract_bearer_token("mytoken123");
    assert_eq!(token, None);
}

#[test]
fn test_extract_bearer_token_malformed_no_panic() {
    assert_eq!(AuthMiddleware::extract_bearer_token("Béarer x"), None);
    assert_eq!(AuthMiddleware::extract_bearer_token("🔑🔑🔑"), None);
    assert_eq!(AuthMiddleware::extract_bearer_token("Bearer "), None);
    assert_eq!(AuthMiddleware::extract_bearer_token("Basic abc"), None);
}

#[test]
fn an_identified_principal_with_no_grant_is_refused() {
    let identified = |module: &str, principal: Principal| ChainVerdict::Identified {
        module: module.to_string(),
        principal,
        resolved: None,
    };
    let refused = |role_bindings: &crate::config::RoleBindings, v: ChainVerdict, why: &str| {
        match resolve_identity_from_bindings(role_bindings, v) {
            Err(IdentityRefusal::NoGrant) => {}
            other => panic!(
                "{why}: refused NoGrant, got {:?}",
                other.map(|(_, gov)| gov.key.map(|k| k.id.clone()))
            ),
        }
    };

    let bare = crate::config::RoleBindings::new();
    refused(
        &bare,
        identified("test-groups-module", grp_principal("test:nobody", &[])),
        "a roleless principal",
    );
    refused(
        &bare,
        identified("test-groups-module", grp_principal("test:dev", &["dev"])),
        "a role principal under a module with no role_bindings table",
    );

    let table = bindings_for(
        "test-groups-module",
        &[("dev", binding(Some(&["pa"]), None, None))],
    );
    let governed = table;
    refused(
        &governed,
        identified("test-groups-module", grp_principal("test:nobody", &[])),
        "a roleless principal under a governed module",
    );
    refused(
        &governed,
        identified("test-groups-module", grp_principal("test:ops", &["ops"])),
        "an unbound role under a governed module",
    );

    let (who, gov) = resolve_identity_from_bindings(
        &governed,
        identified("test-groups-module", grp_principal("test:dev", &["dev"])),
    )
    .expect("a bound role earns a key and is admitted");
    assert!(who.0.is_some() && gov.key.is_some());
    let (who, gov) = resolve_identity_from_bindings(&bare, ChainVerdict::Open).expect("open door");
    assert!(who.0.is_none() && gov.key.is_none());
}

#[test]
fn the_refuse_every_ungoverned_rule_against_1_5_5s_guard() {
    let table = bindings_for(
        "test-groups-module",
        &[("dev", binding(Some(&["pa"]), None, None))],
    );
    let none = crate::config::RoleBindings::new();
    let roleless = grp_principal("test:nobody", &[]);
    let ops = grp_principal("test:ops", &["ops"]);
    for (bindings, principal, admitted_by_1_5_5) in [
        (&none, &roleless, true),
        (&none, &ops, true),
        (&table, &roleless, true),
        (&table, &ops, false),
    ] {
        assert!(!admits_ungoverned_under(
            true,
            "test-groups-module",
            principal,
            bindings
        ));
        assert_eq!(
            admits_ungoverned_under(false, "test-groups-module", principal, bindings),
            admitted_by_1_5_5,
            "{principal:?}"
        );
    }
}

#[test]
fn test_upstream_credentials_deserialize() {
    assert!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("invalid").is_err(),
        "an unrecognized upstream_credentials value must fail to deserialize"
    );
    assert_eq!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("passthrough").unwrap(),
        crate::auth::UpstreamCreds::Passthrough
    );
    assert_eq!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("own").unwrap(),
        crate::auth::UpstreamCreds::Own
    );
}

fn role_table(
    roles: &[(&str, crate::config::RoleBindingCfg)],
) -> std::collections::BTreeMap<String, crate::config::RoleBindingCfg> {
    roles
        .iter()
        .map(|(r, b)| (r.to_string(), b.clone()))
        .collect()
}

#[test]
fn test_synth_key_omitted_pools_grants_all_pools() {
    let table = role_table(&[("dev", binding(None, None, None))]);
    let p = grp_principal("test:dev", &["dev"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("a bound role must synthesize a key");
    assert_eq!(
        key.allowed_scopes, None,
        "omitted allowed_pools = ALL pools = None on the key"
    );
    assert!(key.enabled);
    assert_eq!(key.id, "test:dev");
    assert!(key.group.is_none());
}

#[test]
fn test_synth_key_explicit_empty_pools_fails_closed_c6_flip() {
    let table = role_table(&[("dev", binding(Some(&[]), None, None))]);
    let p = grp_principal("test:dev", &["dev"]);
    assert!(
        crate::governance::synthesize_principal_key(&p, Some(&table)).is_none(),
        "allowed_pools: [] must be the empty set (no access), not all pools"
    );

    let table = role_table(&[
        ("dev", binding(Some(&[]), None, None)),
        ("ops", binding(Some(&[]), None, None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    assert!(
        crate::governance::synthesize_principal_key(&p, Some(&table)).is_none(),
        "an all-bindings-[] union must fail closed"
    );

    let table = role_table(&[
        ("dev", binding(Some(&[]), None, None)),
        ("ops", binding(None, None, None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("an omitted-pools binding grants all pools");
    assert_eq!(key.allowed_scopes, None);
}

#[test]
fn test_synth_key_pool_union_and_all_pools_dominates() {
    let table = role_table(&[
        ("a", binding(Some(&["p1"]), None, None)),
        ("b", binding(Some(&["p2", "p1"]), None, None)),
    ]);
    let p = grp_principal("test:u", &["a", "b"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("bound roles must synthesize a key");
    assert_eq!(
        key.allowed_scopes,
        Some(vec![ScopeRef::pool("p1"), ScopeRef::pool("p2")])
    );

    let table = role_table(&[
        ("a", binding(Some(&["p1"]), None, None)),
        ("c", binding(None, None, None)),
    ]);
    let p = grp_principal("test:u", &["a", "c"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("bound roles must synthesize a key");
    assert_eq!(
        key.allowed_scopes, None,
        "one omitted-pools binding widens the union to ALL pools"
    );
}

#[test]
fn test_synth_key_unbound_roles_grant_nothing() {
    let p = grp_principal("test:u", &["strangers"]);

    let table = role_table(&[("dev", binding(None, None, None))]);
    assert!(crate::governance::synthesize_principal_key(&p, Some(&table)).is_none());

    assert!(crate::governance::synthesize_principal_key(&p, None).is_none());
}

#[test]
fn test_synth_key_bound_group_lands_in_group_binding() {
    let table = role_table(&[("dev", binding(None, Some("eng"), None))]);
    let p = grp_principal("test:dev", &["dev"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("a bound role must synthesize a key");
    assert_eq!(key.group.as_deref(), Some("eng"));

    let table = role_table(&[
        ("dev", binding(None, Some("eng"), None)),
        ("ops", binding(None, Some("platform"), None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("bound roles must synthesize a key");
    assert_eq!(key.group.as_deref(), Some("eng"));
}

#[test]
fn test_synth_key_reserved_id_prefixes_refused() {
    let table = role_table(&[("dev", binding(None, None, None))]);
    for id in ["group:evil", "vk_0123456789abcdef"] {
        let p = grp_principal(id, &["dev"]);
        assert!(
            crate::governance::synthesize_principal_key(&p, Some(&table)).is_none(),
            "reserved principal id '{id}' must not synthesize a key"
        );
    }
}

const X_ADMIN_TOKEN: &str = "x-admin-token";

fn decode_body(resp: Response) -> serde_json::Value {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test body must collect")
    });
    serde_json::from_slice(&bytes).expect("auth-failure body must be valid JSON")
}

fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        serde_json::Value::Object(o) => o.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

#[test]
fn a_door_refusal_retains_its_exact_query_in_a_wiping_target() {
    use std::sync::Arc;

    fn wiped_when_dropped<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    let seen = Arc::new(std::sync::Mutex::new(None));
    let observed = Arc::clone(&seen);
    let target = "/v1/responses?token=query-canary";
    let door: RefusalDoor = (
        Arc::new(move |reason, target| {
            assert_eq!(reason, busbar_contract::caps::ReasonCode::Unauthenticated);
            *observed.lock().unwrap() = Some(target.to_owned());
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap()
        }),
        zeroize::Zeroizing::new(target.to_owned()),
    );
    wiped_when_dropped(&door.1);
    let response = refuse_door(&door);
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(seen.lock().unwrap().as_deref(), Some(target));
}

#[test]
fn test_unauthorized_body_carries_no_busbar_vocabulary() {
    const FORBIDDEN: &[&str] = &[
        "virtual key",
        "client token",
        "client_token",
        "allowlist",
        "disabled",
        "passthrough",
        "busbar",
        "unauthorized",
        "admin",
    ];
    let paths = [
        "/v1beta/models/x:verb",
        "/pa/v1/messages",
        "/v1/kind/action",
        "/v1/responses",
        "/v2/chat",
        "/model/vendor.model/converse",
        "/api/v1/admin/keys",
        "/totally/unknown/path",
    ];
    for path in paths {
        // This is the fallback formatter continuation. Actual mounted-door routing is
        // exercised by root product tests; no application or invented plane table is needed.
        let ingress = crate::plane_driver::dispatch::Ingress::Fallback(
            crate::ingress::protocols::residual_dialect_for_path(path),
        );
        let response = unauthorized_ingress_response(ingress);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = decode_body(response);
        let mut strings = Vec::new();
        collect_strings(&body, &mut strings);
        for s in &strings {
            let lc = s.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(
                    !lc.contains(bad),
                    "auth-failure body for '{path}' leaked busbar vocabulary '{bad}': {body}"
                );
            }
        }
    }
}

#[test]
fn an_all_pass_admin_continuation_retains_the_401_refusal() {
    let verdict = complete_chain(chain_position_verdict("slow-oidc", AuthVerdict::Pass));
    let door = admin_door_from_bindings(
        &Default::default(),
        &Operator::new("operator-provider"),
        "operator",
        verdict,
        None,
        crate::admin::seam::admin_verb_rung,
    );
    let refusal = admin_principal_or_response(door).expect_err("all-Pass denies");
    assert_eq!(refusal.status().as_u16(), 401);
}

#[test]
fn test_caller_token_debug_redacts_value() {
    let secret = "sk-caller-secret-CCCC";
    let present = CallerToken(Some(secret.to_string()));
    let dbg = format!("{present:?}");
    assert!(
        !dbg.contains(secret) && !dbg.contains("sk-caller"),
        "CallerToken Debug leaked the token value: {dbg}"
    );
    assert!(
        dbg.contains("present"),
        "CallerToken Debug should report presence: {dbg}"
    );

    let absent = CallerToken(None);
    let dbg_absent = format!("{absent:?}");
    assert!(
        dbg_absent.contains("absent"),
        "CallerToken Debug should report absence: {dbg_absent}"
    );
}

#[test]
fn test_admin_scope_cap_ceilings_external_module() {
    use busbar_contract::authz::{Grants, Scope};
    let operator = Operator::new("operator-provider");
    let principal = grp_principal("test:ops", &["ops"]);
    let module = "test-scope-module";
    let granted = |configured: Option<&str>, bind_module: &str| {
        let bindings = bindings_for(bind_module, &[("ops", binding(None, None, Some("full")))]);
        let caps = configured
            .map(|cap| (module.to_string(), cap.to_string()))
            .into_iter()
            .collect();
        cap_admin_scope(
            admin_scope_from_bindings(
                &bindings,
                &operator,
                "operator:local",
                Some(module),
                Some(&principal),
            ),
            module_scope_cap(&caps, &operator, module),
        )
    };

    assert_eq!(
        granted(None, module),
        Grants::of(Scope::ReadOnly),
        "an external module without an explicit cap must be ceilinged to read-only"
    );
    assert_eq!(
        granted(Some("full"), module),
        Grants::of(Scope::Full),
        "an explicit full cap must let the full binding through"
    );
    assert_eq!(
        granted(Some("full"), "other-module"),
        Grants::default(),
        "a binding under another module's table must grant nothing"
    );
}

#[test]
fn an_unanswered_operator_does_not_open_a_verifier() {
    use crate::auth::{Operator, OperatorCredential};
    let digest = busbar_contract::redacted::sha256_hex(b"tok");
    // Explicit constructor DATA for an unanswered provider, not a fabricated root registry.
    // The root's actual operator/carrier controls separately exercise its real installed axis.
    let open = |digest| {
        Operator::open(
            "operator-provider",
            std::iter::empty(),
            &|module: &str| module == "operator-provider",
            false,
            digest,
            |_| panic!("an unanswered operator must not invoke a verifier factory"),
        )
        .expect("an unanswered operator is represented explicitly")
    };
    assert!(matches!(
        *open(Some(digest)),
        OperatorCredential::Unanswered
    ));
    assert!(matches!(*open(None), OperatorCredential::Unanswered));
}

pub(super) fn admin_headers(bearer: Option<&str>, header: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(b) = bearer {
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {b}")).expect("a header value"),
        );
    }
    if let Some(h) = header {
        headers.insert(
            HeaderName::from_static(X_ADMIN_TOKEN),
            HeaderValue::from_str(h).expect("a header value"),
        );
    }
    headers
}

#[test]
fn operator_answer_continuation_preserves_identified_and_refusal_types() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    // The old producer returned Ready immediately from both verify/probe; its assertions
    // classified answers, rather than proving a Pending await. Real Pending is tested at root.
    let outcome = |verified: Verified| {
        let answered = Judgement::answered(verified.into());
        let verdict = complete_chain(chain_position_verdict(
            "operator-provider",
            answered.verdict,
        ));
        let operator = Operator::new("operator-provider");
        let cap = if matches!(&verdict, ChainVerdict::Identified { .. }) {
            module_scope_cap(&Default::default(), &operator, "operator-provider")
        } else {
            None
        };
        (verdict, cap)
    };
    assert!(matches!(
        outcome(Verified::Identity(VerifiedIdentity {
            subject: "admin".into(),
            ..Default::default()
        })),
        (ChainVerdict::Identified { .. }, _)
    ));
    for refused in [
        Verified::Reject,
        Verified::Pass,
        Verified::Overloaded,
        Verified::Failed,
    ] {
        assert_eq!(
            outcome(refused.clone()),
            (ChainVerdict::Denied, None),
            "{refused:?}: 1.5.5's refusal"
        );
    }
}

#[tokio::test]
async fn operator_answer_response_projection_preserves_503_and_legacy_401() {
    use busbar_contract::auth_calls::Verified;
    async fn inspect(door: AdminDoor) -> (u16, Option<String>, String) {
        let response = admin_principal_or_response(door).expect_err("a refusal has no principal");
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .map(|value| value.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, retry, String::from_utf8(body.to_vec()).unwrap())
    }
    let project = |verdict| {
        let identified = matches!(&verdict, ChainVerdict::Identified { .. });
        let claim = unclaimed_admin_replay(identified, None, 7);
        let operator = Operator::new("operator-provider");
        (
            admin_door_from_bindings(
                &Default::default(),
                &operator,
                "admin",
                verdict,
                None,
                crate::admin::seam::admin_verb_rung,
            ),
            PendingClaim::of(claim, None),
        )
    };
    let classified = |verified: Verified| {
        let answered = Judgement::answered(verified.into());
        admin_probe_projection(
            admin_chain_outcome(
                complete_chain(chain_position_verdict(
                    "operator-provider",
                    answered.verdict,
                )),
                answered.no_verdict,
            ),
            project,
        )
        .0
    };
    let rejected = inspect(classified(Verified::Reject)).await;
    assert_eq!(rejected.0, 401, "a bad credential is the admin401");
    assert_eq!(rejected.1, None, "a401 names no Retry-After");
    let overloaded = inspect(classified(Verified::Overloaded)).await;
    assert_eq!(
        overloaded, rejected,
        "an overloaded operator answer uses the same bytes"
    );
    let failed = inspect(classified(Verified::Failed)).await;
    assert_eq!(
        (failed.0, failed.1.as_deref()),
        (503, Some("1")),
        "a verdict-less answer projects503+Retry-After (SIGN-auth-kind 2026-10-30)"
    );
    let body: serde_json::Value = serde_json::from_str(&failed.2).expect("the real admin envelope");
    assert_eq!(body["error"]["code"], "unavailable", "{failed:?}");
}

#[tokio::test]
async fn external_admin_answer_projection_preserves_failed_faulted_and_reject_responses() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    async fn inspect(door: AdminDoor) -> (u16, Option<String>, String) {
        let response = admin_principal_or_response(door).expect_err("a refusal has no principal");
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .map(|value| value.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, retry, String::from_utf8(body.to_vec()).unwrap())
    }
    let project = |verdict| {
        let identified = matches!(&verdict, ChainVerdict::Identified { .. });
        let claim = unclaimed_admin_replay(identified, None, 7);
        let operator = Operator::new("operator-provider");
        (
            admin_door_from_bindings(
                &Default::default(),
                &operator,
                "admin",
                verdict,
                None,
                crate::admin::seam::admin_verb_rung,
            ),
            PendingClaim::of(claim, None),
        )
    };
    let classified = |verified: Verified, faulted| {
        let answered = admin_verdict_of(verified.into(), faulted);
        admin_probe_projection(
            admin_chain_outcome(
                complete_chain(chain_position_verdict("ext", answered.verdict)),
                answered.no_verdict,
            ),
            project,
        )
        .0
    };
    let rejected = inspect(classified(Verified::Reject, false)).await;
    assert_eq!(
        (rejected.0, rejected.1.as_deref()),
        (401, None),
        "{rejected:?}"
    );
    for (what, verified, faulted) in [
        ("FAILED", Verified::Failed, false),
        (
            "FAULT",
            Verified::Identity(VerifiedIdentity {
                subject: "faulted".into(),
                ..Default::default()
            }),
            true,
        ),
    ] {
        let answered = inspect(classified(verified, faulted)).await;
        assert_eq!(
            (answered.0, answered.1.as_deref()),
            (503, Some("1")),
            "{what}:503+Retry-After (SIGN-auth-kind 2026-10-30): {answered:?}"
        );
    }
}

#[test]
fn the_sync_admin_door_probe_fails_closed_when_the_operator_verifier_is_overloaded() {
    let project = |verdict| {
        let identified = matches!(&verdict, ChainVerdict::Identified { .. });
        let claim = unclaimed_admin_replay(identified, None, 7);
        let operator = Operator::new("operator-provider");
        (
            admin_door_from_bindings(
                &Default::default(),
                &operator,
                "admin",
                verdict,
                None,
                crate::admin::seam::admin_verb_rung,
            ),
            PendingClaim::of(claim, None),
        )
    };
    let answered = Judgement::answered(busbar_contract::auth_calls::Verified::Overloaded.into());
    let (door, _) = admin_probe_projection(
        admin_chain_outcome(
            complete_chain(chain_position_verdict(
                "operator-provider",
                answered.verdict,
            )),
            answered.no_verdict,
        ),
        project,
    );
    assert_eq!(
        admin_scope_from_door(door.clone()),
        busbar_contract::authz::Grants::default()
    );
    assert_eq!(door, AdminDoor::Denied);
}

#[test]
fn the_sync_admin_door_keeps_no_verdict_for_the_root_http_projection() {
    use busbar_contract::auth_calls::Verified;
    for verified in [Verified::Failed, Verified::Reject, Verified::Overloaded] {
        let expected = if matches!(verified, Verified::Failed) {
            AdminDoor::Unavailable(VerifierUnavailable::NoVerdict)
        } else {
            AdminDoor::Denied
        };
        for operator in [true, false] {
            let answered = if operator {
                Judgement::answered(verified.clone().into())
            } else {
                admin_verdict_of(verified.clone().into(), false)
            };
            let verdict = complete_chain(chain_position_verdict("provider", answered.verdict));
            let (door, claim) = admin_probe_projection(
                admin_chain_outcome(verdict, answered.no_verdict),
                |verdict| {
                    let identified = matches!(&verdict, ChainVerdict::Identified { .. });
                    // Actual production filtering must ignore even supplied replay metadata for
                    // an unidentified answer; no fake producer or application is constructed.
                    let replay = Some((
                        "provider".to_string(),
                        Box::new(Replay {
                            key: "unidentified".into(),
                            ttl_secs: 60,
                        }),
                    ));
                    let claim = unclaimed_admin_replay(identified, replay, 7);
                    let op = Operator::new("operator-provider");
                    (
                        admin_door_from_bindings(
                            &Default::default(),
                            &op,
                            "admin",
                            verdict,
                            None,
                            crate::admin::seam::admin_verb_rung,
                        ),
                        PendingClaim::of(claim, None),
                    )
                },
            );
            assert_eq!(door, expected, "{verified:?}");
            assert!(claim.is_none(), "an unidentified request claims nothing");
            assert!(!admin_door_admits(&door, "GET", "/api/v1/admin/keys"));
            assert_eq!(
                admin_scope_from_door(door),
                busbar_contract::authz::Grants::default(),
                "an unavailable or rejecting verifier grants nothing"
            );
        }
    }
}

#[test]
fn the_admin_head_hands_the_request_through_as_presented() {
    let mut headers = admin_headers(Some("tok"), Some("hdr"));
    headers.insert(
        axum::http::header::HOST,
        HeaderValue::from_static("node.example:8443"),
    );
    let head = admin_head("POST", "/api/v1/admin/keys?limit=2", &headers, 7);
    assert_eq!(head.point, busbar_contract::abi::auth::AuthPoint::Head);
    assert_eq!(
        (
            head.method.as_str(),
            head.path.as_str(),
            head.query.as_deref()
        ),
        ("POST", "/api/v1/admin/keys", Some("limit=2"))
    );
    assert_eq!(head.authority, "node.example:8443");
    assert_eq!(head.timestamp, 7);
    let names: Vec<&str> = head.lines.iter().map(|l| l.0.as_str()).collect();
    assert_eq!(names, ["authorization", X_ADMIN_TOKEN, "host"]);
}

struct Answered(Option<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for Answered {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl busbar_contract::auth_calls::Verifying for Answered {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.take()
    }
}

#[test]
fn a_data_plane_door_overloaded_or_without_a_verdict_denies_the_chain() {
    use busbar_contract::auth_calls::Verified;
    // Internal outcome→public chain-result continuation. An error is terminal before any
    // later provider; actual OIDC identity/verification is qualified separately at the root.
    for verified in [Verified::Overloaded, Verified::Failed] {
        let judged = data_verdict_of("door", verified.clone().into(), false).map(|judged| {
            chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied)
        });
        assert_eq!(
            deny_unavailable_chain(judged),
            ChainVerdict::Denied,
            "{verified:?} must deny, not pass"
        );
    }
}

#[test]
fn the_data_plane_walk_hands_an_overloaded_or_verdict_less_door_back_apart() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    let judged = |verified: Verified| {
        data_verdict_of("door", verified.into(), false).map(|judged| {
            chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied)
        })
    };
    assert_eq!(
        judged(Verified::Overloaded),
        Err(VerifierUnavailable::Overloaded),
        "an overloaded door is handed back apart, never a reject or a pass"
    );
    assert_eq!(
        judged(Verified::Failed),
        Err(VerifierUnavailable::NoVerdict),
        "a door with no verdict is handed back apart (SIGN-auth-kind 2026-10-30)"
    );
    assert_eq!(
        judged(Verified::Reject),
        Ok(ChainVerdict::Denied),
        "a REJECT is the denial"
    );
    let faulted = data_verdict_of(
        "door",
        Verified::Identity(VerifiedIdentity {
            subject: "faulted".into(),
            ..Default::default()
        })
        .into(),
        true,
    )
    .map(|judged| chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied));
    assert_eq!(
        faulted,
        Err(VerifierUnavailable::NoVerdict),
        "a FAULTED door is handed back apart, never admitted on its answer"
    );
}

fn at_capacity_503() -> (u16, Option<String>, Option<String>, String) {
    (
        503,
        Some(busbar_contract::protocol::APPLICATION_JSON.to_string()),
        Some("1".to_string()),
        r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#
            .to_string(),
    )
}

#[tokio::test]
async fn data_verifier_outcome_projection_preserves_the_503_and_401_envelopes() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    async fn inspect(response: Response) -> (u16, Option<String>, Option<String>, String) {
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_string())
        };
        let (content_type, retry_after) = (header("content-type"), header("retry-after"));
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (
            status,
            content_type,
            retry_after,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }
    // Internal outcome/identity→response continuation. Both production callers use these
    // exact factories; actual HTTP delivery and genuine credentials have separate root controls.
    let no_grant = resolve_identity_from_bindings(
        &Default::default(),
        ChainVerdict::Identified {
            module: "test-groups-module".into(),
            principal: grp_principal("test:admins", &["admins"]),
            resolved: None,
        },
    )
    .expect_err("an identified unbound principal has no grant");
    let all_pass = inspect(identity_refusal_response(no_grant, None, true, || {
        unauthorized_ingress_response(crate::plane_driver::dispatch::Ingress::Fallback(None))
    }))
    .await;
    assert_eq!(
        all_pass.0, 401,
        "the unbound-identity refusal: {all_pass:?}"
    );
    let rejected = inspect(identity_refusal_response(
        IdentityRefusal::Denied,
        None,
        true,
        || unauthorized_ingress_response(crate::plane_driver::dispatch::Ingress::Fallback(None)),
    ))
    .await;
    assert_eq!(rejected, all_pass, "a REJECT: the 1.5.5 401, byte for byte");
    let overloaded = data_verdict_of("door", Verified::Overloaded.into(), false)
        .err()
        .expect("overload stays apart");
    assert_eq!(
        inspect(data_verifier_error_response(overloaded)).await,
        at_capacity_503(),
        "an overloaded door (Q134)"
    );
    let failed = data_verdict_of("door", Verified::Failed.into(), false)
        .err()
        .expect("no verdict stays apart");
    assert_eq!(
        inspect(data_verifier_error_response(failed)).await,
        at_capacity_503(),
        "a FAILED door: 503 + Retry-After, refused (SIGN-auth-kind 2026-10-30)"
    );
    let faulted = data_verdict_of(
        "door",
        Verified::Identity(VerifiedIdentity {
            subject: "faulted".into(),
            ..Default::default()
        })
        .into(),
        true,
    )
    .err()
    .expect("a fault overrides its purported identity");
    assert_eq!(
        inspect(data_verifier_error_response(faulted)).await,
        at_capacity_503(),
        "a FAULTED door: 503 + Retry-After, refused (SIGN-auth-kind 2026-10-30)"
    );
    // The two exchange NoVerdict status/header oracles are retained in
    // exchange_verifier_outcome_projection_preserves_failed_and_faulted_503.
}

#[test]
fn external_admin_answer_projection_keeps_identity_and_all_refusal_types() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    // INTERNAL outcome/projection DATA. Actual OIDC requests from both credential carriers
    // separately establish the selected-candidate loan; this does not assert sync I/O readiness.
    let project = |verified: Verified| {
        let answered = admin_verdict_of(verified.into(), false);
        let verdict = complete_chain(chain_position_verdict("ext-door", answered.verdict));
        let operator = Operator::new("operator-provider");
        let cap = if matches!(&verdict, ChainVerdict::Identified { .. }) {
            module_scope_cap(&Default::default(), &operator, "ext-door")
        } else {
            None
        };
        let door = admin_door_from_bindings(
            &Default::default(),
            &operator,
            "operator",
            verdict.clone(),
            cap,
            crate::admin::seam::admin_verb_rung,
        );
        ((verdict, cap), door)
    };
    for _ in 0..2 {
        let (chain, door) = project(Verified::Identity(VerifiedIdentity {
            subject: "ext:who".into(),
            groups: vec!["ops".into()],
            ..Default::default()
        }));
        assert!(
            matches!(chain, (ChainVerdict::Identified { ref module, .. }, _) if module == "ext-door")
        );
        assert!(matches!(door, AdminDoor::Identified(..)));
    }
    for otherwise in [
        Verified::Reject,
        Verified::Pass,
        Verified::Overloaded,
        Verified::Failed,
    ] {
        assert_eq!(
            project(otherwise.clone()).0,
            (ChainVerdict::Denied, None),
            "{otherwise:?}: the 1.5.5 refusal"
        );
    }
}

#[test]
fn successive_admin_answer_projections_do_not_reuse_an_earlier_identity() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    let project = |verified: Verified| {
        let answer = admin_verdict_of(verified.into(), false);
        let verdict = complete_chain(chain_position_verdict("ext-door", answer.verdict));
        let cap = if matches!(&verdict, ChainVerdict::Identified { .. }) {
            module_scope_cap(
                &Default::default(),
                &Operator::new("operator-provider"),
                "ext-door",
            )
        } else {
            None
        };
        (verdict, cap)
    };
    assert!(
        matches!(project(Verified::Identity(VerifiedIdentity { subject: "ext:who".into(), groups: vec!["ops".into()], ..Default::default() })),
        (ChainVerdict::Identified { ref module, .. }, _) if module == "ext-door")
    );
    assert_eq!(
        project(Verified::Reject),
        (ChainVerdict::Denied, None),
        "a later refusal is never replaced by an earlier Identified outcome"
    );
}

fn hook_answer(
    key: Option<&str>,
    strips: Vec<busbar_contract::auth_calls::Strip>,
) -> busbar_contract::auth_calls::VerifyAnswer {
    use busbar_contract::auth_calls::{Replay, Verified, VerifiedIdentity, VerifyAnswer};
    let identity = Verified::Identity(VerifiedIdentity {
        subject: "hook:sender".into(),
        groups: vec!["hooks".into()],
        replay: key.map(|key| {
            Box::new(Replay {
                key: key.to_string(),
                ttl_secs: 300,
            })
        }),
        ..VerifiedIdentity::default()
    });
    VerifyAnswer {
        strips,
        ..VerifyAnswer::from(identity)
    }
}

fn replay_gov() -> std::sync::Arc<crate::governance::GovState> {
    let actual = crate::real_store::store();
    let gov = crate::governance::GovState::new(actual.clone(), None).expect("gov");
    assert!(gov.attach_store_calls(actual));
    std::sync::Arc::new(gov)
}

#[tokio::test]
async fn a_replay_claim_with_no_store_calls_to_redeem_in_is_refused() {
    use busbar_contract::auth_calls::{Replay, VerifiedIdentity};
    let bare = crate::governance::GovState::new(crate::real_store::store(), None).expect("gov");
    let now = busbar_kernel::store::now();
    let asks = VerifiedIdentity {
        subject: "subject".into(),
        replay: Some(Box::new(Replay {
            key: "message-1".into(),
            ttl_secs: 300,
        })),
        ..VerifiedIdentity::default()
    };
    assert!(!signed_replay_claimed(Some(&bare), "verifier", &asks, now).await);
    assert!(!signed_replay_claimed(None, "verifier", &asks, now).await);
    let none = VerifiedIdentity {
        subject: "subject".into(),
        ..VerifiedIdentity::default()
    };
    assert!(signed_replay_claimed(Some(&bare), "verifier", &none, now).await);
}

#[tokio::test]
async fn the_signed_ingress_claims_its_identitys_replay_key() {
    use busbar_contract::auth_calls::{Replay, VerifiedIdentity};
    let gov = replay_gov();
    let now = busbar_kernel::store::now();
    let asks = VerifiedIdentity {
        subject: "subject".into(),
        replay: Some(Box::new(Replay {
            key: "message-1".into(),
            ttl_secs: 300,
        })),
        ..VerifiedIdentity::default()
    };
    assert!(
        signed_replay_claimed(Some(gov.as_ref()), "verifier", &asks, now).await,
        "the first presentation wins its claim"
    );
    assert!(
        !signed_replay_claimed(Some(gov.as_ref()), "verifier", &asks, now).await,
        "the same key inside its TTL is a replay"
    );
    let none = VerifiedIdentity {
        subject: "subject".into(),
        ..VerifiedIdentity::default()
    };
    for _ in 0..2 {
        assert!(
            signed_replay_claimed(Some(gov.as_ref()), "verifier", &none, now).await,
            "an identity asking for no claim is never refused for one"
        );
    }
}

#[tokio::test]
async fn a_replayed_verified_identity_inside_its_ttl_is_denied() {
    let gov = replay_gov();
    // INTERNAL post-verification claim continuation; no fake verifier or chain.
    let run = |key: &str, gov: Option<std::sync::Arc<crate::governance::GovState>>| {
        let answered = chain_verdict_of(hook_answer(Some(key), Vec::new()));
        let verdict = complete_chain(chain_position_verdict("door", answered.verdict));
        let pending = PendingClaim::of(
            ReplayClaim::of("door", answered.replay, busbar_kernel::store::now()),
            gov,
        );
        async move {
            deny_unavailable_chain(claimed_chain_identity(Ok(verdict), pending.as_ref()).await)
        }
    };
    let first = run("standard-webhooks/msg_1", Some(gov.clone())).await;
    assert!(
        matches!(first, ChainVerdict::Identified { .. }),
        "{first:?}"
    );
    assert_eq!(
        run("standard-webhooks/msg_1", Some(gov.clone())).await,
        ChainVerdict::Denied,
        "the same message inside its TTL is a replay"
    );
    let other = run("standard-webhooks/msg_2", Some(gov)).await;
    assert!(
        matches!(other, ChainVerdict::Identified { .. }),
        "{other:?}"
    );
    assert_eq!(
        run("standard-webhooks/msg_3", None).await,
        ChainVerdict::Denied,
        "no governance to claim in refuses"
    );
}

#[tokio::test]
async fn a_replayed_verified_delivery_is_denied_before_dispatch() {
    // INTERNAL post-verification admission over the actual conditional Store. The former
    // NamingDoor/echo server only invented verification; real HTTP auth is exercised at root.
    let gov = replay_gov();
    let bindings = bindings_for("door", &[("hooks", binding(None, None, None))]);
    let run = || {
        let answered = chain_verdict_of(hook_answer(Some("standard-webhooks/msg_1"), Vec::new()));
        let verdict = complete_chain(chain_position_verdict("door", answered.verdict));
        let pending = PendingClaim::of(
            ReplayClaim::of("door", answered.replay, busbar_kernel::store::now()),
            Some(gov.clone()),
        );
        (verdict, pending)
    };
    let (verdict, pending) = run();
    assert!(admit_verified_session(&bindings, verdict, pending.as_ref())
        .await
        .is_ok());
    let (verdict, pending) = run();
    let refused = admit_verified_session(&bindings, verdict, pending.as_ref())
        .await
        .expect_err("the replay must never reach a handler");
    assert_eq!(refused, IdentityRefusal::Denied);
    let response = identity_refusal_response(refused, None, true, || {
        unauthorized_ingress_response(crate::plane_driver::dispatch::Ingress::Fallback(
            crate::ingress::protocols::residual_dialect_for_path("/pa/v1/messages"),
        ))
    });
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the production refusal projection returns the same 401 envelope as native ingress"
    );
}

#[test]
fn named_credential_stripping_preserves_both_request_targets_and_other_headers() {
    use busbar_contract::auth_calls::Strip;
    // INTERNAL request-mutation continuation. Actual webhook verification declares field
    // strips; no real auth product is claimed to declare these query strips.
    let mut request = Request::builder()
        .uri("/echo?x=1&api_key=s3cret&y=a%20b&api%5Fkey=t")
        .header("authorization", "Bearer signed")
        .header("x-hook-secret", "hs")
        .header("x-trace", "t-1")
        .body(Body::empty())
        .unwrap();
    let original = axum::extract::OriginalUri(request.uri().clone());
    request.extensions_mut().insert(original);
    let mut consumed = consumed_from_carriers(&[AUTHORIZATION], None, false, false);
    strike_named(
        &mut request,
        &mut consumed,
        &[Strip::field("X-Hook-Secret"), Strip::query("api_key")],
    );
    ConsumedCredentials::strip_from(Some(&consumed), request.headers_mut());
    let headers: Vec<&str> = request.headers().keys().map(|name| name.as_str()).collect();
    assert!(!headers.contains(&"x-hook-secret"), "{headers:?}");
    assert!(!headers.contains(&"authorization"), "{headers:?}");
    assert!(headers.contains(&"x-trace"), "{headers:?}");
    assert_eq!(request.uri().to_string(), "/echo?x=1&y=a%20b");
    assert_eq!(
        request
            .extensions()
            .get::<axum::extract::OriginalUri>()
            .unwrap()
            .0
            .to_string(),
        "/echo?x=1&y=a%20b"
    );
}

#[tokio::test]
async fn an_admin_identity_replayed_is_denied_and_its_named_lines_ride_out() {
    let gov = replay_gov();
    let now = busbar_kernel::store::now();
    let project = || {
        let mut carried = AdminCarried::default();
        let (verdict, replay) = carry_admin_outcome(
            &mut carried,
            "ext-door",
            chain_verdict_of(hook_answer(
                Some("signed/admin_1"),
                vec![Strip::field("x-hook-secret")],
            )),
        );
        let verdict = complete_chain(chain_position_verdict("ext-door", verdict));
        let pending = PendingClaim::of(
            unclaimed_admin_replay(
                matches!(&verdict, ChainVerdict::Identified { .. }),
                replay.map(|r| ("ext-door".into(), r)),
                now,
            ),
            Some(gov.clone()),
        );
        let door = admin_door_from_bindings(
            &bindings_for(
                "ext-door",
                &[("hooks", binding(None, None, Some("read-only")))],
            ),
            &Operator::new("operator-provider"),
            "operator",
            verdict,
            None,
            crate::admin::seam::admin_verb_rung,
        );
        (door, pending, carried.strips)
    };
    let (door, pending, strips) = project();
    let first = Ok::<_, VerifierUnavailable>(
        claimed_admin_door(door, pending.as_ref(), "GET", "/", true).await,
    );
    assert!(matches!(first, Ok(AdminDoor::Identified(..))), "{first:?}");
    assert_eq!(strips, vec![Strip::field("x-hook-secret")]);
    let (door, pending, _) = project();
    assert_eq!(
        probed_admin_claim(door, pending.as_ref(), "GET", "/", true),
        AdminDoor::Denied,
        "the replay is refused"
    );
    let (door, pending, _) = project();
    assert!(
        admin_scope_from_door(probed_admin_claim(
            door,
            pending.as_ref(),
            "GET",
            "/",
            false
        )) != busbar_contract::authz::Grants::default(),
        "a dry run claims nothing"
    );
}

async fn still_unclaimed(gov: &crate::governance::GovState, provider: &str, key: &str) -> bool {
    let replay = busbar_contract::auth_calls::Replay {
        key: key.to_string(),
        ttl_secs: 300,
    };
    replay_claimed(Some(gov), provider, &replay, busbar_kernel::store::now()).await
}

#[tokio::test]
async fn a_delivery_refused_for_its_grant_leaves_its_replay_key_unclaimed() {
    let gov = replay_gov();
    let run = || {
        let answered = chain_verdict_of(hook_answer(Some("standard-webhooks/msg_r6"), Vec::new()));
        let verdict = complete_chain(chain_position_verdict("door", answered.verdict));
        let pending = PendingClaim::of(
            ReplayClaim::of("door", answered.replay, busbar_kernel::store::now()),
            Some(gov.clone()),
        );
        (verdict, pending)
    };
    for _ in 0..2 {
        let (verdict, pending) = run();
        assert!(matches!(
            admit_verified_session(&Default::default(), verdict, pending.as_ref()).await,
            Err(IdentityRefusal::NoGrant)
        ));
    }
    let bindings = bindings_for("door", &[("hooks", binding(None, None, None))]);
    let (verdict, pending) = run();
    assert!(
        admit_verified_session(&bindings, verdict, pending.as_ref())
            .await
            .is_ok(),
        "binding the group must admit the still-unclaimed delivery"
    );
    let (verdict, pending) = run();
    assert!(
        matches!(
            admit_verified_session(&bindings, verdict, pending.as_ref()).await,
            Err(IdentityRefusal::Denied)
        ),
        "the admitted delivery now owns its replay claim"
    );
}

#[tokio::test]
async fn a_session_refused_for_its_grant_claims_no_replay_key() {
    let gov = replay_gov();
    let now = busbar_kernel::store::now();
    for _ in 0..2 {
        let answered = chain_verdict_of(hook_answer(Some("standard-webhooks/msg_r6s"), Vec::new()));
        let verdict = complete_chain(chain_position_verdict("door", answered.verdict));
        let pending = PendingClaim::of(
            ReplayClaim::of("door", answered.replay, now),
            Some(gov.clone()),
        );
        let refused = admit_verified_session(&Default::default(), verdict, pending.as_ref())
            .await
            .expect_err("no grant: refused");
        assert_eq!(refused, IdentityRefusal::NoGrant, "refused for its grant");
    }
    assert!(
        still_unclaimed(&gov, "door", "standard-webhooks/msg_r6s").await,
        "a refused session holds no claim"
    );
}

#[tokio::test]
async fn an_admin_identity_refused_for_scope_leaves_its_replay_key_unclaimed() {
    use busbar_contract::authz::Scope;
    let gov = replay_gov();
    let now = busbar_kernel::store::now();
    // INTERNAL verified-identity/scope/claim continuation over actual conditional Store.
    let project = || {
        let answered = chain_verdict_of(hook_answer(Some("signed/admin_r6"), Vec::new()));
        let verdict = complete_chain(chain_position_verdict("ext-door", answered.verdict));
        let pending = PendingClaim::of(
            unclaimed_admin_replay(true, answered.replay.map(|r| ("ext-door".into(), r)), now),
            Some(gov.clone()),
        );
        let door = admin_door_from_bindings(
            &bindings_for(
                "ext-door",
                &[("hooks", binding(None, None, Some("read-only")))],
            ),
            &Operator::new("operator-provider"),
            "operator",
            verdict,
            None,
            crate::admin::seam::admin_verb_rung,
        );
        (door, pending)
    };
    for _ in 0..2 {
        let (door, pending) = project();
        let refused = Ok::<_, VerifierUnavailable>(
            claimed_admin_door(door, pending.as_ref(), "POST", "/", true).await,
        );
        let Ok(AdminDoor::Identified(_, grants)) = &refused else {
            panic!("identified, not authorized, not a replay: {refused:?}");
        };
        assert!(!grants.allows(Scope::Full), "{grants:?}");
    }
    let (door, pending) = project();
    assert!(
        matches!(
            probed_admin_claim(door, pending.as_ref(), "POST", "/", true),
            AdminDoor::Identified(..)
        ),
        "the probe refuses for scope too, claiming nothing"
    );
    let (door, pending) = project();
    let admitted = Ok::<_, VerifierUnavailable>(
        claimed_admin_door(door, pending.as_ref(), "GET", "/", true).await,
    );
    assert!(
        matches!(admitted, Ok(AdminDoor::Identified(..))),
        "the authorized request wins the still-free claim: {admitted:?}"
    );
    let (door, pending) = project();
    assert_eq!(
        probed_admin_claim(door, pending.as_ref(), "GET", "/", true),
        AdminDoor::Denied,
        "its replay is refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_racing_identical_deliveries_admit_at_most_one() {
    let gov = replay_gov();
    let bindings = std::sync::Arc::new(bindings_for(
        "door",
        &[("hooks", binding(None, None, None))],
    ));
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut racing = Vec::new();
    for _ in 0..8 {
        let gov = gov.clone();
        let bindings = bindings.clone();
        let barrier = barrier.clone();
        racing.push(tokio::spawn(async move {
            let answered =
                chain_verdict_of(hook_answer(Some("standard-webhooks/msg_race"), Vec::new()));
            let verdict = complete_chain(chain_position_verdict("door", answered.verdict));
            let pending = PendingClaim::of(
                ReplayClaim::of("door", answered.replay, busbar_kernel::store::now()),
                Some(gov),
            );
            barrier.wait().await;
            match admit_verified_session(&bindings, verdict, pending.as_ref()).await {
                Ok(_) => true,
                Err(IdentityRefusal::Denied) => false,
                Err(other) => panic!("unexpected grant refusal: {other:?}"),
            }
        }));
    }
    let mut admitted = 0;
    for one in racing {
        admitted += usize::from(one.await.unwrap());
    }
    assert_eq!(
        admitted, 1,
        "the actual conditional Store admits exactly one of eight racing claims"
    );
}

// Ordinary root replacements for the synthetic door/GovCtx cohort live in
// busbar/src/tests/kernel_application/auth_governance_routes.rs. The actual /stats
// endpoint consumes GovCtx; session admission exposes its principal/key without
// introducing a plane handler merely to echo request extensions.

#[test]
fn a_signed_verify_keeps_the_lines_its_auth_named_whatever_its_verdict() {
    use busbar_contract::auth_calls::VerifiedIdentity;
    let named = vec![
        Strip::field("x-double-signature"),
        Strip::query("x-double-key"),
    ];
    let identity = Verified::Identity(VerifiedIdentity {
        subject: "double-id".into(),
        ..VerifiedIdentity::default()
    });
    for verified in [
        identity.clone(),
        Verified::Pass,
        Verified::Reject,
        Verified::Failed,
        Verified::Overloaded,
    ] {
        let answer = VerifyAnswer {
            strips: named.clone(),
            ..VerifyAnswer::from(verified.clone())
        };
        let mut strips = vec![Strip::field("x-earlier-line")];
        assert_eq!(signed_verdict_of(answer, false, &mut strips), verified);
        assert_eq!(
            strips,
            [vec![Strip::field("x-earlier-line")], named.clone()].concat(),
            "{verified:?}: the verifier's named lines join the union"
        );
    }
    let faulted = VerifyAnswer {
        strips: named.clone(),
        ..VerifyAnswer::from(identity)
    };
    let mut strips = Vec::new();
    assert_eq!(
        signed_verdict_of(faulted, true, &mut strips),
        Verified::Failed,
        "a faulted verify never admits"
    );
    assert_eq!(strips, named, "a faulted verify's named lines are kept");
}

#[test]
fn declared_carrier_order_selects_only_its_own_header_lines() {
    // INTERNAL carrier-selection continuation over metadata DATA, including an arbitrary
    // first carrier. The actual root's separate statement test pins installed metadata.
    let carriers = ["x-other-key", "authorization"].map(HeaderName::from_static);
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("from-x-api-key"));
    assert_eq!(carried_credential(&carriers, &headers), None);
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer from-bearer"),
    );
    assert_eq!(
        carried_credential(&carriers, &headers),
        Some("from-bearer".to_string())
    );
    headers.insert("x-other-key", HeaderValue::from_static("from-other"));
    assert_eq!(
        carried_credential(&carriers, &headers),
        Some("from-other".to_string()),
        "the style's first line wins"
    );
}

#[test]
fn the_gate_strips_the_styles_lines_and_the_operator_credentials() {
    // Internal stripping continuation over explicit carrier DATA. The root's actual carrier
    // tests separately prove what the installed default style/operator rows declare.
    let style = ["authorization", "x-api-key", "x-goog-api-key"].map(HeaderName::from_static);
    let operator = [X_ADMIN_TOKEN.to_string()];
    let consumed = consumed_from_carriers(&style, Some(&operator), false, false);
    let mut headers = HeaderMap::new();
    for name in [
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        X_ADMIN_TOKEN,
        "x-trace",
    ] {
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static("v"));
    }
    consumed.strip(&mut headers);
    let kept: Vec<String> = headers.keys().map(|n| n.as_str().to_string()).collect();
    assert_eq!(kept, ["x-trace"]);
}

fn verbs_binding(yaml: &str) -> crate::config::RoleBindingCfg {
    serde_yaml::from_str(yaml).expect("`verbs:` is a role-binding key")
}

#[test]
fn a_role_granting_verbs_by_name_is_identified_with_its_allow_list() {
    use busbar_contract::authz::{Grants, Scope};
    // Internal projection over explicit binding/principal/rung DATA. The real root named-verb
    // gate separately exercises the actual registered core-admin table and real OIDC verifier.
    let operator = Operator::new("operator-provider");
    let rungs = std::collections::BTreeMap::from([
        ("post_config_apply", Scope::Full),
        ("post_keys", Scope::Full),
        ("get_keys", Scope::ReadOnly),
    ]);
    let identified = || ChainVerdict::Identified {
        module: "test-scope-module".to_string(),
        principal: grp_principal("test:ops", &["ops"]),
        resolved: None,
    };
    let bindings = bindings_for(
        "test-scope-module",
        &[("ops", verbs_binding("verbs: [post_config_apply]"))],
    );
    let door = admin_door_from_bindings(
        &bindings,
        &operator,
        "operator:local",
        identified(),
        Some(Scope::Full),
        |name| rungs.get(name).copied(),
    );
    let AdminDoor::Listed(principal, grants, list) = door else {
        panic!("a role granting verbs by name is identified with its list, got {door:?}");
    };
    assert_eq!(principal.id, "test:ops");
    assert_eq!(
        grants,
        Grants::of(Scope::Full),
        "the matrix reaches the named verb's rung"
    );
    assert_eq!(list.rungs, Grants::default(), "no rung is held whole");
    assert!(
        list.admits(Some("post_config_apply"), Scope::Full),
        "the named verb is admitted"
    );
    assert!(
        !list.admits(Some("post_keys"), Scope::Full),
        "a mutation the list does not name is not"
    );
    assert!(
        !list.admits(Some("get_keys"), Scope::ReadOnly),
        "nor is a read the list does not name: a named list is not a rung"
    );
    assert!(
        !list.admits(None, Scope::ReadOnly),
        "and a path the table names no verb for is no verb"
    );
}

#[test]
fn verbs_star_is_exactly_admin_scope_full() {
    use busbar_contract::authz::Scope;
    // Internal projection over explicit binding/principal/rung DATA. The real root named-verb
    // gate separately exercises the actual registered core-admin table and real OIDC verifier.
    let operator = Operator::new("operator-provider");
    let rungs = std::collections::BTreeMap::from([
        ("post_config_apply", Scope::Full),
        ("post_keys", Scope::Full),
        ("get_keys", Scope::ReadOnly),
    ]);
    let identified = || ChainVerdict::Identified {
        module: "test-scope-module".to_string(),
        principal: grp_principal("test:ops", &["ops"]),
        resolved: None,
    };
    let star = bindings_for(
        "test-scope-module",
        &[("ops", verbs_binding("verbs: \"*\""))],
    );
    let full = bindings_for(
        "test-scope-module",
        &[("ops", binding(None, None, Some("full")))],
    );
    for (method, path) in [
        ("POST", "/api/v1/admin/config/apply"),
        ("GET", "/api/v1/admin/keys"),
    ] {
        let by_star = admin_door_from_bindings(
            &star,
            &operator,
            "operator:local",
            identified(),
            Some(Scope::Full),
            |name| rungs.get(name).copied(),
        );
        assert!(matches!(by_star, AdminDoor::Identified(..)), "{by_star:?}");
        assert_eq!(
            by_star,
            admin_door_from_bindings(
                &full,
                &operator,
                "operator:local",
                identified(),
                Some(Scope::Full),
                |name| rungs.get(name).copied()
            ),
            "{method} {path}: `verbs: \"*\"` must be exactly `admin_scope: full`"
        );
    }
}

#[test]
fn a_binding_without_verbs_is_judged_by_its_rung_alone() {
    use busbar_contract::authz::{Grants, Scope};
    // Internal projection over explicit binding/principal/rung DATA. The real root named-verb
    // gate separately exercises the actual registered core-admin table and real OIDC verifier.
    let operator = Operator::new("operator-provider");
    let rungs = std::collections::BTreeMap::from([
        ("post_config_apply", Scope::Full),
        ("post_keys", Scope::Full),
        ("get_keys", Scope::ReadOnly),
    ]);
    let identified = || ChainVerdict::Identified {
        module: "test-scope-module".to_string(),
        principal: grp_principal("test:ops", &["ops"]),
        resolved: None,
    };
    for (scope, rung) in [("read-only", Scope::ReadOnly), ("full", Scope::Full)] {
        let bindings = bindings_for(
            "test-scope-module",
            &[("ops", binding(None, None, Some(scope)))],
        );
        let door = admin_door_from_bindings(
            &bindings,
            &operator,
            "operator:local",
            identified(),
            Some(Scope::Full),
            |name| rungs.get(name).copied(),
        );
        let AdminDoor::Identified(_, grants) = door else {
            panic!("{scope}: a binding with no `verbs` key is never listed, got {door:?}");
        };
        assert_eq!(grants, Grants::of(rung), "{scope}");
    }
}

#[test]
fn the_providers_ceiling_caps_a_named_verb() {
    use busbar_contract::authz::{Grants, Scope};
    // Internal projection over explicit binding/principal/rung DATA. The real root named-verb
    // gate separately exercises the actual registered core-admin table and real OIDC verifier.
    let operator = Operator::new("operator-provider");
    let rungs = std::collections::BTreeMap::from([
        ("post_config_apply", Scope::Full),
        ("post_keys", Scope::Full),
        ("get_keys", Scope::ReadOnly),
    ]);
    let identified = || ChainVerdict::Identified {
        module: "test-scope-module".to_string(),
        principal: grp_principal("test:ops", &["ops"]),
        resolved: None,
    };
    let bindings = bindings_for(
        "test-scope-module",
        &[("ops", verbs_binding("verbs: [get_keys, post_config_apply]"))],
    );
    let door = admin_door_from_bindings(
        &bindings,
        &operator,
        "operator:local",
        identified(),
        Some(Scope::ReadOnly),
        |name| rungs.get(name).copied(),
    );
    let AdminDoor::Listed(_, grants, list) = door else {
        panic!("the named read survives the ceiling, got {door:?}");
    };
    assert_eq!(grants, Grants::of(Scope::ReadOnly));
    assert!(list.admits(Some("get_keys"), Scope::ReadOnly));
    assert!(
        !list.admits(Some("post_config_apply"), Scope::Full),
        "a named mutation above the provider's ceiling is not held"
    );
}

#[test]
fn bearer_separators_consume_ascii_spaces_without_normalizing_token_bytes() {
    for header in ["Bearer token", "Bearer  token", "bEaReR     token"] {
        assert_eq!(
            AuthMiddleware::extract_bearer_token(header).as_deref(),
            Some("token")
        );
    }
    for header in [
        "Bearer",
        "Bearer ",
        "Bearer     ",
        "Bearer\ttoken",
        "Basic token",
        "Béarer token",
    ] {
        assert_eq!(AuthMiddleware::extract_bearer_token(header), None);
    }

    for (header, expected) in [
        ("Bearer token ", "token "),
        ("Bearer token other", "token other"),
        ("Bearer \ttoken", "\ttoken"),
    ] {
        assert_eq!(
            AuthMiddleware::extract_bearer_token(header).as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn repeated_authorization_fields_keep_the_first_credential_after_separator_parsing() {
    let mut headers = HeaderMap::new();
    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer   first"));
    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
    assert_eq!(
        carried_credential(&[AUTHORIZATION], &headers).as_deref(),
        Some("first")
    );
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic first"));
    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
    assert_eq!(carried_credential(&[AUTHORIZATION], &headers), None);
}

#[tokio::test]
async fn admin_unauthorized_challenges_without_changing_the_frozen_error_body() {
    let response = admin_unauthorized_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[axum::http::header::WWW_AUTHENTICATE],
        "Bearer"
    );
    let expected = crate::admin::gate::ApiError::Unauthorized;
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"error": {"code": expected.code(), "message": expected.message()}})
    );
}

#[tokio::test]
async fn absent_challenge_omits_error_advice_but_keeps_resource_discovery() {
    let metadata = "https://resource.example/.well-known/oauth-protected-resource";
    let response = challenge::refuse(
        challenge::ChallengeError::Absent,
        metadata,
        "Authentication is required for this resource.",
        Some("read"),
    );
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[axum::http::header::WWW_AUTHENTICATE],
        format!("Bearer resource_metadata=\"{metadata}\"")
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body, serde_json::json!({"error": "unauthorized"}));
}

#[tokio::test]
async fn presented_credentials_keep_challenge_error_descriptions_and_scope_rules() {
    for (error, status, code) in [
        (
            challenge::ChallengeError::InvalidToken,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
        ),
        (
            challenge::ChallengeError::InsufficientScope,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        ),
    ] {
        let response = challenge::refuse(
            error,
            "https://resource.example/metadata",
            "Safe advisory.",
            Some("read"),
        );
        assert_eq!(response.status(), status);
        let header = response.headers()[axum::http::header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(header.contains(&format!("error=\"{code}\"")));
        assert!(header.contains("error_description=\"Safe advisory.\""));
        assert_eq!(
            header.contains("scope=\"read\""),
            error == challenge::ChallengeError::InsufficientScope
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"error": code, "error_description": "Safe advisory."})
        );
    }
}
