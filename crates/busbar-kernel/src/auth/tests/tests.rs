use super::*;
use busbar_contract::records::ScopeRef;

/// Helper: a `RoleBindingCfg` from optional pool list / group / admin scope.
fn binding(
    allowed_pools: Option<&[&str]>,
    group: Option<&str>,
    admin_scope: Option<&str>,
) -> crate::config::RoleBindingCfg {
    crate::config::RoleBindingCfg {
        allowed_pools: allowed_pools.map(|ps| ps.iter().map(|p| p.to_string()).collect()),
        group: group.map(str::to_string),
        admin_scope: admin_scope.map(str::to_string),
    }
}

/// Helper: a `RoleBindings` table with one module's role->binding entries.
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

/// Helper: an `AuthCfg` whose data-plane chain names the given modules (bare entries).
fn chain_cfg(modules: &[&str]) -> crate::config::AuthCfg {
    let mut cfg = crate::config::AuthCfg::default_none();
    cfg.chain = modules
        .iter()
        .map(|m| crate::config::AuthChainEntry::bare(*m))
        .collect();
    cfg
}

/// Helper: a role-carrying principal (the shape the test-groups-module mints).
fn grp_principal(id: &str, roles: &[&str]) -> Principal {
    let mut p = Principal::from_id(id);
    p.roles = roles.iter().map(|r| r.to_string()).collect();
    p
}

/// `admin_scope_for`: the operator principal is full; role-carrying principals resolve
/// through `role_bindings.<identifying module>` (the UNION of what its bound roles grant, unbound
/// roles grant nothing); a roleless non-operator principal gets nothing; the open posture
/// (no principal) is full.
#[test]
fn admin_scope_resolution() {
    use crate::admin::v1::contract::{Grants, Scope};
    let rb = bindings_for(
        "test-groups-module",
        &[
            ("viewers", binding(None, None, Some("read-only"))),
            ("admins", binding(None, None, Some("full"))),
            ("no-admin", binding(None, None, None)),
        ],
    );
    let module = Some("test-groups-module");
    let app = crate::test_support::TestApp::new()
        .role_bindings(rb)
        .build();

    // Open posture (no principal): full.
    assert_eq!(admin_scope_for(&app, None, None), Grants::of(Scope::Full));
    // The operator principal (the operator credential's): full by definition, no binding required.
    assert_eq!(
        admin_scope_for(
            &app,
            Some(crate::config::operator_provider()),
            Some(&Principal::from_id(crate::config::operator_principal_id()))
        ),
        Grants::of(Scope::Full)
    );
    // ... and ONLY through the operator credential's provider: the same roleless principal from any
    // other module earns nothing.
    assert_eq!(
        admin_scope_for(
            &app,
            module,
            Some(&Principal::from_id(crate::config::operator_principal_id()))
        ),
        Grants::default()
    );
    // Role-bound: the union of the principal's bound roles. `with` is a plain bitwise union (never
    // canonicalized), so `{read-only} ∪ {full}` keeps BOTH bits rather than collapsing to `{full}` —
    // asserted on `allows`, the actual authorization behaviour, not the raw bit pattern.
    let p = grp_principal("test:alice", &["viewers", "admins"]);
    assert!(admin_scope_for(&app, module, Some(&p)).allows(Scope::Full));
    let p = grp_principal("test:alice", &["viewers"]);
    assert_eq!(
        admin_scope_for(&app, module, Some(&p)),
        Grants::of(Scope::ReadOnly)
    );
    // Unbound roles grant nothing (fail closed).
    let p = grp_principal("test:alice", &["strangers"]);
    assert_eq!(admin_scope_for(&app, module, Some(&p)), Grants::default());
    // A role bound WITHOUT an admin_scope grants nothing.
    let p = grp_principal("test:alice", &["no-admin"]);
    assert_eq!(admin_scope_for(&app, module, Some(&p)), Grants::default());
    // A roleless NON-operator principal gets nothing (an external module cannot mint the
    // operator identity by returning a bare id).
    let stranger = Principal::from_id("test:bob");
    assert_eq!(
        admin_scope_for(&app, module, Some(&stranger)),
        Grants::default()
    );
}

// (1.5.2 scope collapse deleted the four sibling/incomparable admin-scope tests:
// `sibling_roles_union_keeps_both_grants`, `sibling_roles_union_is_not_full`,
// `mint_capped_by_hooks_register_grants_only_read`, `hooks_register_capped_by_mint_grants_only_read`.
// With only {read-only, full}, roles can no longer hold incomparable grants and a ceiling can never
// collapse a binding to a surprising sibling meet.)

/// Module scoping: bindings are NESTED BY MODULE, so a role asserted by module A must NOT
/// ride module B's binding. A binding that lives only under "other-module" grants nothing to a
/// principal identified by the test-groups-module.
#[test]
fn admin_scope_bindings_are_module_scoped() {
    use crate::admin::v1::contract::{Grants, Scope};
    let rb = bindings_for(
        "other-module",
        &[("admins", binding(None, None, Some("full")))],
    );
    let app = crate::test_support::TestApp::new()
        .role_bindings(rb)
        .build();
    let p = grp_principal("test:alice", &["admins"]);
    assert!(
        admin_scope_for(&app, Some("test-groups-module"), Some(&p)) == Grants::default(),
        "a role asserted by module A must not ride module B's binding"
    );
    // Control: the SAME principal identified by the binding's own module resolves.
    assert_eq!(
        admin_scope_for(&app, Some("other-module"), Some(&p)),
        Grants::of(Scope::Full)
    );
    // A module with no binding table at all grants nothing.
    assert_eq!(
        admin_scope_for(&app, Some("unbound-module"), Some(&p)),
        Grants::default()
    );
}

// `assert_uuid_v4_shaped` moved with its callers (the synthetic request-id shape of one dialect's
// auth failure) to `crates/busbar-llm/src/engine/tests/auth_native_envelope_tests.rs`; its sibling
// `test_synth_amzn_request_id_is_uuid_v4` already lives in busbar-llm beside that codec.

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
    // A multibyte char in the scheme position must not panic (was a `h[..7]` UTF-8 boundary bug).
    assert_eq!(AuthMiddleware::extract_bearer_token("Béarer x"), None);
    assert_eq!(AuthMiddleware::extract_bearer_token("🔑🔑🔑"), None);
    assert_eq!(AuthMiddleware::extract_bearer_token("Bearer "), None); // empty token
    assert_eq!(AuthMiddleware::extract_bearer_token("Basic abc"), None);
}

/// A configured chain module that recognizes the credential IDENTIFIES: the verdict carries BOTH
/// the identifying module name and the principal (the struct variant), because role_bindings are
/// nested by module and policy resolution needs both halves.
#[test]
fn test_chain_identifies_with_module_and_principal() {
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["test-groups-module"]));
    match mw.run_chain(Some("grp:dev")) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "test-groups-module");
            assert_eq!(principal.id, "test:dev");
            assert_eq!(principal.roles, vec!["dev".to_string()]);
        }
        other => panic!("expected Identified, got {other:?}"),
    }
    assert!(mw.validate_token(Some("grp:dev")));
    assert!(!mw.is_open());
}

/// FAIL CLOSED: a NON-EMPTY chain where every module passes (no module recognized the presented
/// credential, or none was presented) DENIES. This is the successor of the old static-allowlist
/// "wrong token rejected" coverage.
#[test]
fn test_nonempty_chain_fails_closed_on_all_pass() {
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["test-groups-module"]));
    assert_eq!(
        mw.run_chain(Some("not-a-recognized-credential")),
        ChainVerdict::Denied,
        "an unrecognized credential must be denied by a configured chain"
    );
    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential at all must be denied by a configured chain"
    );
    assert!(!mw.validate_token(Some("tok3")));
    assert!(!mw.validate_token(None));
    assert!(!mw.validate_token(Some(""))); // empty token never matches
}

/// ITEM 144 — an IDENTIFIED principal that earns no governance key is REFUSED, never admitted
/// `key: None` (no pool ACL, no budget, spend booked to `anonymous`). The guard is "no key" alone:
/// a ROLELESS principal, a role principal under a module with NO `role_bindings` table, and a role
/// principal whose roles are unbound under a module that HAS one are all `NoGrant`. The two admitted
/// shapes stay admitted: `Open` (anonymous by explicit `chain: []`) and a principal that earned a key.
#[test]
fn a_principal_without_a_governance_key_is_refused() {
    let identified = |module: &str, principal: Principal| ChainVerdict::Identified {
        module: module.to_string(),
        principal,
        resolved: None,
    };
    let refused =
        |app: &crate::state::App, v: ChainVerdict, why: &str| match resolve_data_plane_identity(
            app, v,
        ) {
            Err(IdentityRefusal::NoGrant) => {}
            Ok((_, gov)) => panic!(
                "{why}: admitted with key {:?} — fails open",
                gov.key.map(|k| k.id.clone())
            ),
            Err(other) => panic!("{why}: expected NoGrant, got {other:?}"),
        };

    // No bindings table for any module.
    let bare = crate::test_support::TestApp::new().build();
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

    // A bindings table for the module: an unbound role (and no role) still earns nothing.
    let table = bindings_for(
        "test-groups-module",
        &[("dev", binding(Some(&["pa"]), None, None))],
    );
    let governed = crate::test_support::TestApp::new()
        .role_bindings(table)
        .build();
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

    // Positive controls: the bound role earns a key and is admitted under it; `Open` is anonymous.
    let (who, gov) = resolve_data_plane_identity(
        &governed,
        identified("test-groups-module", grp_principal("test:dev", &["dev"])),
    )
    .expect("a bound role earns a key and is admitted");
    assert!(who.0.is_some() && gov.key.is_some());
    let (who, gov) = resolve_data_plane_identity(&bare, ChainVerdict::Open).expect("open door");
    assert!(who.0.is_none() && gov.key.is_none());
}

/// The EMPTY chain is the open front door (the old `none`/`passthrough` modes): every request is
/// admitted anonymously (`ChainVerdict::Open`), with or without a credential.
#[test]
fn test_empty_chain_is_open_front_door() {
    let mw = AuthMiddleware::new_builtin(&crate::config::AuthCfg::default_none());
    assert!(mw.is_open());
    assert_eq!(mw.run_chain(None), ChainVerdict::Open);
    assert_eq!(mw.run_chain(Some("anything")), ChainVerdict::Open);
    assert!(mw.validate_token(None));
    assert!(mw.validate_token(Some("anything")));
}

// `test_open_door_regardless_of_upstream_creds` MOVED to `tests/auth_cross_plane.rs`:
// `App::upstream_creds()` reads through `engine_tables_view()`, which only the REAL `busbar_llm`
// plane's `build_runtime` populates with the configured `upstream_credentials` — an
// integration-test target, never this `#[cfg(test)]` unit module (see `endpoints_cross_plane.rs`'s
// header for the same reason).

/// `chain: [keys]` sets the `keys_in_chain` flag rather than installing a boxed module: virtual
/// keys authenticate on the governance path, so the entry records operator intent for
/// validation/reporting and the boxed chain stays empty.
#[test]
fn test_keys_in_chain_sets_flag_not_module() {
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["keys"]));
    assert!(mw.keys_in_chain, "chain: [keys] must set keys_in_chain");
    assert!(
        mw.chain_names().is_empty(),
        "keys is engine-handled, never a boxed module"
    );

    let mw = AuthMiddleware::new_builtin(&crate::config::AuthCfg::default_none());
    assert!(!mw.keys_in_chain, "an empty chain must not claim keys");

    // keys + an external module: the flag is set AND the boxed module still identifies.
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["keys", "test-groups-module"]));
    assert!(mw.keys_in_chain);
    assert_eq!(mw.chain_names(), vec!["test-groups-module"]);
    assert!(mw.validate_token(Some("grp:dev")));
    assert!(!mw.validate_token(Some("wrong")), "still fail-closed");
}

#[test]
fn test_upstream_credentials_deserialize() {
    // `upstream_credentials` deserializes snake_case; an unknown value is rejected at config LOAD.
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

// ===================== SYNTHESIZED PRINCIPAL KEY (governance re-key) =====================

/// Helper: the granting table for one module, handed to `synthesize_principal_key` the way the
/// middleware does (`app.role_bindings.get(identifying_module)`).
fn role_table(
    roles: &[(&str, crate::config::RoleBindingCfg)],
) -> std::collections::BTreeMap<String, crate::config::RoleBindingCfg> {
    roles
        .iter()
        .map(|(r, b)| (r.to_string(), b.clone()))
        .collect()
}

/// OMITTED `allowed_pools` on a granting binding = ALL pools. The `VirtualKey` runtime encoding
/// carries the intent intact (`None` = all pools). The key is pure auth: no inline caps of any
/// kind exist on the struct (limits live on groups only), so the only policy handle is `group`.
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

/// REGRESSION for the `allowed_pools` flip: an explicit `allowed_pools: []` is the EMPTY SET
/// (no pools), no longer an "all pools" alias. When EVERY granting binding says `[]`, the union
/// is empty and NO key is synthesized at all (fail closed - no data-plane access).
#[test]
fn test_synth_key_explicit_empty_pools_fails_closed_c6_flip() {
    let table = role_table(&[("dev", binding(Some(&[]), None, None))]);
    let p = grp_principal("test:dev", &["dev"]);
    assert!(
        crate::governance::synthesize_principal_key(&p, Some(&table)).is_none(),
        "allowed_pools: [] must be the empty set (no access), not all pools"
    );

    // Two granting bindings, both explicit []: still the empty union, still no key.
    let table = role_table(&[
        ("dev", binding(Some(&[]), None, None)),
        ("ops", binding(Some(&[]), None, None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    assert!(
        crate::governance::synthesize_principal_key(&p, Some(&table)).is_none(),
        "an all-bindings-[] union must fail closed"
    );

    // But an explicit [] beside an omitted-pools binding does NOT poison the grant: omitted
    // means ALL pools, which dominates the union.
    let table = role_table(&[
        ("dev", binding(Some(&[]), None, None)),
        ("ops", binding(None, None, None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("an omitted-pools binding grants all pools");
    assert_eq!(key.allowed_scopes, None);
}

/// Explicit pool lists union across granting bindings (deduplicated); an omitted-pools binding
/// anywhere in the grant set widens the union to ALL pools.
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

/// Unbound roles grant nothing, and no binding table at all grants nothing (fail closed).
#[test]
fn test_synth_key_unbound_roles_grant_nothing() {
    let p = grp_principal("test:u", &["strangers"]);
    // The identifying module has a table, but none of the principal's roles are bound in it.
    let table = role_table(&[("dev", binding(None, None, None))]);
    assert!(crate::governance::synthesize_principal_key(&p, Some(&table)).is_none());
    // The identifying module has NO binding table (module-scoped fail-closed: bindings that live
    // under another module's table are simply not passed in for this module).
    assert!(crate::governance::synthesize_principal_key(&p, None).is_none());
}

/// A bound `group:` lands in the synthesized key's `group` binding (the group chain is where
/// limits are enforced). The first granting role in the principal's role order wins.
#[test]
fn test_synth_key_bound_group_lands_in_group_binding() {
    let table = role_table(&[("dev", binding(None, Some("eng"), None))]);
    let p = grp_principal("test:dev", &["dev"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("a bound role must synthesize a key");
    assert_eq!(key.group.as_deref(), Some("eng"));

    // Two granting roles with groups: the first in role order carries.
    let table = role_table(&[
        ("dev", binding(None, Some("eng"), None)),
        ("ops", binding(None, Some("platform"), None)),
    ]);
    let p = grp_principal("test:dev", &["dev", "ops"]);
    let key = crate::governance::synthesize_principal_key(&p, Some(&table))
        .expect("bound roles must synthesize a key");
    assert_eq!(key.group.as_deref(), Some("eng"));
}

/// Reserved bucket namespaces: a principal id shaped like a group bucket (`group:...`) or a real
/// virtual key id (`vk_...`) would alias another ledger cell, so no key is synthesized (fail
/// closed) even when a binding grants.
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

/// Helper: build a request with a single header set, for `extract_client_token` unit tests.
fn req_with(name: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri("/v1/messages")
        .header(name, value)
        .body(Body::empty())
        .expect("test request must build")
}

#[test]
fn test_extract_client_token_authorization_bearer() {
    let req = req_with("authorization", "Bearer tok-abc");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-abc".to_string())
    );
}

#[test]
fn test_extract_client_token_x_api_key() {
    // Anthropic SDK carrier: raw token, no scheme prefix.
    let req = req_with("x-api-key", "tok-x-api-key");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-x-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_x_goog_api_key() {
    // Gemini SDK carrier: raw token, no scheme prefix.
    let req = req_with("x-goog-api-key", "tok-x-goog-api-key");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-x-goog-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_precedence_is_authorization_first() {
    // Authorization wins over x-api-key, which wins over x-goog-api-key.
    let req = Request::builder()
        .uri("/v1/messages")
        .header("authorization", "Bearer from-auth")
        .header("x-api-key", "from-x-api-key")
        .header("x-goog-api-key", "from-goog")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("from-auth".to_string())
    );

    // Without Authorization, x-api-key wins over x-goog-api-key.
    let req = Request::builder()
        .uri("/v1/messages")
        .header("x-api-key", "from-x-api-key")
        .header("x-goog-api-key", "from-goog")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("from-x-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_empty_carrier_falls_through() {
    // A present-but-blank x-api-key must not mask a token in x-goog-api-key.
    let req = Request::builder()
        .uri("/v1/messages")
        .header("x-api-key", "")
        .header("x-goog-api-key", "tok-x-goog-api-key")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-x-goog-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_none_when_no_carrier() {
    let req = Request::builder()
        .uri("/v1/messages")
        .body(Body::empty())
        .unwrap();
    assert_eq!(AuthMiddleware::extract_client_token(&req), None);
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_api_key() {
    // A PRESENT but non-Bearer Authorization header (AWS SigV4, or Basic) must NOT short-circuit
    // extract_client_token to None: extract_bearer_token returns None for these schemes, so the
    // code must FALL THROUGH to x-api-key. This is the bedrock-SigV4-plus-vendor-key shape the
    // multi-scheme design targets (a client signs the upstream request with SigV4 in
    // Authorization while carrying the busbar token in x-api-key). A regression that made any
    // present Authorization header short-circuit would silently break those clients yet pass
    // every bearer-only / carrier-only test.
    for non_bearer in [
        "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/svc/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef",
        "Basic dXNlcjpwYXNz",
    ] {
        let req = Request::builder()
            .uri("/v1/messages")
            .header("authorization", non_bearer)
            .header("x-api-key", "tok")
            .body(Body::empty())
            .expect("test request must build");
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok".to_string()),
            "a non-bearer Authorization ('{non_bearer}') must fall through to x-api-key"
        );
    }
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_goog_api_key() {
    // Symmetric to the x-api-key case: a present-but-non-bearer Authorization must fall through
    // PAST the (empty/absent) x-api-key carrier all the way to x-goog-api-key, locking the full
    // multi-scheme chain. A regression short-circuiting on the non-bearer Authorization, or one
    // that stopped after x-api-key, would be caught here.
    let req = Request::builder()
        .uri("/v1/messages")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA.../svc/aws4_request",
        )
        .header("x-goog-api-key", "goog-tok")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("goog-tok".to_string()),
        "a non-bearer Authorization must fall through to x-goog-api-key"
    );
}

// THE VENDOR-SHAPED AUTH-FAILURE TESTS live in the LLM plane, in `crates/busbar-llm/src/engine/
// tests/auth_native_envelope_tests.rs`. They pin what each LLM dialect's registered
// writer answers a bad credential with (the residual dialect a path resolves to, the per-dialect
// envelope / status / headers / copy, the router-ingress coverage) — the plane's behaviour reached
// through core's neutral resolver — so they run in the plane's own test target, the one binary
// with a single `busbar_kernel` and the real dialect registrations.

/// A deployment with no plane mounted, so every path below resolves through the residual arm.
fn residual_app() -> std::sync::Arc<crate::state::App> {
    crate::test_support::TestApp::new().build()
}

/// Decode the JSON body of an `unauthorized_response`. Synchronously drains the (in-memory,
/// already-complete) body — no network, no runtime needed.
fn decode_body(resp: Response) -> serde_json::Value {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test body must collect")
    });
    serde_json::from_slice(&bytes).expect("auth-failure body must be valid JSON")
}

/// Recursively collect every JSON string value reachable in `v` (object values, array elements,
/// and the leaf string itself), so a leak-vocabulary scan covers the message regardless of the
/// field the per-protocol writer placed it on (`error.message` / top-level `message` / `__type`).
fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        serde_json::Value::Object(o) => o.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

#[test]
fn test_unauthorized_body_carries_no_busbar_vocabulary() {
    // Regression for the auth-model leak: the auth-failure wire body must NOT name busbar's
    // internal auth concepts. Previously the literal "invalid or disabled virtual key" (and
    // "unauthorized" / "admin unauthorized") were reflected verbatim into the native error body
    // — a deterministic proxy tell that also discloses the per-virtual-key enable/disable model.
    // Sweep the ingress path shapes (incl. the admin-looking and unknown-path fallbacks) through
    // `unauthorized_response` itself and assert no leaked token appears anywhere in the JSON. The
    // plane's twin, busbar-llm `engine/tests/auth_native_envelope_tests.rs`, sweeps the same
    // data-plane paths through the live stack, including the one path shape named after its dialect.
    const FORBIDDEN: &[&str] = &[
        "virtual key",
        "client token",
        "client_token",
        "allowlist",
        "disabled",
        "passthrough",
        "busbar",
        "unauthorized", // busbar-internal reason wording, not vendor copy
        "admin",
    ];
    let paths = [
        "/v1beta/models/x:generateContent",
        "/pa/v1/messages",
        "/v1/chat/completions",
        "/v2/chat",
        "/model/vendor.model/converse",
        "/api/v1/admin/keys",    // admin path → inferred-proto fallback
        "/totally/unknown/path", // unknown → fallback
    ];
    for path in paths {
        let body = decode_body(unauthorized_response(&residual_app(), path));
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
fn test_extract_admin_header_token_empty_filtered() {
    // A present-but-blank `x-admin-token` must be treated as
    // ABSENT, mirroring the empty-filter `extract_client_token` applies to the vendor carriers.
    // The OLD code mapped a blank header to `Some("")` (no `.filter(|t| !t.is_empty())`), so this
    // unit test fails against it; the filtered helper now yields `None`.
    let blank = req_with(X_ADMIN_TOKEN, "");
    assert_eq!(
        admin_carriers(blank.headers()).1,
        None,
        "a blank x-admin-token must be treated as absent (None)"
    );

    // A whitespace-only value is NOT blank (it is a non-empty string); it is preserved verbatim
    // and will simply fail the constant-time compare downstream — the filter is empty-only, not a
    // trim, matching extract_client_token's carrier filter exactly.
    let present = req_with(X_ADMIN_TOKEN, "admintok");
    assert_eq!(
        admin_carriers(present.headers()).1,
        Some("admintok".to_string()),
        "a non-empty x-admin-token must be carried verbatim"
    );

    // Absent header → None (unchanged).
    let absent = Request::builder()
        .uri("/api/v1/admin/keys")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(admin_carriers(absent.headers()).1, None);
}

/// The `admin.forbidden` audit is bounded by the SAME per-(principal, window) counter
/// the mutation rate limiter already uses, not written unconditionally. Drives 50 forbidden GETs
/// (an UNBOUND role, so `admin_scope_for` returns `Grants::default()` and even a read is 403) from
/// ONE principal and asserts the durable-write-through only fired once or twice, not 50 times.
#[tokio::test]
async fn forbidden_admin_requests_audit_once_per_window() {
    use crate::test_support::TestApp;

    crate::metrics::init();

    // Unique per test run so concurrently-running tests sharing the process-global `AUDIT` ring
    // cannot be counted here, and this test's own records cannot be miscounted by a sibling.
    let unique = format!(
        "unbound-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let principal_id = format!("test:{unique}");

    let app = TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for _ in 0..50 {
        let r = client
            .get(&url)
            .bearer_auth(format!("grp:{unique}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            403,
            "an unbound role must be forbidden even on a GET (Grants::default() never allows \
             ReadOnly), got {}",
            r.status()
        );
    }

    let n = crate::audit_ring::AUDIT
        .export()
        .iter()
        .filter(|e| e.action == "admin.forbidden" && e.principal == principal_id)
        .count();
    assert!(
        (1..=2).contains(&n),
        "expected 1 or 2 durable audit records for 50 forbidden requests from one principal \
         (bounded by the per-(principal, window) counter, with <=2 absorbing a window-boundary \
         straddle), got {n}"
    );

    handle.abort();
}

// ── 1.5.2 admin-plane OIDC: scope collapse authorization + external admin-module dispatch/offload ──

/// A test-only external admin module that SLEEPS on the (blocking-pool) thread before returning —
/// stands in for a wedged admin IdP doing blocking JWKS/introspection I/O. Returns `Pass` (so the
/// chain fail-closed-denies) once it wakes. Injected via `TestApp::admin_module` as an external
/// module, so the admin middleware OFFLOADS its call off the reactor.
struct SleepingAdminModule(std::time::Duration);
impl crate::auth::AuthModule for SleepingAdminModule {
    fn name(&self) -> &'static str {
        "slow-oidc"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> crate::auth::AuthVerdict {
        std::thread::sleep(self.0);
        crate::auth::AuthVerdict::Pass
    }
}

/// A test-only external admin module that identifies a ROLELESS principal carrying the reserved
/// operator id `"admin"` — the privilege-escalation probe: an external module returning the
/// operator id must NOT reach `Grants::of(Full)`.
struct RolelessAdminModule;
impl crate::auth::AuthModule for RolelessAdminModule {
    fn name(&self) -> &'static str {
        "ext-admin"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> crate::auth::AuthVerdict {
        crate::auth::AuthVerdict::Identify(Principal::from_id("admin"))
    }
}

/// Serve `app` on an ephemeral port; returns (base_url, join handle). Caller aborts the handle.
async fn serve_app(
    app: std::sync::Arc<crate::state::App>,
) -> (String, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

/// A `full` admin binding satisfies a MUTATION endpoint (now `Full` after the scope collapse): a
/// `POST` is admitted past the authorization gate (not 401/403). The identifying module is the
/// `test-scope-module` external-admin stand-in.
#[tokio::test]
async fn admin_plugin_full_binding_allows_mutation() {
    crate::metrics::init();
    let rb = bindings_for(
        "test-scope-module",
        &[("minters", binding(None, None, Some("full")))],
    );
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .role_bindings(rb)
        .build();
    // An external module defaults to a `read-only` ceiling; lift it to `full` so the full binding is
    // not capped below the mutation scope (the cap is exercised separately).
    let a = std::sync::Arc::get_mut(&mut app).expect("unshared App Arc");
    a.auth_scope_caps
        .insert("test-scope-module".to_string(), "full".to_string());
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();
    // A mutation endpoint (POST /hooks is now Full). Full grant ⇒ authorization passes; the empty
    // body then 400s at the handler — anything but 401/403 proves the scope gate admitted it.
    let r = client
        .post(format!("{base}/api/v1/admin/hooks"))
        .bearer_auth("grp:minters")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_ne!(r.status().as_u16(), 401, "full binding must authenticate");
    assert_ne!(
        r.status().as_u16(),
        403,
        "full binding must satisfy the Full mutation scope, got {}",
        r.status()
    );
    handle.abort();
}

/// A `read-only` admin binding: a `GET` is admitted (ReadOnly), a mutating `POST` is FORBIDDEN (403,
/// the frozen forbidden envelope) — the 1.5.2 collapse makes every mutation `Full`, which a
/// read-only grant never satisfies.
#[tokio::test]
async fn admin_plugin_readonly_binding_get_ok_post_403() {
    crate::metrics::init();
    let rb = bindings_for(
        "test-scope-module",
        &[("viewers", binding(None, None, Some("read-only")))],
    );
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .role_bindings(rb)
        .build();
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();
    let get = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("grp:viewers")
        .send()
        .await
        .unwrap();
    assert_ne!(
        get.status().as_u16(),
        403,
        "read-only binding must satisfy a GET (ReadOnly), got {}",
        get.status()
    );
    assert_ne!(
        get.status().as_u16(),
        401,
        "read-only binding authenticates"
    );
    let post = client
        .post(format!("{base}/api/v1/admin/hooks"))
        .bearer_auth("grp:viewers")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status().as_u16(),
        403,
        "read-only binding must NOT satisfy a Full mutation, got {}",
        post.status()
    );
    let body = post.text().await.unwrap();
    assert!(
        body.contains("\"forbidden\""),
        "403 must carry the frozen forbidden envelope: {body}"
    );
    handle.abort();
}

/// The module `max_admin_scope: read-only` ceiling CAPS a `full` binding down to read-only: a `POST`
/// (Full) is 403 even though the role binds `full`, because the identifying module's ceiling meets it
/// down to read-only (`Grants::capped_by`).
#[tokio::test]
async fn admin_max_admin_scope_caps_binding() {
    crate::metrics::init();
    let rb = bindings_for(
        "test-scope-module",
        &[("ops", binding(None, None, Some("full")))],
    );
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .role_bindings(rb)
        .build();
    let a = std::sync::Arc::get_mut(&mut app).expect("unshared App Arc");
    a.auth_scope_caps
        .insert("test-scope-module".to_string(), "read-only".to_string());
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();
    let post = client
        .post(format!("{base}/api/v1/admin/hooks"))
        .bearer_auth("grp:ops")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status().as_u16(),
        403,
        "a read-only ceiling must cap a full binding below the Full mutation scope, got {}",
        post.status()
    );
    handle.abort();
}

/// An external admin module returning the reserved operator id `"admin"` ROLELESS must fall
/// to `Grants::default()` — denied even on a GET (never `Grants::of(Full)`, which is gated on the
/// compiled `ADMIN_TOKENS_PRINCIPAL_ID`, not the string id). Driven through the offloaded plugin
/// dispatch path.
#[tokio::test]
async fn roleless_external_admin_principal_denied() {
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext-admin".to_string()])
        .admin_module("ext-admin", Box::new(RolelessAdminModule))
        .build();
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();
    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("anything")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "a roleless external principal id 'admin' must get Grants::default() (403), never Full; got {}",
        r.status()
    );
    handle.abort();
}

/// A wedged (sleeping) external admin module must NOT stall the reactor — it is OFFLOADED to
/// the blocking pool, so `/healthz` (and a concurrent admin request) stay responsive while it sleeps.
#[tokio::test]
async fn admin_offload_does_not_stall_healthz() {
    crate::metrics::init();
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["slow-oidc".to_string()])
        .admin_module(
            "slow-oidc",
            Box::new(SleepingAdminModule(std::time::Duration::from_millis(800))),
        )
        .build();
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();

    // Kick off an admin request that will OFFLOAD and sleep 800ms on a blocking thread.
    let admin_url = format!("{base}/api/v1/admin/keys");
    let c2 = client.clone();
    let admin = tokio::spawn(async move {
        c2.get(&admin_url)
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
    });
    // Give it a moment to enter the offloaded blocking sleep.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // /healthz must RESPOND PROMPTLY — the reactor is NOT parked on the sleeping module. The status
    // reflects app HEALTH (a lane-less test fixture reports 503), which is orthogonal to the offload;
    // the invariant under test is that a response arrives at all, fast, while the admin module sleeps.
    let start = std::time::Instant::now();
    let hz = client.get(format!("{base}/healthz")).send().await.unwrap();
    let elapsed = start.elapsed();
    assert!(
        hz.status().as_u16() == 200 || hz.status().as_u16() == 503,
        "/healthz must return a health verdict (200/503), not hang, while an admin module sleeps; \
         got {}",
        hz.status()
    );
    assert!(
        elapsed < std::time::Duration::from_millis(400),
        "/healthz stalled for {elapsed:?} behind a sleeping admin module — the chain was not \
         offloaded off the reactor"
    );

    // The offloaded admin request still completes (fail-closed 401: the sleeper returns Pass ⇒ the
    // non-empty chain denies).
    let r = admin.await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "a sleeping admin module that ultimately Passes fail-closed-denies (401), got {}",
        r.status()
    );
    handle.abort();
}

/// THE AUDIENCE-BOUND PLANE BOUNDARY end-to-end through the real router + `auth_middleware` in
/// GOVERNANCE mode (1.6.0): an AUDIENCE-BOUND token whose `sub` is a
/// fully valid enabled binding must be rejected 401 on the residual data plane - both a proxy
/// ingress route (`/pa/v1/messages`) and a chain-verdict-only route (`/stats`, which admits on the
/// chain verdict alone and so shows the blast radius is EVERY key-authenticated route, not just
/// the proxy ones) - while the sibling PLAIN token for the same binding is admitted. Before the
/// boundary, serde ignored the unknown `a` claim and an audience-bound token was silently a full
/// data-plane key.
/// (The full router-table-enumerated ratchet lands with the P2 core route-auth table, which is
/// what makes every mounted route enumerable; these two routes pin the two admission shapes.)
#[tokio::test]
async fn test_audience_bound_token_is_rejected_on_the_data_plane() {
    use crate::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call is expected on the 401 paths; the plain-token /stats control makes no
    // upstream call either.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (key, plain_token) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "audience-agent".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();

    // Mint the audience-bound sibling for the SAME sub + generation with the same signer key.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
    let generation = verifier
        .verify(plain_token.expose_secret().as_str(), 1_000_000_000, None)
        .expect("plain claims")
        .generation;
    let bound_token = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        "https://busbar.example.com/rpc",
        Some("client-1"),
    );

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Audience-bound token on the proxy ingress: 401.
    let r = client
        .post(format!("http://{addr}/pa/v1/messages"))
        .header("authorization", format!("Bearer {bound_token}"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "audience-bound token must be rejected on the data-plane ingress"
    );

    // Audience-bound token on a chain-verdict-only route: 401.
    let r = client
        .get(format!("http://{addr}/stats"))
        .header("authorization", format!("Bearer {bound_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "audience-bound token must be rejected on /stats (chain-verdict-only admission)"
    );

    // Control: the PLAIN sibling for the same binding is admitted on /stats.
    let r = client
        .get(format!("http://{addr}/stats"))
        .header(
            "authorization",
            format!("Bearer {}", plain_token.expose_secret()),
        )
        .send()
        .await
        .unwrap();
    assert_ne!(
        r.status().as_u16(),
        401,
        "the plain data-plane sibling must still be admitted"
    );

    handle.abort();
    server.shutdown().await;
}

/// Regression for the empty-token governance bypass: the governance branch
/// must reject a request that presents NO credential BEFORE calling `gov.lookup`, rather than
/// looking up `sha256("")`. We deliberately seed a virtual key whose `generation_hash == sha256("")` —
/// the pathological state (reachable via direct DB writes / a future seeding path that
/// bypasses `generate_secret`) — and confirm an unauthenticated request
/// is STILL rejected 401 instead of resolving to that key. Before the fix, the no-token request
/// would call `gov.lookup("")`, match this enabled key, and be admitted unauthenticated.
#[tokio::test]
async fn test_governance_rejects_empty_token_even_if_empty_secret_key_exists() {
    use crate::governance::{GovState, MemoryStore, RecordStore, ScopeRef, VirtualKey};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call should happen — auth must reject before routing.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    // The pathological key: its hash is sha256("") — what an empty-token lookup would compute.
    store
        .put_key(&VirtualKey {
            id: "empty".to_string(),
            generation_hash: busbar_contract::redacted::sha256_hex(b""),
            name: "empty".to_string(),
            allowed_scopes: Some(vec![ScopeRef::pool("pa")]),
            enabled: true,
            created_at: 0,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        })
        .unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // No credential at all → must be 401 (NOT admitted by the sha256("") key).
    let r_none = client.post(&url).body(body.clone()).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "an unauthenticated request must be rejected even when a key hashing the empty secret \
             exists in the store (got {})",
        r_none.status()
    );

    // A present-but-empty x-api-key must also reject (empty carrier is treated as absent).
    let r_empty = client
        .post(&url)
        .header("x-api-key", "")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_empty.status().as_u16(),
        401,
        "a present-but-empty credential must be rejected (got {})",
        r_empty.status()
    );

    handle.abort();
    server.shutdown().await;
}

#[test]
fn test_auth_middleware_debug_redacts_tokens() {
    // `AuthMiddleware`'s manual `Debug` must expose only shape (chain length + keys flag), never
    // any credential material. There are no static client tokens anymore; the invariant is that ONLY
    // the whitelisted shape fields appear, so a future field holding a secret cannot leak through a
    // derived Debug. (1.5.3: the upstream-credential MODE is no longer on the middleware at all — it
    // moved to the `pools:` section — so it is no longer part of this shape.)
    let cfg = chain_cfg(&["keys", "test-groups-module"]);
    let mw = AuthMiddleware::new_builtin(&cfg);
    let dbg = format!("{mw:?}");
    assert!(
        dbg.contains("chain_len"),
        "AuthMiddleware Debug should report the chain length: {dbg}"
    );
    assert!(
        dbg.contains("keys_in_chain"),
        "AuthMiddleware Debug should report the keys flag: {dbg}"
    );
    // Nothing beyond the three shape fields is printed (the struct formatter would name any
    // additional field before its value).
    for forbidden in ["token", "secret", "credential"] {
        assert!(
            !dbg.to_ascii_lowercase()
                .replace("keys_in_chain", "")
                .contains(forbidden),
            "AuthMiddleware Debug printed an unexpected field '{forbidden}': {dbg}"
        );
    }
}

#[test]
fn test_caller_token_debug_redacts_value() {
    // `CallerToken` wraps a caller credential threaded into request extensions. Its manual
    // `Debug` must never print the token value (a derived `Debug` would). Present vs. absent is
    // reported; the secret itself is not.
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

// ─────────────────────────────────────────────────────────────────────────────
// BACK-COMPAT REGRESSION: governance is ALWAYS constructed (RAM store by default), but must be
// INERT until an admin token is configured. A legacy deploy that never opted into governance (no
// admin token, no minted keys) must behave EXACTLY as it did when `governance:` defaulted to
// disabled: the static `auth.chain` gates ingress and inference succeeds. These pin that the
// on-by-default governance engine does NOT silently supersede the static chain / open relay.
// See `auth/mod.rs`: the vkey-resolution branch is gated on `admin_token_hash().is_some()`.
// ─────────────────────────────────────────────────────────────────────────────

/// (d) WITH admin token but the request lacks any virtual key: even with an OPEN static chain,
/// active governance still requires a vkey and rejects the tokenless request. This is the
/// documented "governance supersedes the open relay" behaviour — preserved when active.
#[tokio::test]
async fn test_governance_active_with_admin_token_rejects_missing_vkey() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call should happen — auth must reject before routing.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        // Open static chain — but active governance supersedes it.
        .upstream_creds(crate::auth::UpstreamCreds::Own)
        .keys_chain()
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // No virtual key under active governance → 401, even with an open static chain.
    let r_none = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "active governance must require a virtual key even behind an open static chain (got {})",
        r_none.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// The module `max_admin_scope` ceiling (App.auth_scope_caps) still caps what role_bindings
/// grant, exercised through `dry_run_admin_scope` (the same chain -> bindings -> cap pipeline
/// the admin middleware runs):
///   - an external module DEFAULTS to a read-only ceiling, so a full binding is capped;
///   - an explicit `max_admin_scope: full` cap lifts the ceiling;
///   - module scoping holds through the full stack: a binding under another module's table
///     earns the identified principal nothing;
///   - a credential no module identifies is denied outright.
#[test]
fn test_admin_scope_cap_ceilings_external_module() {
    use crate::admin::v1::contract::{Grants, Scope};
    crate::metrics::init();

    let mk_app = |cap: Option<&str>, bind_module: &str| {
        let mut app = crate::test_support::TestApp::new().build();
        let a = std::sync::Arc::get_mut(&mut app).expect("freshly built App Arc is unshared");
        a.admin_chain = vec!["test-scope-module".to_string()];
        a.role_bindings = bindings_for(bind_module, &[("ops", binding(None, None, Some("full")))]);
        if let Some(c) = cap {
            a.auth_scope_caps
                .insert("test-scope-module".to_string(), c.to_string());
        }
        app
    };

    // Default ceiling for an external module is read-only: the full binding is capped.
    let app = mk_app(None, "test-scope-module");
    assert_eq!(
        dry_run_admin_scope(&app, &admin_headers(Some("grp:ops"), None)),
        Grants::of(Scope::ReadOnly),
        "an external module without an explicit cap must be ceilinged to read-only"
    );

    // Explicit max_admin_scope: full lifts the ceiling; the full binding now lands.
    let app = mk_app(Some("full"), "test-scope-module");
    assert_eq!(
        dry_run_admin_scope(&app, &admin_headers(Some("grp:ops"), None)),
        Grants::of(Scope::Full),
        "an explicit full cap must let the full binding through"
    );

    // Module scoping through the full stack: the binding lives under ANOTHER module's table, so
    // the principal (identified by test-scope-module) earns no scope at all.
    let app = mk_app(Some("full"), "other-module");
    assert!(
        dry_run_admin_scope(&app, &admin_headers(Some("grp:ops"), None)) == Grants::default(),
        "a binding under another module's table must grant nothing"
    );

    // A credential no chain module identifies: denied (fail closed).
    let app = mk_app(Some("full"), "test-scope-module");
    assert!(
        dry_run_admin_scope(&app, &admin_headers(Some("not-a-grp"), None)) == Grants::default()
    );
}

/// AF1 (security-visibility): an EMPTY admin chain is the anonymous OPEN dev posture — a property of
/// the CHAIN, not a grant any caller earned. `dry_run_admin_scope` MUST NOT report it as `Full`
/// (letting it fall through to `admin_scope_for(None, None)` would): that masks the fail-open from
/// the `PUT /api/v1/admin/admin-auth` lock-out guard (`survives = dry_run(..).contains(Full)`) and
/// would let the admin API be swung open to the whole network on one unnoticed call. The dry-run
/// reports NO earned grant instead, so the guard refuses and the open posture stays a config.yaml +
/// restart opt-in.
#[test]
fn test_dry_run_empty_admin_chain_is_not_full() {
    use crate::admin::v1::contract::{Grants, Scope};
    crate::metrics::init();

    let mut app = crate::test_support::TestApp::new().build();
    let a = std::sync::Arc::get_mut(&mut app).expect("freshly built App Arc is unshared");
    a.admin_chain = vec![]; // the empty / open posture

    // No admin credential presented: an empty chain earns nothing (NOT Full).
    let g = dry_run_admin_scope(&app, &admin_headers(None, None));
    assert!(
        !g.contains(Scope::Full),
        "an empty admin_auth chain must NOT dry-run to Full — that masks the fail-open the \
         PUT /admin/admin-auth lock-out guard reads"
    );
    assert_eq!(
        g,
        Grants::default(),
        "an empty chain is reported as no earned grant, never full"
    );

    // ...and even WITH an arbitrary credential waved, the empty chain still earns no Full: the
    // (absent) chain is what decides, not what the caller presented.
    assert!(
        !dry_run_admin_scope(
            &app,
            &admin_headers(Some("anything"), Some("x-admin-token"))
        )
        .contains(Scope::Full),
        "an empty chain must not grant Full to any presented credential"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// 1.5.2 DATA-PLANE / ADMIN-TOKEN DECOUPLING.
// The admin token no longer gates the data plane; admission is decided SOLELY by the chain shape.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Local helper: serve a router on an ephemeral port, returning (addr, join handle).
async fn dp_serve(
    app: std::sync::Arc<crate::state::App>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// A governance engine (admin token set) with ONE enabled, pool-`pa` virtual key. Returns (gov, secret).
fn dp_gov_with_key() -> (std::sync::Arc<crate::governance::GovState>, String) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = std::sync::Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (_k, secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    (gov, secret.expose_secret().as_str().to_string())
}

fn dp_ok_state() -> std::sync::Arc<crate::test_support::MockServerState> {
    use crate::test_support::{MockResponse, MockServerState};
    let state = std::sync::Arc::new(MockServerState::new());
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: serde_json::json!({
                "id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    state
}

/// `chain:[keys]` + a DISABLED vkey → 401 (disabled ⇒ Reject, never a synth re-admit).
#[tokio::test]
async fn test_1_5_2_keys_chain_disabled_vkey_rejected() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let key_id = gov.all_keys().unwrap()[0].id.clone();
    gov.update_key(&key_id, Some(false), None).unwrap(); // freeze it
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .bearer_auth(&secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "a disabled vkey must be rejected (never re-admitted via synth)"
    );
    handle.abort();
    server.shutdown().await;
}

/// The `keys` ENGINE ARM resolves the vkey (Identified{resolved:Some}); no verdict of it is ever
/// cached (revocation stays per-request). Before 1.5.2 no keys engine arm / no `resolved` field
/// existed at all.
#[test]
fn test_1_5_2_keys_arm_resolves_the_vkey() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    crate::metrics::init();
    let store = std::sync::Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[9u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap();
    let (_k, secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "ce".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = secret.expose_secret().as_str();
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["keys"]));
    let now = busbar_kernel::store::now();
    let verdict = mw.run_chain_with(Some(secret), Some(&gov), now, None);
    assert!(
        matches!(
            verdict,
            ChainVerdict::Identified {
                resolved: Some(_),
                ..
            }
        ),
        "the keys arm must resolve the vkey"
    );
}

/// `chain: [keys]` is NOT an open front door. `keys` is engine-handled and installs no boxed
/// module, so the boxed chain stays empty — but the operator asked for authentication and got it.
/// Reading emptiness alone reports the door open while key auth is enforcing, and
/// `Root::admin_grant` turns that report into `VerbScope::Full` for every caller. The construction
/// path already spells the predicate correctly (`chain.is_empty() && !keys_in_chain`); this pins
/// the accessor to the same rule.
#[test]
fn a_keys_only_chain_is_not_an_open_front_door() {
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["keys"]));
    assert!(mw.keys_in_chain, "precondition: keys sets the flag");
    assert!(
        mw.chain_names().is_empty(),
        "precondition: keys installs no boxed module"
    );
    assert!(
        !mw.is_open(),
        "chain: [keys] authenticates, so the front door is CLOSED — reporting it open grants \
         VerbScope::Full to every caller at Root::admin_grant"
    );

    // The genuinely open posture still reads open.
    let none = AuthMiddleware::new_builtin(&crate::config::AuthCfg::default_none());
    assert!(none.is_open(), "no module and no keys arm IS the open door");

    // keys + a boxed module: closed by both halves.
    let both = AuthMiddleware::new_builtin(&chain_cfg(&["keys", "test-groups-module"]));
    assert!(!both.is_open(), "a boxed module closes the door regardless");
}

/// THE OPERATOR CREDENTIAL, as the auth axis answers it: with no row under the operator credential's
/// key, the registry opens nothing — the credential is `Unanswered`, and the admin chain defers it
/// (and, alone, denies). How an opened module judges the two carriers is the authenticate step's
/// (the authenticate step's own `operator` tests).
#[test]
fn the_operator_credential_opens_from_the_axis() {
    use crate::auth::{open_operator, OperatorCredential};
    let digest = busbar_contract::redacted::sha256_hex(b"tok");
    // This crate's test binary links no auth row, so its linked registry has none to open.
    let linked = std::sync::Arc::new(crate::preflight::linked().expect("the linked registry"));
    let none = Default::default();
    let open = |digest| open_operator(&linked, digest, &none).expect("opens");
    assert!(matches!(
        *open(Some(digest)),
        OperatorCredential::Unanswered
    ));
    assert!(matches!(*open(None), OperatorCredential::Unanswered));
}

/// TEST-ONLY: a request's head presenting `bearer` as its Bearer and `header` on the second admin
/// carrier.
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

/// TEST-ONLY: the admin chain as the synchronous probe walks it (the sync [`admin_door`]'s walk),
/// over the two admin carriers. A chain that cannot be judged on the spot reads `Denied`.
pub(super) fn run_admin_chain_on(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> (ChainVerdict, Option<busbar_contract::authz::Scope>) {
    let headers = admin_headers(bearer, header);
    let walk = std::pin::pin!(run_admin_chain(app, "GET", "/", &headers, true));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(walk, &mut cx) {
        std::task::Poll::Ready(Ok(answer)) => answer,
        std::task::Poll::Ready(Err(_)) | std::task::Poll::Pending => (ChainVerdict::Denied, None),
    }
}

/// An operator credential's door stand-in: answers `verified` to every verify, on the spot and
/// submitted.
struct OperatorDouble(busbar_contract::auth_calls::Verified);

struct OperatorAnswer(Option<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for OperatorAnswer {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl busbar_contract::auth_calls::Verifying for OperatorAnswer {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.take()
    }
}

impl busbar_contract::auth_calls::AuthCalls for OperatorDouble {
    fn name(&self) -> &str {
        "operator-double"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.0.clone().into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(OperatorAnswer(Some(self.0.clone().into())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// An app whose admin chain is the operator credential alone, its door answering `verified`.
pub(super) fn operator_app(
    verified: busbar_contract::auth_calls::Verified,
) -> std::sync::Arc<crate::state::App> {
    let op = crate::config::operator_provider();
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec![op.to_string()])
        .build();
    let operator = Operator::open(
        op,
        std::iter::empty(),
        true,
        Some("digest".to_string()),
        |_| Ok(std::sync::Arc::new(OperatorDouble(verified))),
    )
    .expect("opens");
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules: std::collections::HashMap::new(),
        operator,
    });
    app
}

/// The admin chain of [`operator_app`] over `verified`, awaited, for a request presenting a Bearer.
async fn walk(verified: busbar_contract::auth_calls::Verified) -> AdminChainAnswer {
    let app = operator_app(verified);
    let headers = admin_headers(Some("tok"), None);
    run_admin_chain(&app, "GET", "/", &headers, false).await
}

/// THE ADMIN DOOR ON THE OPERATOR'S DOOR (ARCHITECT ruling 2026-09-30, AUTH-DOOR Q1): the operator
/// credential's verify is AWAITED, and its answer is read apart — an identity admits, a bad
/// credential is the 1.5.5 refusal (Denied, 401), and an overloaded verifier or one that answered no
/// verdict is 503 `unavailable`, never a 401. RED: were an overloaded or failed verify folded into a
/// bad credential (as the cold lane did), the two `Err` arms below would read `Ok(Denied)`.
#[tokio::test]
async fn the_operator_door_is_awaited_and_its_outage_is_not_a_bad_credential() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    let identity = Verified::Identity(VerifiedIdentity {
        subject: "admin".into(),
        ..VerifiedIdentity::default()
    });
    assert!(matches!(
        walk(identity).await,
        Ok((ChainVerdict::Identified { .. }, _))
    ));
    assert!(matches!(
        walk(Verified::Reject).await,
        Ok((ChainVerdict::Denied, None))
    ));
    assert!(matches!(
        walk(Verified::Pass).await,
        Ok((ChainVerdict::Denied, None))
    ));
    assert_eq!(
        walk(Verified::Overloaded).await.err(),
        Some(AdminUnavailable::Overloaded)
    );
    assert_eq!(
        walk(Verified::Failed).await.err(),
        Some(AdminUnavailable::Outage)
    );
}

/// The 503 an admin chain that could not be judged answers: the frozen v1 envelope's `unavailable`.
#[tokio::test]
async fn an_unjudged_admin_chain_answers_503_unavailable() {
    let mut bodies = Vec::new();
    for why in [AdminUnavailable::Overloaded, AdminUnavailable::Outage] {
        let resp = admin_unavailable_response(why);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        bodies.push(body);
    }
    assert_eq!(
        bodies[0], bodies[1],
        "an outage answers the overloaded verifier's bytes: no new customer string"
    );
    let v: serde_json::Value = serde_json::from_slice(&bodies[0]).expect("json");
    assert_eq!(v["error"]["code"], "unavailable");
}

/// The synchronous admin door (the dry run, the root's admin unit) PROBES the operator credential
/// (`verify_now`): an overloaded verifier grants nothing, and the door is `Denied`, fail-closed.
#[test]
fn the_sync_admin_door_probe_fails_closed_when_the_operator_verifier_is_overloaded() {
    let app = operator_app(busbar_contract::auth_calls::Verified::Overloaded);
    let headers = admin_headers(Some("tok"), None);
    assert!(dry_run_admin_scope(&app, &headers) == busbar_contract::authz::Grants::default());
    assert_eq!(admin_door(&app, "GET", "/", &headers), AdminDoor::Denied);
}

/// The operator credential's door reads the request's head: its method, its path and query apart,
/// its authority off the `host` line, and every field line as presented.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// L2-AUTH-1 (ARCHITECT ruling 2026-10-03): a data-plane door that answers no verdict, or whose
// `max_inflight` is full, is a REJECT on the data plane — 1.5.5's 401, never a pass to the next
// position and never a new status. (The admin chain keeps its ruled 503.)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A kind-neutral double of one opened auth instance that answers every `verify` with `verified`
/// (an overloaded verifier, or one that answered no verdict).
struct AnswersOnly(busbar_contract::auth_calls::Verified);

/// A `verify` answered before anything crossed.
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

impl busbar_contract::auth_calls::AuthCalls for AnswersOnly {
    fn name(&self) -> &str {
        "answers-only"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.0.clone().into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Answered(Some(self.0.clone().into())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// The chain `[answers-only door, test-groups stand-in]`: the second position identifies
/// `grp:<role>`, so a first position that PASSED would admit.
fn door_then_identifier(verified: busbar_contract::auth_calls::Verified) -> AuthMiddleware {
    let identifier = crate::auth::stand_in::InProcessAuth::new(Box::new(TestGroupsModule));
    AuthMiddleware::from_doors_for_test(vec![
        (
            "door".to_string(),
            std::sync::Arc::new(AnswersOnly(verified)) as std::sync::Arc<dyn AuthCalls>,
        ),
        (
            "test-groups-module".to_string(),
            std::sync::Arc::new(identifier),
        ),
    ])
}

/// An overloaded door and a door that answered no verdict each STOP the chain denied: the identifier
/// behind them is never reached (RED if either were read as a pass: the chain would admit).
#[tokio::test]
async fn a_data_plane_door_overloaded_or_without_a_verdict_denies_the_chain() {
    use busbar_contract::auth_calls::Verified;
    for verified in [Verified::Overloaded, Verified::Failed] {
        let auth = std::sync::Arc::new(door_then_identifier(verified.clone()));
        let verdict = AuthMiddleware::run_chain_on_request_path(
            &auth,
            Some("grp:admins".into()),
            ChainHead::default(),
            None,
            None,
        )
        .await;
        assert_eq!(
            verdict,
            ChainVerdict::Denied,
            "{verified:?} must deny, not pass"
        );
    }
}

/// On the wire: the request an overloaded (or verdict-less) data-plane door refuses is answered
/// with 1.5.5's 401, byte for byte the refusal an all-pass chain earns — no 503, no new body.
#[tokio::test]
async fn a_data_plane_door_overloaded_or_without_a_verdict_answers_the_1_5_5_401() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    use busbar_contract::auth_calls::Verified;
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let ask = |auth: AuthMiddleware| {
        let app = TestApp::new()
            .lane(
                LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"),
            )
            .pool("pa", &[(0, 1)])
            .auth(std::sync::Arc::new(auth))
            .build();
        async move {
            let (addr, handle) = dp_serve(app).await;
            let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
            let r = reqwest::Client::new()
                .post(format!("http://{addr}/pa/v1/messages"))
                .bearer_auth("not-a-credential-anyone-knows")
                .body(body)
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            let content_type = r
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or_default().to_string());
            let text = r.text().await.unwrap();
            handle.abort();
            (status, content_type, text)
        }
    };
    // The 1.5.5 refusal: a configured chain whose every position passed.
    let all_pass = ask(AuthMiddleware::new_builtin(&chain_cfg(&[
        "test-groups-module",
    ])))
    .await;
    assert_eq!(all_pass.0, 401, "the all-pass refusal: {all_pass:?}");
    for verified in [Verified::Overloaded, Verified::Failed] {
        let refused = ask(door_then_identifier(verified.clone())).await;
        assert_eq!(
            refused, all_pass,
            "{verified:?}: the 1.5.5 401, byte for byte"
        );
    }
    server.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// L2-AUTH-4 (ARCHITECT ruling 2026-10-03): admin_auth's EXTERNAL modules open on the auth axis.
// A door among them is awaited, lent the request's head and 1.5.5's candidate (`bearer.or(header)`),
// never cached by the kernel, and an overloaded or verdict-less door is the ruled 503.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// An external admin door that identifies `ext:<who>` only when the lent credential is `tok`, and
/// otherwise answers `otherwise`.
struct LentCredentialDoor(busbar_contract::auth_calls::Verified);

impl LentCredentialDoor {
    fn answer(
        &self,
        r: &busbar_contract::auth_calls::VerifyRequest,
    ) -> busbar_contract::auth_calls::VerifyAnswer {
        use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
        match r.credential.as_ref().map(|c| c.expose_secret().as_slice()) {
            Some(b"tok") => Verified::Identity(VerifiedIdentity {
                subject: "ext:who".into(),
                groups: vec!["ops".into()],
                ..VerifiedIdentity::default()
            })
            .into(),
            _ => self.0.clone().into(),
        }
    }
}

impl busbar_contract::auth_calls::AuthCalls for LentCredentialDoor {
    fn name(&self) -> &str {
        "lent-credential-door"
    }
    fn facts(&self) -> u32 {
        busbar_contract::abi::auth::FACT_CACHEABLE
    }
    fn verify_now(
        &self,
        r: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.answer(r))
    }
    fn verify(
        &self,
        r: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(OperatorAnswer(Some(self.answer(&r))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// An app whose admin chain is the external door `ext-door` alone (opened as a door: not cold).
fn external_door_app(
    otherwise: busbar_contract::auth_calls::Verified,
) -> std::sync::Arc<crate::state::App> {
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext-door".to_string()])
        .build();
    let mut modules = std::collections::HashMap::new();
    modules.insert(
        "ext-door".to_string(),
        AdminModule {
            calls: std::sync::Arc::new(LentCredentialDoor(otherwise)),
            cold: false,
        },
    );
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules,
        operator: Operator::new(crate::config::operator_provider()),
    });
    app
}

/// The external admin door judges the candidate it is lent — the Bearer, else the admin header, as
/// 1.5.5 handed an external module `bearer.or(header)` — awaited and on the spot; its identity is
/// never cached by the kernel (R3: a door caches inside itself, even one stating cacheable); an
/// overloaded door and one with no verdict are the ruled 503, a reject and a pass the 1.5.5 401.
#[tokio::test]
async fn an_external_admin_door_is_lent_the_candidate_and_its_outage_is_the_ruled_503() {
    use busbar_contract::auth_calls::Verified;
    for headers in [
        admin_headers(Some("tok"), None),
        admin_headers(None, Some("tok")),
    ] {
        let app = external_door_app(Verified::Reject);
        assert!(matches!(
            run_admin_chain(&app, "GET", "/", &headers, false).await,
            Ok((ChainVerdict::Identified { ref module, .. }, _)) if module == "ext-door"
        ));
        assert!(matches!(
            admin_door(&app, "GET", "/", &headers),
            AdminDoor::Identified(..)
        ));
    }
    let wrong = admin_headers(Some("not-tok"), None);
    for (otherwise, want) in [
        (Verified::Reject, Ok(())),
        (Verified::Pass, Ok(())),
        (Verified::Overloaded, Err(AdminUnavailable::Overloaded)),
        (Verified::Failed, Err(AdminUnavailable::Outage)),
    ] {
        let app = external_door_app(otherwise.clone());
        let got = run_admin_chain(&app, "GET", "/", &wrong, false).await;
        match want {
            Ok(()) => assert!(
                matches!(got, Ok((ChainVerdict::Denied, None))),
                "{otherwise:?}: the 1.5.5 refusal"
            ),
            Err(why) => assert_eq!(got.err(), Some(why), "{otherwise:?}: the ruled 503"),
        }
    }
}
