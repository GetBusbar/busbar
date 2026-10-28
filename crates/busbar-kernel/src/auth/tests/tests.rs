use super::*;
use busbar_contract::records::ScopeRef;

/// The protocol a test lane names. The kernel test binary registers no dialect (its built-ins are
/// the neutral `proto-*` set), so a lane's protocol here is a name nothing resolves, exactly as the
/// dialect word it replaces was: the neutral crate's tests spell no dialect.
const LANE_PROTOCOL: &str = "unregistered-lane-protocol";

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
        verbs: None,
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
    use busbar_contract::authz::{Grants, Scope};
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
// auth failure) to the retired engine crate's `src/engine/tests/auth_native_envelope_tests.rs`; its sibling
// `test_synth_amzn_request_id_is_uuid_v4` already lives in the retired engine crate beside that codec.

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

/// AN IDENTIFIED PRINCIPAL WITH NO GRANT IS REFUSED (owner-signed 2026-10-24, M30; 1.5.5 admitted it
/// ungoverned and booked its spend to `anonymous`). A roleless principal, a role principal under a
/// module with no `role_bindings` table, a roleless principal under a governed module, and an unbound
/// role under a governed module are all `NoGrant`. `Open` stays anonymous and a bound role earns its
/// key. RED against 1.5.5's three-part guard, which admitted the first three.
#[test]
fn an_identified_principal_with_no_grant_is_refused() {
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
            other => panic!(
                "{why}: refused NoGrant, got {:?}",
                other.map(|(_, gov)| gov.key.map(|k| k.id.clone()))
            ),
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

    // A bindings table for the module.
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

/// THE RULE AND 1.5.5'S GUARD SIDE BY SIDE (Q20, item 144): under `refuse_every` (shipped, M30) no
/// keyless principal is admitted, whatever its roles and whatever its module's bindings; 1.5.5's
/// three-part guard refused only roles under a module that has a table.
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
// `App::upstream_creds()` reads through `engine_tables_view()`, which only the REAL the retired engine crate
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

/// The operator credential's second carrier, as the linked operator plugin states it (test data:
/// the kernel names no credential line).
const X_ADMIN_TOKEN: &str = "x-admin-token";

/// The client token the default inbound style yields on `req` (a test binary's stand-in axis
/// answers the double's style: the linked header auth's three carriers, in 1.5.5 order).
fn extract(req: &Request<Body>) -> Option<String> {
    AuthMiddleware::new_builtin(&crate::config::AuthCfg::default_none())
        .extract_client_token(req.headers())
}

/// The admin candidate the operator credential's carriers yield on `headers` (the double's).
fn admin_candidate(headers: &HeaderMap) -> Option<String> {
    carried_credential(
        &header_names(&crate::test_support::outbound_auth::double_operator_carriers()),
        headers,
    )
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
    assert_eq!(extract(&req), Some("tok-abc".to_string()));
}

#[test]
fn test_extract_client_token_x_api_key() {
    // Anthropic SDK carrier: raw token, no scheme prefix.
    let req = req_with("x-api-key", "tok-x-api-key");
    assert_eq!(extract(&req), Some("tok-x-api-key".to_string()));
}

#[test]
fn test_extract_client_token_x_goog_api_key() {
    // Gemini SDK carrier: raw token, no scheme prefix.
    let req = req_with("x-goog-api-key", "tok-x-goog-api-key");
    assert_eq!(extract(&req), Some("tok-x-goog-api-key".to_string()));
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
    assert_eq!(extract(&req), Some("from-auth".to_string()));

    // Without Authorization, x-api-key wins over x-goog-api-key.
    let req = Request::builder()
        .uri("/v1/messages")
        .header("x-api-key", "from-x-api-key")
        .header("x-goog-api-key", "from-goog")
        .body(Body::empty())
        .unwrap();
    assert_eq!(extract(&req), Some("from-x-api-key".to_string()));
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
    assert_eq!(extract(&req), Some("tok-x-goog-api-key".to_string()));
}

#[test]
fn test_extract_client_token_none_when_no_carrier() {
    let req = Request::builder()
        .uri("/v1/messages")
        .body(Body::empty())
        .unwrap();
    assert_eq!(extract(&req), None);
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
            extract(&req),
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
        extract(&req),
        Some("goog-tok".to_string()),
        "a non-bearer Authorization must fall through to x-goog-api-key"
    );
}

// THE VENDOR-SHAPED AUTH-FAILURE TESTS live in the LLM plane, in the retired engine crate's `src/engine/
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
    // plane's twin, the retired engine crate `engine/tests/auth_native_envelope_tests.rs`, sweeps the same
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
        "/v1beta/models/x:verb", // a colon-verb path shape
        "/pa/v1/messages",
        "/v1/kind/action",
        "/v1/responses", // F25 row 65: the legacy sweep's dialect this list had dropped
        "/v2/chat",
        "/model/vendor.model/converse", // F25 row 65: the legacy sweep's converse path shape
        "/api/v1/admin/keys",           // admin path → inferred-proto fallback
        "/totally/unknown/path",        // unknown → fallback
    ];
    for path in paths {
        let body = decode_body(unauthorized_response(&residual_app(), path, None));
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
        admin_candidate(blank.headers()),
        None,
        "a blank x-admin-token must be treated as absent (None)"
    );

    // A whitespace-only value is NOT blank (it is a non-empty string); it is preserved verbatim
    // and will simply fail the constant-time compare downstream — the filter is empty-only, not a
    // trim, matching extract_client_token's carrier filter exactly.
    let present = req_with(X_ADMIN_TOKEN, "admintok");
    assert_eq!(
        admin_candidate(present.headers()),
        Some("admintok".to_string()),
        "a non-empty x-admin-token must be carried verbatim"
    );

    // Absent header → None (unchanged).
    let absent = Request::builder()
        .uri("/api/v1/admin/keys")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(admin_candidate(absent.headers()), None);
}

/// The `admin.forbidden` audit is bounded by the SAME per-(principal, window) counter
/// the mutation rate limiter already uses, not written unconditionally. Drives 50 forbidden GETs
/// (an UNBOUND role, so `admin_scope_for` returns `Grants::default()` and even a read is 403) from
/// ONE principal and asserts the durable-write-through only fired once or twice, not 50 times.
#[tokio::test]
async fn forbidden_admin_requests_audit_once_per_window() {
    use crate::test_support::TestApp;

    crate::snapshot::init();

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

    let n = crate::audit::auditlog::AUDIT_LOG
        .list_filtered(0, crate::audit_ring::MAX_AUDIT_ENTRIES, None, None)
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

// ── 1.5.2 admin-plane OIDC: scope collapse authorization + external admin-module dispatch ────────

/// A test-only external admin DOOR whose `verify` answers only after a delay, from a thread of its
/// own (the dispatcher worker the plugin runs on) — stands in for a wedged admin IdP doing
/// JWKS/introspection I/O. Answers `Pass` (so the chain fail-closed-denies) once it wakes; it never
/// answers on the spot.
struct SleepingAdminDoor(std::time::Duration);

/// A `verify` the plugin answers later, from its own thread.
struct AnsweredLater(tokio::sync::oneshot::Receiver<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for AnsweredLater {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::future::Future::poll(std::pin::Pin::new(&mut self.0), cx).map(|answer| {
            answer.unwrap_or_else(|_| busbar_contract::auth_calls::Verified::Failed.into())
        })
    }
}

impl busbar_contract::auth_calls::Verifying for AnsweredLater {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.try_recv().ok()
    }
}

impl busbar_contract::auth_calls::AuthCalls for SleepingAdminDoor {
    fn name(&self) -> &str {
        "slow-oidc"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let hold = self.0;
        std::thread::spawn(move || {
            std::thread::sleep(hold);
            let _ = tx.send(busbar_contract::auth_calls::Verified::Pass.into());
        });
        Box::new(AnsweredLater(rx))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
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
    crate::snapshot::init();
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
    crate::snapshot::init();
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
    crate::snapshot::init();
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
/// compiled `ADMIN_TOKENS_PRINCIPAL_ID`, not the string id). Driven through the
/// external-module dispatch path.
#[tokio::test]
async fn roleless_external_admin_principal_denied() {
    crate::snapshot::init();
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

/// A wedged (sleeping) external admin door must NOT stall the reactor — its `verify` is submitted
/// and AWAITED, so `/healthz` (and a concurrent admin request) stay responsive while it sleeps.
#[tokio::test]
async fn a_slow_admin_door_does_not_stall_healthz() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["slow-oidc".to_string()])
        .admin_door(
            "slow-oidc",
            std::sync::Arc::new(SleepingAdminDoor(std::time::Duration::from_millis(800))),
        )
        .build();
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();

    // Kick off an admin request whose door answers only after 800ms.
    let admin_url = format!("{base}/api/v1/admin/keys");
    let c2 = client.clone();
    let admin = tokio::spawn(async move {
        c2.get(&admin_url)
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
    });
    // Give it a moment to reach the door.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // /healthz must RESPOND PROMPTLY — the reactor is NOT parked on the sleeping module. The status
    // reflects app HEALTH (a lane-less test fixture reports 503), which is orthogonal to the door;
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
        "/healthz stalled for {elapsed:?} behind a sleeping admin door — the chain parked a \
         reactor worker instead of awaiting it"
    );

    // The awaited admin request still completes (fail-closed 401: the sleeper returns Pass ⇒ the
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

    crate::snapshot::init();

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
        .verify(
            plain_token.expose(&crate::seal::lend()).as_str(),
            1_000_000_000,
            None,
        )
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
            LaneSpec::new("test-model", LANE_PROTOCOL, &server.base_url())
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
            format!("Bearer {}", plain_token.expose(&crate::seal::lend())),
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

    crate::snapshot::init();

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
            LaneSpec::new("test-model", LANE_PROTOCOL, &server.base_url())
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

    crate::snapshot::init();

    // No upstream call should happen — auth must reject before routing.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .lane(
            LaneSpec::new("test-model", LANE_PROTOCOL, &server.base_url())
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
    use busbar_contract::authz::{Grants, Scope};
    crate::snapshot::init();

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
    use busbar_contract::authz::{Grants, Scope};
    crate::snapshot::init();

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
    (
        gov,
        secret.expose(&crate::seal::lend()).as_str().to_string(),
    )
}

fn dp_ok_state() -> std::sync::Arc<crate::test_support::MockServerState> {
    use crate::test_support::{MockResponse, MockServerState};
    let state = std::sync::Arc::new(MockServerState::new());
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            // A kind-neutral answer: the door refuses before any lane is dialled, so no dialect
            // ever reads it.
            body: serde_json::json!({"id": "r1", "answer": "hi"}),
        });
    }
    state
}

/// `chain:[keys]` + a DISABLED vkey → 401 (disabled ⇒ Reject, never a synth re-admit).
#[tokio::test]
async fn test_1_5_2_keys_chain_disabled_vkey_rejected() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::snapshot::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let key_id = gov.all_keys().unwrap()[0].id.clone();
    gov.update_key(&key_id, Some(false), None).unwrap(); // freeze it
    let app = TestApp::new()
        .lane(LaneSpec::new("m", LANE_PROTOCOL, &server.base_url()).api_key("up"))
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
    crate::snapshot::init();
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
    let secret = secret.expose(&crate::seal::lend()).as_str();
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
    let linked = crate::preflight::linked().expect("the linked registry");
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
/// over the two admin carriers.
pub(super) fn run_admin_chain_on(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> (ChainVerdict, Option<busbar_contract::authz::Scope>) {
    let headers = admin_headers(bearer, header);
    let mut carried = AdminCarried::default();
    let walk = std::pin::pin!(run_admin_chain(
        app,
        "GET",
        "/",
        &headers,
        true,
        &mut carried
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(walk, &mut cx) {
        std::task::Poll::Ready(answer) => answer,
        std::task::Poll::Pending => (ChainVerdict::Denied, None),
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
        &|m: &str| crate::config::names_operator(m),
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
    run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await
}

/// THE ADMIN DOOR ON THE OPERATOR'S DOOR: the operator credential's verify is AWAITED, and an
/// identity admits while a bad credential, a pass, an overloaded verifier and one that answered no
/// verdict are each 1.5.5's refusal (Denied, the 401). The admin-door 503 (Q134) is not a signed
/// accepted difference, so 1.5.5's answer stands. RED: an overloaded or failed verify read as a
/// pass would admit through a later module; read as an outage it would be a new status.
#[tokio::test]
async fn the_operator_door_is_awaited_and_an_unjudged_verify_is_the_1_5_5_refusal() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    let identity = Verified::Identity(VerifiedIdentity {
        subject: "admin".into(),
        ..VerifiedIdentity::default()
    });
    assert!(matches!(
        walk(identity).await,
        (ChainVerdict::Identified { .. }, _)
    ));
    for refused in [
        Verified::Reject,
        Verified::Pass,
        Verified::Overloaded,
        Verified::Failed,
    ] {
        assert_eq!(
            walk(refused.clone()).await,
            (ChainVerdict::Denied, None),
            "{refused:?}: 1.5.5's refusal"
        );
    }
}

/// On the wire: an operator-credential door that is overloaded, or answered no verdict, is answered
/// 1.5.5's admin 401, byte for byte the refusal a bad credential earns — no 503.
#[tokio::test]
async fn an_unjudged_operator_door_answers_the_1_5_5_admin_401() {
    use busbar_contract::auth_calls::Verified;
    crate::snapshot::init();
    let mut answers = Vec::new();
    for verified in [Verified::Reject, Verified::Overloaded, Verified::Failed] {
        let (base, handle) = serve_app(operator_app(verified)).await;
        let r = reqwest::Client::new()
            .get(format!("{base}/api/v1/admin/keys"))
            .bearer_auth("tok")
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        answers.push((status, r.text().await.unwrap()));
        handle.abort();
    }
    assert_eq!(answers[0].0, 401, "a bad credential is the admin 401");
    assert_eq!(
        answers[1], answers[0],
        "an overloaded verifier: the same bytes"
    );
    assert_eq!(
        answers[2], answers[0],
        "a verdict-less verifier: the same bytes"
    );
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
// L2-AUTH-1 (ARCHITECT ruling 2026-10-03): a data-plane door that answers no verdict is a REJECT
// on the data plane — 1.5.5's 401, never a pass to the next position. A door whose `max_inflight`
// is full stops the chain too, never a pass; the data plane answers it 503 with `Retry-After`
// (owner ruling Q134, 2026-10-07, which supersedes L2-AUTH-1 for that one answer).
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

/// Q134 (owner ruling 2026-10-07): the walk the data-plane middleware runs hands an overloaded
/// door back APART, so the middleware can answer it 503; a door with no verdict is still the
/// denial, and in neither case is the identifier behind it reached. RED: were `Overloaded` folded
/// into a reject (as before Q134), the first assertion would read `Ok(Denied)`.
#[tokio::test]
async fn the_data_plane_walk_hands_an_overloaded_door_back_apart() {
    use busbar_contract::auth_calls::Verified;
    let judged = |verified: Verified| async move {
        let auth = std::sync::Arc::new(door_then_identifier(verified));
        AuthMiddleware::judge_chain_on_request_path(
            &auth,
            Some("grp:admins".into()),
            ChainHead::default(),
            None,
            None,
        )
        .await
    };
    assert_eq!(
        judged(Verified::Overloaded).await,
        Err(VerifierOverloaded),
        "an overloaded door is handed back apart, never a reject or a pass"
    );
    assert_eq!(
        judged(Verified::Failed).await,
        Ok(ChainVerdict::Denied),
        "a door with no verdict is still the denial"
    );
}

/// On the wire: the request a verdict-less data-plane door refuses is answered with 1.5.5's 401,
/// byte for byte the refusal an all-pass chain earns. An OVERLOADED door (its `max_inflight` full)
/// is answered 503 with `Retry-After: 1` and the gateway's at-capacity body, the bytes the inbound
/// cap sheds with: no new customer string (owner ruling Q134, 2026-10-07). RED before Q134: the
/// overloaded door answered the 401.
#[tokio::test]
async fn a_data_plane_door_without_a_verdict_answers_the_1_5_5_401_and_an_overloaded_one_503() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    use busbar_contract::auth_calls::Verified;
    crate::snapshot::init();
    let server = MockServer::new(dp_ok_state()).await;
    let ask = |auth: AuthMiddleware| {
        let app = TestApp::new()
            .lane(LaneSpec::new("m", LANE_PROTOCOL, &server.base_url()).api_key("up"))
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
            let header = |name: &str| {
                r.headers()
                    .get(name)
                    .map(|v| v.to_str().unwrap_or_default().to_string())
            };
            let (content_type, retry_after) = (header("content-type"), header("retry-after"));
            let text = r.text().await.unwrap();
            handle.abort();
            (status, content_type, retry_after, text)
        }
    };
    // The 1.5.5 refusal: a configured chain whose every position passed.
    let all_pass = ask(AuthMiddleware::new_builtin(&chain_cfg(&[
        "test-groups-module",
    ])))
    .await;
    assert_eq!(all_pass.0, 401, "the all-pass refusal: {all_pass:?}");
    let no_verdict = ask(door_then_identifier(Verified::Failed)).await;
    assert_eq!(
        no_verdict, all_pass,
        "a door with no verdict: the 1.5.5 401, byte for byte"
    );
    // The at-capacity 503 the inbound cap sheds with, byte for byte (`limits::admission`).
    let overloaded = ask(door_then_identifier(Verified::Overloaded)).await;
    assert_eq!(
        overloaded,
        (
            503,
            Some(busbar_contract::protocol::APPLICATION_JSON.to_string()),
            Some("1".to_string()),
            r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#
                .to_string(),
        ),
        "an overloaded door: 503, Retry-After, the at-capacity body (Q134)"
    );
    server.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// L2-AUTH-4 (ARCHITECT ruling 2026-10-03): admin_auth's EXTERNAL modules open on the auth axis.
// A door among them is awaited, lent the request's head and 1.5.5's candidate (`bearer.or(header)`),
// never cached by the kernel, and an overloaded or verdict-less door is 1.5.5's refusal (401).
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
        match r
            .credential
            .as_ref()
            .map(|c| c.expose(&crate::seal::lend()).as_slice())
        {
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

/// An app whose admin chain is the external door `ext-door` alone.
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
        },
    );
    // The operator credential's row still states the admin lines the candidate is read from: the
    // carriers the build opened it with, kept across the swap of the chain's modules.
    let carriers = app.admin_modules.operator.carriers().to_vec();
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules,
        operator: Operator::new(crate::config::operator_provider()).with_carriers(carriers),
    });
    app
}

/// The external admin door judges the candidate it is lent — the Bearer, else the admin header, as
/// 1.5.5 handed an external module `bearer.or(header)` — awaited and on the spot (the kernel keeps
/// no verdict: R3, a door caches inside itself); a reject, a pass, an overloaded door and one with no
/// verdict are each 1.5.5's refusal (the 401: the admin-door 503 is not a signed accepted
/// difference).
#[tokio::test]
async fn an_external_admin_door_is_lent_the_candidate_and_an_unjudged_verify_is_the_1_5_5_refusal()
{
    use busbar_contract::auth_calls::Verified;
    for headers in [
        admin_headers(Some("tok"), None),
        admin_headers(None, Some("tok")),
    ] {
        let app = external_door_app(Verified::Reject);
        assert!(matches!(
            run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await,
            (ChainVerdict::Identified { ref module, .. }, _) if module == "ext-door"
        ));
        assert!(matches!(
            admin_door(&app, "GET", "/", &headers),
            AdminDoor::Identified(..)
        ));
    }
    let wrong = admin_headers(Some("not-tok"), None);
    for otherwise in [
        Verified::Reject,
        Verified::Pass,
        Verified::Overloaded,
        Verified::Failed,
    ] {
        let app = external_door_app(otherwise.clone());
        assert_eq!(
            run_admin_chain(&app, "GET", "/", &wrong, false, &mut Default::default()).await,
            (ChainVerdict::Denied, None),
            "{otherwise:?}: the 1.5.5 refusal"
        );
    }
}

/// A door that counts its verifies and answers from a script: `script[n]` for the n-th verify, the
/// last answer thereafter. It states `FACT_CACHEABLE`, so a kernel that cached a cacheable door's
/// verdict would answer the second request from the cache.
struct ScriptedDoor {
    script: Vec<busbar_contract::auth_calls::Verified>,
    verifies: std::sync::atomic::AtomicUsize,
}

impl ScriptedDoor {
    fn answer(&self) -> busbar_contract::auth_calls::VerifyAnswer {
        let n = self
            .verifies
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.script[n.min(self.script.len() - 1)].clone().into()
    }
}

impl busbar_contract::auth_calls::AuthCalls for ScriptedDoor {
    fn name(&self) -> &str {
        "scripted-door"
    }
    fn facts(&self) -> u32 {
        busbar_contract::abi::auth::FACT_CACHEABLE
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.answer())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(OperatorAnswer(Some(self.answer())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// THE KERNEL HOLDS NO VERDICT CACHE (Q1: the kernel's verdict cache is deleted; a door caches
/// inside itself, THE DESIGN §11 R3). The same credential presented twice is verified twice, one
/// door call per request, even though the door states `FACT_CACHEABLE` — and the second verdict is
/// the door's second answer: a door that identified the credential and then revoked it denies the
/// second request. Before Q1 the kernel's `CredentialCache` answered a COLD module's repeated
/// credential from its cache (one module call, the first verdict); any kernel cache that answered
/// a door's credential the same way turns both assertions RED (one verify, `Identified` again).
#[tokio::test]
async fn every_request_is_verified_by_the_door_and_the_kernel_caches_no_verdict() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    let door = std::sync::Arc::new(ScriptedDoor {
        script: vec![
            Verified::Identity(VerifiedIdentity {
                subject: "ext:who".into(),
                groups: vec!["ops".into()],
                ..VerifiedIdentity::default()
            }),
            Verified::Reject,
        ],
        verifies: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext-door".to_string()])
        .build();
    let mut modules = std::collections::HashMap::new();
    modules.insert(
        "ext-door".to_string(),
        AdminModule {
            calls: door.clone(),
        },
    );
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules,
        operator: Operator::new(crate::config::operator_provider()),
    });
    let headers = admin_headers(Some("tok"), None);
    assert!(matches!(
        run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await,
        (ChainVerdict::Identified { ref module, .. }, _) if module == "ext-door"
    ));
    assert_eq!(
        run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await,
        (ChainVerdict::Denied, None),
        "the second request is the door's second answer, never a cached Identified"
    );
    assert_eq!(
        door.verifies.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one door verify per request"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// K3 #9 / #10 (ARCHITECT SECURITY rulings A and B): a verified identity's replay claim is claimed
// by the kernel before admitting (THE DESIGN §6, Inbound verify: "already TAKEN is 401"), and the
// lines an auth names are struck before any plane sees the request (§6.4), whatever its verdict.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A door that answers every `verify` with `answer` — its verdict, its identity's replay claim and
/// the lines it names — on the spot and awaited alike.
struct NamingDoor(busbar_contract::auth_calls::VerifyAnswer);

impl busbar_contract::auth_calls::AuthCalls for NamingDoor {
    fn name(&self) -> &str {
        "naming-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(self.0.clone())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Answered(Some(self.0.clone())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// An identity in group `hooks`, asking for the replay claim `key` (none when `None`), its door
/// naming `strips`.
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

/// The data-plane chain `[door]` over `answer`.
fn naming_chain(
    answer: busbar_contract::auth_calls::VerifyAnswer,
) -> std::sync::Arc<AuthMiddleware> {
    std::sync::Arc::new(AuthMiddleware::from_doors_for_test(vec![(
        "door".to_string(),
        std::sync::Arc::new(NamingDoor(answer)) as std::sync::Arc<dyn AuthCalls>,
    )]))
}

/// A governance engine over a fresh store double opened through its door, as boot opens the
/// configured store: its record store and its v3 calls, where a replay claim is redeemed.
fn replay_gov() -> std::sync::Arc<crate::governance::GovState> {
    use busbar_contract::store_calls::StoreDoor;
    let opened = crate::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(crate::test_support::store_double::door),
            crate::test_support::store_double::NAME,
            b"{}",
        )
        .expect("the store double opens through its door");
    let gov = crate::governance::GovState::new(opened.records, None).expect("gov");
    assert!(gov.attach_store_calls(opened.calls.expect("a door-opened store has its calls")));
    std::sync::Arc::new(gov)
}

/// FAIL-CLOSED: governance whose store has no v3 calls to redeem in refuses an identity that asks
/// for a replay claim, as no governance at all does; one that asks for none is admitted.
#[tokio::test]
async fn a_replay_claim_with_no_store_calls_to_redeem_in_is_refused() {
    use busbar_contract::auth_calls::{Replay, VerifiedIdentity};
    let bare = crate::governance::GovState::new(
        std::sync::Arc::new(crate::governance::MemoryStore::new()),
        None,
    )
    .expect("gov");
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

/// RED (Q128 arch u27 LOW): the signed ingress claims the replay key its verified identity asks
/// for, under its verifier, as the data chain and the admin door claim theirs (THE DESIGN §6
/// "Inbound verify", l.845-846): the first presentation wins the claim, the same key inside its TTL
/// loses it, and an identity that asks for no claim is never refused for one. RED before: the
/// signed arm never claimed, so a replayed signed request was admitted every time.
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

/// RED (K3 #9): a signed message replayed inside its claim's TTL is refused. The first delivery
/// claims `door/<key>` and is admitted; the same key again is `Denied`; another key is admitted;
/// and with no governance to claim in, an identity that asks for a claim is `Denied` (fail-closed).
/// RED before: the chain dropped `replay`, so every delivery was `Identified`.
#[tokio::test]
async fn a_replayed_signed_message_inside_its_ttl_is_denied() {
    let gov = replay_gov();
    let run = |key: &str, gov: Option<std::sync::Arc<crate::governance::GovState>>| {
        let auth = naming_chain(hook_answer(Some(key), Vec::new()));
        async move {
            AuthMiddleware::run_chain_on_request_path(
                &auth,
                Some("signed".into()),
                ChainHead::default(),
                gov,
                None,
            )
            .await
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

/// The gate as the router layers it, in front of one handler at `/echo` that answers what a plane
/// handed this request would read: the request's URI and the router's original URI, and its field
/// line names after the host strips what the gate consumed (as every plane handoff strips them).
async fn echo_behind_the_gate(
    app: std::sync::Arc<crate::state::App>,
) -> (String, tokio::task::JoinHandle<()>) {
    async fn echo(
        axum::extract::OriginalUri(original): axum::extract::OriginalUri,
        consumed: Option<axum::Extension<ConsumedCredentials>>,
        req: Request<Body>,
    ) -> axum::Json<serde_json::Value> {
        let mut headers = req.headers().clone();
        ConsumedCredentials::strip_from(consumed.as_ref().map(|c| &c.0), &mut headers);
        let names: Vec<&str> = headers.keys().map(|n| n.as_str()).collect();
        axum::Json(serde_json::json!({
            "uri": req.uri().to_string(),
            "original": original.to_string(),
            "headers": names,
        }))
    }
    let handle = std::sync::Arc::new(crate::state::AppHandle::new(app));
    let core_routes: &'static crate::core_routes::CoreRouteTable = Box::leak(Box::default());
    let router = axum::Router::new()
        .route("/echo", axum::routing::any(echo))
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            move |app: crate::state::CurrentApp,
                  req: axum::extract::Request,
                  next: axum::middleware::Next| {
                auth_middleware(app, core_routes, req, next)
            },
        ))
        .with_state(handle);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), served)
}

/// An app whose data-plane chain is `[door]` over `answer`, its `hooks` group bound (so the
/// identity earns a key), governance over a fresh in-memory store.
fn naming_app(
    answer: busbar_contract::auth_calls::VerifyAnswer,
) -> std::sync::Arc<crate::state::App> {
    let mut rb = crate::config::RoleBindings::default();
    rb.entry("door".to_string())
        .or_default()
        .entry("hooks".to_string())
        .or_default();
    crate::test_support::TestApp::new()
        .auth(naming_chain(answer))
        .role_bindings(rb)
        .governance(replay_gov())
        .build()
}

/// RED (K3 #9), on the wire: the same signed delivery twice inside its TTL — the first is served,
/// the second is the data plane's 401 (a sender's retry inside the window included, as the spec
/// requires). RED before: both were served.
#[tokio::test]
async fn a_replayed_signed_delivery_is_answered_401_the_second_time() {
    crate::snapshot::init();
    let app = naming_app(hook_answer(Some("standard-webhooks/msg_1"), Vec::new()));
    let (base, served) = echo_behind_the_gate(app).await;
    let deliver = || async {
        reqwest::Client::new()
            .post(format!("{base}/echo"))
            .bearer_auth("signed")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(deliver().await, 200, "the first delivery is served");
    assert_eq!(deliver().await, 401, "the replay is refused");
    served.abort();
}

/// RED (K3 #10): the field line and the query key an auth names never reach the plane — the line
/// is struck with the gate's own carriers (`authorization` too), and the query key leaves the
/// request's URI and the router's original URI, every other pair kept byte for byte, in order (a
/// percent-encoded spelling of the key leaves too). A line the auth did not name crosses. RED
/// before: the answer's `strips` had no consumer, so `x-hook-secret` and `api_key` reached the plane.
#[tokio::test]
async fn an_auth_named_header_and_query_key_never_reach_the_plane() {
    use busbar_contract::auth_calls::Strip;
    crate::snapshot::init();
    let app = naming_app(hook_answer(
        None,
        vec![Strip::field("X-Hook-Secret"), Strip::query("api_key")],
    ));
    let (base, served) = echo_behind_the_gate(app).await;
    let seen: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{base}/echo?x=1&api_key=s3cret&y=a%20b&api%5Fkey=t"
        ))
        .bearer_auth("signed")
        .header("x-hook-secret", "hs")
        .header("x-trace", "t-1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    served.abort();
    let headers: Vec<&str> = seen["headers"]
        .as_array()
        .expect("names")
        .iter()
        .filter_map(|n| n.as_str())
        .collect();
    assert!(!headers.contains(&"x-hook-secret"), "{headers:?}");
    assert!(!headers.contains(&"authorization"), "{headers:?}");
    assert!(headers.contains(&"x-trace"), "{headers:?}");
    assert_eq!(seen["uri"], "/echo?x=1&y=a%20b");
    assert_eq!(seen["original"], "/echo?x=1&y=a%20b");
}

/// An app whose admin chain is the external door `ext-door` over `answer`, its `hooks` group bound
/// read-only, governance over a fresh in-memory store.
fn naming_admin_app(
    answer: busbar_contract::auth_calls::VerifyAnswer,
) -> std::sync::Arc<crate::state::App> {
    let rb = bindings_for(
        "ext-door",
        &[("hooks", binding(None, None, Some("read-only")))],
    );
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext-door".to_string()])
        .role_bindings(rb)
        .governance(replay_gov())
        .build();
    let mut modules = std::collections::HashMap::new();
    modules.insert(
        "ext-door".to_string(),
        AdminModule {
            calls: std::sync::Arc::new(NamingDoor(answer)),
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

/// RED (K3 #9 and #10, the admin door): an admin identity that asks for a replay claim is admitted
/// once and `Denied` the second time; the dry run claims nothing, so it still reports the grant;
/// and the lines the module named ride out of the walk whatever its verdict. RED before: the admin
/// chain dropped both, so the second request was admitted and no line was named.
#[tokio::test]
async fn an_admin_identity_replayed_is_denied_and_its_named_lines_ride_out() {
    use busbar_contract::auth_calls::Strip;
    let app = naming_admin_app(hook_answer(
        Some("signed/admin_1"),
        vec![Strip::field("x-hook-secret")],
    ));
    let headers = admin_headers(Some("signed"), None);
    let mut strips = Vec::new();
    let first = judge_admin_door(&app, "GET", "/", &headers, false, true, &mut strips).await;
    assert!(matches!(first, AdminDoor::Identified(..)), "{first:?}");
    assert_eq!(strips, vec![Strip::field("x-hook-secret")]);
    assert_eq!(
        admin_door(&app, "GET", "/", &headers),
        AdminDoor::Denied,
        "the replay is refused"
    );
    assert!(
        dry_run_admin_scope(&app, &headers) != busbar_contract::authz::Grants::default(),
        "a dry run claims nothing"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE AUTH x DISPATCH ROWS, DRIVEN THROUGH THE SERVED DOOR (F25 rehome of the retired engine crate's
// `engine/tests/auth_dispatch_tests.rs`). The served data plane installs each plane claim as a
// door route at the data-plane bar (`RouteAuth::Key`, `build_split_routers_serving_doors`), so the
// kernel's `auth_middleware` decides admission before the plane is asked anything. These tests
// mount that exact shape: a door route at the pool path whose handler answers 200 with what the
// gate handed it (the governance context, the resolved key, the principal). A 200 is the gate's
// admission and a 401 its refusal; the echoed facts pin WHO the gate made the caller.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The request body every row below posts (the door reads none of it).
const DOOR_BODY: &str =
    r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#;

/// A door route at `path` on the data-plane bar whose handler answers 200 with what the auth gate
/// attached: `gov=attached|absent key=<resolved key id or -> principal=<principal id or ->`.
fn admitting_door(path: &str) -> busbar_kernel::plane_routes::PlaneRouteSpec {
    busbar_kernel::plane_routes::PlaneRouteSpec {
        path: path.to_string(),
        method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
        auth: busbar_contract::abi::mechanism::route::RouteAuth::Key,
        handler: std::sync::Arc::new(|ctx: busbar_kernel::plane_routes::PlaneReqCtx| {
            Box::pin(async move {
                let gov = if ctx.gov.is_some() {
                    "attached"
                } else {
                    "absent"
                };
                let key = ctx
                    .gov
                    .as_ref()
                    .and_then(|g| g.key())
                    .map_or_else(|| "-".to_string(), |k| k.id.clone());
                let principal = ctx
                    .principal
                    .as_ref()
                    .and_then(|p| p.0.as_ref())
                    .map_or_else(|| "-".to_string(), |p| p.id.clone());
                axum::response::Response::new(axum::body::Body::from(format!(
                    "gov={gov} key={key} principal={principal}"
                )))
            })
        }),
    }
}

/// Serve `app`'s data plane as production builds it, with an admitting door at each of `paths`.
async fn door_serve(
    app: std::sync::Arc<crate::state::App>,
    paths: &[&str],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    crate::snapshot::init();
    let doors = paths.iter().map(|p| admitting_door(p)).collect();
    let (router, _admin, _handle) = crate::build_split_routers_serving(
        app,
        doors,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// One POST to the door at `path`, presenting `credential` on the header `carrier` (`None` = no
/// credential at all). Returns (status, content-type, body).
async fn door_post(
    addr: std::net::SocketAddr,
    path: &str,
    credential: Option<(&str, &str)>,
) -> (u16, Option<String>, String) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .body(DOOR_BODY);
    if let Some((carrier, value)) = credential {
        req = req.header(carrier, value);
    }
    let r = req.send().await.unwrap();
    let status = r.status().as_u16();
    let ct = r
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = r.text().await.unwrap();
    (status, ct, body)
}

/// The `Authorization: Bearer` carrier, spelled as the SDKs send it.
fn bearer(secret: &str) -> String {
    format!("Bearer {secret}")
}

/// [`door_post`] presenting `secret` on `Authorization: Bearer`.
async fn door_bearer(
    addr: std::net::SocketAddr,
    path: &str,
    secret: &str,
) -> (u16, Option<String>, String) {
    let auth = bearer(secret);
    door_post(addr, path, Some(("authorization", auth.as_str()))).await
}

/// A governance engine with a signing key, `admin_token` deciding whether it is active.
fn door_gov(admin_token: Option<&str>) -> std::sync::Arc<crate::governance::GovState> {
    let store = std::sync::Arc::new(crate::governance::MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    std::sync::Arc::new(
        crate::governance::GovState::new_with_signer(
            store,
            admin_token.map(str::to_string),
            Some(signer),
        )
        .unwrap(),
    )
}

/// Mint one signed key named `name`, allowed on `pools`. Returns (key id, secret).
fn door_mint(gov: &crate::governance::GovState, name: &str, pools: &[&str]) -> (String, String) {
    let (key, secret) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: name.to_string(),
                allowed_pools: Some(pools.iter().map(|p| p.to_string()).collect()),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    (
        key.id,
        secret.expose(&crate::seal::lend()).as_str().to_string(),
    )
}

/// A deployment with pool `pa` (one lane, never dialled: the door answers before any dispatch).
fn door_app() -> crate::test_support::TestApp {
    crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new("test-model", LANE_PROTOCOL, "http://127.0.0.1:1")
                .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
}

/// The 200 body the door answers for an admitted caller.
fn admitted(gov: &str, key: &str, principal: &str) -> String {
    format!("gov={gov} key={key} principal={principal}")
}

/// F25 row 49: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_chain_accepts_all_carriers_and_native_401.
/// Pins: a chain-identified, role-bound token is admitted 200 on each of the three carriers
/// (Authorization, x-api-key, x-goog-api-key); a wrong token, an identified-but-unbound
/// principal and no credential are each 401 with an `application/json` envelope carrying `error`.
#[tokio::test]
async fn test_chain_accepts_all_carriers_and_native_401() {
    let token = "grp:carrier";
    let app = door_app()
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .role_bindings(bindings_for(
            "test-groups-module",
            &[("carrier", binding(None, None, None))],
        ))
        .build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let auth = bearer(token);
    for (carrier, value) in [
        ("authorization", auth.as_str()),
        ("x-api-key", token),
        ("x-goog-api-key", token),
    ] {
        let (status, _, body) = door_post(addr, url, Some((carrier, value))).await;
        assert_eq!(status, 200, "a valid token via {carrier} must pass: {body}");
        assert!(
            body.starts_with("gov=attached key=") && body.ends_with(" principal=test:carrier"),
            "the chain identified the token via {carrier} and the bound role keyed it: {body}"
        );
        assert!(
            !body.contains("key=- "),
            "a bound role is admitted under a governance key: {body}"
        );
    }

    // Wrong token via x-api-key → 401, native JSON envelope with an `error` object.
    let (status, ct, body) = door_post(addr, url, Some(("x-api-key", "not-the-token"))).await;
    assert_eq!(status, 401, "wrong token must be 401: {body}");
    assert_eq!(
        ct.as_deref(),
        Some("application/json"),
        "401 must carry application/json native envelope, not text/plain"
    );
    let env: serde_json::Value = serde_json::from_str(&body).expect("401 body is JSON");
    assert!(
        env.get("error").is_some_and(serde_json::Value::is_object),
        "native error envelope must contain an `error` object: {env}"
    );

    // Identified, but the role is unbound under the module's bindings table: no governance key →
    // 401, same envelope (1.5.5's guard, v1.5.5 auth/mod.rs:1543).
    let (status, ct, body) = door_post(addr, url, Some(("x-api-key", "grp:unbound"))).await;
    assert_eq!(
        status, 401,
        "an unbound role under a governed module must be refused: {body}"
    );
    assert_eq!(ct.as_deref(), Some("application/json"));

    // No credential at all → 401, still JSON.
    let (status, ct, body) = door_post(addr, url, None).await;
    assert_eq!(status, 401, "missing token must be 401: {body}");
    assert_eq!(ct.as_deref(), Some("application/json"));

    handle.abort();
}

/// F25 row 50: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_disabled_virtual_key_is_rejected_401.
/// Pins, in one rig (`chain: [keys]` + active governance): a disabled signed key 401, an unknown
/// key `sk-vk-nope` 401, and an enabled key of the same shape 200 under its own key id.
#[tokio::test]
async fn test_disabled_virtual_key_is_rejected_401() {
    let gov = door_gov(Some("admintok"));
    let (dis_id, disabled_secret) = door_mint(&gov, "kdis", &["pa"]);
    let (ena_id, enabled_secret) = door_mint(&gov, "kena", &["pa"]);
    // Freeze the first key via the PATCH-shaped update (mint always starts `enabled: true`).
    gov.update_key(&dis_id, Some(false), None).unwrap();
    let app = door_app().keys_chain().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let (status, _, body) = door_bearer(addr, url, &disabled_secret).await;
    assert_eq!(
        status, 401,
        "a disabled virtual key must be rejected: {body}"
    );

    let (status, _, body) = door_bearer(addr, url, "sk-vk-nope").await;
    assert_eq!(status, 401, "unknown key must be rejected: {body}");

    let (status, _, body) = door_bearer(addr, url, &enabled_secret).await;
    assert_eq!(status, 200, "an enabled virtual key must pass auth: {body}");
    assert_eq!(body, admitted("attached", &ena_id, &ena_id));

    handle.abort();
}

/// F25 row 51: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_governance_accepts_vendor_carriers_and_native_401.
/// Pins: under `chain: [keys]` + active governance, a minted signed key (allowed on `pa`) is
/// admitted 200 via `x-goog-api-key` and via `x-api-key`; an unknown key via `x-goog-api-key` is 401
/// with `application/json`.
#[tokio::test]
async fn test_governance_accepts_vendor_carriers_and_native_401() {
    let gov = door_gov(Some("admintok"));
    let (key_id, secret) = door_mint(&gov, "kc", &["pa"]);
    let app = door_app().keys_chain().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    for carrier in ["x-goog-api-key", "x-api-key"] {
        let (status, _, body) = door_post(addr, url, Some((carrier, secret.as_str()))).await;
        assert_eq!(
            status, 200,
            "valid virtual key via {carrier} must pass governance: {body}"
        );
        assert_eq!(body, admitted("attached", &key_id, &key_id));
    }

    let (status, ct, body) = door_post(addr, url, Some(("x-goog-api-key", "sk-vk-nope"))).await;
    assert_eq!(
        status, 401,
        "an unknown virtual key via x-goog-api-key must be 401: {body}"
    );
    assert_eq!(
        ct.as_deref(),
        Some("application/json"),
        "401 must carry the native application/json envelope, not text/plain"
    );

    handle.abort();
}

/// F25 row 52: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_governance_revoked_signed_token_key_rejected.
/// Pins: a live signed key is admitted 200; after `revoke` (which leaves `enabled` true)
/// `is_revoked` holds and the SAME token is refused 401.
#[tokio::test]
async fn test_governance_revoked_signed_token_key_rejected() {
    let gov = door_gov(Some("admintok"));
    let (key_id, secret) = door_mint(&gov, "revocable", &["pa"]);
    let app = door_app().keys_chain().governance(gov.clone()).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let (status, _, body) = door_bearer(addr, url, &secret).await;
    assert_eq!(
        status, 200,
        "a live signed-token key must authenticate: {body}"
    );
    assert_eq!(body, admitted("attached", &key_id, &key_id));

    gov.revoke(&key_id, "audit regression").unwrap();
    assert!(gov.is_revoked(&key_id), "revoke must denylist the subject");

    let (status, _, body) = door_bearer(addr, url, &secret).await;
    assert_eq!(
        status, 401,
        "a REVOKED signed-token key's presented token must be rejected: {body}"
    );

    handle.abort();
}

/// F25 row 53: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_governance_inert_without_admin_token_static_token_admitted.
/// Pins: an INERT engine (no admin token) does not supersede the static chain — the chain's
/// bound token `grp:static` is admitted 200 and `not-the-token` is still 401.
#[tokio::test]
async fn test_governance_inert_without_admin_token_static_token_admitted() {
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            None,
        )
        .unwrap(),
    );
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );
    let app = door_app()
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .governance(gov)
        .role_bindings(bindings_for(
            "test-groups-module",
            &[("static", binding(None, None, None))],
        ))
        .build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let (status, _, body) = door_bearer(addr, url, "grp:static").await;
    assert_eq!(
        status, 200,
        "an inert governance engine must NOT supersede the static chain: {body}"
    );
    assert!(
        body.ends_with(" principal=test:static"),
        "the static chain identified the caller: {body}"
    );

    let (status, _, body) = door_bearer(addr, url, "not-the-token").await;
    assert_eq!(
        status, 401,
        "the static chain must still reject a token it does not identify: {body}"
    );

    handle.abort();
}

/// F25 row 54: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_governance_inert_without_admin_token_open_relay_admits.
/// Pins: an INERT engine (no admin token), no auth chain, `upstream_credentials: own` — a request
/// with no credential is admitted 200 anonymous (the open relay is not superseded).
#[tokio::test]
async fn test_governance_inert_without_admin_token_open_relay_admits() {
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            None,
        )
        .unwrap(),
    );
    let app = door_app()
        .upstream_creds(crate::auth::UpstreamCreds::Own)
        .governance(gov)
        .build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;

    let (status, _, body) = door_post(addr, "/pa/v1/messages", None).await;
    assert_eq!(
        status, 200,
        "an inert governance engine must NOT supersede the open relay: {body}"
    );
    assert_eq!(body, admitted("attached", "-", "-"));

    handle.abort();
}

/// F25 row 55: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_governance_active_with_admin_token_enforces_minted_key.
/// Pins, in one rig (`chain: [keys]` + ACTIVE governance): the minted signed key 200, an unknown
/// token `sk-vk-unknown` 401.
#[tokio::test]
async fn test_governance_active_with_admin_token_enforces_minted_key() {
    let gov = door_gov(Some("admintok"));
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );
    let (key_id, secret) = door_mint(&gov, "k", &["pa"]);
    let app = door_app().keys_chain().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let (status, _, body) = door_bearer(addr, url, &secret).await;
    assert_eq!(
        status, 200,
        "an enabled virtual key must pass under active governance: {body}"
    );
    assert_eq!(body, admitted("attached", &key_id, &key_id));

    let (status, _, body) = door_bearer(addr, url, "sk-vk-unknown").await;
    assert_eq!(
        status, 401,
        "active governance must reject an unknown token: {body}"
    );

    handle.abort();
}

/// F25 row 56: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_inert_governance_persisted_key_is_not_enforced_static_chain_wins.
/// Pins: a store that still holds a key (scoped to pool `restricted` only) under an INERT engine
/// confers nothing — the persisted secret is 401 from the static chain, and the chain's own token
/// is admitted 200 under the chain's key, never the persisted one.
#[tokio::test]
async fn test_inert_governance_persisted_key_is_not_enforced_static_chain_wins() {
    use crate::governance::RecordStore as _;
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = std::sync::Arc::new(crate::governance::MemoryStore::new());
    store
        .put_key(&crate::governance::VirtualKey {
            id: "kold".to_string(),
            generation_hash: busbar_contract::redacted::sha256_hex(persisted_secret.as_bytes()),
            name: "kold".to_string(),
            allowed_scopes: Some(vec![ScopeRef::pool("restricted")]),
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
    let gov = std::sync::Arc::new(crate::governance::GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );
    let app = door_app()
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .governance(gov)
        .role_bindings(bindings_for(
            "test-groups-module",
            &[("static-chain", binding(None, None, None))],
        ))
        .build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;
    let url = "/pa/v1/messages";

    let (status, _, body) = door_bearer(addr, url, persisted_secret).await;
    assert_eq!(
        status, 401,
        "an inert engine's persisted key must confer nothing — the static chain rejects it: {body}"
    );

    let (status, _, body) = door_bearer(addr, url, "grp:static-chain").await;
    assert_eq!(
        status, 200,
        "the static chain governs an inert engine: {body}"
    );
    assert!(
        body.ends_with(" principal=test:static-chain"),
        "the static chain identified the caller: {body}"
    );
    assert!(
        !body.contains("key=kold "),
        "the persisted key's controls are not consulted: {body}"
    );

    handle.abort();
}

/// F25 row 58: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_1_5_2_open_chain_admin_token_no_credential_admits_anon.
/// Pins: `chain: []` + governance with an admin token and a minted key + no credential → 200
/// ANONYMOUS (no key, no principal).
#[tokio::test]
async fn test_1_5_2_open_chain_admin_token_no_credential_admits_anon() {
    let gov = door_gov(Some("admintok"));
    let _ = door_mint(&gov, "vk", &["pa"]);
    let app = door_app().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;

    let (status, _, body) = door_post(addr, "/pa/v1/messages", None).await;
    assert_eq!(
        status, 200,
        "chain:[] + admin token + no credential must admit ANONYMOUS: {body}"
    );
    assert_eq!(body, admitted("attached", "-", "-"));

    handle.abort();
}

/// F25 row 59: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_1_5_2_open_chain_inserts_default_govctx_no_500.
/// Pins: an open-chain request carries a DEFAULT governance context to the handler (never a 500
/// `MissingExtension`): not 500, exactly 200, and the handler saw the context attached.
#[tokio::test]
async fn test_1_5_2_open_chain_inserts_default_govctx_no_500() {
    let gov = door_gov(Some("admintok"));
    let _ = door_mint(&gov, "vk", &["pa"]);
    let app = door_app().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;

    let (status, _, body) = door_post(addr, "/pa/v1/messages", None).await;
    assert_ne!(
        status, 500,
        "open chain must insert a default GovCtx (no MissingExtension 500): {body}"
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        body.starts_with("gov=attached "),
        "the open arm inserts the default context: {body}"
    );

    handle.abort();
}

/// F25 row 60: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_1_5_2_open_chain_valid_vkey_ignored_not_metered.
/// Pins: `chain: []` + admin token + a VALID key voluntarily presented → 200 PURE ANONYMOUS: the
/// gate resolves no key (so nothing downstream can meter one) and the key's ledger records no spend.
#[tokio::test]
async fn test_1_5_2_open_chain_valid_vkey_ignored_not_metered() {
    let gov = door_gov(Some("admintok"));
    let (key_id, secret) = door_mint(&gov, "vk", &["pa"]);
    let app = door_app().governance(gov.clone()).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;

    let (status, _, body) = door_bearer(addr, "/pa/v1/messages", &secret).await;
    assert_eq!(
        status, 200,
        "open chain admits regardless of the presented vkey: {body}"
    );
    assert_eq!(
        body,
        admitted("attached", "-", "-"),
        "an empty chain must NOT resolve a presented vkey (pure anonymous)"
    );
    let spend = gov
        .usage_for(
            &crate::cost::CostModel::flat(1),
            &key_id,
            busbar_kernel::store::now(),
        )
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(
        spend, 0,
        "an empty chain must NOT meter a presented vkey (pure anonymous)"
    );

    handle.abort();
}

/// F25 row 61: rehomed from the retired engine crate's src/engine/tests/auth_dispatch_tests.rs::test_1_5_2_keys_chain_valid_vkey_admits.
/// Pins: `chain: [keys]` + a valid enabled signed key → 200, admitted under that key.
#[tokio::test]
async fn test_1_5_2_keys_chain_valid_vkey_admits() {
    let gov = door_gov(Some("admintok"));
    let (key_id, secret) = door_mint(&gov, "vk", &["pa"]);
    let app = door_app().keys_chain().governance(gov).build();
    let (addr, handle) = door_serve(app, &["/pa/v1/messages"]).await;

    let (status, _, body) = door_bearer(addr, "/pa/v1/messages", &secret).await;
    assert_eq!(
        status, 200,
        "chain:[keys] + valid enabled vkey must admit: {body}"
    );
    assert_eq!(body, admitted("attached", &key_id, &key_id));

    handle.abort();
}

/// F25 row 65: rehomed from the retired engine crate's src/engine/tests/auth_native_envelope_tests.rs::test_unauthorized_body_carries_no_busbar_vocabulary.
/// Pins: over the live stack (token mode, a wrong credential, no plane mounted), the auth-failure
/// body for EVERY data-plane path shape the legacy swept — including `/v1/responses` and the
/// converse shape — is JSON and names none of busbar's auth vocabulary.
#[tokio::test]
async fn test_unauthorized_body_carries_no_busbar_vocabulary_on_the_live_stack() {
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
    crate::snapshot::init();
    let app = door_app()
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .build();
    let (addr, handle) = dp_serve(app).await;
    let paths = [
        "/v1beta/models/x:verb",
        "/pa/v1/messages",
        "/v1/kind/action",
        "/v1/responses",
        "/v2/chat",
        "/model/vendor.model/converse",
        "/totally/unknown/path",
    ];
    for path in paths {
        let (status, ct, raw) = door_post(addr, path, Some(("x-api-key", "wrong-token"))).await;
        assert!(
            status == 401 || status == 403,
            "'{path}' must be refused by the auth gate (got {status}): {raw}"
        );
        assert_eq!(ct.as_deref(), Some("application/json"), "'{path}': {raw}");
        let body: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("auth-failure body for '{path}' must be JSON ({e}): {raw}"));
        let mut strings = Vec::new();
        collect_strings(&body, &mut strings);
        assert!(
            !strings.is_empty(),
            "'{path}' body carries a message: {body}"
        );
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
    handle.abort();
}

/// F25 row 71: rehomed from the retired engine crate's src/engine/tests/auth_native_envelope_tests.rs::test_admin_prefix_is_boundary_safe.
/// Pins: `/apix/v1/messages` (a path that merely starts with the bytes `/api`) with a wrong token is
/// refused by the NORMAL data-plane branch — a 401 in the residual dialect's native
/// `application/json` envelope with `error.type == "authentication_error"` — never the admin
/// branch's frozen `{error:{code}}` envelope and never a 500.
#[tokio::test]
async fn test_admin_prefix_is_boundary_safe() {
    crate::snapshot::init();
    let app = crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new("test-model", LANE_PROTOCOL, "http://127.0.0.1:1")
                .api_key("busbar-upstream-key"),
        )
        .pool("apix", &[(0, 1)])
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .build();
    let (addr, handle) = dp_serve(app).await;

    let (status, ct, raw) = door_post(
        addr,
        "/apix/v1/messages",
        Some(("x-api-key", "wrong-token")),
    )
    .await;
    assert_eq!(
        status, 401,
        "an /apix path with a wrong token must be a normal 401, not 500/admin: {raw}"
    );
    assert_eq!(ct.as_deref(), Some("application/json"));
    let env: serde_json::Value = serde_json::from_str(&raw).expect("401 body is JSON");
    assert_eq!(
        env["error"]["type"],
        busbar_contract::protocol::KIND_AUTHENTICATION,
        "expected the data plane's native authentication_error: {env}"
    );
    assert!(
        env["error"].get("code").is_none(),
        "the admin branch's frozen {{error:{{code}}}} envelope must not answer a non-admin path: {env}"
    );

    handle.abort();
}

/// THE SIGNED-REQUEST VERIFIER NAMES ITS LINES ON EVERY ARM (THE DESIGN §6.3, l.925: "Every auth
/// called names its credential lines whatever its verdict, and the transport strips the union").
/// The gate keeps the lines the verifier's answer named, whatever its verdict, and a faulted
/// answer is a refusal even when its verdict reads as an identity. RED: the gate read only
/// `.verified` off the answer, so the named lines were dropped and never struck before the plane.
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Row 159, K3#1 (ARCHITECT ruling 2026-10-17): THE KERNEL NAMES NO INBOUND CREDENTIAL LINE. The
// lines a caller's credential sits on are the default inbound style's, the carrier marks of the one
// auth row stating `FACT_DEFAULT_INBOUND_STYLE`, walked in its Statement's order; the operator
// credential's lines are its row's own marks.

/// A verify-only fixture whose Statement states the default inbound style over lines no 1.5.5
/// build ever read: what the kernel reads is the style's words, not its own.
struct OtherStyle;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for OtherStyle {
    fn open(_settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Self)
    }

    fn verify(
        &self,
        _request: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

/// The style's lines, in its Statement's order.
const OTHER_LINES: [&str; 2] = ["x-other-key", "authorization"];

const OTHER_MARKS: &[busbar_contract::abi::mechanism::door::MarkWord] = &[
    busbar_contract::abi::sdk::auth_door::carrier(OTHER_LINES[0]),
    busbar_contract::abi::sdk::auth_door::carrier(OTHER_LINES[1]),
];

const OTHER_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        busbar_contract::abi::auth::FACT_DEFAULT_INBOUND_STYLE,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

mod other_style {
    busbar_contract::auth_verify_door!(
        super::OtherStyle,
        busbar_contract::abi::sdk::auth_door::with_tail(
            busbar_contract::abi::mechanism::door::Statement {
                mark_words: super::OTHER_MARKS.as_ptr(),
                mark_words_len: super::OTHER_MARKS.len(),
                ..busbar_contract::abi::sdk::door::statement("other-style", "1.0.0", 4)
            },
            super::OTHER_TAIL,
        )
    );
}

/// `chain: [keys]` over a registry linking the fixture style. The test build reads no Statement
/// (it has no loader), so the row states the lines its door's Statement states.
fn other_style_chain() -> AuthMiddleware {
    let registry = crate::test_support::rows::Rows::new()
        .with_linked_style(
            crate::preflight::LinkedRow::Auth(("other-style", "other-style", other_style::door)),
            &OTHER_LINES,
        )
        .into_rows();
    AuthMiddleware::new(
        &chain_cfg(&["keys"]),
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the chain builds")
}

/// RED on a kernel that names its own carriers: the credential is read off the style's own lines,
/// in the style's order, and a line the style does not state carries nothing (`x-api-key` is no
/// line of this style).
#[test]
fn the_client_token_is_read_off_the_default_inbound_styles_own_lines() {
    let mw = other_style_chain();
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("from-x-api-key"));
    assert_eq!(mw.extract_client_token(&headers), None);
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer from-bearer"),
    );
    assert_eq!(
        mw.extract_client_token(&headers),
        Some("from-bearer".to_string())
    );
    headers.insert("x-other-key", HeaderValue::from_static("from-other"));
    assert_eq!(
        mw.extract_client_token(&headers),
        Some("from-other".to_string()),
        "the style's first line wins"
    );
    let names: Vec<&str> = mw.carriers().iter().map(HeaderName::as_str).collect();
    assert_eq!(names, ["x-other-key", "authorization"]);
}

/// The host strips the default inbound style's lines from every plane's request, whichever carried
/// the credential, and the operator credential's own lines when an admin chain is configured.
#[test]
fn the_gate_strips_the_styles_lines_and_the_operator_credentials() {
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec![crate::config::operator_provider().to_string()])
        .build();
    let consumed = gate_consumed(&app, false, false);
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

// ── #77(9) l.2279: the per-verb allow-list on a role binding ────────────────────────────────────

/// An app whose admin chain is the `test-scope-module` stand-in (`grp:<role>` identifies a principal
/// carrying exactly that role), ceilinged at `cap`, binding `ops` to `ops` — with the closed admin
/// verb table's kind-neutral double registered, so a `verbs:` name has a rung.
fn verbs_app(ops: crate::config::RoleBindingCfg, cap: &str) -> std::sync::Arc<crate::state::App> {
    crate::test_support::install_admin_verb_table_double();
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["test-scope-module".to_string()])
        .role_bindings(bindings_for("test-scope-module", &[("ops", ops)]))
        .build();
    let a = std::sync::Arc::get_mut(&mut app).expect("unshared App Arc");
    a.auth_scope_caps
        .insert("test-scope-module".to_string(), cap.to_string());
    app
}

/// A binding parsed off its config text, as an operator writes it under
/// `auth.role_bindings.<provider>.<role>:`.
fn verbs_binding(yaml: &str) -> crate::config::RoleBindingCfg {
    serde_yaml::from_str(yaml).expect("`verbs:` is a role-binding key")
}

/// THE DOOR READS THE ALLOW-LIST. A role granting verbs BY NAME is identified WITH its list: the
/// matrix holds every rung a named verb needs (here `full`, for one mutation), and the list holds
/// exactly the names. RED before #77(9)'s allow-list: `RoleBindingCfg` had no `verbs`, so the door
/// had nothing to read and the principal, holding no `admin_scope`, earned no grant at all.
#[test]
fn a_role_granting_verbs_by_name_is_identified_with_its_allow_list() {
    use busbar_contract::authz::{Grants, Scope};
    crate::snapshot::init();
    let app = verbs_app(verbs_binding("verbs: [post_config_apply]"), "full");
    let door = admin_door(
        &app,
        "POST",
        "/api/v1/admin/config/apply",
        &admin_headers(Some("grp:ops"), None),
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

/// `verbs: "*"` IS `admin_scope: full`: the same door verdict, value for value — an `Identified`
/// principal holding the full rung, no list. RED before the allow-list: the key did not parse.
#[test]
fn verbs_star_is_exactly_admin_scope_full() {
    crate::snapshot::init();
    let star = verbs_app(verbs_binding("verbs: \"*\""), "full");
    let full = verbs_app(binding(None, None, Some("full")), "full");
    let headers = admin_headers(Some("grp:ops"), None);
    for (method, path) in [
        ("POST", "/api/v1/admin/config/apply"),
        ("GET", "/api/v1/admin/keys"),
    ] {
        let by_star = admin_door(&star, method, path, &headers);
        assert!(matches!(by_star, AdminDoor::Identified(..)), "{by_star:?}");
        assert_eq!(
            by_star,
            admin_door(&full, method, path, &headers),
            "{method} {path}: `verbs: \"*\"` must be exactly `admin_scope: full`"
        );
    }
}

/// A binding with NO `verbs` key is judged exactly as before: `read-only` and `full` stay the
/// 1.5.5 shorthands, an `Identified` verdict with the rung, never a list.
#[test]
fn a_binding_without_verbs_is_judged_by_its_rung_alone() {
    use busbar_contract::authz::{Grants, Scope};
    crate::snapshot::init();
    let headers = admin_headers(Some("grp:ops"), None);
    for (scope, rung) in [("read-only", Scope::ReadOnly), ("full", Scope::Full)] {
        let app = verbs_app(binding(None, None, Some(scope)), "full");
        let door = admin_door(&app, "POST", "/api/v1/admin/config/apply", &headers);
        let AdminDoor::Identified(_, grants) = door else {
            panic!("{scope}: a binding with no `verbs` key is never listed, got {door:?}");
        };
        assert_eq!(grants, Grants::of(rung), "{scope}");
    }
}

/// The provider's `max_admin_scope:` caps a NAMED verb exactly as it caps an `admin_scope`: under a
/// `read-only` ceiling a named mutation is dropped and only the named read stays held.
#[test]
fn the_providers_ceiling_caps_a_named_verb() {
    use busbar_contract::authz::{Grants, Scope};
    crate::snapshot::init();
    let app = verbs_app(
        verbs_binding("verbs: [get_keys, post_config_apply]"),
        "read-only",
    );
    let door = admin_door(
        &app,
        "GET",
        "/api/v1/admin/keys",
        &admin_headers(Some("grp:ops"), None),
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

/// THE ADMIN GATE ENFORCES THE LIST, at the one chokepoint every admin path crosses: the named
/// mutation passes authorization (no admin surface is mounted in this binary, so it then falls
/// through — anything but 401/403), a mutation the list does not name is the 403 a missing rung
/// gets, in its envelope. RED before the allow-list: the `verbs` key did not exist, so the
/// principal held no grant and the named mutation was refused too.
#[tokio::test]
async fn the_admin_gate_admits_only_the_listed_verbs() {
    crate::snapshot::init();
    let app = verbs_app(verbs_binding("verbs: [post_config_apply]"), "full");
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();
    let listed = client
        .post(format!("{base}/api/v1/admin/config/apply"))
        .bearer_auth("grp:ops")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_ne!(
        listed.status().as_u16(),
        401,
        "the listed role authenticates"
    );
    assert_ne!(
        listed.status().as_u16(),
        403,
        "the listed verb must pass authorization, got {}",
        listed.status()
    );
    for (method, path) in [
        (reqwest::Method::POST, "/api/v1/admin/keys"),
        (reqwest::Method::GET, "/api/v1/admin/keys"),
    ] {
        let refused = client
            .request(method.clone(), format!("{base}{path}"))
            .bearer_auth("grp:ops")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(
            refused.status().as_u16(),
            403,
            "{method} {path}: a verb the list does not name is refused"
        );
        let needed = if method == reqwest::Method::GET {
            "read-only"
        } else {
            "full"
        };
        assert_eq!(
            refused.text().await.unwrap(),
            format!(
                "{{\"error\":{{\"code\":\"forbidden\",\"message\":\"this endpoint requires the \
                 `{needed}` admin scope\"}}}}"
            ),
            "{method} {path}: the refusal is the existing scope refusal, byte for byte"
        );
    }
    handle.abort();
}

// ── the lines an external admin module is lent ───────────────────────────────────────────────

/// A line no admin style names: a module may still name it among its own carriers.
const STRAY_LINE: &str = "x-api-key";

/// An external admin module that names its own `carriers` (and states `facts`): it identifies the
/// candidate `tok` it is lent, and when it is lent none, the first of its carriers it is lent that
/// carries `tok` (bare or as a Bearer); otherwise it passes. It keeps the names of every line it
/// was lent.
struct CarrierReader {
    carriers: Vec<String>,
    facts: u32,
    lent: std::sync::Mutex<Vec<Vec<String>>>,
}

impl CarrierReader {
    fn answer(
        &self,
        r: &busbar_contract::auth_calls::VerifyRequest,
    ) -> busbar_contract::auth_calls::VerifyAnswer {
        use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
        self.lent
            .lock()
            .unwrap()
            .push(r.lines.iter().map(|(n, _)| n.clone()).collect());
        let lent = r
            .credential
            .as_ref()
            .map(|c| c.expose(&crate::seal::lend()).clone());
        let own = || {
            self.carriers.iter().find_map(|c| {
                r.lines
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(c))
                    .map(|(_, v)| v.expose(&crate::seal::lend()).clone())
            })
        };
        let token = lent.or_else(own);
        let holds = token.is_some_and(|t| t == b"tok" || t == b"Bearer tok");
        if holds {
            Verified::Identity(VerifiedIdentity {
                subject: "ext:who".into(),
                groups: vec!["ops".into()],
                ..VerifiedIdentity::default()
            })
            .into()
        } else {
            Verified::Pass.into()
        }
    }
}

impl busbar_contract::auth_calls::AuthCalls for CarrierReader {
    fn name(&self) -> &str {
        "carrier-reader"
    }
    fn facts(&self) -> u32 {
        self.facts
    }
    fn carriers(&self) -> Vec<String> {
        self.carriers.clone()
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

/// An app whose admin chain is `reader` alone, the operator credential's row stating the admin
/// lines it was built with.
fn reader_admin_app(reader: std::sync::Arc<CarrierReader>) -> std::sync::Arc<crate::state::App> {
    let mut app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext-reader".to_string()])
        .build();
    let mut modules = std::collections::HashMap::new();
    modules.insert("ext-reader".to_string(), AdminModule { calls: reader });
    let carriers = app.admin_modules.operator.carriers().to_vec();
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules,
        operator: Operator::new(crate::config::operator_provider()).with_carriers(carriers),
    });
    app
}

/// A reader naming the admin style's own lines and [`STRAY_LINE`] among its carriers.
fn stray_reader(facts: u32) -> std::sync::Arc<CarrierReader> {
    let app = crate::test_support::TestApp::new().build();
    let mut carriers = app.admin_modules.operator.carriers().to_vec();
    carriers.push(STRAY_LINE.to_string());
    std::sync::Arc::new(CarrierReader {
        carriers,
        facts,
        lent: std::sync::Mutex::default(),
    })
}

/// The admin plane's answer through the router to a GET under the native API's root carrying
/// `headers`: (status, content-type, body).
async fn admin_answer(
    app: std::sync::Arc<crate::state::App>,
    headers: &[(&str, &str)],
) -> (u16, Option<String>, Vec<u8>) {
    crate::snapshot::init();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new().get(format!("http://{addr}/api/v1/admin/keys"));
    for (n, v) in headers {
        req = req.header(*n, *v);
    }
    let resp = req.send().await.unwrap();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let status = resp.status().as_u16();
    let body = resp.bytes().await.unwrap().to_vec();
    serving.abort();
    (status, content_type, body)
}

/// RED (/status row 192; 1.5.5 handed an admin module the Bearer, else the admin line, and no
/// other): an external admin module is lent only the lines named both by its own carriers and by
/// the operator credential's style. A valid token carried only on a line the module names but the
/// admin style does not is no credential: the chain denies, and the admin plane answers 1.5.5's
/// admin 401 bytes. The module never sees that line.
#[tokio::test]
async fn an_admin_module_is_not_lent_a_line_the_admin_style_does_not_name() {
    let reader = stray_reader(0);
    let app = reader_admin_app(std::sync::Arc::clone(&reader));
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(STRAY_LINE),
        HeaderValue::from_static("tok"),
    );
    assert!(matches!(
        run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await,
        (ChainVerdict::Denied, _)
    ));
    assert!(matches!(
        admin_door(&app, "GET", "/", &headers),
        AdminDoor::Denied
    ));
    for lines in reader.lent.lock().unwrap().iter() {
        assert!(
            !lines.iter().any(|n| n.eq_ignore_ascii_case(STRAY_LINE)),
            "the module was lent {STRAY_LINE}: {lines:?}"
        );
    }
    let want = admin_unauthorized_response();
    let want_type = want
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let want_status = want.status().as_u16();
    let want_body = {
        use http_body_util::BodyExt as _;
        want.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    };
    assert_eq!(
        admin_answer(app, &[(STRAY_LINE, "tok")]).await,
        (want_status, want_type, want_body),
        "the 1.5.5 admin 401"
    );
}

/// The same module, its token on the Bearer the admin style names, is identified as before.
#[tokio::test]
async fn an_admin_module_is_identified_on_the_admin_styles_bearer() {
    let reader = stray_reader(0);
    let app = reader_admin_app(reader);
    let headers = admin_headers(Some("tok"), None);
    assert!(matches!(
        run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await,
        (ChainVerdict::Identified { ref module, .. }, _) if module == "ext-reader"
    ));
    assert!(matches!(
        admin_door(&app, "GET", "/", &headers),
        AdminDoor::Identified(..)
    ));
}

/// A module whose tail states that it reads every header line is still lent every line.
#[tokio::test]
async fn an_all_headers_admin_module_is_lent_every_line() {
    let reader = stray_reader(busbar_contract::abi::auth::FACT_INBOUND_ALL_HEADERS);
    let app = reader_admin_app(std::sync::Arc::clone(&reader));
    let mut headers = admin_headers(Some("tok"), None);
    headers.insert(
        HeaderName::from_static(STRAY_LINE),
        HeaderValue::from_static("other"),
    );
    headers.insert(
        HeaderName::from_static("x-unnamed"),
        HeaderValue::from_static("1"),
    );
    let _ = run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await;
    let lent = reader.lent.lock().unwrap();
    let lines = lent.last().expect("the module was called");
    for name in [STRAY_LINE, "x-unnamed", "authorization"] {
        assert!(
            lines.iter().any(|n| n.eq_ignore_ascii_case(name)),
            "{name} not lent: {lines:?}"
        );
    }
}
