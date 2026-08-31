use super::*;
use axum::http::header::CONTENT_TYPE;
use busbar_api::ScopeRef;

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

    // Open posture (no principal): full.
    assert_eq!(admin_scope_for(None, None, &rb), Grants::of(Scope::Full));
    // The operator principal (admin-tokens): full by definition, no binding required.
    #[cfg(feature = "auth-admin-tokens")]
    assert_eq!(
        admin_scope_for(
            Some(crate::config::ADMIN_TOKENS_MODULE),
            Some(&Principal::from_id(
                busbar_auth_admin_tokens::ADMIN_TOKENS_PRINCIPAL_ID
            )),
            &rb
        ),
        Grants::of(Scope::Full)
    );
    // Role-bound: the union of the principal's bound roles. `with` is a plain bitwise union (never
    // canonicalized), so `{read-only} ∪ {full}` keeps BOTH bits rather than collapsing to `{full}` —
    // asserted on `allows`, the actual authorization behaviour, not the raw bit pattern.
    let p = grp_principal("test:alice", &["viewers", "admins"]);
    assert!(admin_scope_for(module, Some(&p), &rb).allows(Scope::Full));
    let p = grp_principal("test:alice", &["viewers"]);
    assert_eq!(
        admin_scope_for(module, Some(&p), &rb),
        Grants::of(Scope::ReadOnly)
    );
    // Unbound roles grant nothing (fail closed).
    let p = grp_principal("test:alice", &["strangers"]);
    assert_eq!(admin_scope_for(module, Some(&p), &rb), Grants::default());
    // A role bound WITHOUT an admin_scope grants nothing.
    let p = grp_principal("test:alice", &["no-admin"]);
    assert_eq!(admin_scope_for(module, Some(&p), &rb), Grants::default());
    // A roleless NON-operator principal gets nothing (an external module cannot mint the
    // operator identity by returning a bare id).
    let stranger = Principal::from_id("test:bob");
    assert_eq!(
        admin_scope_for(module, Some(&stranger), &rb),
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
    let p = grp_principal("test:alice", &["admins"]);
    assert!(
        admin_scope_for(Some("test-groups-module"), Some(&p), &rb) == Grants::default(),
        "a role asserted by module A must not ride module B's binding"
    );
    // Control: the SAME principal identified by the binding's own module resolves.
    assert_eq!(
        admin_scope_for(Some("other-module"), Some(&p), &rb),
        Grants::of(Scope::Full)
    );
    // A module with no binding table at all grants nothing.
    assert_eq!(
        admin_scope_for(Some("unbound-module"), Some(&p), &rb),
        Grants::default()
    );
}

/// Assert a string is canonical UUID-v4 shaped: five dash-separated lowercase-hex groups of
/// lengths 8-4-4-4-12, with the version nibble == '4' and the variant nibble in {8,9,a,b}.
fn assert_uuid_v4_shaped(id: &str) {
    let segs: Vec<&str> = id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-requestid must be UUID-v4 shaped (8-4-4-4-12), got '{id}'"
    );
    assert!(
        id.chars()
            .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "UUID must be lowercase hex with dashes only, got '{id}'"
    );
    // Version nibble: first char of the third group.
    assert_eq!(
        segs[2].chars().next(),
        Some('4'),
        "UUID version nibble must be 4, got '{id}'"
    );
    // Variant nibble: first char of the fourth group must be one of 8,9,a,b.
    assert!(
        matches!(segs[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
        "UUID variant nibble must be 8/9/a/b, got '{id}'"
    );
}

// `test_synth_amzn_request_id_is_uuid_v4` RELOCATED to `busbar-llm`
// (`src/tests/proto/phase1_5_relocated_tests.rs`): it named the
// witnessed `bedrock::synth_amzn_request_id` codec fn directly, so it now lives beside that codec.
// `assert_uuid_v4_shaped` stays here — its other callers below still use it.

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

/// `upstream_credentials` selects WHOSE credential goes upstream; it does not gate the front
/// door. With an empty chain both modes admit everything (the old none/passthrough split is now
/// chain-shape for the front door + this knob for egress). 1.5.3: the knob itself moved OFF `auth:`
/// onto the `pools:` section, so the middleware no longer carries it at all — which is the strongest
/// possible form of "it does not gate the front door".
#[test]
fn test_open_door_regardless_of_upstream_creds() {
    for uc in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        let cfg = crate::config::AuthCfg::default_none();
        let mw = AuthMiddleware::new_builtin(&cfg);
        assert!(mw.validate_token(None));
        assert!(mw.validate_token(Some("anything")));
        // The mode lives on the App (all-pools default + per-pool override), not on the chain.
        let app = crate::test_support::TestApp::new()
            .upstream_creds(uc)
            .build();
        assert_eq!(app.upstream_creds(), uc);
    }
}

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
    let req = req_with("x-api-key", "tok-anthropic");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-anthropic".to_string())
    );
}

#[test]
fn test_extract_client_token_x_goog_api_key() {
    // Gemini SDK carrier: raw token, no scheme prefix.
    let req = req_with("x-goog-api-key", "tok-gemini");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-gemini".to_string())
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
        .header("x-goog-api-key", "tok-gemini")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("tok-gemini".to_string())
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
        "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/bedrock/aws4_request, \
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
            "AWS4-HMAC-SHA256 Credential=AKIA.../bedrock/aws4_request",
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

/// The dialect an auth-failure envelope is shaped in for `path`, on a deployment with NO plane
/// mounted — the residual arm of the ONE resolver `unauthorized_response` reads. A mounted plane's
/// answer is a different arm entirely and is pinned where the mount lives (`plane_tests`, and the
/// live-stack 413 tests in `crate::tests`).
fn residual_dialect(path: &str) -> &'static str {
    crate::ingress::native::envelope_dialect(
        crate::plane::PlaneDispatch::default().ingress_of(path),
    )
}

/// A deployment with no plane mounted, so every path below resolves through the residual arm.
fn residual_app() -> std::sync::Arc<crate::state::App> {
    crate::test_support::TestApp::new().build()
}

#[test]
fn test_residual_dialect_inference() {
    assert_eq!(
        residual_dialect("/v1beta/models/gemini-1.5:generateContent"),
        "gemini"
    );
    // The stable `v1` Gemini alias the router also registers (`/v1/models/*rest`). A colon
    // `:<action>` in the final segment is the Gemini generateContent/streamGenerateContent shape
    // → gemini (mirrors main.rs::proto_for_path so the two classifiers cannot drift).
    assert_eq!(
        residual_dialect("/v1/models/gemini-pro:generateContent"),
        "gemini"
    );
    assert_eq!(
        residual_dialect("/v1/models/gemini-1.5-pro:streamGenerateContent"),
        "gemini"
    );
    // `/v1/models/...` WITHOUT a colon action is the OpenAI `model.retrieve` shape (`GET
    // /v1/models/{id}`) — shape the auth error as OpenAI so an OpenAI SDK gets a decodable body.
    assert_eq!(residual_dialect("/v1/models/gpt-4o"), "openai");
    // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
    assert_eq!(residual_dialect("/v1beta/models/gemini-pro"), "gemini");
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse"),
        "bedrock"
    );
    assert_eq!(
        residual_dialect("/model/anthropic.claude/converse-stream"),
        "bedrock"
    );
    // A pool/model literally named "model" hitting `/model/v1/messages` must NOT be classified
    // as bedrock (no `/converse[-stream]` suffix) — it falls through to anthropic.
    assert_eq!(residual_dialect("/model/v1/messages"), "anthropic");
    // `/model/` prefix without a Converse suffix and without `/v1/messages` is unknown → openai.
    assert_eq!(residual_dialect("/model/foo/bar"), "openai");
    assert_eq!(residual_dialect("/v1/messages"), "anthropic");
    assert_eq!(residual_dialect("/pa/v1/messages"), "anthropic");
    assert_eq!(
        residual_dialect("/anthropic/claude/v1/messages"),
        "anthropic"
    );
    assert_eq!(residual_dialect("/v1/chat/completions"), "openai");
    assert_eq!(residual_dialect("/v2/chat"), "cohere");
    assert_eq!(residual_dialect("/v1/responses"), "responses");
    // Unknown → generic (openai-shaped) envelope.
    assert_eq!(residual_dialect("/stats"), "openai");
}

/// Decode the JSON body of an `unauthorized_response` for shape assertions. Synchronously
/// drains the (in-memory, already-complete) body — no network, no runtime needed.
fn decode_body(resp: Response) -> serde_json::Value {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test body must collect")
    });
    serde_json::from_slice(&bytes).expect("auth-failure body must be valid JSON")
}

#[test]
fn test_unauthorized_response_is_json_with_native_envelope() {
    // Every supported ingress protocol must get its DISTINCTIVE native error SHAPE, not just
    // `application/json` — a wrong-shaped 401 is a deterministic proxy tell a native SDK
    // would choke on. One assertion per `proto_for_path` arm.

    // Gemini → {"error":{"code":400,"message":..,"status":"INVALID_ARGUMENT"}}, HTTP 400. The
    // genuine Generative Language API does NOT return 401/UNAUTHENTICATED for a bad API key; it
    // returns HTTP 400 INVALID_ARGUMENT. A 401/UNAUTHENTICATED body is a tell the google-genai
    // SDK never sees from real Google on the bad-key path.
    let resp = unauthorized_response(&residual_app(), "/v1beta/models/x:generateContent");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "gemini body: {body}"
    );

    // Gemini stable-v1 alias (`/v1/models/<m>:generateContent`) must shape IDENTICALLY to the
    // v1beta surface — an earlier bug mis-shaped it as an OpenAI 401.
    let resp = unauthorized_response(&residual_app(), "/v1/models/gemini-pro:generateContent");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "stable-v1 gemini status"
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "stable-v1 gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "stable-v1 gemini body: {body}"
    );

    // Anthropic → top-level {"type":"error","error":{"type":"authentication_error",..}}.
    let resp = unauthorized_response(&residual_app(), "/pa/v1/messages");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = decode_body(resp);
    assert_eq!(body["type"], "error", "anthropic top-level type: {body}");
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "anthropic error.type: {body}"
    );

    // OpenAI → {"error":{"type":"authentication_error","code":"invalid_api_key",..}} (no
    // top-level type=error). The genuine OpenAI bad-key 401 body carries
    // `error.code: "invalid_api_key"`, which the official SDK surfaces as
    // `AuthenticationError.code`; emitting `code: null` is a deterministic proxy tell. The
    // writers pair that code ONLY with `error.type: "authentication_error"`, so the envelope
    // must carry that pairing on the most common failure path.
    let resp = unauthorized_response(&residual_app(), "/v1/chat/completions");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "openai auth status"
    );
    let body = decode_body(resp);
    assert!(
        body.get("type").is_none(),
        "openai must NOT carry a top-level type: {body}"
    );
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "openai error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
            body["error"]["code"], "invalid_api_key",
            "openai bad-key body must carry code=invalid_api_key (not null), the SDK-visible tell: {body}"
        );

    // Responses → {"error":{"type":"authentication_error","code":"invalid_api_key","param":null,..}}
    // (same OpenAI-family bad-key shape, with the SDK-visible code populated).
    let resp = unauthorized_response(&residual_app(), "/v1/responses");
    let body = decode_body(resp);
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "responses error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
        body["error"]["code"], "invalid_api_key",
        "responses bad-key body must carry code=invalid_api_key (not null): {body}"
    );
    assert!(
        body["error"].get("param").is_some(),
        "responses envelope carries a param field: {body}"
    );

    // Cohere → bare {"message":..} with NO `error` and NO `type`.
    let resp = unauthorized_response(&residual_app(), "/v2/chat");
    let body = decode_body(resp);
    assert!(
        body.get("message").is_some(),
        "cohere body has a top-level message: {body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "cohere body must be bare (no error/type): {body}"
    );

    // Bedrock → {"__type":"AccessDeniedException","message":..}, HTTP 403, x-amzn-* headers.
    let resp = unauthorized_response(&residual_app(), "/model/anthropic.claude/converse");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Bedrock SigV4 auth failure is 403, not 401"
    );
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry a synthetic x-amzn-requestid")
        .to_string();
    // Real Bedrock x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12 lowercase hex). A flat
    // 32-hex-no-dashes value is a protocol tell — assert the canonical shape, not just presence.
    assert_uuid_v4_shaped(&req_id);
    let body = decode_body(resp);
    assert_eq!(
        body["__type"], "AccessDeniedException",
        "bedrock __type: {body}"
    );
    assert!(
        body.get("error").is_none(),
        "bedrock body uses __type, not an error object: {body}"
    );
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
    // Sweep EVERY supported ingress path (incl. the unknown-path fallback) and assert no leaked
    // token appears anywhere in the JSON. The invalid-vs-disabled distinction must also be gone.
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
        "/v1beta/models/x:generateContent", // gemini
        "/pa/v1/messages",                  // anthropic
        "/v1/chat/completions",             // openai
        "/v1/responses",                    // responses
        "/v2/chat",                         // cohere
        "/model/anthropic.claude/converse", // bedrock
        "/api/v1/admin/keys",               // admin path → inferred-proto fallback (openai)
        "/totally/unknown/path",            // unknown → openai fallback
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
fn test_vendor_auth_failure_message_is_plausible_per_proto() {
    // The wire message is keyed PURELY off the inferred protocol (independent of the failure
    // reason) and reads like genuine vendor copy. Lock the exact strings so a regression that
    // reintroduces busbar wording — or distinguishes invalid-vs-disabled — is caught.
    assert_eq!(
        vendor_auth_failure_message("anthropic"),
        "invalid x-api-key"
    );
    assert_eq!(
        vendor_auth_failure_message("openai"),
        "Incorrect API key provided."
    );
    assert_eq!(
        vendor_auth_failure_message("responses"),
        "Incorrect API key provided."
    );
    // Byte-for-byte the gemini codec's `GEMINI_BAD_KEY_MESSAGE`, pinned as a literal (like the five
    // siblings above) so this core auth test names no dialect module; gemini owns the const's value.
    assert_eq!(
        vendor_auth_failure_message("gemini"),
        "API key not valid. Please pass a valid API key."
    );
    assert_eq!(vendor_auth_failure_message("cohere"), "invalid api token");
    // AWS conveys AccessDenied via __type / x-amzn-errortype, not a message string.
    assert_eq!(vendor_auth_failure_message("bedrock"), "");
    // Any unknown future proto: a neutral credential message, never busbar vocabulary.
    assert_eq!(
        vendor_auth_failure_message("some-future-proto"),
        "authentication failed"
    );
}

#[test]
fn test_every_router_ingress_path_maps_to_non_fallback_proto() {
    // Coupling guard (router route table ↔ proto_for_path ↔ protocol_for). Each real
    // ingress path the router registers must resolve to a SPECIFIC proto, not the unknown-path
    // `openai` fallback applied via the final `else`. If a future route is added without
    // updating proto_for_path, callers on that protocol would silently get an OpenAI-shaped 401
    // — a partial defeat of the indistinguishability promise. We assert the expected mapping
    // explicitly (a sample path per registered ingress family), so a regression is caught.
    let cases = [
        ("/v1/messages", "anthropic"),
        ("/somepool/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/v2/chat", "cohere"),
        ("/v1/responses", "responses"),
        ("/v1beta/models/gemini-1.5:generateContent", "gemini"),
        // BOTH Gemini ingress prefixes the router registers (main.rs) must resolve to a
        // non-fallback proto. The stable `v1` alias was previously omitted here, masking the
        // missing `/v1/models/` arm in the residual classifier (a `:`-action path mis-shaped
        // as openai).
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
    ];
    for (path, expected) in cases {
        assert_eq!(
            residual_dialect(path),
            expected,
            "router ingress path '{path}' must map to '{expected}', not the fallback"
        );
        // And the resolved proto must be a real protocol (never the dead `None` arm). Neutral
        // registry seam: a KNOWN protocol has a registered declaration (`decl_for`), reached
        // without naming the witnessed codec (`protocol_for`).
        assert!(
            crate::proto::decl_for(residual_dialect(path)).is_some(),
            "proto for '{path}' must resolve to a known protocol"
        );
    }
}

/// End-to-end through the real router + `auth_middleware` with a CONFIGURED chain: the busbar
/// client credential authenticates via `x-goog-api-key` (Gemini SDK), via `x-api-key` (Anthropic
/// SDK), and via `Authorization: Bearer`. A missing/wrong credential is rejected 401 with the
/// native error envelope shaped for the inferred ingress protocol (`application/json`, not
/// `text/plain`). The chain is the test-groups-module (`grp:<role>` identifies).
#[tokio::test]
async fn test_chain_accepts_all_carriers_and_native_401() {
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let token = "grp:carrier";

    let state = Arc::new(MockServerState::new());
    // Three admitted requests reach the upstream; queue three OK bodies.
    for _ in 0..3 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
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

    // Bearer still works.
    let r_bearer = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
        "valid token via Authorization: Bearer must pass (got {})",
        r_bearer.status()
    );

    // x-api-key (Anthropic SDK carrier) works.
    let r_xapi = client
        .post(&url)
        .header("x-api-key", token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
        "valid token via x-api-key must pass (got {})",
        r_xapi.status()
    );

    // x-goog-api-key (Gemini SDK carrier) works.
    let r_goog = client
        .post(&url)
        .header("x-goog-api-key", token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_goog.status().as_u16(),
        200,
        "valid token via x-goog-api-key must pass (got {})",
        r_goog.status()
    );

    // Wrong token via x-api-key → 401 with native (anthropic, inferred from /v1/messages) envelope.
    let r_wrong = client
        .post(&url)
        .header("x-api-key", "not-the-token")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r_wrong.status().as_u16(), 401, "wrong token must be 401");
    assert_eq!(
        r_wrong
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "401 must carry application/json native envelope, not text/plain"
    );
    let env: serde_json::Value = r_wrong.json().await.unwrap();
    // Anthropic native error envelope: {"type":"error","error":{...}}.
    assert!(
        env.get("error").is_some(),
        "native error envelope must contain an `error` object: {env}"
    );

    // Missing credential entirely → 401 (still JSON).
    let r_missing = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_missing.status().as_u16(),
        401,
        "missing token must be 401"
    );
    assert_eq!(
        r_missing
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: an unauthenticated
/// POST to `/v2/chat` (Cohere) and `/v1/responses` (Responses) must be rejected 401 with the
/// RESPECTIVE protocol's native error envelope — not an Anthropic/OpenAI-shaped body. The
/// existing multi-carrier test only covers the Anthropic path, leaving these two protocol
/// envelopes untested on the auth boundary (an indistinguishability failure if regressed).
#[tokio::test]
async fn test_cohere_and_responses_ingress_token_mode_native_401() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call is made — auth rejects before routing — but TestApp needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new("test-model", crate::proto::PROTO_OPENAI, &server.base_url())
                .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}]}).to_string();

    // Cohere `/v2/chat` → bare {"message":..}, no `error`, no `type`.
    let r_cohere = client
        .post(format!("http://{addr}/v2/chat"))
        .header("x-api-key", "wrong-token")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r_cohere.status().as_u16(), 401, "cohere wrong token → 401");
    assert_eq!(
        r_cohere
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_cohere.json().await.unwrap();
    assert!(
        env.get("message").is_some(),
        "cohere 401 must carry a bare message: {env}"
    );
    assert!(
        env.get("error").is_none() && env.get("type").is_none(),
        "cohere 401 must be the bare envelope (no error/type): {env}"
    );

    // Responses `/v1/responses` → {"error":{"type":"authentication_error","code":"invalid_api_key",..}}
    // (the genuine OpenAI-family bad-key 401 carries the SDK-visible code=invalid_api_key, which
    // the writers pair with type=authentication_error).
    let r_resp = client
        .post(format!("http://{addr}/v1/responses"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_resp.status().as_u16(), 401, "responses wrong token → 401");
    assert_eq!(
        r_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_resp.json().await.unwrap();
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "responses 401 must carry error.type=authentication_error: {env}"
    );
    assert_eq!(
        env["error"]["code"], "invalid_api_key",
        "responses 401 must carry the SDK-visible code=invalid_api_key (not null): {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on the
/// Bedrock ingress path (`/model/<id>/converse`) must be rejected with HTTP 403 (NOT 401 —
/// a native SigV4 auth failure is 403) carrying `x-amzn-errortype: AccessDeniedException`, a
/// UUID-v4-shaped `x-amzn-requestid`, and a body whose `__type` is `AccessDeniedException`. The
/// existing end-to-end auth tests only cover anthropic/cohere/responses; the bedrock-specific
/// status + typing headers were exercised only by a direct `unauthorized_response` call that
/// bypasses the middleware → router stack, so a regression dropping the 403/headers in the full
/// pipeline would be uncaught.
#[tokio::test]
async fn test_bedrock_ingress_wrong_token_is_403_native_envelope() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // Auth rejects before routing, so no upstream call is made; TestApp still needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string();

    let r = client
        .post(format!("http://{addr}/model/anthropic.claude/converse"))
        .header("authorization", "Bearer wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status().as_u16(),
        403,
        "a Bedrock SigV4 auth failure must be 403, not 401 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = r
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry x-amzn-requestid")
        .to_string();
    assert_uuid_v4_shaped(&req_id);
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        env["__type"], "AccessDeniedException",
        "bedrock body must use __type=AccessDeniedException: {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on EITHER
/// registered Gemini ingress prefix — the `v1beta` surface (`/v1beta/models/<id>:generateContent`)
/// AND the stable `v1` alias (`/v1/models/<id>:generateContent`) — must be rejected with the
/// Gemini-native bad-key envelope: HTTP 400, `error.code == 400`, `error.status ==
/// "INVALID_ARGUMENT"` (a real Generative Language API bad key is 400 INVALID_ARGUMENT, NOT
/// 401/UNAUTHENTICATED). The stable-v1 path was previously mis-shaped as an OpenAI 401 because
/// `proto_for_path` had no `/v1/models/` arm — this exercises both prefixes through the full stack.
#[tokio::test]
async fn test_gemini_ingress_wrong_token_is_native_bad_key_envelope() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}).to_string();

    // Both registered Gemini ingress prefixes must produce the identical native bad-key envelope.
    for path in [
        "/v1beta/models/gemini-1.5:generateContent",
        "/v1/models/gemini-1.5:generateContent",
    ] {
        let r = client
            .post(format!("http://{addr}{path}"))
            .header("x-goog-api-key", "wrong-token")
            .body(body.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(
            r.status().as_u16(),
            400,
            "a Gemini bad-key auth failure on '{path}' must be 400 INVALID_ARGUMENT (got {})",
            r.status()
        );
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let env: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            env["error"]["code"], 400,
            "gemini error.code on '{path}': {env}"
        );
        assert_eq!(
            env["error"]["status"], "INVALID_ARGUMENT",
            "gemini error.status on '{path}' must be INVALID_ARGUMENT: {env}"
        );
    }

    handle.abort();
    server.shutdown().await;
}

/// Regression for the over-broad admin-prefix detection: a path that merely STARTS WITH the
/// bytes `/api` but is not a registered `/api/...` route (e.g. `/apix/...`) must NOT be
/// classified as admin. Under TOKEN mode with a wrong token it should be rejected by the normal
/// auth branch with the inferred-protocol native 401 envelope — never routed down the admin
/// branch (which would early-return without the `CallerToken` extension and 500 in a non-admin
/// handler). `/apix/v1/messages` infers the anthropic protocol via the `/v1/messages` suffix.
#[tokio::test]
async fn test_admin_prefix_is_boundary_safe() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = chain_cfg(&["test-groups-module"]);
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto::PROTO_ANTHROPIC,
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("apix", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body =
        json!({"model": "apix", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Wrong token to `/apix/v1/messages`: rejected by the NORMAL auth branch, not the admin
    // branch — a normal-protocol native 401 (anthropic), NOT the admin "admin unauthorized"
    // path and NOT a 500 from a missing CallerToken extension.
    let r = client
        .post(format!("http://{addr}/apix/v1/messages"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "an /apix path with a wrong token must be a normal 401, not 500/admin-500 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    // Anthropic native envelope (inferred from the `/v1/messages` suffix), proving the path was
    // shaped by the normal ingress branch rather than the admin branch.
    assert_eq!(env["type"], "error", "expected anthropic envelope: {env}");
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "expected anthropic authentication_error: {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware`: a virtual key with `enabled: false`
/// must be rejected with 401, while the same secret on an enabled key is admitted. Guards the
/// `Some(key) if key.enabled => ... else 401` authz path, which had no test (a regression that
/// dropped the `if key.enabled` guard would otherwise pass CI — an authz bypass).
#[tokio::test]
async fn test_disabled_virtual_key_is_rejected_401() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // Mock upstream that returns a valid Anthropic-shaped body, so an ADMITTED request reaches
    // 200 rather than failing for an unrelated reason.
    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            }),
        });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let mk_spec = |name: &str| crate::governance::NewKeySpec {
        name: name.to_string(),
        allowed_pools: Some(vec!["pa".to_string()]),
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (dis_key, disabled_secret) = gov
        .mint_signed(mk_spec("kdis"), 2_000_000_000, 1_000_000_000)
        .unwrap();
    let (_ena_key, enabled_secret) = gov
        .mint_signed(mk_spec("kena"), 2_000_000_000, 1_000_000_000)
        .unwrap();
    // Freeze the first key via the PATCH-shaped update (mint always starts `enabled: true`).
    gov.update_key(&dis_key.id, Some(false), None).unwrap();
    let disabled_secret = disabled_secret.as_str();
    let enabled_secret = enabled_secret.as_str();

    let app = TestApp::new()
        .lane(
            LaneSpec::new("glm-4.5", crate::proto::PROTO_OPENAI, &server.base_url())
                .provider("zai"),
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
    let req =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Disabled key → 401.
    let r_dis = client
        .post(&url)
        .bearer_auth(disabled_secret)
        .body(req.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_dis.status().as_u16(),
        401,
        "a disabled virtual key must be rejected"
    );

    // Unknown secret → 401 (control: lookup miss is the same 401 path).
    let r_bogus = client
        .post(&url)
        .bearer_auth("sk-vk-nope")
        .body(req.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bogus.status().as_u16(),
        401,
        "unknown key must be rejected"
    );

    // Enabled key with the same shape → NOT 401 (admitted past auth).
    let r_ena = client
        .post(&url)
        .bearer_auth(enabled_secret)
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ena.status().as_u16(),
        200,
        "an enabled virtual key must pass auth (got {})",
        r_ena.status()
    );

    handle.abort();
    server.shutdown().await;
}

#[test]
fn test_extract_admin_header_token_empty_filtered() {
    // A present-but-blank `x-admin-token` must be treated as
    // ABSENT, mirroring the empty-filter `extract_client_token` applies to the vendor carriers.
    // The OLD code mapped a blank header to `Some("")` (no `.filter(|t| !t.is_empty())`), so this
    // unit test fails against it; the filtered helper now yields `None`.
    let blank = req_with(X_ADMIN_TOKEN, "");
    assert_eq!(
        extract_admin_header_token(&blank),
        None,
        "a blank x-admin-token must be treated as absent (None)"
    );

    // A whitespace-only value is NOT blank (it is a non-empty string); it is preserved verbatim
    // and will simply fail the constant-time compare downstream — the filter is empty-only, not a
    // trim, matching extract_client_token's carrier filter exactly.
    let present = req_with(X_ADMIN_TOKEN, "admintok");
    assert_eq!(
        extract_admin_header_token(&present),
        Some("admintok".to_string()),
        "a non-empty x-admin-token must be carried verbatim"
    );

    // Absent header → None (unchanged).
    let absent = Request::builder()
        .uri("/api/v1/admin/keys")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(extract_admin_header_token(&absent), None);
}

/// A present-but-blank `x-admin-token` must be rejected on
/// the admin surface. Driven end-to-end through the real router + `auth_middleware` so the
/// extraction + constant-time compare are exercised together. A correct token via the same header
/// authorizes, proving the 401 is the empty-filter and not a blanket reject.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_blank_header_token_rejected() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Blank x-admin-token (and no Bearer) → 401: a blank header is treated as absent.
    let r_blank = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_blank.status().as_u16(),
        401,
        "a blank x-admin-token must be rejected (treated as absent), got {}",
        r_blank.status()
    );

    // Correct x-admin-token → authorized, proving the reject above is the empty-filter.
    let r_ok = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a correct x-admin-token must authorize, got {}",
        r_ok.status()
    );

    handle.abort();
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

    let n = crate::admin::audit::AUDIT
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

/// Regression for the admin-token carrier-level timing oracle: the two admin
/// carriers (Authorization: Bearer and x-admin-token) are combined with a bitwise-OR fold, NOT a
/// short-circuiting `||`. Behaviorally this means EITHER carrier alone authorizes, AND a request
/// presenting BOTH carriers is authorized whenever EITHER matches — regardless of which one. We
/// drive it through the real router so the inline fold in `auth_middleware` is exercised:
///   - correct Bearer + wrong x-admin-token  → authorized (header compare ran, didn't veto)
///   - wrong Bearer  + correct x-admin-token  → authorized (Bearer miss didn't short-circuit away
///                                               the header compare)
///   - wrong + wrong                          → 401
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_both_carriers_or_fold_no_short_circuit() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Correct Bearer + WRONG x-admin-token → authorized (the header compare must not veto a
    // matching Bearer; the fold is OR, not AND).
    let r = client
        .get(&url)
        .bearer_auth("admintok")
        .header(X_ADMIN_TOKEN, "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "correct Bearer + wrong x-admin-token must authorize (OR fold), got {}",
        r.status()
    );

    // WRONG Bearer + correct x-admin-token → authorized. This is the short-circuit regression: a
    // `||` would have stopped after the Bearer miss only if the header were checked next, but the
    // real risk is the inverse ordering — assert the header compare is reached and admits.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "wrong Bearer + correct x-admin-token must authorize (header compare must run), got {}",
        r.status()
    );

    // Both wrong → 401.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "also-wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "both carriers wrong must be rejected"
    );

    handle.abort();
}

// ── 1.5.2 admin-plane OIDC: scope collapse authorization + external admin-module dispatch/offload ──

/// A test-only external admin module that SLEEPS on the (blocking-pool) thread before returning —
/// stands in for a wedged admin IdP doing blocking JWKS/introspection I/O. Returns `Pass` (so the
/// chain fail-closed-denies) once it wakes. Injected via `TestApp::admin_module`, which forces
/// `has_plugin`, so the admin middleware OFFLOADS it off the reactor.
struct SleepingAdminModule(std::time::Duration);
impl crate::auth::AuthModule for SleepingAdminModule {
    fn name(&self) -> &'static str {
        "slow-oidc"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> crate::auth::AuthOutcome {
        std::thread::sleep(self.0);
        crate::auth::AuthOutcome::Pass
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
    fn authenticate(&self, _candidate: Option<&str>) -> crate::auth::AuthOutcome {
        crate::auth::AuthOutcome::Identify(Principal::from_id("admin"))
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

/// Regression for the admin-surface carrier-separation invariant promised
/// by the comment at the top of the `is_admin` branch: the `/admin` operator surface is guarded
/// ONLY by `Authorization: Bearer` and `x-admin-token` — NOT by the vendor-SDK client-token
/// carriers (`x-api-key` / `x-goog-api-key`) that `extract_client_token` also reads. A future
/// DRY refactor unifying admin extraction onto `extract_client_token` would let the operator
/// admin token be presented via the carriers every native vendor SDK populates, turning any
/// leaked/observed client header into operator-surface (key create/delete) access. This pins the
/// boundary: the CORRECT admin secret presented via `x-api-key` or `x-goog-api-key` MUST 401,
/// while the two sanctioned admin carriers MUST authorize.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_not_acceptable_via_vendor_carriers() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // The admin secret presented via the vendor-SDK carriers MUST be rejected: these carriers are
    // the client-token surface, NOT the operator surface. Exercise BOTH carriers, on BOTH the
    // GET (list) and POST (create) admin verbs, since the admin auth branch is verb-agnostic.
    for carrier in ["x-api-key", "x-goog-api-key"] {
        let r_get = client
            .get(&url)
            .header(carrier, "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_get.status().as_u16(),
            401,
            "admin secret via {carrier} (GET) must NOT reach the admin surface, got {}",
            r_get.status()
        );

        let r_post = client
            .post(&url)
            .header(carrier, "admintok")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_post.status().as_u16(),
            401,
            "admin secret via {carrier} (POST) must NOT reach the admin surface, got {}",
            r_post.status()
        );
    }

    // The two sanctioned admin carriers MUST authorize (proving the 401s above are carrier
    // separation, not a blanket reject).
    let r_bearer = client
        .get(&url)
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
        "Authorization: Bearer admintok must authorize the admin surface, got {}",
        r_bearer.status()
    );
    let r_hdr = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_hdr.status().as_u16(),
        200,
        "x-admin-token: admintok must authorize the admin surface, got {}",
        r_hdr.status()
    );

    handle.abort();
}

/// THE MCP PLANE BOUNDARY end-to-end through the real router + `auth_middleware` in GOVERNANCE
/// mode (1.6.0): an AUDIENCE-BOUND token whose `sub` is a
/// fully valid enabled binding must be rejected 401 on the data plane - both a proxy ingress
/// route (`/pa/v1/messages`) and a chain-verdict-only route (`/stats`, which admits on the chain
/// verdict alone and so shows the blast radius is EVERY key-authenticated route, not just the
/// proxy ones) - while the sibling PLAIN token for the same binding is admitted. Before the boundary,
/// serde ignored the unknown `a` claim and the MCP token was silently a full data-plane key.
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
                name: "mcp-agent".to_string(),
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
        .verify(plain_token.as_str(), 1_000_000_000, None)
        .expect("plain claims")
        .generation;
    let bound_token = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        "https://busbar.example.com/mcp",
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
        .header("authorization", format!("Bearer {}", plain_token.as_str()))
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

/// End-to-end through the real router + `auth_middleware` in GOVERNANCE mode, exercising the
/// non-`Authorization` carriers (`x-goog-api-key`, `x-api-key`) into the virtual-key lookup.
/// The existing governance test only uses `Authorization: Bearer`, and the multi-carrier test
/// runs under static-token mode (`governance=None`) — so the intersection (a virtual key
/// presented via a vendor-SDK carrier resolving the governance lookup) was untested. A
/// regression that stopped threading those carriers into `gov.lookup` would otherwise pass CI.
#[tokio::test]
async fn test_governance_accepts_vendor_carriers_and_native_401() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    // Two admitted requests (x-goog-api-key, x-api-key) reach the upstream; queue two bodies.
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (_key, token) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "kc".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

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

    // Valid virtual key via x-goog-api-key (Gemini SDK carrier) → admitted past governance auth.
    let r_goog = client
        .post(&url)
        .header("x-goog-api-key", secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_goog.status().as_u16(),
        200,
        "valid virtual key via x-goog-api-key must pass governance (got {})",
        r_goog.status()
    );

    // Valid virtual key via x-api-key (Anthropic SDK carrier) → admitted past governance auth.
    let r_xapi = client
        .post(&url)
        .header("x-api-key", secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
        "valid virtual key via x-api-key must pass governance (got {})",
        r_xapi.status()
    );

    // Bad secret via x-goog-api-key → native JSON 401 (governance lookup miss).
    let r_bad = client
        .post(&url)
        .header("x-goog-api-key", "sk-vk-nope")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "an unknown virtual key via x-goog-api-key must be 401"
    );
    assert_eq!(
        r_bad
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "401 must carry the native application/json envelope, not text/plain"
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
    use crate::governance::{GovState, MemoryStore, ScopeRef, Store, VirtualKey};
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
            generation_hash: crate::sigv4::sha256_hex(b""),
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

/// A signed-token key must STOP authenticating after `revoke`, even though `revoke` denylists the
/// subject but DELIBERATELY leaves `enabled = true` (it preserves the binding for history) — so
/// the `enabled` check alone is not enough, `verify_token` must also consult the denylist.
/// (Formerly also covered the now-removed legacy hashed-secret `gov.lookup(secret)` fallback,
/// which had the same regression via a separate code path; that path no longer exists — see 1.5.0
/// migration notes, "1.4.x keys no longer authenticate" — so this test now exercises only the
/// signed-token path.)
#[tokio::test]
async fn test_governance_revoked_signed_token_key_rejected() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let (key, token) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "revocable".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

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
        .governance(gov.clone())
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

    // Baseline: the freshly-minted signed token authenticates (200, proxied upstream).
    let ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        ok.status().as_u16(),
        200,
        "a live signed-token key must authenticate (got {})",
        ok.status()
    );

    // Revoke the subject (denylists it WITHOUT flipping `enabled`, exactly as `revoke_key` does).
    gov.revoke(&key.id, "audit regression").unwrap();
    assert!(gov.is_revoked(&key.id), "revoke must denylist the subject");

    // The same token must now be REJECTED 401 — a revoked key's signed token is dead.
    let denied = client
        .post(&url)
        .bearer_auth(secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status().as_u16(),
        401,
        "a REVOKED signed-token key's Bearer token must be rejected (got {})",
        denied.status()
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

// ===================== INBOUND BEDROCK SigV4 WIRING TESTS =====================

/// Sign a Bedrock-shaped POST and return the full `Authorization` header value plus the headers
/// (host / x-amz-date / x-amz-content-sha256) the client would send, using the SAME signer
/// (`crate::sigv4::sign_v4`) a real client uses. `amzdate` controls the signature timestamp.
fn sign_bedrock_request(
    secret: &str,
    access_key_id: &str,
    region: &str,
    service: &str,
    path: &str,
    body: &[u8],
    amzdate: &str,
) -> (String, Vec<(String, String)>) {
    let datestamp = &amzdate[0..8];
    let payload_hash = crate::sigv4::sha256_hex(body);
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let canonical_uri = crate::sigv4::uri_encode_path(path);
    let (sig, signed_headers) = crate::sigv4::sign_v4(
        secret,
        region,
        service,
        "POST",
        &canonical_uri,
        "",
        &headers,
        &payload_hash,
        amzdate,
        datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{datestamp}/{region}/{service}/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
    );
    (auth, headers)
}

/// Build a `Request` with the given Authorization + signed headers (for `verify_bedrock_sigv4`).
fn bedrock_request(path: &str, auth: &str, headers: &[(String, String)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(AUTHORIZATION, auth);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(Body::empty()).expect("test request must build")
}

fn gov_with_aws_key() -> (std::sync::Arc<crate::governance::GovState>, String, String) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, None).unwrap());
    let (_key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            crate::store::now(),
        )
        .unwrap();
    (gov, akid, secret)
}

#[test]
fn test_verify_bedrock_sigv4_roundtrip_admits_with_govctx() {
    // A request signed with the key's REAL secret verifies and yields the owning (enabled) key.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let amzdate = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &amzdate);
    let req = bedrock_request(path, &auth, &headers);
    let key =
        verify_bedrock_sigv4(&gov, &req, b"").expect("a correctly-signed request must verify");
    // Behavioral: the function resolved the SPECIFIC owning key (not just "some enabled key").
    // Tying to the key's identity (name) is a stronger statement than `key.enabled`, which merely
    // restates an input property. The owning key here is the one `gov_with_aws_key` created.
    assert_eq!(
        key.name, "bedrock",
        "verify must resolve the AWS-credentialed key that owns this AccessKeyId"
    );
}

#[test]
fn test_verify_bedrock_sigv4_roundtrip_with_escaped_query_param_admits() {
    // Regression for the query-string double-encoding bug: `canonical_query_string` must NOT
    // re-URI-encode the wire query string, which arrives already percent-encoded once by the
    // client. A real SigV4 client signs a CanonicalQueryString built from ONE encoding pass over
    // its query params, and sends that SAME single-encoded text on the wire. If busbar's inbound
    // verifier ran the wire text through the encoder a second time, the canonical query string it
    // reconstructs would diverge from what the client signed, and EVERY request carrying a query
    // parameter that needed escaping (here, a literal '/' in the value) would fail verification.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let amzdate = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let datestamp = &amzdate[0..8];
    let path = "/model/anthropic.claude/converse";
    // The client's ONE correct URI-encoding of a value containing '/' (per AWS SigV4 query rules,
    // which — unlike CanonicalURI — are never double-encoded).
    let wire_query = "p=a%2Fb";
    let payload_hash = crate::sigv4::sha256_hex(b"");
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let canonical_uri = crate::sigv4::uri_encode_path(path);
    // The client signs the wire query text UNCHANGED — that IS its CanonicalQueryString.
    let (sig, signed_headers) = crate::sigv4::sign_v4(
        &secret,
        "us-east-1",
        "bedrock",
        "POST",
        &canonical_uri,
        wire_query,
        &headers,
        &payload_hash,
        &amzdate,
        datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{datestamp}/us-east-1/bedrock/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
    );
    let full_path = format!("{path}?{wire_query}");
    let req = bedrock_request(&full_path, &auth, &headers);
    let key = verify_bedrock_sigv4(&gov, &req, b"")
        .expect("a correctly-signed request with an escaped query param must verify");
    assert_eq!(key.name, "bedrock");
}

#[test]
fn test_verify_bedrock_sigv4_wrong_secret_rejected() {
    crate::metrics::init();
    let (gov, akid, _secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    // Sign with a DIFFERENT secret than the key's.
    let (auth, headers) = sign_bedrock_request(
        "not-the-real-secret",
        &akid,
        "us-east-1",
        "bedrock",
        path,
        b"",
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // `verify_bedrock_sigv4` collapses every failure to the SAME opaque `Err(())` (no
    // enumeration oracle). Assert that exact value, not just `is_err()`. The variant-level
    // distinction — that a wrong secret is a `SignatureMismatch`, NOT a distinct key-not-found
    // variant — is pinned one layer down in `sigv4::verify_inbound_sigv4`'s tests (a real-secret
    // signature verified against the dummy secret yields `SignatureMismatch`).
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, b""),
        Err(()),
        "a wrong-secret signature must be rejected with the opaque Err(())"
    );
}

#[test]
fn test_verify_bedrock_sigv4_unknown_access_key_id_rejected() {
    crate::metrics::init();
    let (gov, _akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    // A well-formed signature under an AccessKeyId that does not exist in the store.
    let (auth, headers) = sign_bedrock_request(
        &secret,
        "AKIADOESNOTEXIST0000",
        "us-east-1",
        "bedrock",
        path,
        b"",
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // Identical opaque `Err(())` to the wrong-secret case above — the unknown-AccessKeyId path is
    // verified against a dummy secret precisely so it is indistinguishable from a bad signature
    // (no AccessKeyId-enumeration oracle). Assert the exact value, not just `is_err()`.
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, b""),
        Err(()),
        "unknown AccessKeyId must be rejected with the SAME opaque Err(()) as a bad signature"
    );
}

#[test]
fn test_verify_bedrock_sigv4_expired_date_rejected() {
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    // Sign with a timestamp 10 minutes in the past — outside the ±5min skew window.
    let stale = crate::store::now().saturating_sub(crate::sigv4::CLOCK_SKEW_SECS + 60);
    let (a, _d) = crate::sigv4::format_amz_time(stale);
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &a);
    let req = bedrock_request(path, &auth, &headers);
    assert!(
        verify_bedrock_sigv4(&gov, &req, b"").is_err(),
        "an expired x-amz-date must be rejected"
    );
}

#[test]
fn test_verify_bedrock_sigv4_missing_authorization_rejected() {
    crate::metrics::init();
    let (gov, _akid, _secret) = gov_with_aws_key();
    // No Authorization header at all.
    let req = Request::builder()
        .method("POST")
        .uri("/model/anthropic.claude/converse")
        .body(Body::empty())
        .unwrap();
    assert!(verify_bedrock_sigv4(&gov, &req, b"").is_err());
}

#[test]
fn test_verify_bedrock_sigv4_disabled_key_rejected() {
    crate::metrics::init();
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, None).unwrap());
    let (key, _b, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            crate::store::now(),
        )
        .unwrap();
    // Disable the key.
    gov.update_key(&key.id, Some(false), None).unwrap();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &a);
    let req = bedrock_request(path, &auth, &headers);
    assert!(
        verify_bedrock_sigv4(&gov, &req, b"").is_err(),
        "a correctly-signed request for a DISABLED key must be rejected"
    );
}

#[test]
fn test_verify_bedrock_sigv4_revoked_key_rejected() {
    // A dual-credential key minted with
    // BOTH a busbar signed bearer token AND a SigV4 credential is bound to ONE subject id. `revoke`
    // denylists that subject but DELIBERATELY leaves `enabled = true` (it preserves the binding for
    // history). The signed-token path consults the denylist and rejects; before the fix the inbound
    // SigV4 admit path resolved purely by AccessKeyId -> key and admitted on `key.enabled` alone,
    // NEVER consulting the denylist — so the revoked key's SigV4 credential kept authenticating.
    // The fix gates the SigV4 admit on `!gov.is_revoked(&key.id)`, mirroring the signed-token path.
    crate::metrics::init();
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, None).unwrap());
    // A DUAL-credential key: `create_key_with_aws` issues a signed bearer AND a SigV4 credential.
    let (key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "dual".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            crate::store::now(),
        )
        .unwrap();

    let amzdate = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let path = "/model/anthropic.claude/converse";

    // Baseline: before revocation, the correctly-signed SigV4 request ADMITS.
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &amzdate);
    let req = bedrock_request(path, &auth, &headers);
    let admitted = verify_bedrock_sigv4(&gov, &req, b"")
        .expect("a non-revoked dual-credential key must admit via SigV4");
    assert_eq!(admitted.name, "dual");

    // Revoke by subject id. This denylists the subject WITHOUT flipping `enabled` (revoke preserves
    // the binding), exactly as the admin `revoke_key` verb does.
    gov.revoke(&key.id, "audit regression").unwrap();
    assert!(gov.is_revoked(&key.id), "revoke must denylist the subject");

    // Re-sign a fresh request (same secret/akid) and assert the SigV4 path now REJECTS — the revoked
    // subject's SigV4 credential must be rejected exactly like its signed token would be.
    let amzdate2 = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let (auth2, headers2) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &amzdate2);
    let req2 = bedrock_request(path, &auth2, &headers2);
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req2, b""),
        Err(()),
        "a correctly-signed SigV4 request for a REVOKED (denylisted) key must be rejected"
    );
}

#[test]
fn test_verify_bedrock_sigv4_body_matches_signed_hash_admits() {
    // (a) A non-empty body whose bytes hash to the signed `x-amz-content-sha256` is accepted.
    // This exercises the body-integrity bind on a real payload (the roundtrip test signs an empty
    // body): the verifier must re-hash THESE bytes and find they match the signed digest.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, body, &a);
    let req = bedrock_request(path, &auth, &headers);
    let key = verify_bedrock_sigv4(&gov, &req, body)
        .expect("a correctly-signed request whose body matches the signed hash must verify");
    assert_eq!(key.name, "bedrock");
}

#[test]
fn test_verify_bedrock_sigv4_tampered_body_rejected() {
    // (b) THE core fix: a VALID signature (signed over the original body) but the body bytes
    // actually delivered are DIFFERENT (a MitM tampered them in transit). The signature still
    // verifies against the declared `x-amz-content-sha256`, but the bytes no longer hash to it, so
    // the request MUST be rejected — fail-closed — with the SAME opaque `Err(())` as any other
    // failure (no oracle distinguishing "body tampered" from "bad signature").
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let signed_body = br#"{"max_tokens":16}"#;
    let tampered_body = br#"{"max_tokens":999999}"#;
    // Sign over the ORIGINAL body (so Authorization + x-amz-content-sha256 are valid for it)...
    let (auth, headers) = sign_bedrock_request(
        &secret,
        &akid,
        "us-east-1",
        "bedrock",
        path,
        signed_body,
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // ...but feed the verifier the TAMPERED bytes (what the middleware would have buffered).
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, tampered_body),
        Err(()),
        "a body whose bytes don't match the signed x-amz-content-sha256 must fail-closed"
    );
}

#[test]
fn test_verify_bedrock_sigv4_unsigned_payload_rejected() {
    // (c) `UNSIGNED-PAYLOAD` is rejected for this governed ingress: we require a signed payload, so
    // a client declaring it did not hash its body cannot authenticate. Sign a request normally,
    // then overwrite the x-amz-content-sha256 header with the sentinel; the body-integrity gate
    // rejects it independently of any signature check, with the same opaque `Err(())`.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let body = b"some-body";
    let (auth, mut headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, body, &a);
    for (k, v) in headers.iter_mut() {
        if k == X_AMZ_CONTENT_SHA256 {
            *v = "UNSIGNED-PAYLOAD".to_string();
        }
    }
    let req = bedrock_request(path, &auth, &headers);
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, body),
        Err(()),
        "UNSIGNED-PAYLOAD must be rejected for governed Bedrock ingress"
    );
}

#[test]
fn test_has_sigv4_authorization_detects_scheme() {
    let yes = Request::builder()
        .uri("/x")
        .header(
            AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=a/b/c/d/aws4_request, SignedHeaders=host, Signature=z",
        )
        .body(Body::empty())
        .unwrap();
    assert!(has_sigv4_authorization(&yes));
    let bearer = Request::builder()
        .uri("/x")
        .header(AUTHORIZATION, "Bearer tok")
        .body(Body::empty())
        .unwrap();
    assert!(!has_sigv4_authorization(&bearer));
    let none = Request::builder().uri("/x").body(Body::empty()).unwrap();
    assert!(!has_sigv4_authorization(&none));
}

#[test]
fn test_canonical_query_string_sorts_but_does_not_reencode() {
    assert_eq!(canonical_query_string(None), "");
    assert_eq!(canonical_query_string(Some("")), "");
    // Sorted by key.
    assert_eq!(canonical_query_string(Some("b=2&a=1")), "a=1&b=2");
    // Bare key signs as key= (empty value).
    assert_eq!(canonical_query_string(Some("flag")), "flag=");
    // REGRESSION (bug: re-URI-encoding the already-encoded wire query string): `query` is the RAW
    // wire query string, i.e. ALREADY percent-encoded once by the client (per AWS SigV4, the client
    // builds its wire query string and its CanonicalQueryString with the SAME single encoding pass).
    // A wire value like `a%2Fb` (the client's one correct encoding of `a/b`) must pass through
    // UNCHANGED — re-encoding it here would double-encode the `%` into `a%252Fb`, diverging from
    // what the client signed and breaking verification of every request with an escaped query char.
    assert_eq!(canonical_query_string(Some("p=a%2Fb")), "p=a%2Fb");
    // A literal (unencoded) '/' on the wire — also valid, since '/' is unreserved-in-query per RFC
    // 3986 and some clients don't escape it — likewise passes through unchanged: busbar trusts the
    // wire bytes are exactly what the client signed, it does not re-derive the "should be" encoding.
    assert_eq!(canonical_query_string(Some("p=a/b")), "p=a/b");
}

// ─────────────────────────────────────────────────────────────────────────────
// BACK-COMPAT REGRESSION: governance is ALWAYS constructed (RAM store by default), but must be
// INERT until an admin token is configured. A legacy deploy that never opted into governance (no
// admin token, no minted keys) must behave EXACTLY as it did when `governance:` defaulted to
// disabled: the static `auth.chain` gates ingress and inference succeeds. These pin that the
// on-by-default governance engine does NOT silently supersede the static chain / open relay.
// See `auth/mod.rs`: the vkey-resolution branch is gated on `admin_token_hash().is_some()`.
// ─────────────────────────────────────────────────────────────────────────────

/// (a) DEFAULT DEPLOY, NO admin token, a configured static auth chain: a request bearing a
/// credential that chain recognizes MUST be admitted by the static chain (governance is inert and
/// does NOT require a virtual key). Before the fix this 401'd because the always-present engine
/// forced a vkey lookup that no minted key could satisfy.
#[tokio::test]
async fn test_governance_inert_without_admin_token_static_token_admitted() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let token = "grp:static";
    let auth_cfg = chain_cfg(&["test-groups-module"]);
    // The default-deploy governance engine: RAM store, NO admin token, NO minted keys → INERT.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
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

    // The static token MUST be honoured by the static chain — governance is inert, so no vkey needed.
    let r_ok = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the static [tokens] chain (got {})",
        r_ok.status()
    );

    // A WRONG token is still rejected by the static chain (the chain still gates, as before).
    let r_bad = client
        .post(&url)
        .bearer_auth("not-the-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "the static chain must still reject a non-allowlisted token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (b) NO admin token + EMPTY chain (open relay): a request presenting NO token MUST be admitted —
/// the open front door's accept-every-request semantics are honoured because governance is inert.
/// Before the fix the always-present engine rejected the tokenless request.
#[tokio::test]
async fn test_governance_inert_without_admin_token_open_relay_admits() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());

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
        // Empty chain = open relay (the old `mode: none`).
        .upstream_creds(crate::auth::UpstreamCreds::Own)
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

    // NO token — the open relay must admit (governance is inert, not superseding the open door).
    let r_none = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the open relay (got {})",
        r_none.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (c) WITH admin token + a minted enabled key: governance is ACTIVE, so a valid virtual key is
/// admitted and an unknown token is rejected — the enforcement path is unchanged once active.
#[tokio::test]
async fn test_governance_active_with_admin_token_enforces_minted_key() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    });
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    // Admin token set → governance is ACTIVE (this is the real minted-keys deploy).
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );
    let (_key, token) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "k".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let secret = token.as_str();

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

    // The enabled virtual key is admitted.
    let r_ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an enabled virtual key must pass under active governance (got {})",
        r_ok.status()
    );

    // An unknown token is rejected — enforcement is live.
    let r_bad = client
        .post(&url)
        .bearer_auth("sk-vk-unknown")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "active governance must reject an unknown token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

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

/// BYPASS-EDGE (the durable-store-with-persisted-keys-but-admin-token-removed case): a store that
/// STILL holds a virtual key, but whose engine has NO admin token, is INERT. A request bearing that
/// persisted key's secret is therefore NOT governed by the key's per-key controls — it falls through
/// to the STATIC auth.chain. This pins the exact "bypass by mistake" behaviour the boot guard warns
/// about: the key's `allowed_pools` (here a pool the request does NOT target) is NOT enforced, and
/// the static chain (a token allowlist that does NOT list the key secret) is what decides admission.
///
/// The auth gate keys inertness on `admin_token_hash().is_some()`, independent of the store backend,
/// so a seeded `MemoryStore` + `None` admin token faithfully reproduces the durable-store edge for
/// the middleware's purposes (the store's DURABILITY only matters for the boot-time banner, covered
/// by the main-crate tests).
#[tokio::test]
async fn test_inert_governance_persisted_key_is_not_enforced_static_chain_wins() {
    use crate::governance::{GovState, MemoryStore, ScopeRef, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    for _ in 0..2 {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "hi"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1}
            }),
        });
    }
    let server = MockServer::new(state).await;

    // A key PERSISTED from a prior run, scoped to pool "restricted" ONLY (a pool the request below
    // does NOT target). If the key's controls were enforced, a request to pool "pa" bearing this
    // secret would be pool-ACL rejected. Under an INERT engine they are NOT consulted at all.
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kold".to_string(),
            generation_hash: crate::sigv4::sha256_hex(persisted_secret.as_bytes()),
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
    // NO admin token → INERT: the persisted key's controls are bypassed.
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );

    // The STATIC chain is what actually gates now - a chain that recognizes a DIFFERENT
    // credential shape (`grp:<role>`), NOT the persisted key secret.
    let static_token = "grp:static-chain";
    let auth_cfg = chain_cfg(&["test-groups-module"]);

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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
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

    // (1) The persisted key secret is NOT in the static allowlist → the static chain REJECTS it.
    // This is the crux: the persisted key confers NOTHING now (its controls are inert); only the
    // static chain speaks. (If governance were still enforcing, this same secret would be ADMITTED
    // as a valid vkey — then pool-ACL/budget/RPM rejected. The 401-from-the-static-chain proves the
    // vkey path is not taken.)
    let r_key = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_key.status().as_u16(),
        401,
        "an inert engine's persisted key must confer nothing — the static chain (which does not \
         list it) rejects it (got {})",
        r_key.status()
    );

    // (2) The STATIC token is admitted — the static chain is fully in charge, and the key's zero
    // budget / zero RPM (which would block EVERY request if enforced) are NOT consulted. A 200 here
    // is the direct proof the persisted key's controls are bypassed.
    let r_static = client
        .post(&url)
        .bearer_auth(static_token)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_static.status().as_u16(),
        200,
        "the static chain governs an inert engine; the persisted key's 0-budget/0-RPM are NOT \
         enforced (got {})",
        r_static.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// CONTROL for the bypass-edge test: the SAME persisted key, but WITH an admin token set →
/// governance is ACTIVE and the key's per-key controls ARE enforced. The pool-ACL alone is enough
/// to prove enforcement: the key is scoped to "restricted" but the request targets "pa", so an
/// active engine rejects it (403 pool-ACL), whereas the inert twin above let the static chain decide.
#[tokio::test]
async fn test_active_governance_persisted_key_is_enforced() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream body queued — enforcement must reject before any upstream call.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    // Admin token SET → ACTIVE: the key resolves and its pool-ACL is enforced.
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );
    let (_key, persisted_secret) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "kold".to_string(),
                allowed_pools: Some(vec!["restricted".to_string()]), // NOT "pa"
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();
    let persisted_secret = persisted_secret.as_str();

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

    // The key resolves (active engine) but its allowed_pools excludes "pa" → pool-ACL 403. The key
    // IS enforced — the opposite of the inert twin, where the static chain decided instead.
    let r = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "an active engine enforces the persisted key's pool-ACL (got {})",
        r.status()
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
        dry_run_admin_scope(&app, Some("grp:ops"), None),
        Grants::of(Scope::ReadOnly),
        "an external module without an explicit cap must be ceilinged to read-only"
    );

    // Explicit max_admin_scope: full lifts the ceiling; the full binding now lands.
    let app = mk_app(Some("full"), "test-scope-module");
    assert_eq!(
        dry_run_admin_scope(&app, Some("grp:ops"), None),
        Grants::of(Scope::Full),
        "an explicit full cap must let the full binding through"
    );

    // Module scoping through the full stack: the binding lives under ANOTHER module's table, so
    // the principal (identified by test-scope-module) earns no scope at all.
    let app = mk_app(Some("full"), "other-module");
    assert!(
        dry_run_admin_scope(&app, Some("grp:ops"), None) == Grants::default(),
        "a binding under another module's table must grant nothing"
    );

    // A credential no chain module identifies: denied (fail closed).
    let app = mk_app(Some("full"), "test-scope-module");
    assert!(dry_run_admin_scope(&app, Some("not-a-grp"), None) == Grants::default());
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
    let g = dry_run_admin_scope(&app, None, None);
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
        !dry_run_admin_scope(&app, Some("anything"), Some("x-admin-token")).contains(Scope::Full),
        "an empty chain must not grant Full to any presented credential"
    );
}

/// The structural SigV4 gate rejects a malformed `AWS4-HMAC-SHA256` Authorization header
/// WITHOUT reading the request body. Discriminator: the client announces a `Content-Length` and then
/// sends ZERO body bytes. If the gate rejects on headers alone, the 403 arrives immediately; if the
/// (pre-fix) code buffers the body first (`axum::body::to_bytes`), the server blocks waiting for
/// bytes that never arrive, and the client's read hangs (this test drives `axum::serve` directly,
/// with no `TimeoutBody`/read-timeout wrapper, specifically so an unbounded hang is the only
/// alternative to an immediate response - there is no third outcome to confuse the result).
#[tokio::test]
async fn structural_sigv4_gate_rejects_without_reading_the_body() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;
    let auth_cfg = chain_cfg(&["test-groups-module"]);
    // The inbound-SigV4 verify branch runs only when governance is enabled with an admin token
    // configured (`auth/mod.rs`'s `app.governance.filter(|g| g.admin_token_hash().is_some())`) - a
    // deploy with no admin token can never have a virtual key to resolve against. Without this the
    // request falls through the plain bearer-token path instead, which never touches the SigV4
    // structural gate at all (and rejects just as fast, defeating the discriminator).
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(
            std::sync::Arc::new(crate::governance::MemoryStore::new()),
            Some("admintok".to_string()),
        )
        .unwrap(),
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
        .auth(Arc::new(AuthMiddleware::new_builtin(&auth_cfg)))
        .governance(gov)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Malformed: `AWS4-HMAC-SHA256` with no Credential/SignedHeaders/Signature at all, and no
    // x-amz-content-sha256/x-amz-date headers either - fails `parse_authorization_header` AND the
    // header-presence checks, so both gate conditions independently reject it. A large
    // Content-Length is announced; NO body bytes are ever sent.
    sock.write_all(
        b"POST /model/anthropic.claude/converse HTTP/1.1\r\n\
          Host: localhost\r\n\
          Authorization: AWS4-HMAC-SHA256\r\n\
          Content-Length: 1000000\r\n\
          \r\n",
    )
    .await
    .unwrap();
    sock.flush().await.unwrap();

    let mut buf = [0u8; 512];
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf))
        .await
        .expect(
            "the structural gate did NOT reject before reading the body: the connection hung \
             waiting for body bytes that were never sent, meaning `to_bytes` was called first",
        )
        .unwrap();
    assert!(outcome > 0, "expected a response, got EOF");
    let resp = String::from_utf8_lossy(&buf[..outcome]);
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected an immediate 403 from the structural gate: {resp}"
    );

    handle.abort();
    server.shutdown().await;
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
    (gov, secret.as_str().to_string())
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

/// `chain:[]` + admin token + NO credential → 200 ANONYMOUS (the previously-impossible
/// "protected admin API, open relay" posture). Before 1.5.2 the admin token forced a vkey
/// on every data-plane request, so a no-credential request was 401.
#[tokio::test]
async fn test_1_5_2_open_chain_admin_token_no_credential_admits_anon() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    // Default auth = empty chain (open front door). Admin token present (governance active).
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "chain:[] + admin token + no credential must admit ANONYMOUS (open relay, protected admin)"
    );
    handle.abort();
    server.shutdown().await;
}

/// A `chain:[]` request carries a DEFAULT `GovCtx` (never a 500 MissingExtension). Same wire path
/// as the anonymous-admit case above: a 200 (rather than a 500) through the real router proves the
/// downstream `Extension<GovCtx>` extraction found the default GovCtx the Open arm inserts.
#[tokio::test]
async fn test_1_5_2_open_chain_inserts_default_govctx_no_500() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let body = serde_json::json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8}).to_string();
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/pa/v1/messages"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_ne!(
        r.status().as_u16(),
        500,
        "open chain must insert a default GovCtx (no MissingExtension 500)"
    );
    assert_eq!(r.status().as_u16(), 200);
    handle.abort();
    server.shutdown().await;
}

/// `chain:[]` + admin token + a VALID vkey voluntarily presented → 200, and the key is NOT
/// metered (pure anonymous: an empty chain resolves NOTHING). Before 1.5.2 the vkey path
/// resolved and metered it.
#[tokio::test]
async fn test_1_5_2_open_chain_valid_vkey_ignored_not_metered() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let key_id = gov.all_keys().unwrap()[0].id.clone();
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .governance(gov.clone())
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
        200,
        "open chain admits regardless of the presented vkey"
    );
    // PURE ANONYMOUS: the voluntarily-presented key was ignored → its ledger recorded no spend.
    let cost = crate::cost::CostModel::flat(1);
    let spend = gov
        .usage_for(&cost, &key_id, crate::store::now())
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(
        spend, 0,
        "an empty chain must NOT resolve/meter a presented vkey (pure anonymous)"
    );
    handle.abort();
    server.shutdown().await;
}

/// `chain:[keys]` + admin token + a VALID enabled vkey → 200 (admitted + governed, unchanged).
#[tokio::test]
async fn test_1_5_2_keys_chain_valid_vkey_admits() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
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
        200,
        "chain:[keys] + valid enabled vkey must admit"
    );
    handle.abort();
    server.shutdown().await;
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

/// An IdP-style principal (the `test-groups-module` stand-in) whose role BINDS a group is
/// admitted with a SYNTHESIZED governance key: pool ACL applies (granted pool serves, ungranted 403).
#[tokio::test]
async fn test_1_5_2_role_bound_principal_synthesized() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::metrics::init();
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, _secret) = dp_gov_with_key();
    let rb = bindings_for(
        "test-groups-module",
        &[("eng", binding(Some(&["pa"]), None, None))],
    );
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_ANTHROPIC, &server.base_url()).api_key("up"))
        .pool("pa", &[(0, 1)])
        .pool("pb", &[(0, 1)])
        .auth(std::sync::Arc::new(AuthMiddleware::new_builtin(
            &chain_cfg(&["test-groups-module"]),
        )))
        .governance(gov)
        .role_bindings(rb)
        .build();
    let (addr, handle) = dp_serve(app).await;
    let mk = |pool: &str| {
        reqwest::Client::new()
            .post(format!("http://{addr}/{pool}/v1/messages"))
            .bearer_auth("grp:eng")
            .body(serde_json::json!({"model": pool, "messages": [{"role":"user","content":"hi"}], "max_tokens": 8}).to_string())
            .send()
    };
    assert_eq!(
        mk("pa").await.unwrap().status().as_u16(),
        200,
        "granted pool serves (synth key)"
    );
    assert_eq!(
        mk("pb").await.unwrap().status().as_u16(),
        403,
        "ungranted pool is pool-ACL denied"
    );
    handle.abort();
    server.shutdown().await;
}

/// The ADMIN path still bypasses governance (empty GovCtx) and mint still works: the admin
/// token authenticates `/api/v1/admin/*` and returns above the data-plane gate, unchanged.
/// (Gated on `auth-admin-tokens`: the operator admin-token module is compiled out under
/// `--no-default-features`, so there is no admin-token authenticator to exercise there.)
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_1_5_2_admin_path_bypasses_governance_and_mints() {
    use crate::test_support::TestApp;
    crate::metrics::init();
    let (gov, _secret) = dp_gov_with_key();
    let app = TestApp::new().governance(gov).build();
    let (addr, handle) = dp_serve(app).await;
    // Mint a key through the admin API using the operator admin token.
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(crate::auth::X_ADMIN_TOKEN, "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "minted-via-admin"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "admin token must authenticate the admin API and mint (got {})",
        r.status()
    );
    // Wrong admin token → 401 (admin gate still enforced).
    let bad = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(crate::auth::X_ADMIN_TOKEN, "nope")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "x"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong admin token must be rejected"
    );
    handle.abort();
}

/// The `keys` ENGINE ARM is CACHE-EXEMPT: running a keys chain WITH a credential cache
/// resolves the vkey (Identified{resolved:Some}) but writes NOTHING to the cache (revocation stays
/// per-request). Before 1.5.2 no keys engine arm / no `resolved` field existed at all.
#[test]
fn test_1_5_2_keys_arm_is_cache_exempt() {
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
    let secret = secret.as_str();
    let mw = AuthMiddleware::new_builtin(&chain_cfg(&["keys"]));
    let cache = crate::auth_cache::CredentialCache::new();
    let now = crate::store::now();
    let verdict = mw.run_chain_cached(Some(secret), Some(&cache), Some(&gov), None);
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
    assert!(
        cache.get(crate::config::KEYS_MODULE, secret, now).is_none(),
        "the keys engine arm must NOT cache vkey verdicts (revocation window unchanged)"
    );
}

/// A correctly-signed Bedrock SigV4 ingress request under `chain:[keys]` is VERIFIED by the
/// pre-step and admitted (GovCtx attached, routes to upstream). The SigV4 pre-step now runs because
/// the chain names `keys`, NOT because an admin token is set.
#[tokio::test]
async fn test_1_5_2_sigv4_ingress_under_keys_chain_admitted() {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    crate::metrics::init();
    let state = std::sync::Arc::new(MockServerState::new());
    state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: serde_json::json!({
            "id": "chatcmpl-1", "object": "chat.completion", "model": "foo",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }),
    });
    let server = MockServer::new(state).await;

    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (_key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            crate::store::now(),
        )
        .unwrap();

    let app = TestApp::new()
        .lane(LaneSpec::new("foo", crate::proto::PROTO_OPENAI, &server.base_url()).provider("zai"))
        .pool("foo", &[(0, 1)])
        .keys_chain()
        .governance(gov)
        .build();
    let (addr, handle) = dp_serve(app).await;

    let path = "/model/foo/converse";
    let body = serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
        .to_string();
    let amzdate = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let (auth, headers) = sign_bedrock_request(
        &secret,
        &akid,
        "us-east-1",
        "bedrock",
        path,
        body.as_bytes(),
        &amzdate,
    );
    let mut rb = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header(AUTHORIZATION, auth)
        .body(body);
    for (k, v) in &headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    let r = rb.send().await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "a correctly-signed Bedrock SigV4 request under chain:[keys] must verify and be admitted (got {})",
        r.status()
    );
    handle.abort();
    server.shutdown().await;
}
