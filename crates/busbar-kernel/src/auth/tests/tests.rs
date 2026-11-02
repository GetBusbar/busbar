use super::*;
use busbar_contract::records::ScopeRef;

const LANE_PROTOCOL: &str = "unregistered-lane-protocol";

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

struct SleepingAdminDoor(std::time::Duration);

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

async fn serve_app(
    app: std::sync::Arc<crate::state::App>,
) -> (String, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn a_slow_admin_door_does_not_stall_healthz() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["slow-oidc".to_string()])
        .admin_door(
            "slow-oidc",
            std::sync::Arc::new(SleepingAdminDoor(std::time::Duration::from_millis(800))),
        )
        .build();
    let (base, handle) = serve_app(app).await;
    let client = reqwest::Client::new();

    let admin_url = format!("{base}/api/v1/admin/keys");
    let c2 = client.clone();
    let admin = tokio::spawn(async move {
        c2.get(&admin_url)
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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

    let r = admin.await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "a sleeping admin module that ultimately Passes fail-closed-denies (401), got {}",
        r.status()
    );
    handle.abort();
}

#[tokio::test]
async fn test_audience_bound_token_is_rejected_on_the_data_plane() {
    use crate::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use crate::governance::GovState;
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = crate::real_store::store();
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

#[tokio::test]
async fn test_governance_rejects_empty_token_even_if_empty_secret_key_exists() {
    use crate::governance::{GovState, RecordStore, ScopeRef, VirtualKey};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = crate::real_store::store();

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

    let r_none = client.post(&url).body(body.clone()).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "an unauthenticated request must be rejected even when a key hashing the empty secret \
             exists in the store (got {})",
        r_none.status()
    );

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

#[tokio::test]
async fn test_governance_active_with_admin_token_rejects_missing_vkey() {
    use crate::governance::GovState;
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = crate::real_store::store();
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .lane(
            LaneSpec::new("test-model", LANE_PROTOCOL, &server.base_url())
                .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
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

/// Internal policy continuation: real callers supply their verified principal and configured
/// bindings/caps to these same production functions. Real OIDC refusal is covered separately in
/// the root's test_nonempty_chain_fails_closed_on_all_pass, including the old not-a-grp input.
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

async fn dp_serve(
    app: std::sync::Arc<crate::state::App>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

fn dp_gov_with_key() -> (std::sync::Arc<crate::governance::GovState>, String) {
    use crate::governance::{GovState, NewKeySpec};
    let store = crate::real_store::store();
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

            body: serde_json::json!({"id": "r1", "answer": "hi"}),
        });
    }
    state
}

#[tokio::test]
async fn test_1_5_2_keys_chain_disabled_vkey_rejected() {
    use crate::test_support::{LaneSpec, MockServer, TestApp};
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let server = MockServer::new(dp_ok_state()).await;
    let (gov, secret) = dp_gov_with_key();
    let key_id = gov.all_keys().unwrap()[0].id.clone();
    gov.update_key(&key_id, Some(false), None).unwrap();
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

#[test]
fn the_operator_credential_opens_from_the_axis() {
    use crate::auth::{open_operator, OperatorCredential};
    let digest = busbar_contract::redacted::sha256_hex(b"tok");

    let linked = crate::preflight::linked().expect("the linked registry");
    let none = Default::default();
    let open = |digest| open_operator(&linked, digest, &none).expect("opens");
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

async fn walk(verified: busbar_contract::auth_calls::Verified) -> AdminChainAnswer {
    let app = operator_app(verified);
    let headers = admin_headers(Some("tok"), None);
    run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default()).await
}

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

async fn admin_get(app: std::sync::Arc<crate::state::App>) -> (u16, Option<String>, String) {
    let (base, handle) = serve_app(app).await;
    let r = reqwest::Client::new()
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("tok")
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let retry_after = r
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().unwrap_or_default().to_string());
    let text = r.text().await.unwrap();
    handle.abort();
    (status, retry_after, text)
}

#[tokio::test]
async fn an_operator_door_without_a_verdict_answers_503_and_an_overloaded_one_the_1_5_5_admin_401()
{
    use busbar_contract::auth_calls::Verified;
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let rejected = admin_get(operator_app(Verified::Reject)).await;
    assert_eq!(rejected.0, 401, "a bad credential is the admin 401");
    assert_eq!(rejected.1, None, "a 401 names no Retry-After");
    let overloaded = admin_get(operator_app(Verified::Overloaded)).await;
    assert_eq!(
        overloaded, rejected,
        "an overloaded verifier: the same bytes"
    );
    let failed = admin_get(operator_app(Verified::Failed)).await;
    assert_eq!(
        (failed.0, failed.1.as_deref()),
        (503, Some("1")),
        "a verdict-less verifier: 503 + Retry-After (SIGN-auth-kind 2026-10-30): {failed:?}"
    );
    let body: serde_json::Value = serde_json::from_str(&failed.2).expect("the admin envelope");
    assert_eq!(body["error"]["code"], "unavailable", "{failed:?}");
}

#[tokio::test]
async fn an_external_admin_door_without_a_verdict_answers_503_and_a_reject_401() {
    use busbar_contract::auth_calls::Verified;
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let door = |calls: std::sync::Arc<dyn AuthCalls>| {
        crate::test_support::TestApp::new()
            .admin_chain(vec!["ext".to_string()])
            .admin_door("ext", calls)
            .build()
    };
    let rejected = admin_get(door(std::sync::Arc::new(AnswersOnly(Verified::Reject)))).await;
    assert_eq!(
        (rejected.0, rejected.1.as_deref()),
        (401, None),
        "{rejected:?}"
    );
    for (what, calls) in [
        (
            "FAILED",
            std::sync::Arc::new(AnswersOnly(Verified::Failed)) as std::sync::Arc<dyn AuthCalls>,
        ),
        (
            "FAULT",
            std::sync::Arc::new(FaultingDoor) as std::sync::Arc<dyn AuthCalls>,
        ),
    ] {
        let answered = admin_get(door(calls)).await;
        assert_eq!(
            (answered.0, answered.1.as_deref()),
            (503, Some("1")),
            "{what}: 503 + Retry-After (SIGN-auth-kind 2026-10-30): {answered:?}"
        );
    }
}

#[test]
fn the_sync_admin_door_probe_fails_closed_when_the_operator_verifier_is_overloaded() {
    let app = operator_app(busbar_contract::auth_calls::Verified::Overloaded);
    let headers = admin_headers(Some("tok"), None);
    assert!(dry_run_admin_scope(&app, &headers) == busbar_contract::authz::Grants::default());
    assert_eq!(admin_door(&app, "GET", "/", &headers), AdminDoor::Denied);
}

#[test]
fn the_sync_admin_door_keeps_no_verdict_for_the_root_http_projection() {
    use busbar_contract::auth_calls::Verified;
    let headers = admin_headers(Some("tok"), None);
    for verified in [Verified::Failed, Verified::Reject, Verified::Overloaded] {
        let expected = if matches!(verified, Verified::Failed) {
            AdminDoor::Unavailable(VerifierUnavailable::NoVerdict)
        } else {
            AdminDoor::Denied
        };
        for app in [
            operator_app(verified.clone()),
            crate::test_support::TestApp::new()
                .admin_chain(vec!["ext".to_string()])
                .admin_door("ext", std::sync::Arc::new(AnswersOnly(verified.clone())))
                .build(),
        ] {
            let judged = admin_verdict(&app, "GET", "/api/v1/admin/keys", &headers);
            assert_eq!(judged.door, expected, "{verified:?}");
            assert!(
                judged.claim.is_none(),
                "an unidentified request claims nothing"
            );
            assert!(!admin_door_admits(
                &judged.door,
                "GET",
                "/api/v1/admin/keys"
            ));
            assert_eq!(
                dry_run_admin_scope(&app, &headers),
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

struct AnswersOnly(busbar_contract::auth_calls::Verified);

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

struct FaultingDoor;

struct FaultedCall(Option<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for FaultedCall {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl busbar_contract::auth_calls::Verifying for FaultedCall {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn faulted(&self) -> bool {
        true
    }
}

impl busbar_contract::auth_calls::AuthCalls for FaultingDoor {
    fn name(&self) -> &str {
        "faulting-door"
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
        use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
        Box::new(FaultedCall(Some(
            Verified::Identity(VerifiedIdentity {
                subject: "faulted".into(),
                ..VerifiedIdentity::default()
            })
            .into(),
        )))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
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

    let carriers = app.admin_modules.operator.carriers().to_vec();
    std::sync::Arc::get_mut(&mut app)
        .expect("freshly built App Arc is unshared")
        .admin_modules = std::sync::Arc::new(AdminAuthChain {
        modules,
        operator: Operator::new(crate::config::operator_provider()).with_carriers(carriers),
    });
    app
}

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

fn naming_chain(
    answer: busbar_contract::auth_calls::VerifyAnswer,
) -> std::sync::Arc<AuthMiddleware> {
    std::sync::Arc::new(AuthMiddleware::from_doors_for_test(vec![(
        "door".to_string(),
        std::sync::Arc::new(NamingDoor(answer)) as std::sync::Arc<dyn AuthCalls>,
    )]))
}

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

#[tokio::test]
async fn a_replayed_signed_delivery_is_answered_401_the_second_time() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[tokio::test]
async fn an_auth_named_header_and_query_key_never_reach_the_plane() {
    use busbar_contract::auth_calls::Strip;
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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
    assert!(matches!(first, Ok(AdminDoor::Identified(..))), "{first:?}");
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

fn replay_app(
    answer: busbar_contract::auth_calls::VerifyAnswer,
    gov: std::sync::Arc<crate::governance::GovState>,
    bound: bool,
) -> std::sync::Arc<crate::state::App> {
    let mut rb = crate::config::RoleBindings::default();
    if bound {
        rb.entry("door".to_string())
            .or_default()
            .entry("hooks".to_string())
            .or_default();
    }
    crate::test_support::TestApp::new()
        .auth(naming_chain(answer))
        .role_bindings(rb)
        .governance(gov)
        .build()
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
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let gov = replay_gov();
    let answer = hook_answer(Some("standard-webhooks/msg_r6"), Vec::new());
    let deliver = |base: String| async move {
        reqwest::Client::new()
            .post(format!("{base}/echo"))
            .bearer_auth("signed")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    let (unbound, served) =
        echo_behind_the_gate(replay_app(answer.clone(), gov.clone(), false)).await;
    assert_eq!(deliver(unbound.clone()).await, 401, "no grant: refused");
    assert_eq!(deliver(unbound).await, 401, "no grant again: refused");
    served.abort();
    let (bound, served) = echo_behind_the_gate(replay_app(answer, gov, true)).await;
    assert_eq!(
        deliver(bound.clone()).await,
        200,
        "the group bound, the redelivery is served: the refused ones claimed nothing"
    );
    assert_eq!(deliver(bound).await, 401, "its replay is refused");
    served.abort();
}

#[tokio::test]
async fn a_session_refused_for_its_grant_claims_no_replay_key() {
    let gov = replay_gov();
    let answer = hook_answer(Some("standard-webhooks/msg_r6s"), Vec::new());
    for _ in 0..2 {
        let refused = crate::auth::admit::admit_session(
            replay_app(answer.clone(), gov.clone(), false),
            Some("signed".into()),
            String::new(),
        )
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
    let app = naming_admin_app(hook_answer(Some("signed/admin_r6"), Vec::new()));
    let headers = admin_headers(Some("signed"), None);
    let mut strips = Vec::new();
    for _ in 0..2 {
        let refused = judge_admin_door(&app, "POST", "/", &headers, false, true, &mut strips).await;
        let Ok(AdminDoor::Identified(_, grants)) = &refused else {
            panic!("identified, not authorized, not a replay: {refused:?}");
        };
        assert!(!grants.allows(Scope::Full), "{grants:?}");
    }
    assert!(
        matches!(
            admin_door(&app, "POST", "/", &headers),
            AdminDoor::Identified(..)
        ),
        "the probe refuses for scope too, claiming nothing"
    );
    let admitted = judge_admin_door(&app, "GET", "/", &headers, false, true, &mut strips).await;
    assert!(
        matches!(admitted, Ok(AdminDoor::Identified(..))),
        "the authorized request wins the still-free claim: {admitted:?}"
    );
    assert_eq!(
        admin_door(&app, "GET", "/", &headers),
        AdminDoor::Denied,
        "its replay is refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_racing_identical_deliveries_admit_at_most_one() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let app = replay_app(
        hook_answer(Some("standard-webhooks/msg_race"), Vec::new()),
        replay_gov(),
        true,
    );
    let (base, served) = echo_behind_the_gate(app).await;
    let deliver = || {
        let base = base.clone();
        tokio::spawn(async move {
            reqwest::Client::new()
                .post(format!("{base}/echo"))
                .bearer_auth("signed")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    let racing: Vec<_> = (0..8).map(|_| deliver()).collect();
    let mut statuses = Vec::new();
    for one in racing {
        statuses.push(one.await.unwrap());
    }
    served.abort();
    statuses.sort_unstable();
    let mut expected = vec![200];
    expected.extend([401; 7]);
    assert_eq!(statuses, expected, "exactly one admitted");
}

const DOOR_BODY: &str =
    r#"{"model":"pa","messages":[{"role":"user","content":"hi"}],"max_tokens":16}"#;

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

async fn door_serve(
    app: std::sync::Arc<crate::state::App>,
    paths: &[&str],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

fn bearer(secret: &str) -> String {
    format!("Bearer {secret}")
}

async fn door_bearer(
    addr: std::net::SocketAddr,
    path: &str,
    secret: &str,
) -> (u16, Option<String>, String) {
    let auth = bearer(secret);
    door_post(addr, path, Some(("authorization", auth.as_str()))).await
}

fn door_gov(admin_token: Option<&str>) -> std::sync::Arc<crate::governance::GovState> {
    let store = crate::real_store::store();
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

fn door_app() -> crate::test_support::TestApp {
    crate::test_support::TestApp::new()
        .lane(
            crate::test_support::LaneSpec::new("test-model", LANE_PROTOCOL, "http://127.0.0.1:1")
                .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
}

fn admitted(gov: &str, key: &str, principal: &str) -> String {
    format!("gov={gov} key={key} principal={principal}")
}

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

    let (status, ct, body) = door_post(addr, url, Some(("x-api-key", "grp:unbound"))).await;
    assert_eq!(
        status, 401,
        "an unbound role under a governed module must be refused: {body}"
    );
    assert_eq!(ct.as_deref(), Some("application/json"));

    let (status, ct, body) = door_post(addr, url, None).await;
    assert_eq!(status, 401, "missing token must be 401: {body}");
    assert_eq!(ct.as_deref(), Some("application/json"));

    handle.abort();
}

#[tokio::test]
async fn test_disabled_virtual_key_is_rejected_401() {
    let gov = door_gov(Some("admintok"));
    let (dis_id, disabled_secret) = door_mint(&gov, "kdis", &["pa"]);
    let (ena_id, enabled_secret) = door_mint(&gov, "kena", &["pa"]);

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

#[tokio::test]
async fn test_governance_inert_without_admin_token_static_token_admitted() {
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(crate::real_store::store(), None).unwrap(),
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

#[tokio::test]
async fn test_governance_inert_without_admin_token_open_relay_admits() {
    let gov = std::sync::Arc::new(
        crate::governance::GovState::new(crate::real_store::store(), None).unwrap(),
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

#[tokio::test]
async fn test_inert_governance_persisted_key_is_not_enforced_static_chain_wins() {
    use crate::governance::RecordStore as _;
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = crate::real_store::store();
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

#[tokio::test]
async fn test_1_5_2_open_chain_valid_vkey_ignored_not_metered() {
    async fn metering_door_serve(
        app: std::sync::Arc<crate::state::App>,
        gov: std::sync::Arc<crate::governance::GovState>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
        let mut door = admitting_door("/pa/v1/messages");
        let echo = door.handler.clone();
        door.handler = std::sync::Arc::new(move |ctx| {
            let gov = gov.clone();
            let echo = echo.clone();
            Box::pin(async move {
                if let Some(key) = ctx.gov.as_ref().and_then(|g| g.key()) {
                    gov.try_admit(
                        &crate::cost::CostModel::flat(1),
                        key,
                        "pa",
                        crate::store::now(),
                    )
                    .expect("the fixture key has no budget ceiling");
                }
                echo(ctx).await
            })
        });
        let (router, _admin, _handle) = crate::build_split_routers_serving(
            app,
            vec![door],
            busbar_kernel_egress::upstream::max_translate_body_bytes(),
            crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
            crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (addr, handle)
    }

    let gov = door_gov(Some("admintok"));
    let (key_id, secret) = door_mint(&gov, "vk", &["pa"]);
    let app = door_app().governance(gov.clone()).build();
    let (addr, handle) = metering_door_serve(app, gov.clone()).await;

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

    let app = door_app().keys_chain().governance(gov.clone()).build();
    let (addr, handle) = metering_door_serve(app, gov.clone()).await;
    let (status, _, body) = door_bearer(addr, "/pa/v1/messages", &secret).await;
    handle.abort();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(&format!("key={key_id} ")), "{body}");
    let usage = gov
        .usage_for(
            &crate::cost::CostModel::flat(1),
            &key_id,
            crate::store::now(),
        )
        .unwrap()
        .expect("the keys-chain request has a usage row");
    assert_eq!(
        usage.spend_cents, 1,
        "the handler charges one real request fee"
    );
}

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
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

#[tokio::test]
async fn test_admin_prefix_is_boundary_safe() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
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

struct OtherStyle;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for OtherStyle {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open_refusing(
        _settings: &[u8],
        _secrets: &[&[u8]],
    ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
        Ok(Self)
    }

    fn verify(
        &self,
        _request: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

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
