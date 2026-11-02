use busbar_kernel::audit_ring;
use busbar_kernel::config::migrated_store_module;
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel_testkit::test_support::governance::GovStateFixtures;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
use busbar_kernel_testkit::test_support::TestOverlayStore;
use std::sync::Arc;

#[path = "cache_flush_tests.rs"]
mod cache_flush_tests;

#[path = "store_overlay_tests.rs"]
mod store_overlay_tests;

#[path = "price_activation_tests.rs"]
mod price_activation_tests;

#[path = "config_boundary_tests.rs"]
mod config_boundary_tests;

const OAS_OPERATION_STATUSES: &str =
    include_str!("../../tests/fixtures/openapi_operation_statuses_key.txt").trim_ascii();

const LOCKED_CONFIG_MUTATION_MESSAGE: &str = "config mutation refused: this busbar has no writable Store-backed config overlay; edit config.yaml and reload a locked deployment";

fn gov_with_signer(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    let gov = gov_without_at_rest_key(store, admin_token);
    gov.set_at_rest_keys(Some(busbar_kernel::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
    gov
}

fn gov_without_at_rest_key(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

fn audit_principal(app: &mut Arc<busbar_kernel::state::App>, role: &str) {
    let inner = Arc::get_mut(app).expect("sole owner");
    let module = "test-scope-module";
    inner.admin_chain.insert(0, module.to_string());
    inner
        .role_bindings
        .entry(module.to_string())
        .or_default()
        .insert(
            role.to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
    inner
        .auth_scope_caps
        .insert(module.to_string(), "full".to_string());
}

async fn spin_up(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, reqwest::Client::new())
}

async fn serve_with_gov(gov: Arc<GovState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (addr, handle)
}

struct CachingDoor(std::sync::atomic::AtomicUsize);

const FLUSHED: u64 = 3;

struct Passed;

impl std::future::Future for Passed {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::Verifying for Passed {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::AuthCalls for CachingDoor {
    fn name(&self) -> &str {
        "caching-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Passed)
    }
    fn refresh(&self) -> Result<u64, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FLUSHED)
    }
}

#[tokio::test]
async fn test_admin_v1_credential_cache_and_flush_endpoint() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let door = Arc::new(CachingDoor(std::sync::atomic::AtomicUsize::new(0)));

    let operator = busbar_kernel::config::operator_provider();
    let mut app = crate::new_test_app()
        .governance(gov)
        .admin_door("ext-idp", door.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            "ext-idp".to_string(),
            operator.to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let flush = |token: &'static str, body: Option<serde_json::Value>| {
        let mut r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", token);
        if let Some(body) = body {
            r = r
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        r.send()
    };

    let r = flush("grp:viewers", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 0);

    let r = flush("admintok", Some(serde_json::json!({"module": "ext-idp"})))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["flushed"], FLUSHED,
        "what the plugin reported dropping"
    );
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", Some(serde_json::json!({"module": operator})))
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], 0);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], FLUSHED);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 2);

    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"module\": 7}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    handle.abort();
}

fn write_reset_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-reset-{}-{}-{}",
        tag,
        std::process::id(),
        busbar_kernel::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
groups:
  team:
    limits:
      - { budget: 20000, per: month }
",
    )
    .unwrap();
    (dir, config_path, providers_path)
}

fn free_open_units() -> serde_json::Value {
    crate::ensure_seam();
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .find(|decl| decl.fallback)
        .expect("the linked test planes carry the fallback plane")
        .billable_classes
        .iter()
        .map(|c| c.class)
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .map(|c| (c.to_string(), serde_json::json!(0)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}
