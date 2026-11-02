//! Actual admin PUT keeps route-bearing hook policy and HTTP calls on one candidate instance.

use busbar_contract::abi::mechanism::{
    endpoint::{EndpointRequest, EndpointResponse},
    route::{Route, RouteAuth, RouteMethod},
};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};
use busbar_kernel::hooks::{HookEnv, ResolvedPolicy, RoutingContext, RoutingRequest, SignalBag};
use busbar_kernel::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

fn routes() -> Vec<Route> {
    vec![
        Route {
            path: "/hooks/receiver/feedback".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::None,
        },
        Route {
            path: "/hooks/receiver/admin".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::Admin,
        },
    ]
}

#[derive(Default)]
struct Axis {
    opens: AtomicUsize,
    refuse: AtomicBool,
}

struct Calls {
    id: usize,
    opened: Duration,
    routes: Vec<Route>,
}

impl HookCalls for Calls {
    fn name(&self) -> &str {
        "receiving-module"
    }
    fn routes(&self) -> &[Route] {
        &self.routes
    }
    fn serve(
        &self,
        _: EndpointRequest,
        budget: Duration,
    ) -> Pending<Result<EndpointResponse, String>> {
        let body = serde_json::to_vec(&serde_json::json!({"id": self.id, "opened": self.opened.as_millis(), "budget": budget.as_millis()})).unwrap();
        Box::pin(async move {
            Ok(EndpointResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body,
            })
        })
    }
    fn decide(
        &self,
        _: Arc<busbar_contract::abi::host::hook::DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<busbar_contract::abi::hook::DecideOut>> {
        let answer = format!(
            "instance={};opened={};budget={}",
            self.id,
            self.opened.as_millis(),
            budget.as_millis()
        );
        Box::pin(async move { Answered::Broken(answer) })
    }
    fn transform(
        &self,
        _: Arc<busbar_contract::abi::host::hook::DecideFrame>,
        _: Duration,
    ) -> Pending<Answered<busbar_contract::abi::hook::TransformOut>> {
        Box::pin(async { Answered::Broken("unused transform".into()) })
    }
    fn notify(
        &self,
        _: Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        _: Duration,
    ) -> Pending<()> {
        Box::pin(async {})
    }
    fn configure(&self, _: &str, _: &str, _: u64, _: Duration) -> Pending<Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

impl HookAxis for Axis {
    fn routes(&self, _: &str, _: &str, _: &serde_json::Value) -> Result<Vec<Route>, String> {
        Ok(routes())
    }
    fn probe(&self, _: &str, _: &str, _: &serde_json::Value) -> Option<Probed> {
        Some((
            Some(HookFacts {
                name: "receiving-module".into(),
                ..Default::default()
            }),
            Vec::new(),
        ))
    }
    fn open(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err("candidate open refused".into());
        }
        let id = self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Calls {
            id,
            opened: budget,
            routes: routes(),
        }))
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
    fn call_budget(&self) -> Duration {
        Duration::from_secs(1)
    }
}

struct Export;
impl PluginHttpDispatch for Export {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 200,
            headers: Vec::new(),
            body: b"retained-export".to_vec(),
        }
    }
}

#[derive(Default)]
struct Rules {
    refuse: AtomicBool,
    completed: AtomicUsize,
}
impl busbar_kernel::appbuild::RootRules for Rules {
    fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn check_built(&self, app: &busbar_kernel::state::App) -> Result<(), String> {
        self.completed.fetch_add(1, Ordering::SeqCst);
        assert!(app
            .plugin_routes
            .descriptors()
            .iter()
            .any(|route| route.kind == RouteKind::Hook));
        if self.refuse.load(Ordering::SeqCst) {
            Err("physical placement needs restart".into())
        } else {
            Ok(())
        }
    }
}

async fn serve(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    (
        address,
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() }),
    )
}

async fn policy_observation(app: &busbar_kernel::state::App) -> String {
    let ResolvedPolicy::Policy {
        policy, timeout, ..
    } = &app.global_gates[0].1;
    let request = RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "x",
        requested_model: None,
        message_count: 0,
        tool_count: 0,
        has_tools: false,
        total_chars: 0,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
        session: None,
    };
    let context = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    policy
        .decide(&request, &[], &context, *timeout)
        .await
        .unwrap_err()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_only_admin_put_refreshes_both_hook_doors_and_policy_atomically() {
    busbar_kernel_testkit::test_support::metrics::init();
    let axis = Arc::new(Axis::default());
    let rules = Arc::new(Rules::default());
    let env = HookEnv::with_axis(
        busbar_kernel_testkit::test_support::rows::empty(),
        axis.clone(),
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(
            Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new()),
            Some("admintok".into()),
        )
        .unwrap(),
    );
    let mut old = crate::new_test_app().governance(gov).hook_env(env).build();
    let mut definition: busbar_kernel::config::HookCfg =
        serde_json::from_value(serde_json::json!({
            "kind": "gate", "module": "receiving-module", "timeout_ms": 11, "global": true
        }))
        .unwrap();
    let app = Arc::get_mut(&mut old).unwrap();
    app.hook_registry
        .insert("receiver".into(), definition.clone());
    app.global_hooks = vec!["receiver".into()];
    let mut declarations = busbar_kernel_testkit::test_support::hook_route_declarations(
        &mut app.hook_env,
        &app.hook_registry,
    )
    .unwrap();
    declarations.push(RouteDecl {
        owner: "retained-export".into(),
        source_instance: "sink-instance".into(),
        dispatch_available: true,
        kind: RouteKind::Export,
        route: Route {
            path: "/snapshot/probe".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::None,
        },
        scrape: true,
        persistent: true,
        dispatch: Arc::new(Export),
    });
    app.plugin_routes =
        Arc::new(busbar_kernel::plugin_routes::build_route_table(declarations).unwrap());
    app.global_gates = busbar_kernel::hooks::resolve_gate_hooks(
        &app.hook_registry,
        &app.global_hooks,
        &app.hook_env,
        app.config_version,
    );
    app.root_rules = rules.clone();
    let (data, admin, handle) =
        crate::build_split_routers_with_limits(old.clone(), 1 << 20, 0, false);
    let (old_data, _, _) = crate::build_split_routers_with_limits(old.clone(), 1 << 20, 0, false);
    let (data_url, data_task) = serve(data).await;
    let (admin_url, admin_task) = serve(admin).await;
    let (old_url, old_task) = serve(old_data).await;
    let client = reqwest::Client::new();
    let initial: serde_json::Value = client
        .get(format!("{data_url}/hooks/receiver/feedback"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial["opened"], 11);
    assert!(policy_observation(&old)
        .await
        .contains("instance=0;opened=11;budget=11"));

    definition.timeout_ms = 29;
    let changed = client
        .put(format!("{admin_url}/api/v1/admin/hooks/receiver"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status().as_u16(), 200);
    let next = handle.load();
    assert!(!Arc::ptr_eq(&old, &next));
    for (base, path, authenticated) in [
        (&data_url, "/hooks/receiver/feedback", false),
        (&admin_url, "/hooks/receiver/admin", true),
    ] {
        let request = client.get(format!("{base}{path}"));
        let request = if authenticated {
            request.header("x-admin-token", "admintok")
        } else {
            request
        };
        let answer: serde_json::Value = request.send().await.unwrap().json().await.unwrap();
        assert_eq!(
            answer,
            serde_json::json!({"id": 1, "opened": 29, "budget": 29})
        );
    }
    assert_eq!(
        axis.opens.load(Ordering::SeqCst),
        2,
        "preopen and rebuild reuse the candidate's HTTP instance"
    );
    assert!(policy_observation(&next)
        .await
        .contains("instance=1;opened=29;budget=29"));
    assert_eq!(rules.completed.load(Ordering::SeqCst), 1);
    let retained: serde_json::Value = client
        .get(format!("{old_url}/hooks/receiver/feedback"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retained, initial);
    assert!(policy_observation(&old)
        .await
        .contains("instance=0;opened=11;budget=11"));
    assert_eq!(
        client
            .get(format!("{data_url}/snapshot/probe"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "retained-export"
    );
    let retained_export = next
        .plugin_routes
        .descriptors()
        .into_iter()
        .find(|route| route.kind == RouteKind::Export)
        .unwrap();
    assert!(retained_export.persistent);
    assert_eq!(retained_export.source_instance, "sink-instance");

    axis.refuse.store(true, Ordering::SeqCst);
    definition.timeout_ms = 47;
    let failed = client
        .put(format!("{admin_url}/api/v1/admin/hooks/receiver"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status().as_u16(), 400);
    assert!(
        Arc::ptr_eq(&next, &handle.load()),
        "failed candidate never publishes"
    );
    assert_eq!(handle.load().hook_registry["receiver"].timeout_ms, 29);
    axis.refuse.store(false, Ordering::SeqCst);
    rules.refuse.store(true, Ordering::SeqCst);
    let rejected = client
        .put(format!("{admin_url}/api/v1/admin/hooks/receiver"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status().as_u16(), 400);
    assert!(
        Arc::ptr_eq(&next, &handle.load()),
        "completed-candidate refusal keeps the live App"
    );
    assert!(policy_observation(&handle.load())
        .await
        .contains("instance=1;opened=29;budget=29"));
    rules.refuse.store(false, Ordering::SeqCst);
    definition.timeout_ms = 0;
    let defaulted = client
        .put(format!("{admin_url}/api/v1/admin/hooks/receiver"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(defaulted.status().as_u16(), 200);
    let implicit: serde_json::Value = client
        .get(format!("{data_url}/hooks/receiver/feedback"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let opens = axis.opens.load(Ordering::SeqCst);
    definition.timeout_ms = implicit["budget"].as_u64().unwrap();
    let explicit = client
        .put(format!("{admin_url}/api/v1/admin/hooks/receiver"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config": definition}))
        .send()
        .await
        .unwrap();
    assert_eq!(explicit.status().as_u16(), 200);
    let same: serde_json::Value = client
        .get(format!("{data_url}/hooks/receiver/feedback"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        same, implicit,
        "zero and explicit default share the same effective budget"
    );
    assert_eq!(
        axis.opens.load(Ordering::SeqCst),
        opens,
        "staging, preopen and policy resolution all reuse the normalized-budget instance"
    );
    data_task.abort();
    admin_task.abort();
    old_task.abort();
}
