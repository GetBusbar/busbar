use std::sync::Arc;

use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::abi::mechanism::KindCode;
use busbar_kernel::guest::{Claimant, GuestList, LineAuth, Matched};
use busbar_kernel::plugin_routes::{build_route_table, PluginHttpDispatch, RouteDecl, RouteKind};

use super::ListenerPlan;
use crate::root::boot::{ListenerNeed, ListenerNeeds};
use crate::root::loader::boot::{BindOwner, InboundBind};

struct Answer;
impl PluginHttpDispatch for Answer {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 200,
            headers: Vec::new(),
            body: b"served".to_vec(),
        }
    }
}

fn route(owner: &str, path: &str, auth: RouteAuth) -> RouteDecl {
    RouteDecl {
        owner: owner.into(),
        source_instance: owner.into(),
        dispatch_available: true,
        kind: RouteKind::Export,
        route: Route {
            path: path.into(),
            method: RouteMethod::Get,
            auth,
        },
        scrape: false,
        persistent: false,
        dispatch: Arc::new(Answer),
    }
}

fn topology() -> ListenerNeeds {
    ListenerNeeds {
        binds: vec![
            InboundBind {
                owner: BindOwner::Root,
                transport: String::new(),
                at: "listen".into(),
                listen: "127.0.0.1:8080".parse().unwrap(),
                tls: None,
                max_conns: u64::MAX,
            },
            InboundBind {
                owner: BindOwner::Root,
                transport: String::new(),
                at: "admin_listen".into(),
                listen: "127.0.0.1:8081".parse().unwrap(),
                tls: None,
                max_conns: u64::MAX,
            },
            InboundBind {
                owner: BindOwner::Need {
                    instance: "private".into(),
                    kind: KindCode::Export,
                    need: 0,
                },
                transport: "http".into(),
                at: "export.private.settings.ingress".into(),
                listen: "127.0.0.1:8082".parse().unwrap(),
                tls: None,
                max_conns: 7,
            },
        ],
        needs: vec![ListenerNeed {
            instance: "private".into(),
            module: "module-private".into(),
            kind: KindCode::Export,
            need: 0,
            transport: "http".into(),
            auth: String::new(),
            at: "export.private.settings.ingress".into(),
        }],
    }
}

fn plan(topology: ListenerNeeds) -> Arc<ListenerPlan> {
    Arc::new(ListenerPlan {
        initial: topology,
        served: std::sync::OnceLock::new(),
        upgrades: std::sync::OnceLock::new(),
        claim_doors: Arc::default(),
        planes: std::sync::OnceLock::new(),
        plane_sections: std::sync::OnceLock::new(),
        plane_keys: std::sync::OnceLock::new(),
        offers: vec![("http", AuthPoints::HEAD)],
        framers: [("http".into(), (1, false))].into(),
        refusals: std::sync::Mutex::default(),
        nests: Arc::default(),
        plugin_mounts: std::sync::OnceLock::new(),
    })
}

fn app(
    topology: ListenerNeeds,
    routes: Vec<RouteDecl>,
    generation: u64,
) -> Arc<busbar_kernel::state::App> {
    let mut app = busbar_kernel_testkit::test_support::TestApp::new().build();
    let candidate = Arc::get_mut(&mut app).unwrap();
    candidate.plugin_routes =
        Arc::new(build_route_table(routes).expect("valid endpoint declarations"));
    candidate.config_version = generation;
    candidate.config_projection = Some(Arc::new(crate::root::door_steps::DoorConfig {
        listener_routes: std::sync::OnceLock::new(),
        root_binds: Ok(topology
            .binds
            .iter()
            .filter(|bind| bind.owner == BindOwner::Root)
            .cloned()
            .collect()),
        listeners: Ok(topology),
        data_chain: vec![busbar_kernel::config::KEYS_MODULE.into()],
        sections: Default::default(),
        providers: Default::default(),
        model_pools: Default::default(),
    }));
    app
}

#[test]
fn export_only_lists_enforce_physical_ownership_admin_placement_and_method_auth() {
    let topology = topology();
    let plan = plan(topology.clone());
    let app = app(
        topology,
        vec![
            route("private", "/exports/private/scrape", RouteAuth::Key),
            route("public", "/exports/public/scrape", RouteAuth::None),
            route("private", "/exports/private/admin", RouteAuth::Admin),
        ],
        1,
    );
    plan.check(&app).expect("an export-only deployment seals");
    let lists = plan.lists(&app).unwrap();
    let root = &lists.iter().find(|(at, _)| at == "listen").unwrap().1;
    let private = &lists
        .iter()
        .find(|(at, _)| at == "export.private.settings.ingress")
        .unwrap()
        .1;
    assert!(matches!(
        root.matched("GET", "/exports/private/scrape", &[]),
        Matched::NoRoute
    ));
    assert!(matches!(
        private.matched("GET", "/exports/public/scrape", &[]),
        Matched::NoRoute
    ));
    for list in [root, private] {
        assert!(matches!(
            list.matched("GET", "/exports/private/admin", &[]),
            Matched::NoRoute
        ));
    }
    let Matched::Line(line) = private.matched("HEAD", "/exports/private/scrape", &[]) else {
        panic!("HEAD follows the existing GET handler");
    };
    assert!(
        matches!(&line.auth, LineAuth::Chain(names, points) if names.len() == 1 && names[0] == busbar_kernel::config::KEYS_MODULE && *points == AuthPoints::HEAD)
    );
    assert_eq!(line.claimant, Claimant::Need("private".into(), 0));
    assert!(matches!(
        private.matched("POST", "/exports/private/scrape", &[]),
        Matched::MethodMiss(_)
    ));
}

#[test]
fn listener_policy_retains_each_candidate_across_three_new_generations() {
    let topology = topology();
    let plan = plan(topology.clone());
    let first = app(
        topology.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        1,
    );
    let source = |app: Arc<busbar_kernel::state::App>| busbar_kernel::inbound::Listener {
        guests: GuestList::default(),
        auths: Default::default(),
        body_limit: 1024,
        app,
        door_refusals: Vec::new(),
        ids: Vec::new(),
        signed_ingress: busbar_kernel_testkit::test_support::inbound::signed_by_dialect(),
        scope: None,
    };
    let select = plan.policy("export.private.settings.ingress".into());
    plan.check(&first).unwrap();
    let retained = select(&source(Arc::clone(&first))).unwrap();
    for generation in 2..=4 {
        let next = app(
            topology.clone(),
            vec![route("private", "/exports/private/scrape", RouteAuth::None)],
            generation,
        );
        plan.check(&next).unwrap();
        let selected = select(&source(Arc::clone(&next))).unwrap();
        assert!(Arc::ptr_eq(&selected.app, &next));
        assert!(selected
            .guests
            .lines()
            .iter()
            .all(|line| line.auth == LineAuth::None));
        assert!(Arc::ptr_eq(&retained.app, &first));
        assert!(retained
            .guests
            .lines()
            .iter()
            .any(|line| matches!(line.auth, LineAuth::Chain(..))));
    }
    let mut changed = topology;
    changed.binds[2].listen.set_port(9090);
    let refused = app(
        changed,
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        5,
    );
    assert!(plan.check(&refused).is_err());
    assert_eq!(retained.app.config_version, 1);
}

#[test]
fn replacement_without_a_need_does_not_inherit_old_instance_listener_authority() {
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(
        initial.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        1,
    );
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let mut replacement = initial;
    replacement.needs.clear();
    replacement.binds.truncate(2);
    let replacement = app(
        replacement,
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        2,
    );
    plan.check(&replacement)
        .expect("the actual handler can move to the root bind");
    let private = plan
        .guests(&replacement, "export.private.settings.ingress")
        .unwrap();
    assert!(matches!(
        private.matched("GET", "/exports/private/scrape", &[]),
        Matched::NoRoute
    ));
    let root = plan.data_guests(&replacement).unwrap();
    assert!(matches!(
        root.matched("GET", "/exports/private/scrape", &[]),
        Matched::Line(_)
    ));
}

#[test]
fn moving_data_routes_between_bound_listeners_keeps_admin_placement_separate() {
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(
        initial.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        1,
    );
    plan.check(&boot).unwrap();
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let mut moved = initial.clone();
    moved.needs[0].at = "listen".into();
    let moved = app(
        moved,
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        2,
    );
    plan.check(&moved)
        .expect("data routes can move between existing physical listeners");
    let mut admin = initial;
    admin.needs.clear();
    let admin = app(
        admin,
        vec![route(
            "private",
            "/exports/private/scrape",
            RouteAuth::Admin,
        )],
        2,
    );
    assert!(plan.check(&admin).is_err());
    assert_eq!(boot.config_version, 1);
}

#[test]
fn identical_plane_paths_on_distinct_listeners_are_sealed_independently() {
    use busbar_contract::abi::transport::route::{METHOD_GET, PATH_EXACT};
    use busbar_kernel::guest::{Line, Route};
    let mut topology = topology();
    topology.needs[0].kind = KindCode::Plane;
    topology.needs[0].instance = "right".into();
    topology.needs.push(ListenerNeed {
        instance: "left".into(),
        module: "module-left".into(),
        kind: KindCode::Plane,
        need: 0,
        transport: "http".into(),
        auth: String::new(),
        at: "listen".into(),
    });
    let plan = plan(topology.clone());
    plan.planes
        .set(
            ["left", "right"]
                .into_iter()
                .map(|owner| super::ListenerPlaneLine {
                    line: Line {
                        route: Route {
                            methods: METHOD_GET,
                            path_form: PATH_EXACT,
                            path: "/same".into(),
                            fields: Vec::new(),
                            rung: 0,
                        },
                        claimant: Claimant::Plane(owner.into()),
                        dialect: 0,
                        auth: LineAuth::None,
                        upgrade: None,
                        offered: AuthPoints::HEAD,
                    },
                    transport: "http".into(),
                    root_only: false,
                })
                .collect(),
        )
        .unwrap();
    plan.plane_sections
        .set(
            [
                ("left".into(), ("left-resource", false)),
                ("right".into(), ("right-resource", false)),
            ]
            .into(),
        )
        .unwrap();
    plan.plane_keys
        .set(
            [
                ("left".into(), "left-module".into()),
                ("right".into(), "right-module".into()),
            ]
            .into(),
        )
        .unwrap();
    let mut candidate = app(topology, Vec::new(), 1);
    Arc::get_mut(&mut candidate).unwrap().planes =
        Arc::new(["left-module", "right-module"].into_iter().fold(
            busbar_kernel::plane_driver::dispatch::PlaneDispatch::default(),
            |planes, key| {
                planes.admit(
                    key,
                    busbar_kernel::plane_driver::dispatch::PlaneAdmission {
                        audience: key.into(),
                        resource_metadata: format!("https://resource/{key}"),
                    },
                )
            },
        ));
    plan.check(&candidate).unwrap();
    for (at, owner) in [
        ("listen", "left"),
        ("export.private.settings.ingress", "right"),
    ] {
        let guests = plan.guests(&candidate, at).unwrap();
        let Matched::Line(line) = guests.matched("GET", "/same", &[]) else {
            panic!("physical route exists");
        };
        assert_eq!(line.claimant, Claimant::Plane(owner.into()));
        let source = busbar_kernel::inbound::Listener {
            guests: GuestList::default(),
            auths: Default::default(),
            body_limit: 1024,
            app: candidate.clone(),
            door_refusals: Vec::new(),
            ids: Vec::new(),
            signed_ingress: Arc::new(|_, _| true),
            scope: None,
        };
        let scoped = plan.policy(at.into())(&source).unwrap();
        let head = busbar_kernel::inbound::Head {
            method: "GET".into(),
            target: "/same".into(),
            authority: String::new(),
            query: None,
            fields: Vec::new(),
        };
        assert_eq!(
            (scoped.scope.as_ref().unwrap().admission)(&candidate, &head)
                .unwrap()
                .audience,
            format!("{owner}-module")
        );
        assert_eq!((scoped.signed_ingress)(&candidate, "/same"), at == "listen");
    }
}

#[test]
fn declared_default_is_required_only_for_key_routes_without_operator_chain() {
    let mut topology = topology();
    topology.needs[0].auth = "unavailable-inbound-style".into();
    let plan = plan(topology.clone());
    let with_operator = app(
        topology.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        1,
    );
    plan.check(&with_operator)
        .expect("explicit operator chain overrides a declared default");
    for (auth, allowed) in [(RouteAuth::Key, false), (RouteAuth::None, true)] {
        let mut candidate = app(
            topology.clone(),
            vec![route("private", "/exports/private/scrape", auth)],
            2,
        );
        let candidate_mut = Arc::get_mut(&mut candidate).unwrap();
        let projection = Arc::get_mut(candidate_mut.config_projection.as_mut().unwrap())
            .unwrap()
            .downcast_mut::<crate::root::door_steps::DoorConfig>()
            .unwrap();
        projection.data_chain.clear();
        assert_eq!(
            plan.check(&candidate).is_ok(),
            allowed,
            "explicit public routes bypass, Key requires the missing default"
        );
    }
}

#[test]
fn retained_boot_dispatch_keeps_only_its_exact_source_instances_binding() {
    let initial = topology();
    let plan = plan(initial.clone());
    let retained = || {
        let mut route = route("module-namespace", "/observations", RouteAuth::None);
        route.source_instance = "private".into();
        route.scrape = true;
        route.persistent = true;
        route
    };
    let mut removed = initial.clone();
    removed.needs.clear();
    removed.binds.truncate(2);
    let candidate = app(removed, vec![retained()], 2);
    plan.check(&candidate).unwrap();
    assert!(matches!(
        plan.guests(&candidate, "export.private.settings.ingress")
            .unwrap()
            .matched("GET", "/observations", &[]),
        Matched::Line(_)
    ));
    assert!(matches!(
        plan.data_guests(&candidate)
            .unwrap()
            .matched("GET", "/observations", &[]),
        Matched::NoRoute
    ));
    let mut replacement = initial;
    replacement.needs[0].module = "different-module".into();
    let replacement = app(replacement, vec![retained()], 3);
    assert!(
        plan.check(&replacement).is_err(),
        "retained dispatch does not serve a replacement module's Need"
    );
}

#[test]
fn datagram_session_description_keeps_its_existing_http_post_route() {
    use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
    use busbar_kernel::guest::{Line, Route};
    let mut topology = topology();
    topology.binds[2].transport = "datagram-fixture".into();
    topology.needs[0].transport = "datagram-fixture".into();
    topology.needs[0].kind = KindCode::Plane;
    let mut plan = plan(topology.clone());
    Arc::get_mut(&mut plan)
        .unwrap()
        .framers
        .insert("datagram-fixture".into(), (2, true));
    plan.planes
        .set(vec![super::ListenerPlaneLine {
            line: Line {
                route: Route {
                    methods: METHOD_POST,
                    path_form: PATH_EXACT,
                    path: "/session-description".into(),
                    fields: Vec::new(),
                    rung: 0,
                },
                claimant: Claimant::Plane("private".into()),
                dialect: 0,
                auth: LineAuth::None,
                upgrade: None,
                offered: AuthPoints::HEAD,
            },
            transport: "datagram-fixture".into(),
            root_only: false,
        }])
        .unwrap();
    let candidate = app(topology, Vec::new(), 1);
    plan.check(&candidate).unwrap();
    assert!(matches!(
        plan.data_guests(&candidate)
            .unwrap()
            .matched("POST", "/session-description", &[]),
        Matched::Line(_)
    ));
    assert_eq!(plan.stream_binds().count(), 0);
}

#[tokio::test]
async fn physical_routers_share_publication_but_keep_handlers_and_refusals_separate() {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, Response, StatusCode};
    use busbar_kernel::plane_routes::{PlaneRefuseByPathFn, PlaneRouteSpec};
    use tower::ServiceExt as _;
    let mounted = |label: &'static str| PlaneRouteSpec {
        path: "/same".into(),
        method: RouteMethod::Get,
        auth: RouteAuth::None,
        handler: Arc::new(move |ctx| {
            Box::pin(async move {
                let app = ctx
                    .engine
                    .downcast_ref::<busbar_kernel::state::App>()
                    .unwrap();
                Response::new(Body::from(format!("{label}:{}", app.config_version)))
            })
        }),
    };
    let renderer = |label: &'static str| -> PlaneRefuseByPathFn {
        Arc::new(move |refusal| {
            Some(
                Response::builder()
                    .status(refusal.status)
                    .body(Body::from(label))
                    .unwrap(),
            )
        })
    };
    let first = busbar_kernel_testkit::test_support::TestApp::new().build();
    let (left, _, handle) = busbar_kernel::build_split_routers_serving_doors(
        first,
        vec![mounted("left")],
        Vec::new(),
        Vec::new(),
        1024,
        0,
        false,
    );
    handle.bind_door_refuser(renderer("left-refusal"));
    let right = busbar_kernel::build_data_router_on(
        &handle,
        &busbar_kernel::plugin_routes::PluginRouteTable::empty(),
        vec![mounted("right")],
        Vec::new(),
        Vec::new(),
        Some(renderer("right-refusal")),
        1024,
        0,
        false,
    );
    for generation in 2..=4 {
        let mut next = busbar_kernel_testkit::test_support::TestApp::new().build();
        Arc::get_mut(&mut next).unwrap().config_version = generation;
        handle.swap(next);
        for (router, label) in [(&left, "left"), (&right, "right")] {
            let answer = router
                .clone()
                .oneshot(Request::builder().uri("/same").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(answer.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(answer.into_body(), 1024).await.unwrap().as_ref(),
                format!("{label}:{generation}").as_bytes()
            );
        }
    }
    for (router, expected) in [(&left, StatusCode::OK), (&right, StatusCode::NOT_FOUND)] {
        let answer = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            answer.status(),
            expected,
            "root convenience routes exist only on the root listener"
        );
    }
    for (router, expected) in [(&left, "left-refusal"), (&right, "right-refusal")] {
        let answer = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/same")
                    .header("content-length", "2048")
                    .body(Body::from(vec![0_u8; 2048]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(answer.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            to_bytes(answer.into_body(), 1024).await.unwrap().as_ref(),
            expected.as_bytes()
        );
    }
}

#[test]
fn actual_candidate_registry_replaces_the_early_boot_need_projection() {
    let topology = topology();
    let plan = plan(topology.clone());
    let mut candidate = app(topology, Vec::new(), 2);
    let candidate_mut = Arc::get_mut(&mut candidate).unwrap();
    candidate_mut.hook_env.registry = Arc::new(crate::root::loader::PluginRegistry::empty());
    candidate_mut.hook_registry.clear();
    candidate_mut.export_defs.clear();
    let actual = plan.needs(&candidate).unwrap();
    assert!(
        actual.needs.is_empty(),
        "a previous module's projected Need is not authority for the actual replacement candidate"
    );
    assert_eq!(actual.binds.len(), 2);
}

#[test]
fn unopened_dispatch_cannot_replace_a_serving_route_but_new_paths_still_need_restart() {
    let topology = topology();
    let plan = plan(topology.clone());
    let unavailable = |path| {
        let mut route = route("private", path, RouteAuth::None);
        route.dispatch_available = false;
        route
    };
    let missing_at_boot = app(
        topology.clone(),
        vec![unavailable("/exports/private/scrape")],
        1,
    );
    assert!(plan.check(&missing_at_boot).is_err());
    let boot = app(
        topology.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        1,
    );
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let replacement = app(
        topology.clone(),
        vec![unavailable("/exports/private/scrape")],
        2,
    );
    assert!(plan.check(&replacement).is_err());
    let mut no_need = topology;
    no_need.needs.clear();
    let new_path = app(no_need, vec![unavailable("/exports/private/new")], 2);
    plan.check(&new_path)
        .expect("new unmounted paths retain the existing restart-to-apply behavior");
    let mounted = plan.mounted_plugin_paths(&new_path).unwrap();
    assert_eq!(
        busbar_kernel::plugin_routes::paths_awaiting_restart(
            &new_path.plugin_routes,
            &boot.plugin_routes,
            &mounted,
        ),
        vec!["/exports/private/new".to_string()]
    );
}

#[test]
fn renamed_plugin_uses_its_candidate_physical_listener() {
    let initial = topology();
    let plan = plan(initial.clone());
    let declared = |instance: &str| {
        let mut route = route("module-namespace", "/observations", RouteAuth::None);
        route.source_instance = instance.into();
        route.scrape = true;
        route
    };
    let boot = app(initial.clone(), vec![declared("private")], 1);
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let mut renamed = initial;
    renamed.needs[0].instance = "renamed".into();
    let next = app(renamed.clone(), vec![declared("renamed")], 2);
    plan.check(&next)
        .expect("the same generic route resolves the renamed configuration's current dispatcher");
    renamed.needs[0].at = "listen".into();
    let moved = app(renamed, vec![declared("renamed")], 3);
    plan.check(&moved)
        .expect("the renamed candidate can move its actual generic handler");
}

#[test]
fn a_new_data_method_on_a_boot_plugin_path_prepares_a_new_router() {
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(
        initial.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        1,
    );
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let mut post = route("private", "/exports/private/scrape", RouteAuth::None);
    post.route.method = RouteMethod::Post;
    let candidate = app(initial, vec![post], 2);
    plan.check(&candidate)
        .expect("the candidate constructs its own method router");
}

const MIGRATION_PATH: &str = "/exports/private/scrape";
const PRIVATE_LISTENER: &str = "export.private.settings.ingress";
const TEST_BODY_LIMIT: usize = 1024;

struct LabeledAnswer(&'static str);
impl PluginHttpDispatch for LabeledAnswer {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: axum::http::StatusCode::OK.as_u16(),
            headers: Vec::new(),
            body: self.0.as_bytes().to_vec(),
        }
    }
}

fn labeled_route(label: &'static str) -> RouteDecl {
    let mut declared = route("private", MIGRATION_PATH, RouteAuth::None);
    declared.dispatch = Arc::new(LabeledAnswer(label));
    declared
}

async fn physical_answer(
    router: &axum::Router,
    pinned: Option<Arc<busbar_kernel::state::App>>,
) -> (axum::http::StatusCode, axum::body::Bytes) {
    use tower::ServiceExt as _;
    let mut request = axum::http::Request::builder()
        .uri(MIGRATION_PATH)
        .body(axum::body::Body::empty())
        .unwrap();
    if let Some(app) = pinned {
        request.extensions_mut().insert(app);
    }
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), TEST_BODY_LIMIT)
        .await
        .unwrap();
    (status, body)
}

#[tokio::test]
async fn actual_handlers_migrate_only_on_publication_and_old_requests_keep_their_partition() {
    use axum::http::StatusCode;
    let initial = topology();
    let plan = plan(initial.clone());
    let rules = Arc::new(crate::root::door_steps::Rules::default());
    rules.hold_listeners(plan.clone()).unwrap();
    let mut boot = app(initial.clone(), vec![labeled_route("boot")], 1);
    Arc::get_mut(&mut boot).unwrap().root_rules = rules.clone();
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let boot_lifetime = Arc::downgrade(&boot);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(boot.clone()));
    let handle_lifetime = Arc::downgrade(&handle);
    let root = plan.router(&handle, "listen".into(), TEST_BODY_LIMIT, 0, false);
    let private = plan.router(&handle, PRIVATE_LISTENER.into(), TEST_BODY_LIMIT, 0, false);
    assert_eq!(
        physical_answer(&private, None).await,
        (StatusCode::OK, "boot".into())
    );
    assert_eq!(physical_answer(&root, None).await.0, StatusCode::NOT_FOUND);

    let mut moved = initial.clone();
    moved.needs[0].at = "listen".into();
    let mut discarded = app(moved.clone(), vec![labeled_route("discarded")], 2);
    Arc::get_mut(&mut discarded).unwrap().root_rules = rules.clone();
    plan.check(&discarded).unwrap();
    let discarded_routes = Arc::downgrade(&plan.prepared(&discarded, "listen").unwrap());
    let discarded_app = Arc::downgrade(&discarded);
    drop(discarded);
    assert!(discarded_app.upgrade().is_none());
    assert!(
        discarded_routes.upgrade().is_none(),
        "unpublished candidate handlers are released"
    );
    assert_eq!(physical_answer(&private, None).await.1.as_ref(), b"boot");
    assert_eq!(physical_answer(&root, None).await.0, StatusCode::NOT_FOUND);

    let mut incompatible = moved.clone();
    incompatible.needs[0].transport = "missing-accepting-framer".into();
    let rejected = app(incompatible, vec![labeled_route("rejected")], 2);
    assert!(plan.check(&rejected).is_err());
    assert!(plan.prepared(&rejected, "listen").is_none());
    assert!(Arc::ptr_eq(&handle.load(), &boot));
    drop(rejected);

    let unmountable = app(
        initial.clone(),
        vec![route(
            "private",
            "/exports/private/{*tail}/after-tail",
            RouteAuth::None,
        )],
        2,
    );
    let unmountable_lifetime = Arc::downgrade(&unmountable);
    assert!(
        plan.check(&unmountable).is_err(),
        "an invalid later partition rolls back the root router prepared before it"
    );
    assert!(plan.prepared(&unmountable, "listen").is_none());
    drop(unmountable);
    assert!(unmountable_lifetime.upgrade().is_none());
    assert_eq!(physical_answer(&private, None).await.1.as_ref(), b"boot");

    let mut next = app(moved, vec![labeled_route("published")], 2);
    Arc::get_mut(&mut next).unwrap().root_rules = rules.clone();
    plan.check(&next).unwrap();
    let next_lifetime = Arc::downgrade(&next);
    handle.swap(next.clone());
    assert_eq!(
        physical_answer(&root, None).await,
        (StatusCode::OK, "published".into())
    );
    assert_eq!(
        physical_answer(&private, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        physical_answer(&private, Some(boot.clone())).await,
        (StatusCode::OK, "boot".into()),
        "old admission uses its actual old physical handler"
    );
    assert_eq!(
        physical_answer(&root, Some(boot.clone())).await.0,
        StatusCode::NOT_FOUND
    );
    drop(boot);
    assert!(
        boot_lifetime.upgrade().is_none(),
        "the router cache retains no old App"
    );
    drop(next);
    drop(root);
    drop(private);
    drop(handle);
    assert!(
        handle_lifetime.upgrade().is_none(),
        "prepared routers contain no process handle"
    );
    assert!(
        next_lifetime.upgrade().is_none(),
        "retired generation and prepared state drop together"
    );
}

#[tokio::test]
async fn a_swap_between_route_selection_and_auth_keeps_the_selected_generation() {
    let mut initial = topology();
    initial.needs[0].at = "listen".into();
    let plan = plan(initial.clone());
    let boot = app(initial.clone(), vec![labeled_route("selected")], 1);
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let next = app(initial, vec![labeled_route("later")], 2);
    plan.check(&next).unwrap();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(boot));
    let swapping = Arc::downgrade(&handle);
    let router = busbar_kernel::router::serve_listener_generations(
        handle.clone(),
        move |selected| {
            let prepared = plan.prepared(selected, "listen");
            if selected.config_version == 1 {
                swapping.upgrade().unwrap().swap(next.clone());
            }
            prepared
        },
        TEST_BODY_LIMIT,
        0,
        false,
    );
    assert_eq!(physical_answer(&router, None).await.1.as_ref(), b"selected");
    assert_eq!(handle.load().config_version, 2);
    assert_eq!(physical_answer(&router, None).await.1.as_ref(), b"later");
}

#[tokio::test]
async fn newly_opened_data_paths_are_physically_served_without_a_restart_report() {
    use tower::ServiceExt as _;
    const ADDED_PATH: &str = "/exports/private/added";
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(initial.clone(), vec![labeled_route("boot")], 1);
    plan.mount_planes(&super::Served::default(), &boot, &[])
        .unwrap();
    let next = app(
        initial,
        vec![
            labeled_route("current"),
            route("private", ADDED_PATH, RouteAuth::None),
        ],
        2,
    );
    plan.check(&next).unwrap();
    let mounted = plan.mounted_plugin_paths(&next).unwrap();
    assert!(
        busbar_kernel::plugin_routes::paths_awaiting_restart(
            &next.plugin_routes,
            &boot.plugin_routes,
            &mounted,
        )
        .is_empty(),
        "the report uses actual candidate mounts"
    );
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(next));
    let router = plan.router(&handle, PRIVATE_LISTENER.into(), TEST_BODY_LIMIT, 0, false);
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri(ADDED_PATH)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), TEST_BODY_LIMIT)
            .await
            .unwrap()
            .as_ref(),
        b"served"
    );
}

/// The default data chain's keys position is implemented by the kernel, with no AuthCalls
/// object. Listener preparation must preserve that position while collecting only plugin calls.
#[tokio::test]
async fn a_kernel_keys_listener_prepares_and_keeps_real_key_verification() {
    use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY};
    use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE, FLOW_STOP};
    use busbar_contract::auth_calls::StripPlace;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::inbound::{Call, HandIn, Head, Inbound, Listener, Seals};
    use busbar_kernel_testkit::test_support::store_double::MemoryStore;
    const PATH: &str = "/exports/private/secured";
    const OWNER: u64 = 27;
    const LISTENER: u64 = 29;
    const GENERATION: u64 = 1;
    const FRAMING: u64 = 31;
    let topology = topology();
    let mut plan = plan(topology.clone());
    Arc::get_mut(&mut plan).unwrap().offers[0].1 = AuthPoints(POINT_HEAD | POINT_HEAD_BODY);
    let signer = TokenSigner::from_secret_bytes(&[37; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer)).unwrap(),
    );
    let now = busbar_kernel::store::now();
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "listener-key".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    let token_grant = busbar_kernel::seal::lend();
    let live_token = token.expose(&token_grant).as_str();
    let enforcing = busbar_kernel_testkit::test_support::TestApp::new()
        .keys_chain()
        .governance(gov.clone())
        .build();
    let mut candidate = app(
        topology,
        vec![route("private", PATH, RouteAuth::Key)],
        GENERATION,
    );
    let state = Arc::get_mut(&mut candidate).unwrap();
    state.auth = enforcing.auth.clone();
    state.governance = Some(gov.clone());
    assert!(candidate.auth.keys_in_chain);
    assert!(candidate
        .auth
        .position_calls(busbar_kernel::config::KEYS_MODULE)
        .is_none());
    let expected_points = candidate
        .auth
        .position_points(busbar_kernel::config::KEYS_MODULE);
    let verify_point = if expected_points.bits() & POINT_HEAD_BODY != 0 {
        POINT_HEAD_BODY
    } else {
        POINT_HEAD
    };
    plan.check(&candidate)
        .expect("kernel keys requires no opened plugin calls");
    let guests = plan.guests(&candidate, PRIVATE_LISTENER).unwrap();
    let Matched::Line(line) = guests.matched("GET", PATH, &[]) else {
        panic!("protected route remains present");
    };
    assert!(matches!(&line.auth, LineAuth::Chain(names, points)
        if names == &[busbar_kernel::config::KEYS_MODULE] && *points == expected_points));
    let auths = plan.auths(&candidate, &guests).unwrap();
    assert!(
        auths.is_empty(),
        "the kernel position has no counterfeit auth plugin"
    );
    let mut missing = line.clone();
    missing.auth = LineAuth::Chain(
        vec![
            busbar_kernel::config::KEYS_MODULE.into(),
            "missing-auth-plugin".into(),
        ],
        AuthPoints::HEAD,
    );
    assert!(
        plan.auths(&candidate, &GuestList::seal(vec![missing]).unwrap())
            .err()
            .expect("an unprovided plugin position still refuses preparation")
            .contains("missing-auth-plugin"),
        "only the kernel-owned position may lack plugin calls"
    );

    let next = Arc::new(std::sync::atomic::AtomicU64::new(100));
    let inbound = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)),
            mac: Arc::new(|tag| {
                crate::root::loader::dispatch::auth_handle::mint_unit_ref(
                    tag.secret,
                    tag.generation,
                    tag.owner,
                    tag.line,
                    tag.unit,
                )
                .map(|unit| unit.mac)
            }),
        },
        Arc::new(|future| {
            tokio::spawn(future);
        }),
        Arc::new(|_| {}),
    );
    let ids: Vec<_> = (1..=guests.lines().len() as u64).collect();
    inbound
        .install_at(
            OWNER,
            LISTENER,
            GENERATION,
            Listener {
                guests,
                auths,
                body_limit: 1024,
                app: candidate,
                door_refusals: Vec::new(),
                ids,
                signed_ingress: Arc::new(|_, _| false),
                scope: None,
            },
        )
        .unwrap();
    inbound
        .framing_started(OWNER, LISTENER, FRAMING, GENERATION)
        .unwrap();
    let specs = inbound.specs_at(OWNER, LISTENER, GENERATION).unwrap();
    let line = specs
        .iter()
        .find(|spec| spec.points == expected_points.bits())
        .unwrap();
    for (index, (credential, accepted, disabled)) in [
        (None, false, false),
        (Some("not-a-valid-key"), false, false),
        (Some(live_token), true, false),
        (Some(live_token), false, true),
    ]
    .into_iter()
    .enumerate()
    {
        if disabled {
            gov.update_key(&key.id, Some(false), None).unwrap().unwrap();
        }
        let stream = index as u64 + 1;
        inbound
            .grant_stream(OWNER, FRAMING, stream, GENERATION)
            .unwrap();
        let head = Head {
            method: "GET".into(),
            target: PATH.into(),
            authority: "listener.test".into(),
            query: None,
            fields: credential
                .map(|token| {
                    vec![(
                        "authorization".into(),
                        format!("Bearer {token}").into_bytes(),
                    )]
                })
                .unwrap_or_default(),
        };
        let (done, waited) = tokio::sync::oneshot::channel();
        let answered = inbound.auth_call(
            Call {
                owner: OWNER,
                generation: GENERATION,
                auth: line.auth,
                unit: UnitRef::NONE,
                point: verify_point,
                conn: FRAMING,
                stream,
                framing: FRAMING,
                head: head.clone(),
                body: (verify_point == POINT_HEAD_BODY).then(Vec::new),
                deadline: None,
            },
            Box::new(move |answer| {
                let _ = done.send(answer);
            }),
        );
        let answer = match answered {
            Some(answer) => answer,
            None => waited.await.unwrap(),
        }
        .unwrap();
        assert_eq!(
            answer.flow,
            if accepted { FLOW_CONTINUE } else { FLOW_STOP }
        );
        let mut sanitized = head;
        sanitized.fields.retain(|(name, _)| {
            !answer.strips.iter().any(|strip| {
                strip.place == StripPlace::Field && strip.name.eq_ignore_ascii_case(name)
            })
        });
        let handed = inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GENERATION,
                auth: line.auth,
                unit: answer.unit,
                line: line.line,
                conn: FRAMING,
                stream,
                framing: Some(FRAMING),
                head: sanitized.clone(),
            })
            .unwrap();
        assert_eq!(handed.0, if accepted { FLOW_CONTINUE } else { FLOW_STOP });
        if accepted {
            let identified = inbound.admitted(answer.unit.id).unwrap();
            assert_eq!(identified.resolved.unwrap().id, key.id);
            assert!(inbound
                .claim_request(OWNER, FRAMING, stream, &sanitized)
                .is_ok());
        } else {
            assert!(inbound
                .claim_request(OWNER, FRAMING, stream, &sanitized)
                .is_err());
        }
        inbound.stream_ended(OWNER, FRAMING, stream);
    }
    inbound.framing_ended(FRAMING);
}
