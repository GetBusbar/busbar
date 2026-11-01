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
        planes: std::sync::OnceLock::new(),
        plane_sections: std::sync::OnceLock::new(),
        plane_keys: std::sync::OnceLock::new(),
        offers: vec![("http", AuthPoints::HEAD)],
        framers: [("http".into(), (1, false))].into(),
        refusals: std::sync::Mutex::default(),
        nests: std::sync::Mutex::default(),
        mounted: std::sync::OnceLock::new(),
        plugin_mounts: std::sync::OnceLock::new(),
    })
}

fn app(
    topology: ListenerNeeds,
    routes: Vec<RouteDecl>,
    generation: u64,
) -> Arc<busbar_kernel::state::App> {
    let mut app = busbar_kernel::test_support::TestApp::new().build();
    let candidate = Arc::get_mut(&mut app).unwrap();
    candidate.plugin_routes =
        Arc::new(build_route_table(routes).expect("valid endpoint declarations"));
    candidate.config_version = generation;
    candidate.config_projection = Some(Arc::new(crate::root::door_steps::DoorConfig {
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
        signed_ingress: busbar_kernel::inbound::signed_by_dialect(),
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
    plan.freeze_mounts(&boot).unwrap();
    let mut replacement = initial;
    replacement.needs.clear();
    replacement.binds.truncate(2);
    let replacement = app(
        replacement,
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        2,
    );
    assert!(
        plan.check(&replacement).is_err(),
        "changing the default physical placement requires a restart"
    );
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
fn moving_existing_routes_between_bound_listeners_or_admin_refuses_before_publish() {
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(
        initial.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        1,
    );
    plan.check(&boot).unwrap();
    plan.freeze_mounts(&boot).unwrap();
    let mut moved = initial.clone();
    moved.needs[0].at = "listen".into();
    let moved = app(
        moved,
        vec![route("private", "/exports/private/scrape", RouteAuth::Key)],
        2,
    );
    assert!(plan.check(&moved).is_err());
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
    let first = busbar_kernel::test_support::TestApp::new().build();
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
        let mut next = busbar_kernel::test_support::TestApp::new().build();
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
    plan.freeze_mounts(&boot).unwrap();
    let replacement = app(
        topology.clone(),
        vec![unavailable("/exports/private/scrape")],
        2,
    );
    assert!(plan.check(&replacement).is_err());
    let new_path = app(topology, vec![unavailable("/exports/private/new")], 2);
    plan.check(&new_path)
        .expect("new unmounted paths retain the existing restart-to-apply behavior");
}

#[test]
fn renamed_plugin_keeps_a_generic_mount_only_on_its_original_physical_listener() {
    let initial = topology();
    let plan = plan(initial.clone());
    let declared = |instance: &str| {
        let mut route = route("module-namespace", "/observations", RouteAuth::None);
        route.source_instance = instance.into();
        route.scrape = true;
        route
    };
    let boot = app(initial.clone(), vec![declared("private")], 1);
    plan.freeze_mounts(&boot).unwrap();
    let mut renamed = initial;
    renamed.needs[0].instance = "renamed".into();
    let next = app(renamed.clone(), vec![declared("renamed")], 2);
    plan.check(&next)
        .expect("the same generic route resolves the renamed configuration's current dispatcher");
    renamed.needs[0].at = "listen".into();
    let moved = app(renamed, vec![declared("renamed")], 3);
    assert!(
        plan.check(&moved).is_err(),
        "renaming cannot move a boot-static mount to another listener"
    );
}

#[test]
fn a_new_method_on_a_boot_plugin_path_requires_a_new_router() {
    let initial = topology();
    let plan = plan(initial.clone());
    let boot = app(
        initial.clone(),
        vec![route("private", "/exports/private/scrape", RouteAuth::None)],
        1,
    );
    plan.freeze_mounts(&boot).unwrap();
    let mut post = route("private", "/exports/private/scrape", RouteAuth::None);
    post.route.method = RouteMethod::Post;
    let candidate = app(initial, vec![post], 2);
    assert!(plan.check(&candidate).is_err());
}
