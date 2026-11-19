// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Mutex;

use busbar_contract::kinds::codes::KindCode;
use busbar_contract::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::services::Caller;
use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::port_egress::MemberTarget;
use busbar_kernel::upstreams::{ConfiguredUpstreams, UpstreamDef, UpstreamTls};
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::Reply;
use busbar_ports::plane::*;
use busbar_ports::{CallCx, PortError};

struct InventoryPlane {
    routes: Vec<RouteInfo>,
    seen: Mutex<Vec<(u32, u32)>>,
}
fn refused() -> PortError {
    PortError::Call(busbar_plugin_abi::fail::CallError::NotDeclared)
}
impl PlanePort for InventoryPlane {
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn usage_shared(&self) -> (std::sync::Arc<[UsageClass]>, std::sync::Arc<[Box<str>]>) {
        Default::default()
    }
    fn facts(&self) -> u64 {
        busbar_plugin_abi::plane::FB_RESOURCE_ADMISSION
    }
    fn tick_s(&self) -> Option<u64> {
        None
    }
    fn admin_openapi(&self) -> Option<&str> {
        None
    }
    fn charge(&self, _: FaultReason) {}
    fn resource_facts(
        &self,
        mode: u32,
        req: &PlaneIn<'_>,
        body: &[u8],
        _: usize,
    ) -> Result<Vec<u8>, PortError> {
        assert_eq!(mode, busbar_plugin_abi::plane::RESOURCE_INVENTORY);
        assert_eq!(req.route, 7);
        assert_eq!(req.auth, 0);
        assert!(req.identity.is_empty() && req.headers.is_empty() && body.is_empty());
        self.seen.lock().unwrap().push((mode, req.route));
        use busbar_plugin_abi::resource_admission::{write_resource, Forward, Resource, Scope};
        let mut wire = Reply::new();
        write_resource(
            &mut wire,
            &Resource {
                scope: Scope {
                    kind: "pool",
                    value: "chat",
                },
                forwards: vec![Forward {
                    descriptor: 1,
                    pool: "chat",
                    member: "plane/test\u{1f}shared",
                    upstream: "shared",
                    dialect: "",
                    model: "",
                    method: "POST",
                    target: "/generate",
                }],
            },
        )
        .unwrap();
        Ok(wire.as_bytes().to_vec())
    }
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn piece(
        &self,
        _: &mut PlaneSession,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        _: u32,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async { Err(refused()) })
    }
}

fn inventory_fixture() -> (PortDriver, Arc<InventoryPlane>, InventoryInputs) {
    let port = Arc::new(InventoryPlane {
        routes: vec![RouteInfo {
            route: 7,
            methods: METHOD_POST,
            flags: 0,
            auth: busbar_plugin_abi::plane::AUTH_PRINCIPAL,
            pattern: "/resource".into(),
            cred_header: None,
            resource_kinds: vec![Box::<str>::from("pool")].into(),
        }],
        seen: Mutex::default(),
    });
    let caller = Caller::issue(
        &busbar_kernel::seal::acquire(),
        Arc::from("plane/test"),
        KindCode::Plane,
    );
    let driver = PortDriver::new(
        port.clone(),
        Arc::new(KernelServices::new()),
        caller,
        Arc::new(busbar_kernel::refusal::CoreRefusals::new()),
        &|_| None,
    )
    .unwrap();
    let upstream = Arc::new(UpstreamDef {
        resource: None,
        name: "shared".into(),
        allow_private: false,
        url: Some("https://example.invalid/".into()),
        command: None,
        tls: UpstreamTls {
            pin_spki: vec![],
            client_identity: None,
            trust: None,
        },
        auth: None,
    });
    let inputs = InventoryInputs {
        upstreams: Arc::new(ConfiguredUpstreams::from_definitions(BTreeMap::from([(
            "shared".into(),
            upstream,
        )]))),
        targets: Arc::new(|pool, member| {
            if pool != "chat" || member != "plane/test\u{1f}shared" {
                return None;
            }
            let mut target = MemberTarget::bare();
            target.registered_upstream = Some("shared".into());
            Some(target)
        }),
        byte_limit: 1 << 20,
    };
    (driver, port, inputs)
}

#[test]
fn inventory_uses_actual_route_and_registration_inputs() {
    let (driver, port, inputs) = inventory_fixture();
    let inventory = build_inventory(&driver, &driver.routes().data[0], 37, &inputs).unwrap();
    assert_eq!(inventory.instance(), driver.caller().incarnation());
    assert_eq!(inventory.epoch(), 37);
    assert_eq!(
        *port.seen.lock().unwrap(),
        vec![(busbar_plugin_abi::plane::RESOURCE_INVENTORY, 7)]
    );
}

#[test]
fn inventory_refuses_foreign_route_and_missing_actual_target() {
    let (driver, port, mut inputs) = inventory_fixture();
    let mut foreign = driver.routes().data[0].clone();
    foreign.route = 8;
    assert!(build_inventory(&driver, &foreign, 37, &inputs).is_err());
    assert!(port.seen.lock().unwrap().is_empty());
    inputs.targets = Arc::new(|_, _| None);
    assert!(build_inventory(&driver, &driver.routes().data[0], 37, &inputs).is_err());
}

#[test]
fn inventory_refuses_unbounded_or_oversize_output() {
    let (driver, port, mut inputs) = inventory_fixture();
    inputs.byte_limit = 0;
    assert!(build_inventory(&driver, &driver.routes().data[0], 37, &inputs).is_err());
    assert!(port.seen.lock().unwrap().is_empty());
    inputs.byte_limit = 1;
    assert!(build_inventory(&driver, &driver.routes().data[0], 37, &inputs).is_err());
}

fn core_line() -> Line {
    Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: "/healthz".into(),
            fields: vec![],
            rung: 0,
        },
        claimant: Claimant::Clean("core".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    }
}
#[test]
fn core_coverage_requires_exact_declared_path_methods_and_class() {
    let line = core_line();
    let declared = vec![("/healthz".into(), RouteMethod::Get, RouteAuth::None)];
    assert_eq!(
        declared_core_auth(&line, &declared).unwrap(),
        RouteAuth::None
    );
    let mut extra = line.clone();
    extra.route.methods |= METHOD_POST;
    assert!(declared_core_auth(&extra, &declared).is_err());
    let mut duplicate = declared.clone();
    duplicate.push(("/healthz".into(), RouteMethod::Get, RouteAuth::Admin));
    assert!(declared_core_auth(&line, &duplicate).is_err());
    let protected = vec![("/healthz".into(), RouteMethod::Get, RouteAuth::Key)];
    assert!(declared_core_auth(&line, &protected).is_err());
    assert!(declared_core_auth(&line, &[]).is_err());
}

#[tokio::test]
async fn operator_slot_is_built_from_actual_admin_handlers_and_preserves_head_health() {
    use busbar_kernel::inbound::native::{AcceptedConnection, PhysicalListener, RouteTarget};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use tower::ServiceExt as _;
    busbar_core_admin::install();
    let app = crate::root::min3_auth::tests::physical_app().await;
    let transport = crate::root::min3_boot::transports::tests::framer(&["http"]);
    let slot = assemble_admin_slot(&app, "admin_listen", transport.clone()).unwrap();
    assert!(slot
        .prepared()
        .core_lines()
        .any(|(_, _, auth)| auth == RouteAuth::Admin));
    assert!(crate::root::serve::native_slot(&app, "admin_listen").is_none());
    let mut candidate = (*app).clone();
    crate::root::serve::install_native_slots(
        &mut candidate,
        BTreeMap::from([("admin_listen".into(), slot.clone())]),
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        &crate::root::serve::native_slot(&candidate, "admin_listen").unwrap(),
        &slot,
    ));
    // The prior App's projection remains independent of this candidate's publication.
    assert!(crate::root::serve::native_slot(&app, "admin_listen").is_none());
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(candidate)));
    let listener = PhysicalListener::new(
        handle.clone(),
        "admin_listen".into(),
        transport,
        AdmissionClass::Operator,
        Arc::new(|app, name| {
            crate::root::serve::native_slot(app, name).map(|slot| slot.prepared().clone())
        }),
    )
    .unwrap();
    let budget = ProcessAdmission::new(4);
    let connection = listener.connect(
        AcceptedConnection::capture(
            &budget.connection_storage(AdmissionClass::Operator),
            "192.0.2.1",
            "192.0.2.2",
            "http/1.1",
            &[],
        )
        .unwrap(),
    );
    let (request, _owner) = connection
        .head(
            1,
            busbar_kernel::inbound::Head {
                method: "HEAD".into(),
                target: busbar_kernel::auth::HEALTHZ_PATH.into(),
                authority: String::new(),
                query: None,
                fields: Vec::new(),
            },
            budget.try_enter(AdmissionClass::Operator).unwrap(),
            None,
        )
        .unwrap();
    assert!(matches!(
        request.binding().route().target(),
        RouteTarget::Core(RouteAuth::None)
    ));
    assert!(slot.data_for(request.binding()).is_err());
    let credit = request.binding().request().try_reserve(0).unwrap();
    let execution = request
        .finish_input(busbar_contract::secure::SecureVec::new(), credit)
        .unwrap()
        .begin_completion()
        .unwrap()
        .complete_public()
        .unwrap();
    assert!(execution.check_executing().is_ok());
    let router = busbar_kernel::router::serve_listener_generations(
        handle,
        |app| {
            crate::root::serve::native_slot(app, "admin_listen").map(|slot| slot.prepared().clone())
        },
        1024,
        0,
        false,
    );
    let expected = busbar_kernel::endpoints::healthz(busbar_kernel::state::CurrentApp(
        execution.binding().app().clone(),
    ))
    .await
    .status();
    let mut http = axum::http::Request::builder()
        .method("HEAD")
        .uri(busbar_kernel::auth::HEALTHZ_PATH)
        .body(axum::body::Body::empty())
        .unwrap();
    http.extensions_mut()
        .insert(execution.binding().app().clone());
    http.extensions_mut()
        .insert(execution.binding().request().clone());
    http.extensions_mut()
        .insert(execution.binding().snapshot().unwrap());
    let response = router.oneshot(http).await.unwrap();
    assert_eq!(response.status(), expected);
    assert!(axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
    assert!(execution.check_executing().is_ok());
}

#[tokio::test]
async fn operator_slot_refuses_missing_actual_admin_authority() {
    busbar_core_admin::install();
    let app = crate::root::inbound_tests::app(false).await.0;
    assert!(app.native_admin.is_none());
    let transport = crate::root::min3_boot::transports::tests::framer(&["http"]);
    assert!(assemble_admin_slot(&app, "admin_listen", transport).is_err());
}
