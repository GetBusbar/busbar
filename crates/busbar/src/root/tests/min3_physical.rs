// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Mutex;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
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
            resource_kinds: vec!["pool".into()],
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
        offered: busbar_contract::abi::auth::AuthPoints::EMPTY,
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
