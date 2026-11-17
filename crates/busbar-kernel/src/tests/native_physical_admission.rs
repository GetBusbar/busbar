// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_ports::transport::{ConnIn, TransportEvent, TransportOut, TransportSession};
use busbar_ports::PortError;

pub(crate) struct Transport;
fn unsupported<T>() -> Result<T, PortError> {
    Err(PortError::Refused {
        code: busbar_plugin_abi::fail::refused::R_UNSUPPORTED,
        text: "physical admission fixture has no framing calls".into(),
        error: None,
    })
}
impl TransportPort for Transport {
    fn alpn(&self, _: u32) -> &[Box<str>] {
        &[]
    }
    fn defaults(&self, _: u32) -> &[(Box<str>, Box<str>)] {
        &[]
    }
    fn protocols(&self) -> &[Box<str>] {
        &[]
    }
    fn facts(&self) -> u64 {
        busbar_plugin_abi::transport::FB_SERVER
    }
    fn begin(
        &self,
        _: &ConnIn<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<TransportSession, PortError> {
        unsupported()
    }
    fn ingest(
        &self,
        _: &mut TransportSession,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        unsupported()
    }
    fn emit(
        &self,
        _: &mut TransportSession,
        _: u64,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        unsupported()
    }
    fn timer(
        &self,
        _: &mut TransportSession,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        unsupported()
    }
    fn datagram(
        &self,
        _: &mut TransportSession,
        _: u32,
        _: bool,
        _: &[u8],
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        unsupported()
    }
    fn event(
        &self,
        _: &mut TransportSession,
        _: TransportEvent<'_>,
        _: &mut dyn FnMut(TransportOut<'_>),
    ) -> Result<(), PortError> {
        unsupported()
    }
}

fn line(path: &str) -> Line {
    Line {
        route: crate::guest::Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: path.into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Clean("fixture".into()),
        dialect: 0,
        auth: crate::guest::LineAuth::None,
        upgrade: None,
        offered: busbar_contract::abi::auth::AuthPoints::EMPTY,
    }
}

fn head(path: &str) -> Head {
    Head {
        method: "POST".into(),
        target: path.into(),
        ..Head::default()
    }
}

pub(crate) fn app() -> Arc<App> {
    let registry: Arc<dyn busbar_contract::plugin_rows::PluginRows> =
        Arc::new(busbar_plugin_loader::registry::PluginRegistry::empty());
    let resolver = Arc::new(crate::config::secret::SecretResolver::builtins_only());
    let cfg = crate::config::AuthCfg::default_none();
    Arc::new(App::from_test_parts(crate::state::AppParts {
        fallback_runtime_key: "",
        serve_tables: Default::default(),
        port_seats: Default::default(),
        exports: Default::default(),
        root_rules: Arc::new(crate::appbuild::AcceptAll),
        config_projection: Default::default(),
        config_tables: Default::default(),
        store: Arc::new(crate::store::HealthState::new(Vec::new())),
        limits: Default::default(),
        session_store: Arc::new(crate::session::SessionStore::new(1024, None)),
        incremental_scan: false,
        plane_pools: Default::default(),
        auth: Arc::new(crate::auth::AuthMiddleware::new(&cfg, &registry, &resolver).unwrap()),
        rewrite_hooks: Default::default(),
        tap_hooks: Default::default(),
        tap_hooks_candidate: Default::default(),
        tap_hooks_routing: Default::default(),
        tap_hooks_response: Default::default(),
        global_gates: Default::default(),
        pool_orderings: Default::default(),
        pool_decision_gates: Default::default(),
        pool_rewrite_chains: Default::default(),
        plane_gates: Default::default(),
        plane_rewrites: Default::default(),
        hook_env: crate::hooks::HookEnv::new(registry.clone(), resolver.clone()).unwrap(),
        hook_registry: Default::default(),
        requested_signals: Default::default(),
        any_content_hook: false,
        global_hooks: Default::default(),
        base_hook_names: Default::default(),
        groups_registry: Default::default(),
        base_group_names: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
        admin: Default::default(),
        admin_chain: Default::default(),
        auth_instances: Default::default(),
        admin_modules: Arc::new(
            crate::auth::AdminAuthChain::build(&cfg, &registry, &resolver).unwrap(),
        ),
        public_url: None,
        oauth_as: None,
        demotion_record: Default::default(),
        amendments: Default::default(),
        planes: Default::default(),
        plane_slots: Default::default(),
        plane_sections: None,
        auth_scope_caps: Default::default(),
        role_bindings: Default::default(),
        config_path: None,
        providers_path: None,
        overlay_path: None,
        config_version: 0,
        max_keys_per_principal: 0,
        max_auto_provisioned_groups: 0,
        governance: None,
        secret_resolver: resolver,
        cost: Arc::new(crate::cost::CostModel::flat(1)),
        plugins_dir: Default::default(),
        plugins_cfg: Default::default(),
        plugin_admission: None,
        self_key_ttl_secs: crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
        mint_policy: Default::default(),
        request_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        plugin_routes: Arc::new(crate::plugin_routes::PluginRouteTable::empty()),
        boot_route_paths: Default::default(),
        planes_awaiting_restart: Default::default(),
    }))
}

fn prepared(
    app: &App,
    slot: &str,
    port: Arc<dyn TransportPort>,
    path: &str,
) -> Arc<PreparedListener> {
    prepared_with_auth(app, slot, port, path, RouteAuth::None)
}

fn prepared_with_auth(
    app: &App,
    slot: &str,
    port: Arc<dyn TransportPort>,
    path: &str,
    auth: RouteAuth,
) -> Arc<PreparedListener> {
    let line = line(path);
    let guests = GuestList::seal(vec![line.clone()]).unwrap();
    let routes = vec![RouteBinding::core(line, auth).unwrap()];
    let plan = PhysicalPlan::new(slot.into(), port, guests, routes).unwrap();
    Arc::new(
        PreparedListener::new(
            app,
            &crate::plugin_routes::PluginRouteTable::empty(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            false,
        )
        .unwrap()
        .with_physical(plan)
        .unwrap(),
    )
}

struct Fixture {
    listener: PhysicalListener,
    app: Arc<App>,
    prepared: Arc<PreparedListener>,
    budget: Arc<crate::limits::process_admission::ProcessAdmission>,
}
fn fixture() -> Fixture {
    fixture_for(AdmissionClass::Data, RouteAuth::None)
}

fn fixture_for(class: AdmissionClass, auth: RouteAuth) -> Fixture {
    let app = app();
    let port: Arc<dyn TransportPort> = Arc::new(Transport);
    let prepared = prepared_with_auth(&app, "listen", port.clone(), "/one", auth);
    let selected = prepared.clone();
    let listener = PhysicalListener::new(
        Arc::new(AppHandle::new(app.clone())),
        "listen".into(),
        port,
        class,
        Arc::new(move |_, slot| (slot == "listen").then(|| selected.clone())),
    )
    .unwrap();
    Fixture {
        listener,
        app,
        prepared,
        budget: crate::limits::process_admission::ProcessAdmission::with_limits(3, 1024, 128),
    }
}
pub(crate) fn accepted() -> AcceptedConnection {
    accepted_with_certificate(&[])
}
fn accepted_with_certificate(certificate: &[u8]) -> AcceptedConnection {
    let source = crate::limits::process_admission::ProcessAdmission::new(1)
        .connection_storage(AdmissionClass::Data);
    AcceptedConnection::capture(&source, "192.0.2.1", "192.0.2.2", "h2", certificate).unwrap()
}

#[test]
fn accepted_metadata_credit_follows_the_last_real_request_binding() {
    let f = fixture();
    let budget = crate::limits::process_admission::ProcessAdmission::with_limits(1, 64, 8);
    let source = budget.connection_storage(AdmissionClass::Data);
    let facts = AcceptedConnection::capture(&source, "p", "l", "h", b"cert").unwrap();
    assert_eq!(budget.used(), (7, 7));
    assert!(
        budget.try_enter(AdmissionClass::Data).is_ok(),
        "connection storage takes no request count"
    );
    let conn = f.listener.connect(facts);
    let (request, owner) = arrive(&f, &conn, 1);
    let binding = request.binding().clone();
    drop((request, owner, conn));
    assert_eq!(binding.connection().peer_certificate(), b"cert");
    assert_eq!(budget.used(), (7, 7));
    drop(binding);
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn accepted_metadata_denial_precedes_copy_and_leaves_no_credit() {
    let budget = crate::limits::process_admission::ProcessAdmission::with_limits(1, 8, 2);
    let source = budget.connection_storage(AdmissionClass::Data);
    assert!(AcceptedConnection::capture(&source, "p", "l", "h", b"cert").is_err());
    assert_eq!(budget.used(), (0, 0));
}
fn arrive(f: &Fixture, conn: &PhysicalConnection, stream: u64) -> (PhysicalRequest, StreamOwner) {
    conn.head(
        stream,
        head("/one"),
        f.budget.try_enter(f.listener.class).unwrap(),
        None,
    )
    .unwrap()
}

#[test]
fn native_physical_factory_requires_exact_slot_and_transport() {
    let f = fixture();
    let selected = f.prepared.clone();
    let wrong_port: Arc<dyn TransportPort> = Arc::new(Transport);
    assert!(matches!(
        PhysicalListener::new(
            Arc::new(AppHandle::new(f.app.clone())),
            "listen".into(),
            wrong_port,
            AdmissionClass::Data,
            Arc::new(move |_, _| Some(selected.clone())),
        ),
        Err(BindError::Transport)
    ));
    let selected = f.prepared.clone();
    assert!(matches!(
        PhysicalListener::new(
            Arc::new(AppHandle::new(f.app.clone())),
            "private".into(),
            f.listener.transport.clone(),
            AdmissionClass::Data,
            Arc::new(move |_, _| Some(selected.clone())),
        ),
        Err(BindError::Slot)
    ));
}

#[test]
fn native_physical_head_captures_actual_snapshot_route_and_budget() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let binding = request.binding();
    assert!(Arc::ptr_eq(binding.handle(), &f.listener.handle));
    assert!(Arc::ptr_eq(binding.app(), &f.app));
    assert!(Arc::ptr_eq(binding.prepared(), &f.prepared));
    assert_eq!(binding.head().target, "/one");
    assert_eq!(binding.route().line().route.path, "/one");
    assert_eq!(binding.connection().peer(), "192.0.2.1");
    assert_eq!(binding.request().class(), AdmissionClass::Data);
    assert_eq!(f.budget.used(), (8, 8));
}

#[test]
fn native_physical_duplicate_head_preserves_original_stream() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    assert!(matches!(
        conn.head(
            1,
            head("/one"),
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            None
        ),
        Err(ArrivalRefusal::DuplicateStream)
    ));
    assert!(request.binding().check_live().is_ok());
    assert_eq!(f.budget.used(), (8, 8));
}

#[test]
fn native_physical_reset_is_token_scoped_and_connection_scoped() {
    let f = fixture();
    let a = f.listener.connect(accepted());
    let b = f.listener.connect(accepted());
    let (one, owner) = arrive(&f, &a, 1);
    let (two, _two_owner) = arrive(&f, &b, 1);
    assert!(!b.cancel(&owner));
    assert!(one.binding().check_live().is_ok());
    assert!(a.cancel(&owner));
    assert_eq!(one.binding().check_live(), Err(ArrivalRefusal::Cancelled));
    assert!(two.binding().check_live().is_ok());
}

#[test]
fn native_physical_old_owner_cannot_retire_reused_stream() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (first, old_owner) = arrive(&f, &conn, 1);
    assert!(conn.cancel(&old_owner));
    drop(first);
    let (next, next_owner) = arrive(&f, &conn, 1);
    drop(old_owner);
    assert!(next.binding().check_live().is_ok());
    assert!(conn.cancel(&next_owner));
    assert_eq!(next.binding().check_live(), Err(ArrivalRefusal::Cancelled));
}

#[test]
fn native_physical_connection_drop_cancels_retained_requests_without_early_credit_release() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, owner) = arrive(&f, &conn, 1);
    let retained = request.binding().clone();
    drop(conn);
    assert_eq!(retained.check_live(), Err(ArrivalRefusal::Cancelled));
    drop(request);
    drop(owner);
    assert_eq!(f.budget.used(), (8, 8));
    drop(retained);
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_abandoned_request_cannot_later_prepare() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let binding = request.binding().clone();
    drop(request);
    assert_eq!(binding.check_live(), Err(ArrivalRefusal::Cancelled));
}

#[test]
fn native_physical_wrong_class_and_expired_head_do_not_create_streams() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    assert!(matches!(
        conn.head(
            1,
            head("/one"),
            f.budget.try_enter(AdmissionClass::Operator).unwrap(),
            None
        ),
        Err(ArrivalRefusal::Class)
    ));
    assert!(matches!(
        conn.head(
            1,
            head("/one"),
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            Some(Instant::now())
        ),
        Err(ArrivalRefusal::Deadline)
    ));
    let (request, _owner) = arrive(&f, &conn, 1);
    assert!(request.binding().check_live().is_ok());
}

#[test]
fn native_physical_pending_claim_is_not_an_execution_capability() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, owner) = arrive(&f, &conn, 1);
    assert_eq!(
        request.binding().check_executing(),
        Err(ArrivalRefusal::Cancelled)
    );
    let credit = request.binding().request().try_reserve(0).unwrap();
    let request = request.finish_input(SecureVec::new(), credit).unwrap();
    let pending = request.begin_completion().unwrap();
    assert!(pending.binding().check_live().is_ok());
    assert_eq!(
        pending.binding().check_executing(),
        Err(ArrivalRefusal::Cancelled)
    );
    assert!(conn.cancel(&owner));
    assert_eq!(
        pending.binding().check_live(),
        Err(ArrivalRefusal::Cancelled)
    );
    // No final admission constructor is exposed by a physical pending value.
    drop(pending);
}

#[test]
fn native_physical_body_is_frozen_under_its_original_lease() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let credit = request.binding().request().try_reserve(4).unwrap();
    let request = request
        .finish_input(SecureVec::from(&b"body"[..]), credit)
        .unwrap();
    assert_eq!(request.binding().body(), Some(&b"body"[..]));
    assert_eq!(f.budget.used(), (12, 12));
    let retained = request.binding().clone();
    drop(request);
    assert_eq!(f.budget.used(), (12, 12));
    drop(retained);
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_foreign_body_credit_never_enters_the_request() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let other = f.budget.try_enter(AdmissionClass::Data).unwrap();
    let credit = other.try_reserve(4).unwrap();
    assert!(matches!(
        request.finish_input(SecureVec::from(&b"body"[..]), credit),
        Err(ArrivalRefusal::ForeignInput)
    ));
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_body_rejects_unfunded_spare_capacity() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let credit = request.binding().request().try_reserve(4).unwrap();
    let mut body = SecureVec::with_capacity(16).unwrap();
    body.extend(b"body").unwrap();
    assert!(matches!(
        request.finish_input(body, credit),
        Err(ArrivalRefusal::ForeignInput)
    ));
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_head_charges_unused_descriptor_backing() {
    let mut f = fixture();
    f.budget = crate::limits::process_admission::ProcessAdmission::with_limits(3, 256, 128);
    let conn = f.listener.connect(accepted());
    let mut original = head("/one");
    original.fields = Vec::with_capacity(8);
    assert!(matches!(
        conn.head(1, original, f.budget.try_enter(AdmissionClass::Data).unwrap(), None),
        Err(ArrivalRefusal::Capacity)
    ));
    assert_eq!(f.budget.used(), (0, 0));
    // A refused head has not occupied the stream or retained the request permit.
    let (request, _owner) = arrive(&f, &conn, 1);
    assert!(request.binding().check_live().is_ok());
}

#[test]
fn native_physical_head_charges_spare_string_backing() {
    let mut f = fixture();
    f.budget = crate::limits::process_admission::ProcessAdmission::with_limits(3, 256, 128);
    let conn = f.listener.connect(accepted());
    let mut original = head("/one");
    original.authority = String::with_capacity(256);
    original.authority.push_str("a");
    assert!(matches!(
        conn.head(1, original, f.budget.try_enter(AdmissionClass::Data).unwrap(), None),
        Err(ArrivalRefusal::Capacity)
    ));
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_incomplete_body_cannot_enter_completion() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    assert!(matches!(
        request.begin_completion(),
        Err(ArrivalRefusal::BodyIncomplete)
    ));
}

#[test]
fn native_physical_response_owner_retains_request_count_after_input_drop() {
    let f = fixture();
    let conn = f.listener.connect(accepted());
    let (request, response_owner) = arrive(&f, &conn, 1);
    drop(request);
    let second = f.budget.try_enter(AdmissionClass::Data).unwrap();
    assert!(
        f.budget.try_enter(AdmissionClass::Data).is_err(),
        "the response still owns the first request count"
    );
    drop(response_owner);
    let third = f.budget.try_enter(AdmissionClass::Data).unwrap();
    drop((second, third));
}

#[test]
fn native_physical_snapshot_captures_original_fields_once() {
    let mut f = fixture();
    f.budget = crate::limits::process_admission::ProcessAdmission::with_limits(3, 4096, 128);
    let facts = accepted_with_certificate(b"certificate");
    let conn = f.listener.connect(facts);
    let mut original = head("/one");
    original.query = Some(String::new());
    original.authority = "example.test".into();
    original.fields = vec![
        ("x-order".into(), b"first".to_vec()),
        ("x-order".into(), b"second".to_vec()),
    ];
    let (request, _owner) = conn
        .head(
            1,
            original,
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            None,
        )
        .unwrap();
    let credit = request.binding().request().try_reserve(4).unwrap();
    let request = request
        .finish_input(SecureVec::from(&b"body"[..]), credit)
        .unwrap();
    let snapshot = request.binding().snapshot().unwrap();
    let used = f.budget.used();
    let again = request.binding().snapshot().unwrap();
    assert!(Arc::ptr_eq(&snapshot, &again));
    assert_eq!(f.budget.used(), used);
    assert!(snapshot.request().same_request(request.binding().request()));
    assert_eq!(snapshot.method(), "POST");
    assert_eq!(snapshot.path(), "/one");
    assert_eq!(snapshot.query(), "");
    assert!(snapshot.query_present());
    assert_eq!(snapshot.authority(), "example.test");
    assert_eq!(snapshot.peer(), "192.0.2.1");
    assert_eq!(snapshot.tls_peer_cert(), b"certificate");
    assert_eq!(snapshot.body(), b"body");
    assert_eq!(
        snapshot.headers().collect::<Vec<_>>(),
        vec![("x-order", &b"first"[..]), ("x-order", &b"second"[..])]
    );
    drop(request);
    assert_eq!(snapshot.body(), b"body");
    assert!(f.budget.used().0 > 0);
    drop((snapshot, again));
    assert_eq!(f.budget.used(), (0, 0));
}

#[test]
fn native_physical_snapshot_requires_complete_input_and_preserves_absent_query() {
    let mut f = fixture();
    f.budget = crate::limits::process_admission::ProcessAdmission::with_limits(3, 4096, 128);
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    assert!(matches!(
        request.binding().snapshot(),
        Err(super::super::request_snapshot::SnapshotError::Invalid)
    ));
    let credit = request.binding().request().try_reserve(0).unwrap();
    let request = request.finish_input(SecureVec::new(), credit).unwrap();
    let snapshot = request.binding().snapshot().unwrap();
    assert!(!snapshot.query_present());
    assert_eq!(snapshot.query(), "");
}

#[test]
fn native_physical_admin_carrier_requires_operator_and_admin_route() {
    for (class, auth) in [
        (AdmissionClass::Data, RouteAuth::Admin),
        (AdmissionClass::Operator, RouteAuth::None),
    ] {
        let f = fixture_for(class, auth);
        let conn = f.listener.connect(accepted());
        let (request, _owner) = arrive(&f, &conn, 1);
        let credit = request.binding().request().try_reserve(0).unwrap();
        let completing = request
            .finish_input(SecureVec::new(), credit)
            .unwrap()
            .begin_completion()
            .unwrap();
        assert!(matches!(
            completing.into_admin(),
            Err(ArrivalRefusal::Class)
        ));
    }
}

#[test]
fn native_physical_admin_carrier_clone_shares_one_pending_right() {
    let f = fixture_for(AdmissionClass::Operator, RouteAuth::Admin);
    let conn = f.listener.connect(accepted());
    let (request, _owner) = arrive(&f, &conn, 1);
    let credit = request.binding().request().try_reserve(0).unwrap();
    let carrier = request
        .finish_input(SecureVec::new(), credit)
        .unwrap()
        .begin_completion()
        .unwrap()
        .into_admin()
        .unwrap();
    let clone = carrier.clone();
    let binding = carrier.binding().clone();
    let completing = clone.take().unwrap();
    assert!(matches!(carrier.take(), Err(ArrivalRefusal::ForeignInput)));
    drop((carrier, clone));
    assert!(binding.check_live().is_ok());
    drop(completing);
    assert_eq!(binding.check_live(), Err(ArrivalRefusal::Cancelled));
}
