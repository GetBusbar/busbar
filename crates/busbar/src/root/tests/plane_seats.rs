// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! K9: what the boot composes into a MIN-3 plane seat from the configured upstreams. The plane is an ffi handle, so
//! the seat's request path runs in the image suite (W2-SW-PLANE e2e); these are the seams the boot builds: the
//! seat's walk and carrier over the shared upstream table, its needs on the connection table, the transport
//! acceptance it is held to, and the process-tree containment of a stdio child.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::task::{Context, Poll};

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{ConnError, ConnId, Conns, Piece, PollConns, Ticket};
use busbar_contract::json::{json, JsonValueTrait as _};
use busbar_contract::services::Caller;
use busbar_contract::transport::trust::Anchors;
use busbar_contract::transport::ConnFacts;
use busbar_kernel::channels::budget::{ChannelBudget, Claim, UnitBudget};
use busbar_kernel::channels::carrier::Wires;
use busbar_kernel::channels::ChannelReq;
use busbar_kernel::upstreams::{ProgramPin, StdioCommand, UpstreamTls};
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::plane::CARRIER_STDIO;
use busbar_plugin_abi::records::Records;
use busbar_ports::plane::{PlaneIn, PlaneOut, PlaneSession, RouteInfo, TargetIn, UsageClass};
use busbar_ports::{CallCx, PortError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::*;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

fn caller() -> Caller {
    Caller::for_test(
        "mcp".into(),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

/// A plane that states nothing and answers nothing (no FB_PROBES).
struct Quiet;

impl PlanePort for Quiet {
    fn routes(&self) -> &[RouteInfo] {
        &[]
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn facts(&self) -> u64 {
        0
    }
    fn tick_s(&self) -> Option<u64> {
        None
    }
    fn admin_openapi(&self) -> Option<&str> {
        None
    }
    fn charge(&self, _: FaultReason) {}
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
        Box::pin(async move { Err(refused()) })
    }
}

/// A connection table that records the needs declared on it and the anchors sealed, and opens nothing.
#[derive(Default)]
struct Table {
    declared: Mutex<Vec<(InstanceId, NeedId, String)>>,
    anchored: Mutex<Vec<(NeedId, String, Option<String>)>>,
}

impl Conns for Table {
    fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        Err(ConnError::Refused)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Refused)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Ok(ConnFacts::default())
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

impl PollConns for Table {
    fn poll_read(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        Poll::Ready(Err(ConnError::Refused))
    }
    fn anchor(
        &self,
        _: InstanceId,
        need: NeedId,
        _: &str,
        target: &str,
        anchors: &Anchors,
    ) -> Result<(), ConnError> {
        self.anchored
            .lock()
            .unwrap()
            .push((need, target.to_owned(), anchors.key_pin.clone()));
        Ok(())
    }
}

impl DeclaredConns for Table {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        assert!(
            target.is_none(),
            "no target is pinned: the guard judges every dial"
        );
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.transport.clone()));
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        None
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

/// Every reference resolves to the same value.
struct Fixed;

impl SpawnSecrets for Fixed {
    fn resolve<'a>(&'a self, _: &'a SecretRef) -> BoxFut<'a, Option<String>> {
        Box::pin(core::future::ready(Some("value".to_owned())))
    }
}

const PIN_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn upstreams() -> Arc<ConfiguredUpstreams> {
    let section = json!({
        "alpha": {"url": "https://alpha.example/v1", "tls": {"pin_spki": [PIN_HEX]}},
        "beta": {"url": "http://beta.internal:8080"},
        "files": {"command": {"argv": ["/opt/mcp/files"]}},
    });
    Arc::new(
        ConfiguredUpstreams::from_config(
            section.as_object().expect("a map"),
            &BTreeMap::new(),
            &busbar_kernel::plugin_config::upstream_anchor,
        )
        .expect("the upstreams type"),
    )
}

fn shared(table: Option<ConnTable>) -> SeatShared {
    SeatShared {
        upstreams: BTreeMap::from([("mcp".to_owned(), upstreams())]),
        catalogs: BTreeMap::new(),
        channel_budgets: BTreeMap::from([("mcp".to_owned(), ChannelBudget::new().instance())]),
        signals: SignalRegistry::new(),
        secrets: Arc::new(Fixed),
        kernel: Arc::new(Kernel::new()),
        table,
        section_pools: BTreeMap::new(),
    }
}

/// Keyless catalog fixtures must never exercise an inbound owner or mint a credential.
struct UnusedAuth;

impl busbar_kernel::issued::IssuedCredentials for UnusedAuth {
    fn lookup<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: &'a str,
    ) -> BoxFut<'a, busbar_contract::secure::SecureVec> {
        panic!("keyless catalog attempted issued lookup")
    }
}

impl busbar_kernel::plane_grants::ReplayGuard for UnusedAuth {
    fn claim<'a>(
        &'a self,
        _: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        panic!("keyless catalog attempted replay admission")
    }
    fn claim_until<'a>(
        &'a self,
        _: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        panic!("keyless catalog attempted replay admission")
    }
}

async fn catalog() -> (CatalogSeat, String, String) {
    catalog_with_registration_collision(false).await
}

async fn catalog_with_registration_collision(collision: bool) -> (CatalogSeat, String, String) {
    use super::super::{min3_auth, min3_outbound_auth, min3_provider_catalog};
    use busbar_kernel::config::{self, Grammar};
    use busbar_kernel::plane_driver::provider_catalog::ProviderPlane;
    let grammar = Grammar::empty();
    let mut deploy = config::deploy_from_yaml_str(
        "providers:\n  p: {api_key: none}\nmodels:\n  m: {provider: p, upstream_model: wire-model, max_concurrent: 1, attempt_timeout_ms: 321}\npools:\n  fast:\n    members: [{model: m, weight: 7}]\n    breaker: {base_cooldown_secs: 37}\n    failover: {timeout_secs: 17, max_hops: 2, exclusions: [m]}\n    on_exhausted: {fallback_pool: slow}\n  slow:\n    members: [m]\n    on_exhausted: {queue: {max_ms: 100}}\n",
        &grammar,
    ).unwrap();
    if collision {
        let pool = deploy.pools.pools["fast"].clone();
        deploy.pools.pools.insert("mcp".into(), pool);
    }
    let defs = config::providers::catalog_from_str(
        "p: {protocol: wire, base_url: 'https://provider.example/api', path: /invoke}",
        &grammar,
    )
    .unwrap();
    let mut resolved = config::resolve_with_provider_planes(
        &deploy,
        &defs,
        &[ProviderPlane {
            instance: "mcp".into(),
            image: "admitted-kind-fixture".into(),
            dialects: ["wire".to_owned()].into(),
            schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#.into(),
        }],
    )
    .unwrap();
    let plan = resolved.catalogs.remove("mcp").unwrap();
    let fast = plan.select("fast").unwrap().to_owned();
    let slow = plan.select("slow").unwrap().to_owned();
    let allocations = plan
        .targets()
        .keys()
        .enumerate()
        .map(|(i, pair)| {
            (
                pair.clone(),
                min3_provider_catalog::Allocation {
                    destination: busbar_contract::dest::DestinationId::new(100 + i as u64),
                    need: NeedId(100 + i as u32),
                    upstream: format!("catalog-{i}").into(),
                },
            )
        })
        .collect();
    let definitions = upstreams();
    let registration = SeatPool::of("mcp", &definitions).unwrap();
    let bindings = busbar_kernel::auth_bindings::ProviderBindings::default();
    let mut staged = min3_provider_catalog::prepare(
        &resolved.config,
        &plan,
        &allocations,
        &registration,
        &definitions,
        &bindings,
        &BTreeMap::new(),
    )
    .unwrap();
    let faults = crate::root::store_double::NativeFaults::open().await;
    let store = crate::root::real_store::core_over(faults).await;
    let (_directory, holds, _refresh) = busbar_kernel::directory::KernelDirectory::prepare(
        store,
        Arc::new(busbar_kernel::directory::LogEvents),
        Vec::new(),
    )
    .await
    .unwrap();
    let auth = min3_auth::AuthSet::new(
        Vec::new(),
        &holds,
        min3_auth::AuthOwners {
            issued: Arc::new(UnusedAuth),
            replay: Arc::new(UnusedAuth),
            cache: Arc::new(busbar_kernel::auth::verdicts::Verdicts::new(
                busbar_kernel::auth::verdicts::VerdictPolicy::DEFAULT,
            )),
        },
        Duration::from_secs(30),
    )
    .unwrap();
    let cache = Arc::new(busbar_kernel::custody::CredCache::new(
        busbar_kernel::custody::CredPolicy::DEFAULT,
        |_, _| panic!("keyless catalog attempted credential retry"),
        |_, _| panic!("keyless catalog attempted credential mint"),
    ));
    let prepared = min3_outbound_auth::prepare(
        &bindings,
        staged.take_auth_rows(),
        &auth,
        &BTreeMap::new(),
        cache,
    )
    .unwrap();
    (
        CatalogSeat {
            sealed: staged.seal(&prepared).unwrap(),
            pools: plan.pools().clone(),
            plan: Arc::new(plan),
        },
        fast,
        slow,
    )
}

#[tokio::test]
async fn catalog_seat_uses_sealed_routes_policies_targets_and_shared_capacity() {
    let (catalog, fast, slow) = catalog().await;
    let mut pool = SeatPool::of("mcp", &upstreams()).unwrap();
    extend_catalog("mcp", &mut pool, &catalog).unwrap();
    let fast_pool = &pool.pools[&fast];
    assert_eq!(fast_pool.members[0].weight, 7);
    assert_eq!(fast_pool.members[0].attempt_timeout_ms, Some(321));
    assert_eq!(fast_pool.failover.timeout_secs, 17);
    assert_eq!(fast_pool.failover.max_hops, 2);
    assert_eq!(fast_pool.failover.exclusions, ["mcp\u{1f}m"]);
    assert_eq!(
        fast_pool.on_exhausted,
        busbar_kernel_egress::OnExhausted::FallbackPool(slow.clone())
    );
    assert_eq!(
        pool.pools[&slow].on_exhausted,
        busbar_kernel_egress::OnExhausted::Queue { max_ms: 100 }
    );
    let table = Arc::new(Table::default());
    let egress = egress_of(
        "mcp",
        seat_owner(7),
        &ConnTable {
            declared: table.clone(),
            conns: table.clone(),
        },
        &pool,
        Some(&catalog),
    )
    .unwrap();
    let held = egress
        .capacity
        .try_acquire(fast_pool.members[0].destination)
        .unwrap();
    assert!(egress
        .capacity
        .try_acquire(pool.pools[&slow].members[0].destination)
        .is_none());
    assert!(catalog
        .sealed
        .capacity
        .values()
        .all(|slots| slots.available_permits() == 0));
    drop(held);
    assert!(egress
        .capacity
        .try_acquire(pool.pools[&slow].members[0].destination)
        .is_some());
    let probes = probe_targets(&pool);
    for (pair, association) in &catalog.sealed.associations {
        assert!(probes.iter().any(|probe| probe.pool == pair.0
            && probe.qualified_member == pair.1
            && probe.destination == association.destination));
        let target = (catalog.sealed.targets)(&pair.0, &pair.1).unwrap();
        assert!(
            matches!(target.identity, busbar_kernel::plane_driver::port_upstream::TargetIdentity::Model {dialect, model} if &*dialect == "wire" && &*model == "wire-model")
        );
    }
    assert_eq!(table.declared.lock().unwrap().len(), pool.members.len());
    assert_eq!(table.anchored.lock().unwrap().len(), pool.members.len());
}

#[tokio::test]
async fn catalog_composition_keeps_model_definitions_out_of_channel_registrations() {
    let (catalog, _, _) = catalog().await;
    let model_names: Vec<_> = catalog
        .sealed
        .members
        .iter()
        .map(|member| member.upstream.clone())
        .collect();
    let table = Arc::new(Table::default());
    let mut shared = shared(Some(ConnTable {
        declared: table.clone(),
        conns: table.clone(),
    }));
    shared.catalogs.insert("mcp".into(), Arc::new(catalog));
    let wiring = compose(
        &shared,
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current(),
    )
    .unwrap();
    let registrations: Arc<dyn Upstreams> = shared.upstreams["mcp"].clone();
    assert!(Arc::ptr_eq(&wiring.inventory_upstreams, &registrations));
    for pair in shared.catalogs["mcp"].sealed.associations.keys() {
        assert_eq!(
            (wiring.inventory_targets)(&pair.0, &pair.1),
            (shared.catalogs["mcp"].sealed.targets)(&pair.0, &pair.1),
        );
        assert!((wiring.inventory_targets)("unowned-pool", &pair.1).is_none());
    }
    assert!((wiring.inventory_targets)("mcp", "mcp\u{1f}alpha").is_some());
    let session = wiring.carrier.session();
    session.map.point("alpha");
    assert!(session.map.of(0).is_some());
    for name in model_names {
        session.map.point(&name);
        assert!(
            session.map.of(0).is_none(),
            "model destination became a CHANNEL registration"
        );
    }
    assert_eq!(table.declared.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn seat_request_inventory_retains_the_actual_candidate_catalog() {
    let (catalog, _, _) = catalog().await;
    let plan = Arc::clone(&catalog.plan);
    let mut shared = shared(None);
    shared.catalogs.insert("mcp".into(), Arc::new(catalog));
    let wiring = compose(
        &shared,
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current(),
    )
    .unwrap();
    drop(shared);
    let routes = Arc::clone(&wiring.request_routes);
    drop(wiring);
    assert_eq!(
        Arc::strong_count(&plan),
        2,
        "request inventory retains the exact candidate plan"
    );
    drop(routes);
    assert_eq!(Arc::strong_count(&plan), 1);
}

#[tokio::test]
async fn catalog_selector_cannot_alias_the_registration_request_domain() {
    let (catalog, _, _) = catalog_with_registration_collision(true).await;
    let table = Arc::new(Table::default());
    let mut shared = shared(Some(ConnTable {
        declared: table.clone(),
        conns: table.clone(),
    }));
    shared.catalogs.insert("mcp".into(), Arc::new(catalog));
    assert!(compose(
        &shared,
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current()
    )
    .is_err());
    assert!(
        table.declared.lock().unwrap().is_empty(),
        "ambiguous request scope refuses before connection declarations"
    );
}

fn who(instance: u64) -> Namespace {
    Namespace {
        plugin: "plane-mcp".into(),
        name: "mcp".into(),
        instance,
        slot: 0,
    }
}

#[test]
fn a_seat_owner_is_its_own_never_a_dispatch_handle_or_the_root() {
    let owner = seat_owner(7);
    assert_ne!(owner, InstanceId(0));
    assert!(owner.0 >= 1 << 40, "above every 24-bit dispatch handle id");
    assert_ne!(seat_owner(7), seat_owner(8));
    assert!(
        seat_owner(u64::MAX).0 < u64::MAX - 3,
        "below the connector's own test owners"
    );
}

#[test]
fn an_upstream_need_rides_its_url_scheme_with_no_target_pinned() {
    let need = upstream_need("HTTPS://alpha.example/v1");
    assert_eq!(need.transport, "https");
    assert!(need.target_from.is_empty() && need.trust_from.is_empty());
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(upstream_need("http://beta.internal").transport, "http");
}

#[test]
fn verified_tls_is_the_default_and_each_acceptance_admits_only_what_it_names() {
    let none = Accept::default();
    assert!(admitted(none, "https://alpha.example/v1"));
    assert!(!admitted(none, "http://beta.internal:8080/x"));
    assert!(admitted(
        Accept(Accept::PLAINTEXT),
        "http://beta.internal:8080/x"
    ));
    assert!(admitted(
        Accept(Accept::UNVERIFIED_TLS),
        "https://alpha.example/v1"
    ));
    assert!(!admitted(
        Accept(Accept::UNVERIFIED_TLS),
        "http://beta.internal:8080/x"
    ));
    assert_eq!(accept_words(none), Vec::<&str>::new());
    assert_eq!(
        accept_words(Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS)),
        ["plaintext", "unverified_tls"]
    );
}

#[test]
fn an_acceptance_is_audited_and_none_is_silent() {
    let pool = SeatPool::of("mcp", &upstreams()).expect("the seat's pool");
    assert!(!audit_acceptance("mcp", Accept::default(), &pool));
    assert!(audit_acceptance("mcp", Accept(Accept::PLAINTEXT), &pool));
}

#[tokio::test]
async fn a_seat_with_configured_upstreams_is_composed_with_its_walk_and_its_carrier() {
    let table = Arc::new(Table::default());
    let conns = ConnTable {
        declared: Arc::clone(&table) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(&table) as Arc<dyn PollConns>,
    };
    let wiring = compose(
        &shared(Some(conns)),
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current(),
    )
    .expect("the seat composes");
    assert!(wiring.upstream.is_some(), "a FORWARD has a walk to run");
    assert!(
        wiring.probes.is_none(),
        "a plane that states no FB_PROBES is never probed"
    );
    assert_eq!(
        *table.declared.lock().unwrap(),
        [
            (seat_owner(7), NeedId(0), "https".to_owned()),
            (seat_owner(7), NeedId(1), "http".to_owned()),
        ],
        "one need per network upstream, on the seat's own owner"
    );
    let anchored = table.anchored.lock().unwrap().clone();
    assert_eq!(
        anchored.len(),
        2,
        "each member seals its own trust and private-reach policy"
    );
    assert_eq!(anchored[0].0, NeedId(0));
    assert!(anchored[0]
        .2
        .as_deref()
        .is_some_and(|pin| pin.starts_with("sha256/")));

    // The carrier reads the same table: a CHANNEL to a configured upstream finds it, any other name does not.
    let session = wiring.carrier.session();
    session.map.point("files");
    assert!(session.map.of(0).is_some_and(|def| def.command.is_some()));
    session.map.point("ghost");
    assert!(session.map.of(0).is_none());
}

#[test]
fn each_registration_carries_only_its_own_private_reach_into_the_seat() {
    let split = busbar_kernel::upstreams::declared(
        "p",
        &json!({"members": {
            "allowed": {"url":"https://shared.internal", "allow_private":true},
            "denied": {"url":"https://shared.internal"}
        }}),
        &["/members/*"],
        &busbar_kernel::plugin_config::upstream_anchor,
    )
    .unwrap();
    let pool = SeatPool::of("p", &split.definitions).unwrap();
    for member in &pool.members {
        let route = &pool.routes[&member.destination];
        assert_eq!(
            route.anchors.private_reach,
            member.upstream.as_ref() == "allowed"
        );
    }
}

#[tokio::test]
async fn a_seat_with_no_connection_table_still_gets_its_carrier_and_walks_nothing() {
    let wiring = compose(
        &shared(None),
        "mcp",
        Accept::default(),
        &who(3),
        caller(),
        Arc::new(Quiet),
        Handle::current(),
    )
    .expect("the seat composes");
    assert!(wiring.upstream.is_none());
    assert!(wiring.probes.is_none());
    let session = wiring.carrier.session();
    session.map.point("alpha");
    assert!(session.map.of(0).is_some());
}

fn stdio(argv: &[&str]) -> UpstreamDef {
    UpstreamDef {
        resource: None,
        allow_private: false,
        name: "files".into(),
        url: None,
        command: Some(StdioCommand {
            argv: argv.iter().map(|arg| Box::<str>::from(*arg)).collect(),
            env: Vec::new(),
            cwd: None,
            pin: ProgramPin::Unpinned,
            idle_s: 300,
        }),
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth: None,
    }
}

struct CommandAdmission {
    caller: Caller,
    unit: UnitBudget,
    authority: busbar_kernel::channels::authority::ChannelAuthority,
    definition: Arc<UpstreamDef>,
    request: busbar_kernel::plane_driver::request_admission::AdmittedRequest,
    money: busbar_kernel::plane_driver::PlaneMoney,
    _owner: busbar_kernel::host_services::NativeInvocationAdmission,
}

struct NoChildren;
impl busbar_kernel::host_services::NestRoute for NoChildren {
    fn nest(
        &self,
        _: busbar_kernel::host_services::InvocationContext,
        _: busbar_kernel::host_services::Nest,
        _: busbar_kernel::host_services::NestDone,
    ) {
        panic!("command fixture does not nest");
    }
}

struct Posted;
impl busbar_kernel::plane_driver::EndPost for Posted {
    fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
}

impl CommandAdmission {
    async fn new(definition: Arc<UpstreamDef>, budget: &InstanceBudget) -> Self {
        use busbar_kernel::host_services::{InvocationContext, KernelServices, ServingGeneration};
        use busbar_kernel::plane_driver::request_admission::RequestAllocation;
        let core = Arc::new(KernelServices::new());
        let caller = caller();
        let owner = core.admit_native_invocation(&caller).unwrap();
        assert!(core.units().pre_admitted_for(
            1,
            &caller,
            busbar_kernel::host_units::UnitRecord {
                principal: Some(Arc::new(busbar_contract::records::VirtualKey {
                    id: "command-fixture".into(),
                    enabled: true,
                    ..Default::default()
                })),
                depth: 0,
            }
        ));
        let context = InvocationContext::new(
            Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
            caller.clone(),
            1,
        )
        .unwrap();
        let unit = budget.unit();
        let table = Arc::new(ConfiguredUpstreams::from_definitions(
            [(definition.name.clone(), definition.clone())].into(),
        ));
        let routes = RequestRoutes::new("mcp", None, None, None)
            .unwrap()
            .with_registrations(table)
            .unwrap();
        let receipt = RequestAllocation::new(
            context,
            Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
                None,
                0,
                &Default::default(),
            )),
            100,
        )
        .unwrap()
        .registration(&routes, None, &definition.name)
        .unwrap();
        let faults = crate::root::store_double::NativeFaults::open().await;
        let store = crate::root::real_store::core_over(faults).await;
        let governance = Arc::new(
            busbar_kernel::governance::GovState::new_with_core(store, None, None)
                .await
                .unwrap(),
        );
        let money = busbar_kernel::plane_driver::PlaneMoney::new(governance, Arc::new(Posted));
        let request = money
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from([]),
                busbar_kernel::plane_driver::FeeRefund::CallerStatus,
                busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
            )
            .unwrap();
        let authority =
            busbar_kernel::channels::authority::ChannelAuthority::new(request.clone()).unwrap();
        Self {
            caller,
            unit,
            authority,
            definition,
            request,
            money,
            _owner: owner,
        }
    }
}

impl Drop for CommandAdmission {
    fn drop(&mut self) {
        self.money.settle_end_as(
            self.request.unit(),
            busbar_kernel::plane_driver::UnitEnd {
                caller_status: 502,
                cut: true,
                refused_unspent: false,
            },
        );
        self.request.context().retire();
    }
}

fn channel(admission: &CommandAdmission) -> ChannelReq<'_> {
    ChannelReq {
        budget: &admission.unit,
        command: Some(&admission.authority),
        exchange: 1,
        carrier: CARRIER_STDIO,
        flags: 0,
        framing: 0,
        key: "k",
        subject: None,
        head: Records::new(&[]),
    }
}

#[tokio::test]
async fn a_seat_without_its_retained_channel_account_refuses_before_declaring_routes() {
    let table = Arc::new(Table::default());
    let mut shared = shared(Some(ConnTable {
        declared: table.clone(),
        conns: table.clone(),
    }));
    shared.channel_budgets.clear();
    assert!(compose(
        &shared,
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current()
    )
    .is_err());
    assert!(table.declared.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_seat_exposes_the_same_instance_account_to_original_unit_admission() {
    let shared = shared(None);
    let wiring = compose(
        &shared,
        "mcp",
        Accept::default(),
        &who(7),
        caller(),
        Arc::new(Quiet),
        Handle::current(),
    )
    .unwrap();
    let budget = &shared.channel_budgets["mcp"];
    let held: Vec<_> = (0..32)
        .map(|_| {
            budget
                .unit()
                .reserve(
                    Claim {
                        leases: 8,
                        ..Claim::default()
                    },
                    None,
                )
                .unwrap()
        })
        .collect();
    let original_unit = wiring.channel_budget.unit();
    assert!(original_unit
        .reserve(
            Claim {
                leases: 1,
                ..Claim::default()
            },
            None
        )
        .is_err());
    drop(held);
    assert!(original_unit
        .reserve(
            Claim {
                leases: 1,
                ..Claim::default()
            },
            None
        )
        .is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn channel_drivers_across_generations_share_the_retained_instance_account() {
    use busbar_kernel::channels::UpstreamChannels;
    let shared = shared(None);
    let budget = &shared.channel_budgets["mcp"];
    let namespace = who(7);
    let upstream = Arc::new(stdio(&["/bin/cat"]));
    let first_admission = CommandAdmission::new(Arc::clone(&upstream), budget).await;
    let second_admission = CommandAdmission::new(Arc::clone(&upstream), budget).await;
    let first = channels_of(
        &shared,
        budget.clone(),
        &namespace,
        first_admission.caller.clone(),
        Arc::new(Quiet),
        None,
    );
    let second = channels_of(
        &shared,
        budget.clone(),
        &namespace,
        second_admission.caller.clone(),
        Arc::new(Quiet),
        None,
    );
    // This is capacity from the same actual instance, held across both generation drivers.
    let held: Vec<_> = (0..32)
        .map(|_| {
            budget
                .unit()
                .reserve(
                    Claim {
                        leases: 8,
                        ..Claim::default()
                    },
                    None,
                )
                .unwrap()
        })
        .collect();
    assert!(first
        .attach(&namespace.caller(), &upstream, channel(&first_admission))
        .await
        .is_err());
    assert!(second
        .attach(&namespace.caller(), &upstream, channel(&second_admission))
        .await
        .is_err());
    drop(held);
    let one = first
        .attach(&namespace.caller(), &upstream, channel(&first_admission))
        .await
        .unwrap();
    let held: Vec<_> = (0..31)
        .map(|_| {
            budget
                .unit()
                .reserve(
                    Claim {
                        leases: 8,
                        ..Claim::default()
                    },
                    None,
                )
                .unwrap()
        })
        .collect();
    let remaining = budget
        .unit()
        .reserve(
            Claim {
                leases: 7,
                ..Claim::default()
            },
            None,
        )
        .unwrap();
    assert!(second
        .attach(&namespace.caller(), &upstream, channel(&second_admission))
        .await
        .is_err());
    drop(one);
    let two = second
        .attach(&namespace.caller(), &upstream, channel(&second_admission))
        .await
        .unwrap();
    drop((two, remaining, held));
    let foreign = ChannelBudget::new().instance().unit();
    assert!(second
        .attach(
            &namespace.caller(),
            &upstream,
            ChannelReq {
                budget: &foreign,
                ..channel(&second_admission)
            }
        )
        .await
        .is_err());
    assert!(
        second
            .attach(&namespace.caller(), &upstream, channel(&first_admission))
            .await
            .is_err(),
        "equal namespace and unit number never replace the actual caller incarnation"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_contained_stdio_channel_opens_and_carries_bytes_both_ways() {
    let wires = ProcessWires::new(Arc::new(Fixed), None).spawning(Arc::new(ContainedSpawn));
    let process = ChannelBudget::new();
    let instance = process.instance();
    let admission = CommandAdmission::new(Arc::new(stdio(&["/bin/cat"])), &instance).await;
    let req = channel(&admission);
    let wire = wires
        .open(&admission.definition, &req)
        .await
        .expect("the child starts");
    let mut write = wire.write.expect("a stdio wire takes writes");
    let mut read = wire.read;
    write.write_all(b"ping\n").await.expect("written");
    write.flush().await.expect("flushed");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), read.read_exact(&mut got))
        .await
        .expect("the child answers in time")
        .expect("read");
    assert_eq!(&got, b"ping\n");
    drop(wire.hold);
}

/// Whether `pid` is a live process (a zombie is not: it has ended and waits to be reaped).
#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| state != 'Z' && state != 'X')
    })
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_stdio_child_s_whole_process_tree_stops_with_its_generation() {
    let wires = ProcessWires::new(Arc::new(Fixed), None).spawning(Arc::new(ContainedSpawn));
    // The child forks a grandchild and reports its pid; `exec` keeps the child itself alive on its stdin.
    let up = Arc::new(stdio(&[
        "/bin/sh",
        "-c",
        "/bin/sleep 300 & echo $!; exec /bin/cat",
    ]));
    let process = ChannelBudget::new();
    let instance = process.instance();
    let admission = CommandAdmission::new(up, &instance).await;
    let req = channel(&admission);
    let wire = wires
        .open(&admission.definition, &req)
        .await
        .expect("the child starts");
    let mut line = String::new();
    let mut reader = BufReader::new(wire.read);
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("the child reports in time")
        .expect("read");
    let pid: u32 = line.trim().parse().expect("a pid");
    assert!(alive(pid), "the grandchild runs while the generation lives");
    drop(wire.write);
    drop(wire.hold);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !alive(pid),
        "a process the child started outlived its generation"
    );
}
