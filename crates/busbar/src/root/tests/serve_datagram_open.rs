// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(all(feature = "transport-webrtc", linked_section_streams))]

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use busbar_contract::transport::TransportSettings;
use busbar_core_connector::datagram::{Across, LegSink, Pairing};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::udp::{bind, ReadyPort};

use super::super::{self as serving, serve_datagram};
use serving::planes_tests::PUBLISHING;

const OPEN_CALL: &str = "/v1/realtime/calls";
const CARRIER: &str = "webrtc";

type Callback = Arc<dyn Fn() + Send + Sync>;

struct OpeningFramer {
    inner: Arc<dyn FramerDoor>,
    finishes: AtomicUsize,
    on_finish: Mutex<Option<Callback>>,
}

impl OpeningFramer {
    fn new() -> Arc<Self> {
        let plugin = crate::root::test_plugins::linked_transport(
            busbar_transport_webrtc::door,
            crate::root::doors::bind(),
        );
        Arc::new(Self {
            inner: Arc::new(
                crate::root::doors::Dispatched::open(plugin, &TransportSettings::default())
                    .expect("real WebRTC door opens"),
            ),
            finishes: AtomicUsize::new(0),
            on_finish: Mutex::new(None),
        })
    }
}

impl FramerDoor for OpeningFramer {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Finish(input, out) = call {
            let callback = self.on_finish.lock().unwrap().clone();
            if let Some(callback) = callback {
                callback();
            }
            let crossed = self.inner.cross(Call::Finish(input, out));
            assert_eq!(
                crossed.outcome,
                busbar_contract::abi::mechanism::call::Outcome::Ready,
                "the actual WebRTC product completed Finish"
            );
            self.finishes.fetch_add(1, Ordering::SeqCst);
            return crossed;
        }
        self.inner.cross(call)
    }
}

fn offer() -> zeroize::Zeroizing<Vec<u8>> {
    crate::root::serve::serve_datagram::peer::offer_description()
}

fn assert_description(bytes: &[u8]) {
    let sdp = std::str::from_utf8(bytes).expect("SDP answer is text");
    assert!(sdp.starts_with("v=0\r\n"), "{sdp}");
    for field in [
        "a=ice-ufrag:",
        "a=ice-pwd:",
        "a=fingerprint:",
        "a=candidate:",
        "m=application",
    ] {
        assert!(sdp.contains(field), "missing {field}: {sdp}");
    }
}

struct Deployment {
    served: serving::Served,
    app: Arc<busbar_kernel::state::App>,
    key: busbar_contract::records::VirtualKey,
    gov: Arc<busbar_kernel::governance::GovState>,
    post: Arc<crate::root::plane_node::NodeEndPost>,
    money: Arc<busbar_kernel::plane_driver::PlaneMoney>,
    book: Arc<Mutex<crate::root::durability::Durability>>,
    claim: Arc<serve_datagram::ClaimDoor>,
    _connector: Arc<busbar_core_connector::Connector>,
    peer: tokio::task::JoinHandle<()>,
    provider_key: std::path::PathBuf,
}
impl Drop for Deployment {
    fn drop(&mut self) {
        self.peer.abort();
        let _ = std::fs::remove_file(&self.provider_key);
    }
}
impl Deployment {
    async fn requests(&self) -> u64 {
        self.gov
            .usage_for_async(&self.app.cost, &self.key.id, busbar_kernel::store::now())
            .await
            .unwrap()
            .unwrap()
            .requests
    }
}

async fn deployment(instance: &'static str) -> Deployment {
    use crate::root::door_steps::{provider_routes, DoorReach, OutboundAuths};
    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
    use tokio::io::AsyncReadExt;

    crate::root::linked::register_stores(&crate::LINKED);
    let provider_key = std::env::temp_dir().join(format!(
        "busbar-datagram-provider-{instance}-{}.key",
        std::process::id()
    ));
    std::fs::write(&provider_key, b"test-provider-key").unwrap();
    let signing_file = provider_key.with_extension("signing");
    std::fs::write(&signing_file, [9u8; 32]).expect("the actual token signing secret");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                while matches!(socket.read(&mut bytes).await, Ok(n) if n != 0) {}
            });
        }
    });
    let claim =
        serve_datagram::ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap());
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .unwrap();
    let connector = busbar_core_connector::process::build_with_secrets(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    )
    .unwrap();

    if crate::root::connector::installed().is_none() {
        let _ = crate::root::connector::install(connector.clone());
    }
    let services = serving::planes_tests::composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let plane = load_linked::<Plane>(
        &LinkedRow::of(busbar_plane_streaming::door).unwrap(),
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
                connector.clone() as Arc<dyn DeclaredConns>,
            )),
        },
    )
    .unwrap();
    let section = plane.served().section;
    let protocol = {
        let facts = plane.served();
        facts
            .dialect_auth
            .iter()
            .rev()
            .filter(|(_, style, _)| *style == "bearer")
            .find_map(|(dialect, _, _)| facts.dialects.get(*dialect as usize).copied())
            .unwrap()
    };
    let store = crate::root::real_store::core().await;
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("the actual Store settings are JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": {"chain": ["keys"], "admin_auth": [], "signing_key": {"file": signing_file}},
        "store": {"module": "memory", "settings": settings},
    }))
    .expect("the ordinary governed deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the ordinary governed deployment resolves");
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (mut app, _rotation, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(store.clone()),
        false,
    )
    .await
    .expect("the production builder owns the supplied actual Store");
    std::fs::remove_file(&signing_file).expect("the signing secret was resolved at boot");
    let gov = Arc::new(
        GovState::new_with_core(
            store.clone(),
            None,
            Some(TokenSigner::from_secret_bytes(&[9; 32], DEFAULT_KID)),
        )
        .await
        .unwrap(),
    );
    let (key, _) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "datagram caller".into(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
        .unwrap();
    let cost = busbar_kernel::cost::CostModel::flat(1);
    gov.hydrate_budgets_async(&cost, 0).await.unwrap();
    let budget = busbar_kernel::persistence::journal::runtime::BufferBudget {
        records: 4096,
        bytes: 32 * 1024 * 1024,
    };
    let journal = busbar_kernel::persistence::journal::runtime::RuntimeJournal::open(
        store,
        busbar_kernel::door::op_id().counter(),
        budget,
    )
    .await
    .unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            journal.node(),
            journal,
            None,
            budget,
        )
        .await
        .unwrap(),
    ));
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(book.clone());
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    let money = Arc::new(PlaneMoney::new(
        gov.clone(),
        post.clone() as Arc<dyn EndPost>,
    ));
    let tables = busbar_kernel::plane_driver::serve::ServeTables::default();

    app.governance = Some(gov.clone());
    app.cost = Arc::new(cost);
    app.serve_tables = tables.clone();
    let app = Arc::new(app);
    let provider = serde_yaml::from_str::<busbar_kernel::config::ProviderCfg>(&format!(
        "protocol: {protocol}\nbase_url: 'http://{provider_addr}'\napi_key: {{file: '{}'}}\nerror_map: {{}}", provider_key.display()
    )).unwrap();
    let providers = provider_routes(
        &std::collections::HashMap::from([(
            "p".into(),
            busbar_kernel::config::ResolvedProvider::from(provider),
        )]),
        &Default::default(),
    );
    let models_yaml = "{m-cap: {provider: p, upstream_model: gpt-realtime-wire}}";
    let catalog = serde_yaml::from_str::<
        std::collections::HashMap<String, busbar_contract::config::ModelCfg>,
    >(models_yaml)
    .unwrap();
    let secrets: Arc<dyn busbar_contract::secret::SecretResolve> = app.secret_resolver.clone();
    let auths = OutboundAuths::new(
        dispatcher.clone(),
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
            connector.clone() as Arc<dyn DeclaredConns>,
        )),
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    );
    let reach = DoorReach {
        providers: &providers,
        secrets,
        auths: Arc::new(auths),
        conns: connector.clone() as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        catalog: Some(&catalog),
        models: None,
        upgrades: serving::upgrade_carriers(crate::LINKED.transports, &[]),
    };
    let sections = BTreeMap::from([
        (
            section,
            serde_yaml::from_str(&format!(
                "session: {{model: m-cap}}\nmedia: {{listen: '{}'}}",
                claim.local()
            ))
            .unwrap(),
        ),
        (
            busbar_contract::section::RESERVED_MODELS_KEY,
            serde_yaml::from_str(models_yaml).unwrap(),
        ),
    ]);
    let app_for_hooks = app.clone();
    let hooks = serving::HookStage {
        host: Arc::new(move || busbar_kernel::plane_driver::engine_host(&app_for_hooks)),
        gov: gov.clone(),
        journal: None,
    };
    let money_for_plane = money.clone();
    let mut served = serving::compose_planes(
        &[(instance.into(), Arc::new(plane))],
        &dispatcher,
        &services,
        &sections,
        Some("https://gw.example"),
        &move || money_for_plane.clone(),
        Some(&serving::DoorEgress {
            reach: &reach,
            journal: post.clone() as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        Some(&hooks),
        &tables,
    )
    .await
    .unwrap();
    served.post = Some(post.clone());
    served.claim_doors.insert(CARRIER, claim.clone());
    Deployment {
        served,
        app,
        key,
        gov,
        post,
        money,
        book,
        claim,
        _connector: connector,
        peer,
        provider_key,
    }
}

fn routes(g: &mut Deployment) -> (Arc<serving::DataRoutes>, Arc<serve_datagram::ClaimDoor>) {
    let served = std::mem::take(&mut g.served);
    let mut lines = Vec::new();
    let mut of_line = std::collections::HashMap::new();
    for (plane, served) in served.planes.iter().enumerate() {
        for (claim, snapshot) in served
            .snapshot
            .claims
            .iter()
            .enumerate()
            .filter(|(claim, _)| *claim == 1)
        {
            let claim = claim as u32;
            let (line, _) =
                serving::claim_line(&served.instance, claim, snapshot, &[], &[], &[]).unwrap();
            of_line.insert((served.instance.clone(), claim), (plane, claim));
            lines.push(line);
        }
    }
    (
        Arc::new(serving::DataRoutes {
            live: served
                .planes
                .iter()
                .map(|plane| plane.live.current())
                .collect(),
            entries: serving::arrival_entries(&served),
            served,
            claim_doors: None,
            post: g.post.clone(),
            pin: || crate::root::kernel::ROOT_CARD.pin(),
            guests: busbar_kernel::guest::GuestList::seal(lines).unwrap(),
            of_line,
            frames: Default::default(),
        }),
        g.claim.clone(),
    )
}

fn arrival(
    g: &Deployment,
    routes: &serving::DataRoutes,
    target: &str,
) -> (serving::SessionDoor, busbar_kernel::plane_driver::Arrival) {
    let mut req = serving::DoorRequest {
        method: axum::http::Method::POST,
        uri: target.parse().unwrap(),
        headers: Default::default(),
        body: bytes::Bytes::from_owner(offer()),
        gov: Default::default(),
        credential: None,
        ticket: None,
        host_ticket_admission: None,
        app: g.app.clone(),
        scheme: 0,
        consumed_fields: Vec::new(),
    };
    req.gov.key = Some(Arc::new(g.key.clone()));
    let (door, arrival, _) = routes.arrived(0, 1, req);
    (door, arrival)
}

async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(serving::OPEN_HEAD_WAIT, async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the real lifecycle reaches its expected state");
}

async fn cleaned(g: &Deployment, routes: &serving::DataRoutes, framer: &OpeningFramer) -> u64 {
    until(|| {
        g.post.open_units() == 0
            && g.money.open_units() == 0
            && routes.frames_lock().is_empty()
            && !g.book.lock().expect("unpoisoned").audit_records.is_empty()
    })
    .await;
    let unit_key = {
        let book = g.book.lock().expect("unpoisoned");
        assert_eq!(book.audit_records.len(), 1, "one final session record");
        book.audit_records[0].what.unit_key.get()
    };
    assert_eq!(
        g.requests().await,
        1,
        "one real admission, including a failed attachment"
    );
    assert_eq!(
        framer.finishes.load(Ordering::SeqCst),
        1,
        "the actual association finished once"
    );
    unit_key
}

struct EmptyLeg;
impl LegSink for EmptyLeg {
    fn line(&self, _across: Across, _now: std::time::Instant) {}
    fn close(&self) {}
}

struct ReleaseJoin(Arc<std::sync::Barrier>);
impl Drop for ReleaseJoin {
    fn drop(&mut self) {
        self.0.wait();
    }
}

fn assert_book(unit: u64, occupied: bool) {
    let marker = Pairing::new(
        Arc::new(EmptyLeg),
        "127.0.0.1:1".parse().expect("fixture address"),
    );
    let result = crate::root::connector::the().pair(unit, marker);
    assert_eq!(result.is_err(), occupied, "the real pairing-book entry");
    if !occupied {
        crate::root::connector::the().unpair(unit);
    }
}

#[tokio::test]
async fn dropping_the_datagram_opener_before_admission_retires_its_opening() {
    let _one = PUBLISHING.lock().await;
    let mut g = deployment("datagram-cancel-before-admit").await;
    let (routes, _claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let (door, arrival) = arrival(&g, &routes, OPEN_CALL);
    let mut opening = Box::pin(Arc::clone(&routes).open_datagram(
        (framer.clone(), CARRIER.to_string()),
        door,
        arrival,
    ));
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        g.post.open_units(),
        0,
        "the detached session has not been polled"
    );
    drop(opening);
    assert_eq!(
        framer.finishes.load(Ordering::SeqCst),
        1,
        "unjoined custody retired immediately"
    );
    let unit = cleaned(&g, &routes, &framer).await;
    assert_book(unit, false);
    assert_eq!(
        g.book.lock().expect("unpoisoned").audit_records[0]
            .outcome
            .unit_end,
        busbar_contract::caps::Outcome::Refused(
            busbar_contract::caps::StepName::Route,
            busbar_contract::caps::ReasonCode::HandoffMismatch
        )
    );
}

#[tokio::test]
async fn dropping_an_admitted_datagram_opener_before_response_transfer_ends_its_session() {
    let _one = PUBLISHING.lock().await;
    let mut g = deployment("datagram-cancel-before-head").await;
    let (routes, _claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let (door, arrival) = arrival(&g, &routes, OPEN_CALL);
    let mut opening = Box::pin(Arc::clone(&routes).open_datagram(
        (framer.clone(), CARRIER.to_string()),
        door,
        arrival,
    ));
    tokio::select! {
        biased;
        () = until(|| g.money.open_units() == 1 && !routes.frames_lock().is_empty()) => {},
        _ = &mut opening => panic!("custody transferred before the admission observation"),
    }
    assert_eq!(g.money.open_units(), 1);
    let unit = *routes.frames_lock().keys().next().expect("admitted frame");
    assert_book(unit, true);
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 0);
    drop(opening);
    let unit = cleaned(&g, &routes, &framer).await;
    assert_book(unit, false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandonment_during_a_join_retires_the_late_pair_without_holding_the_state_lock() {
    let _one = PUBLISHING.lock().await;
    let mut g = deployment("datagram-cancel-during-join").await;
    let (routes, claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let serve_datagram::Opened {
        description,
        caller,
        head,
        joining,
    } = serve_datagram::Opened::open(&claim, framer.clone(), &offer()).expect("the real opening");
    let opening = serving::DatagramOpening::new(joining);
    let state = Arc::clone(&opening.state);
    let weak = Arc::downgrade(&state);
    *framer.on_finish.lock().expect("unpoisoned") = Some(Arc::new(move || {
        assert!(
            weak.upgrade()
                .expect("live admission state")
                .try_lock()
                .is_ok(),
            "retirement is outside the opening state mutex"
        );
    }));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::clone(&barrier);
    let (entered, joining) = tokio::sync::oneshot::channel();
    let attach = serving::Attach {
        answered: serving::CREATED,
        admitted: Some(Box::new(move |unit| {
            serving::DatagramOpening::admit_with(&state, unit, |joining| {
                joining.admit(unit)?;
                let _ = entered.send(unit);
                resume.wait();
                Ok(())
            })
        })),
        ended: Some(Box::new(|unit| crate::root::connector::the().unpair(unit))),
    };
    let (door, arrival) = arrival(&g, &routes, OPEN_CALL);
    let (verdict, said) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(Arc::clone(&routes).session(door, caller, arrival, verdict, attach));
    let unit = tokio::time::timeout(serving::OPEN_HEAD_WAIT, joining)
        .await
        .expect("the real admission reaches its barrier")
        .expect("the connector has paired the actual unit");
    let release = ReleaseJoin(barrier);
    assert_book(unit, true);
    drop(opening);
    drop(release);
    task.await.expect("normal session cleanup");
    assert!(matches!(said.await.expect("verdict"), Err(None)));
    drop((description, head));
    assert_eq!(cleaned(&g, &routes, &framer).await, unit);
    assert_book(unit, false);
    assert_eq!(
        g.book.lock().expect("unpoisoned").audit_records[0]
            .outcome
            .unit_end,
        busbar_contract::caps::Outcome::Refused(
            busbar_contract::caps::StepName::Route,
            busbar_contract::caps::ReasonCode::HandoffMismatch
        )
    );
}

#[tokio::test]
async fn abandoning_an_unjoined_opening_drops_its_pairing_outside_the_state_mutex() {
    let _one = PUBLISHING.lock().await;
    let mut g = deployment("datagram-drop-outside-lock").await;
    let (_routes, claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let serve_datagram::Opened {
        description,
        caller,
        head,
        joining,
    } = serve_datagram::Opened::open(&claim, framer.clone(), &offer()).expect("opening");
    let opening = serving::DatagramOpening::new(joining);
    let state = Arc::clone(&opening.state);
    let observed = Arc::clone(&state);
    *framer.on_finish.lock().expect("unpoisoned") = Some(Arc::new(move || {
        assert!(
            observed.try_lock().is_ok(),
            "unjoined Drop crosses outside the state mutex"
        );
    }));
    drop(opening);
    assert!(state.lock().expect("unpoisoned").abandoned);
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
    drop((description, caller, head));
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_host_head_wait_timeout_retires_real_custody_and_a_ready_plane_response_transfers_it() {
    let _one = PUBLISHING.lock().await;

    {
        let mut g = deployment("datagram-host-head-timeout").await;
        let (routes, claim) = routes(&mut g);
        let framer = OpeningFramer::new();
        let serve_datagram::Opened {
            description,
            caller,
            head,
            joining,
        } = serve_datagram::Opened::open(&claim, framer.clone(), &offer()).unwrap();
        let opening = serving::DatagramOpening::new(joining);
        let attach = serving::Attach {
            answered: serving::CREATED,
            admitted: Some(opening.admission()),
            ended: Some(Box::new(|unit| crate::root::connector::the().unpair(unit))),
        };
        let (door, arrival) = arrival(&g, &routes, OPEN_CALL);
        let (verdict, said) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(routes.clone().session(
            door,
            serving::ClosingCaller::new(caller),
            arrival,
            verdict,
            attach,
        ));
        assert!(tokio::time::timeout(serving::OPEN_HEAD_WAIT, said)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
        let actual = serve_datagram::plane_head(head, serving::OPEN_HEAD_WAIT)
            .await
            .unwrap();
        assert_eq!(actual.0, 201, "the actual Streaming plane stated its head");
        assert_eq!(g.post.open_units(), 1);
        assert_eq!(g.money.open_units(), 1);
        let unit = *routes.frames_lock().keys().next().unwrap();
        assert_book(unit, true);
        let (_held, pending) = tokio::sync::oneshot::channel::<(u32, serving::HeadFields)>();
        assert_eq!(
            serve_datagram::plane_head(pending, serving::OPEN_HEAD_WAIT).await,
            None
        );
        drop(opening);
        tokio::time::timeout(serving::OPEN_HEAD_WAIT, task)
            .await
            .unwrap()
            .unwrap();
        drop(description);
        assert_eq!(cleaned(&g, &routes, &framer).await, unit);
        assert_book(unit, false);
    }
    {
        let mut g = deployment("datagram-actual-ready-head").await;
        let (routes, _claim) = routes(&mut g);
        let framer = OpeningFramer::new();
        let (door, arrival) = arrival(&g, &routes, OPEN_CALL);
        let response = routes
            .clone()
            .open_datagram((framer.clone(), CARRIER.into()), door, arrival)
            .await;
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        assert!(response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("/v1/realtime/calls/"));
        assert_eq!(
            framer.finishes.load(Ordering::SeqCst),
            0,
            "response readiness transfers custody to the actual live session"
        );
        assert_eq!(g.post.open_units(), 1);
        assert_eq!(g.money.open_units(), 1);
        let unit = *routes
            .frames_lock()
            .keys()
            .next()
            .expect("live session frame");
        assert_book(unit, true);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_description(&body);
        assert_book(unit, true);
        crate::root::connector::the().unpair(unit);
        assert_eq!(cleaned(&g, &routes, &framer).await, unit);
        assert_book(unit, false);
    }
}
