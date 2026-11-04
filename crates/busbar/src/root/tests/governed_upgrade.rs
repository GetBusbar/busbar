// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::loader::dispatch::auth_handle::{
    AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes, RefuseAsk,
    StreamPolicy, UnitSecret,
};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_core_connector::carrier::{Carry, Side};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor, Refused};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Accepted,
    WrongClaim,
    Expired,
    Canceled,
}

// The real loader/kernel bridge supplies every operation. Only the deadline is shortened for
// the expiry case; its cancellation uses the real handed-in owner/framing/stream identities.
struct AdmissionHost {
    actual: crate::root::inbound::LoaderSide,
    case: Case,
    binding: Mutex<Option<(u64, u64, u64)>>,
}
impl AuthHandleHost for AdmissionHost {
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret> {
        self.actual.unit_secret(owner, unit)
    }
    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan {
        self.actual.auth_call(ask, done)
    }
    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        self.hand_in_with_deadline(ask, None)
    }
    fn hand_in_with_deadline(
        &self,
        ask: HandInAsk,
        deadline: Option<Duration>,
    ) -> Result<(u32, UnitRef), &'static str> {
        *self.binding.lock().unwrap() = Some((ask.owner, ask.framing.unwrap(), ask.stream));
        self.actual.hand_in_with_deadline(
            ask,
            if self.case == Case::Expired {
                Some(Duration::from_millis(250))
            } else {
                deadline
            },
        )
    }
    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        self.actual.refuse(ask)
    }
    fn requires_scope(&self) -> bool {
        self.actual.requires_scope()
    }
    fn framing_started(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
    ) -> Result<Option<StreamPolicy>, &'static str> {
        self.actual.framing_started(owner, listener, framing)
    }
    fn stream_open(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
        stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        self.actual.stream_open(owner, listener, framing, stream)
    }
    fn stream_ended(&self, owner: u64, framing: u64, stream: u64) {
        self.actual.stream_ended(owner, framing, stream);
    }
    fn framing_ready(&self, owner: u64, framing: u64) {
        self.actual.framing_ready(owner, framing);
    }
    fn framing_detached(&self, owner: u64, framing: u64) -> Result<(), &'static str> {
        self.actual.framing_detached(owner, framing)
    }
    fn framing_adopting(
        &self,
        source: busbar_contract::framing_scope::AdoptionSource,
        owner: u64,
        framing: u64,
    ) -> Result<busbar_contract::framing_scope::SessionTransfer, &'static str> {
        self.actual.framing_adopting(source, owner, framing)
    }
    fn framing_adopted(&self, owner: u64, framing: u64, conn: u64) -> Result<(), &'static str> {
        self.actual.framing_adopted(owner, framing, conn)
    }
    fn framing_ended(&self, framing: u64) {
        self.actual.framing_ended(framing);
    }
}

type Scope = Arc<dyn busbar_contract::framing_scope::FramingScope>;

struct ObservedAdopter {
    actual: Arc<dyn FramerDoor>,
    claimed: Mutex<Vec<String>>,
    money: Arc<PlaneMoney>,
    book: Arc<Mutex<crate::root::durability::Durability>>,
    plane: crate::root::boot::DoorPlane,
}

fn handler_pieces(plane: &crate::root::boot::DoorPlane) -> u64 {
    use crate::root::loader::dispatch::{in_head, out_head, Frame};
    use busbar_contract::abi::plane::{slot, ArriveIn, ArriveOut, UnitCount};
    use busbar_contract::abi::sdk::door::{abi_str, blank_in, blank_out};
    let mut units = [UnitCount::ZERO; 7];
    let mut input: ArriveIn = blank_in();
    input.head = in_head();
    input.unit = u64::MAX;
    input.method = abi_str("POST");
    input.target = abi_str("/stats");
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    let mut output: ArriveOut = blank_out();
    output.head = out_head();
    let mut frame = Frame::new(input, output);
    assert_eq!(plane.call(slot::ARRIVE, &mut frame).outcome, Outcome::Ready);
    assert_eq!(frame.out.units_written, 7);
    units[0].amount
}

impl FramerDoor for ObservedAdopter {
    fn facts(&self) -> &DoorFacts {
        self.actual.facts()
    }
    fn accepts(&self) -> bool {
        self.actual.accepts()
    }
    fn detaches(&self) -> bool {
        self.actual.detaches()
    }
    fn adopts(&self) -> bool {
        self.actual.adopts()
    }
    fn seals_values(&self) -> bool {
        self.actual.seals_values()
    }
    fn instance(&self) -> Option<u64> {
        self.actual.instance()
    }
    fn io_owner(&self) -> Option<u64> {
        self.actual.io_owner()
    }
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        self.actual.framing_side()
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.actual.side()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.actual.cross(call)
    }
    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        self.actual.cross_on(side, resume, call)
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        self.actual.carry(side, resume, call)
    }
    fn framing_context(&self, listener: u64, connection: u64) -> Result<Option<Scope>, Refused> {
        self.actual.framing_context(listener, connection)
    }
    fn adopting_context(&self, source: Scope) -> Result<Option<Scope>, Refused> {
        self.actual.adopting_context(source)
    }
    #[allow(unsafe_code)]
    fn cross_scoped(
        &self,
        scope: Option<&Scope>,
        side: Option<&dyn Side>,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        if let Call::Adopt(input, _) = &call {
            // SAFETY: this is the connector's live AdoptIn loan, including its bounded facts.
            let claim = unsafe {
                let claim = (*input.facts).claim;
                std::str::from_utf8(std::slice::from_raw_parts(claim.ptr, claim.len)).unwrap()
            };
            self.claimed.lock().unwrap().push(claim.into());
            assert_eq!(
                self.money.open_units(),
                0,
                "adoption precedes paid admission"
            );
            assert!(self.book.lock().unwrap().audit_records.is_empty());
            assert_eq!(
                handler_pieces(&self.plane),
                0,
                "no plane handler precedes actual adoption"
            );
        }
        self.actual.cross_scoped(scope, side, resume, call)
    }
    fn cancel_scoped(&self, scope: Option<&Scope>, side: &dyn Side, call: Carry<'_>) -> Crossed {
        self.actual.cancel_scoped(scope, side, call)
    }
}

fn opened_transport(claim: &str, dispatcher: &Arc<Dispatcher>) -> Arc<dyn FramerDoor> {
    let door = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .find_map(|(_, door)| {
            crate::root::loader::dispatch::kinds::transport::stated(*door)
                .unwrap()
                .claims
                .contains(&claim)
                .then_some(*door)
        })
        .expect("the assembled distribution supplies the real transport");
    let rows = [(claim, door)];
    crate::root::connector::entries_on(
        dispatcher,
        &rows,
        &busbar_contract::transport::TransportSettings::default(),
    )
    .unwrap()
    .remove(0)
    .door
}

async fn exercise(case: Case) {
    let _publishing = PUBLISHING.lock().await;
    let g = governed("governed-upgrade-witness", true);
    let plane = Arc::clone(&g.served.planes[0].live.plugin);
    assert_eq!(handler_pieces(&plane), 0);
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let host = Arc::new(AdmissionHost {
        actual: crate::root::inbound::LoaderSide(Arc::clone(crate::root::inbound::host())),
        case,
        binding: Mutex::new(None),
    });
    assert!(dispatcher.install_auth_handle(host.clone()));
    let http = opened_transport("http", &dispatcher);
    let ws = Arc::new(ObservedAdopter {
        actual: opened_transport("wss", &dispatcher),
        claimed: Mutex::new(Vec::new()),
        money: Arc::clone(&g.money),
        book: Arc::clone(&g.book),
        plane: Arc::clone(&plane),
    });
    assert_eq!(
        ws.facts().claims[0],
        "ws",
        "wss is deliberately not the first claim"
    );
    let mut served = g.served.clone();
    served.planes[0].snapshot.claims[2].verb = "GET".into();
    served.planes[0].snapshot.claims[2].carrier = "wss".into();
    served.planes[0].snapshot.claims[2].flags &= !busbar_contract::abi::plane::CLAIM_OPEN;
    let points = g
        .app
        .auth
        .position_points(busbar_kernel::config::KEYS_MODULE);
    let chain = [(busbar_kernel::config::KEYS_MODULE.into(), points)];
    let offers = crate::root::serve::transport_offers(crate::LINKED.transports, &[]);
    let mounts = crate::root::serve::door_mounts(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        &chain,
        &[],
        &["ws", "wss"],
        &offers,
    )
    .unwrap();
    let routes = mounts.data;
    assert!(routes.guests.lines().iter().any(|line|
        matches!(&line.claimant, busbar_kernel::guest::Claimant::Plane(owner) if owner == "governed-upgrade-witness")
            && line.route.rung == 2 && line.upgrade.as_deref() == Some("wss")));
    crate::root::inbound::stage(routes.guests.clone(), Vec::new());
    crate::root::inbound::publish(&g.app).unwrap();
    let selected = Arc::new(Mutex::new(Vec::new()));
    let selections = Arc::clone(&selected);
    let actual_http = Arc::clone(&http);
    let actual_ws: Arc<dyn FramerDoor> = ws.clone();
    let framers: crate::root::listener::framed::FramerFor = Arc::new(move |claim| {
        if claim == "http" {
            return Some(Arc::clone(&actual_http));
        }
        selections.lock().unwrap().push(claim.to_owned());
        if case == Case::WrongClaim {
            Some(Arc::clone(&actual_http))
        } else {
            Some(Arc::clone(&actual_ws))
        }
    });
    let dispatch_routes = Arc::clone(&routes);
    let dispatch_host = Arc::clone(&host);
    let dispatched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dispatch_count = Arc::clone(&dispatched);
    let framer = crate::root::listener::framed::listener_framer(
        framers,
        "http",
        Arc::new(|source| Ok(source.clone())),
    )
    .unwrap()
    .with_dispatch(Arc::new(move |admission| {
        dispatch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(admission.selected_line().upgrade.as_deref(), Some("wss"));
        match case {
            Case::Expired => {
                let deadline = admission
                    .deadline()
                    .expect("the real hand-in retains its test deadline");
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            }
            Case::Canceled => {
                let (owner, framing, stream) = dispatch_host.binding.lock().unwrap().unwrap();
                crate::root::inbound::host().stream_ended(owner, framing, stream);
            }
            _ => {}
        }
        Some(Arc::clone(&dispatch_routes))
    }));
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let actor = tokio::spawn(crate::root::listener::framed::serve_governed_test(
        server,
        framer,
        false,
        Duration::from_secs(10),
        stopped,
    ));
    let request = format!(
        "GET /framed/upgrade HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", g.token
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut wire = Vec::new();
    if case == Case::Accepted {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut byte = [0; 1];
                assert_eq!(client.read(&mut byte).await.unwrap(), 1);
                wire.push(byte[0]);
                assert!(wire.len() < 4096);
                if wire.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await
        .expect("the genuine governed upgrade commits its handshake");
        assert!(wire.starts_with(b"HTTP/1.1 101"), "{wire:?}");
        assert_eq!(*selected.lock().unwrap(), ["wss"]);
        assert_eq!(*ws.claimed.lock().unwrap(), ["wss"]);
        assert_eq!(
            g.requests(),
            1,
            "the same authenticated admission is charged once"
        );
        assert_eq!(g.money.open_units(), 1);
        assert_eq!(g.post.open_units(), 1);
        assert!(g.book.lock().unwrap().audit_records.is_empty());
        assert!(
            handler_pieces(&plane) > 0,
            "only the adopted governed session invokes the plane"
        );
        // A real masked WS client frame, then the fixture plane's real session echo.
        client
            .write_all(&[
                0x81,
                0x84,
                1,
                2,
                3,
                4,
                b'p' ^ 1,
                b'i' ^ 2,
                b'n' ^ 3,
                b'g' ^ 4,
            ])
            .await
            .unwrap();
        let mut echo = [0; 11];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echo[2..], b"echo:ping");
        assert_eq!(echo[1] & 0x7f, 9);
        client.shutdown().await.unwrap();
    } else {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut bytes = [0; 1024];
                match client.read(&mut bytes).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        wire.extend_from_slice(&bytes[..n]);
                        assert!(wire.len() < 4096);
                        if wire.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("the refused upgrade terminates or produces a bounded refusal");
        assert!(!wire.windows(12).any(|bytes| bytes == b"HTTP/1.1 101"));
        assert!(
            ws.claimed.lock().unwrap().is_empty(),
            "no invalid authority reaches the adopter"
        );
        assert_eq!(
            handler_pieces(&plane),
            0,
            "no invalid upgrade enters the actual plane handler"
        );
        assert_eq!(g.requests(), 0);
        assert_eq!(
            *selected.lock().unwrap(),
            if case == Case::WrongClaim {
                vec!["wss"]
            } else {
                Vec::new()
            },
            "only live upgrade authority may reach transport selection"
        );
    }
    assert_eq!(
        dispatched.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "every case exercises the real plane admission before its controlled boundary"
    );
    assert!(
        host.binding.lock().unwrap().is_some(),
        "the actual transport handed in its request"
    );
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(5), actor)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while g.post.open_units() != 0 || g.money.open_units() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual governed session settles when its transport closes");
    assert_eq!(g.post.node().sweep(g.post.node().arrived()), 0);
    assert_eq!(g.requests(), u64::from(case == Case::Accepted));
    assert_eq!(
        g.book.lock().unwrap().audit_records.len(),
        usize::from(case == Case::Accepted),
        "exactly one terminal audit for the admitted session; none for refused upgrades"
    );
}

#[tokio::test]
async fn actual_upgrade_adopts_the_exact_second_claim_before_governed_plane_money_and_audit() {
    exercise(Case::Accepted).await;
}

#[tokio::test]
async fn a_wrong_transport_claim_never_enters_the_governed_upgrade_handler() {
    exercise(Case::WrongClaim).await;
}

#[tokio::test]
async fn an_expired_transport_admission_never_enters_the_governed_upgrade_handler() {
    exercise(Case::Expired).await;
}

#[tokio::test]
async fn a_canceled_transport_admission_never_enters_the_governed_upgrade_handler() {
    exercise(Case::Canceled).await;
}
