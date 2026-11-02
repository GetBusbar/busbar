// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Datagram opener custody over the real data routes, kernel, pairing book and dropped plane.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::blank_in;
use busbar_contract::abi::transport::EmitIn;
use busbar_core_connector::datagram::{Across, LegSink, Pairing};
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_test_kit::root_door_fixtures::datagram_order::Recording;

use super::super::{self as serving, serve_datagram};
use super::{governed, session_custody_request, session_custody_routes, Governed, PUBLISHING};

const HEAD_PENDING: &str = "/open?head=pending";
const HEAD_READY: &str = "/open?head=ready";
const CARRIER: &str = "datagram-order";
const DESCRIPTION: &[u8] = b"hostfrag";

type Finished = Arc<dyn Fn() + Send + Sync>;

struct OpeningFramer {
    recording: Arc<Recording>,
    settled: AtomicBool,
    finishes: AtomicUsize,
    on_finish: Mutex<Option<Finished>>,
}

impl OpeningFramer {
    fn new() -> Arc<Self> {
        let recording = Recording::new();
        recording.echo_emits();
        Arc::new(Self {
            recording,
            settled: AtomicBool::new(false),
            finishes: AtomicUsize::new(0),
            on_finish: Mutex::new(None),
        })
    }
}

impl FramerDoor for OpeningFramer {
    fn facts(&self) -> &DoorFacts {
        self.recording.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Ingest(input, out) if !self.settled.swap(true, Ordering::SeqCst) => {
                let crossed = self.recording.cross(Call::Ingest(&mut *input, &mut *out));
                let frame_len = out.yielded.frame_len;
                // The existing safe fixture writes one description piece into the host's loan.
                // Its bytes preserve the local-user prefix of the terms already in that loan.
                let mut echo: EmitIn = blank_in();
                echo.framing = input.framing;
                echo.bytes = DESCRIPTION.as_ptr();
                echo.len = DESCRIPTION.len();
                echo.end_of_frame = 1;
                echo.sink = input.sink;
                self.recording.cross(Call::Emit(&mut echo, &mut *out));
                out.yielded.frame_len = frame_len;
                crossed
            }
            Call::Finish(input, out) => {
                self.finishes.fetch_add(1, Ordering::SeqCst);
                let callback = self.on_finish.lock().expect("unpoisoned").clone();
                if let Some(callback) = callback {
                    callback();
                }
                self.recording.cross(Call::Finish(input, out))
            }
            call => self.recording.cross(call),
        }
    }
}

fn routes(g: &mut Governed) -> (Arc<serving::DataRoutes>, Arc<serve_datagram::ClaimDoor>) {
    let mut routes = session_custody_routes(g, false);
    let door = serve_datagram::ClaimDoor::serve(
        ReadyPort::open(bind("127.0.0.1:0").expect("fixture port")).expect("ready port"),
    );
    Arc::get_mut(&mut routes)
        .expect("unshared routes")
        .served
        .claim_doors
        .insert(CARRIER, Arc::clone(&door));
    (routes, door)
}

fn arrival(
    g: &Governed,
    routes: &serving::DataRoutes,
    target: &str,
) -> (serving::SessionDoor, busbar_kernel::plane_driver::Arrival) {
    let mut req = session_custody_request(g, target);
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

async fn cleaned(g: &Governed, routes: &serving::DataRoutes, framer: &OpeningFramer) -> u64 {
    until(|| {
        g.post.open_units() == 0
            && g.money.open_units() == 0
            && routes.frames_lock().is_empty()
            && !g.book.lock().expect("unpoisoned").audit_records.is_empty()
    })
    .await;
    let book = g.book.lock().expect("unpoisoned");
    assert_eq!(book.audit_records.len(), 1, "one final session record");
    assert_eq!(
        g.requests(),
        1,
        "one real admission, including a failed attachment"
    );
    assert_eq!(
        framer.finishes.load(Ordering::SeqCst),
        1,
        "the actual association finished once"
    );
    book.audit_records[0].what.unit_key.get()
}

struct EmptyLeg;
impl LegSink for EmptyLeg {
    fn line(&self, _across: Across, _now: std::time::Instant) {}
    fn close(&self) {}
}

/// Once admission reports the barrier, release its worker even if a subsequent assertion fails.
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

/// Read the existing fixture's OnPieces counter through its pure table, without minting another
/// node unit. A session crossing proves its actual attachment callback has already returned.
fn on_pieces(routes: &serving::DataRoutes) -> u64 {
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::plane::{slot, ArriveIn, ArriveOut, UnitCount};
    const ON_PIECES: usize = 0; // The fixture's existing Stat::OnPieces.
    const STATS_TARGET: &[u8] = b"/stats";
    let mut units = vec![UnitCount::ZERO; routes.served.planes[0].facts.classes.len()];
    let method = axum::http::Method::POST;
    let mut input: ArriveIn = blank_in();
    input.method = AbiStr::over(method.as_str().as_bytes());
    input.target = AbiStr::over(STATS_TARGET);
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    let mut frame = serving::Frame::new(
        input,
        busbar_contract::abi::sdk::door::blank_out::<ArriveOut>(),
    );
    let called = routes.served.planes[0]
        .live
        .plugin
        .call(slot::ARRIVE, &mut frame);
    assert_eq!(called.outcome, Outcome::Ready);
    units[ON_PIECES].amount
}

#[tokio::test]
async fn dropping_the_datagram_opener_before_admission_retires_its_opening() {
    let _one = PUBLISHING.lock().await;
    let mut g = governed("datagram-cancel-before-admit", true);
    let (routes, _claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let (door, arrival) = arrival(&g, &routes, HEAD_PENDING);
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
async fn dropping_a_datagram_opener_waiting_for_the_planes_head_ends_its_session() {
    let _one = PUBLISHING.lock().await;
    let mut g = governed("datagram-cancel-before-head", true);
    let (routes, _claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let (door, arrival) = arrival(&g, &routes, HEAD_PENDING);
    let mut opening = Box::pin(Arc::clone(&routes).open_datagram(
        (framer.clone(), CARRIER.to_string()),
        door,
        arrival,
    ));
    tokio::select! {
        _ = &mut opening => panic!("the plane has stated no head"),
        () = until(|| on_pieces(&routes) > 0) => {}
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
    let mut g = governed("datagram-cancel-during-join", true);
    let (routes, claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let serve_datagram::Opened {
        description,
        caller,
        head,
        joining,
    } = serve_datagram::Opened::open(&claim, framer.clone(), b"offer").expect("the real opening");
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
    let (door, arrival) = arrival(&g, &routes, HEAD_PENDING);
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
    let mut g = governed("datagram-drop-outside-lock", true);
    let (_routes, claim) = routes(&mut g);
    let framer = OpeningFramer::new();
    let serve_datagram::Opened {
        description,
        caller,
        head,
        joining,
    } = serve_datagram::Opened::open(&claim, framer.clone(), b"offer").expect("opening");
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
async fn a_datagram_head_timeout_retires_its_session_but_a_ready_response_transfers_it() {
    let _one = PUBLISHING.lock().await;
    for target in [HEAD_PENDING, HEAD_READY] {
        let mut g = governed("datagram-opening-response", true);
        let (routes, _claim) = routes(&mut g);
        let framer = OpeningFramer::new();
        let (door, arrival) = arrival(&g, &routes, target);
        let response = Arc::clone(&routes)
            .open_datagram((framer.clone(), CARRIER.to_string()), door, arrival)
            .await;
        if target == HEAD_PENDING {
            assert_eq!(
                response.status().as_u16(),
                serving::refusal_status(busbar_contract::caps::ReasonCode::PlanePanic) as u16
            );
            let unit = cleaned(&g, &routes, &framer).await;
            assert_book(unit, false);
        } else {
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert_eq!(
                framer.finishes.load(Ordering::SeqCst),
                0,
                "response readiness transferred custody to the live session"
            );
            assert_eq!(g.post.open_units(), 1);
            assert_eq!(g.money.open_units(), 1);
            let unit = *routes
                .frames_lock()
                .keys()
                .next()
                .expect("live session frame");
            assert_book(unit, true);
            let body = axum::body::to_bytes(response.into_body(), DESCRIPTION.len())
                .await
                .expect("description");
            assert_eq!(body.as_ref(), DESCRIPTION);
            assert_book(unit, true);
            crate::root::connector::the().unpair(unit);
            assert_eq!(cleaned(&g, &routes, &framer).await, unit);
            assert_book(unit, false);
        }
    }
}
