// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SAFE TEST HOST end to end (SDK-SAFE-TEST-HOST §7 MR 2): the facade's own fixtures, linked
//! and cdylib, opened and driven with no `unsafe`; forged doors refused at load. The SHORT re-call
//! (r4's `Pending`) keeps its loans wherever it is moved, belongs to its own instance, and blocks
//! the instance until it is spent (§11.9 T0a); the corrupting mutant flips one wire byte (§11.6);
//! the dropping-media mutant drops RTP/RTCP routes and keeps STUN, DTLS and secured ones (r7.2 §5).

#[path = "fixtures/media_door.rs"]
mod media_door;
#[path = "fixtures/secret_door.rs"]
mod secret_door;
#[path = "fixtures/store_door.rs"]
mod store_door;
#[path = "fixtures/transport_door.rs"]
mod transport_door;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::abi::transport::check::check_datagram;
use busbar_contract::abi::transport::{
    slot, DatagramLane, EmitIn, FramerOut, LocateIn, LocateOut, WriteIn,
};
use busbar_contract::persistence::{DatasetId, PersistenceBackend};
use busbar_plugin_loader::dispatch::kinds::{store_v4::StoreV4, transport::Transport};
use busbar_plugin_loader::dispatch::LoadError;
use busbar_plugin_test::{both, Buf, Called, Host, Image, Loans, Mutant, Opened, Pending, Refused};

fn host() -> Host {
    Host::new(busbar_contract::services::test_caller_binding())
}

#[test]
fn the_store_fixture_opens_through_both_images() {
    both::<StoreV4>("store_fixture", store_door::door, |image, img| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        rt.block_on(async {
            let store = host()
                .store(img, "host-fixture-store", b"{}")
                .await
                .unwrap_or_else(|e| panic!("{image}: {e:?}"));
            let info = store.info();
            assert_eq!(info.dataset, DatasetId([1; 16]), "{image}");
            let clock = store
                .clock(info.dataset)
                .await
                .unwrap_or_else(|e| panic!("{image}: {e:?}"));
            assert_eq!(clock.unix_seconds, 41, "{image}");
        });
    });
}

#[test]
fn a_kind_op_crosses_both_images_with_the_loans_own_lengths() {
    both::<Transport>("transport_fixture", transport_door::door, |image, img| {
        let h = host();
        let mut t = h
            .open(img, "host-fixture-transport", b"{}")
            .unwrap_or_else(|e| panic!("{image}: {e:?}"));
        let mut i = Loans::<WriteIn>::new();
        i.bytes(b"hello").len(999).conn(7);
        match t.call::<{ slot::WRITE }>(i) {
            Called::Ready(a) => {
                assert_eq!(a.outcome(), Outcome::Ready, "{image}: {:?}", a.error());
                assert_eq!(
                    a.get(|o| o.len),
                    5,
                    "{image}: the 5 lent bytes on connection 7, never the forged length 999"
                );
            }
            Called::Pending(p) => {
                p.leak_loans();
                panic!("{image}: write never answers SHORT");
            }
        };
    });
}

#[test]
fn a_forged_door_is_refused_at_load() {
    let h = host();
    let wrong = h.open(
        Image::<Transport>::mutant(Mutant::of(transport_door::door).kind_abi(9)),
        "mutant-kind-abi",
        b"{}",
    );
    assert!(
        matches!(
            wrong,
            Err(Refused::Load(LoadError::KindAbi { door: 9, .. }))
        ),
        "{:?}",
        wrong.err()
    );
    let null = h.open(
        Image::<Transport>::mutant(Mutant::of(transport_door::door).null()),
        "mutant-null",
        b"{}",
    );
    assert!(
        matches!(null, Err(Refused::Load(LoadError::NullDoor))),
        "{:?}",
        null.err()
    );
}

#[test]
#[should_panic(expected = "no cdylib for `no_such_fixture`")]
fn a_missing_cdylib_panics_naming_where_it_looked() {
    let _ = Image::<Transport>::cdylib("no_such_fixture", transport_door::door);
}

#[test]
fn a_mutant_stating_another_version_is_refused_against_its_twin() {
    let wrong = host().open(
        Image::<Transport>::mutant_as(
            Mutant::of(transport_door::door).version("0.0.0-restated"),
            transport_door::door,
        ),
        "mutant-version",
        b"{}",
    );
    assert!(
        matches!(wrong, Err(Refused::Load(LoadError::StatementMismatch))),
        "{:?}",
        wrong.err()
    );
}

#[test]
fn a_transport_stating_another_frame_piece_size_is_refused() {
    let host_size = busbar_contract::abi::transport::FRAME_PIECE_SIZE;
    let wrong = host().open(
        Image::<Transport>::mutant(
            Mutant::of(transport_door::door).frame_piece_size(host_size - 8),
        ),
        "mutant-frame-piece",
        b"{}",
    );
    assert!(
        matches!(
            wrong,
            Err(Refused::Load(LoadError::FramePieceSize { stated, host, .. }))
                if stated == host_size - 8 && host == host_size
        ),
        "{:?}",
        wrong.err()
    );
}

#[test]
#[should_panic(expected = "this row edits a Plane tail only")]
fn a_tail_row_refuses_another_kind_s_door() {
    let _ = Mutant::of(transport_door::door).answer_layout(1);
}

#[test]
fn a_failing_ready_refuses_the_open_once_with_its_text() {
    let before = Mutant::failed_readies();
    let refused = host().open(
        Image::<Transport>::mutant(
            Mutant::of(transport_door::door).failing_ready("fixture: discovery refused"),
        ),
        "mutant-ready",
        b"{}",
    );
    assert!(
        matches!(
            &refused,
            Err(Refused::Ready(text))
                if text == "plugin 'host-fixture-transport' ready failed: fixture: discovery refused"
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(Mutant::failed_readies() - before, 1, "READY is not retried");
}

#[test]
fn scripted_services_answer_what_the_test_says_and_name_the_rest() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::services::HostServices;
    use busbar_plugin_test::{Caller, Reading, Services, Stored, UNSERVED};

    let svc = std::sync::Arc::new(
        Services::new()
            .on_now(|| Reading {
                wall_ns: 5,
                mono_ns: 6,
            })
            .on_sign(|_, data| Stored::ready(data.len() as u64)),
    );
    let caller = Caller::for_test("services-fixture".into(), KindCode::Plane);
    assert_eq!(
        HostServices::now(&*svc),
        Reading {
            wall_ns: 5,
            mono_ns: 6
        }
    );
    assert_eq!(HostServices::sign(&*svc, &caller, b"four").value, 4);
    let unserved = HostServices::random_fill(&*svc, 16);
    assert_eq!(
        (unserved.outcome, unserved.value, unserved.error),
        (
            Outcome::Refused,
            busbar_contract::abi::host::service::REFUSED_UNSERVED,
            UNSERVED
        )
    );
    assert_eq!(svc.unscripted(), ["random_fill"]);
    // The double is what a host binds.
    let _ = host().services(svc);
}

/// What the fixture's `locate` is asked to locate; its re-call answers it as the authority.
const TARGET: &[u8] = b"fixture.example:7443";

/// A LOCATE of [`TARGET`] on `t`, which the fixture answers SHORT on an instance's first call:
/// the pending re-call, and the key to the authority buffer it lent.
fn short_locate(t: &mut Opened<Transport>) -> (Pending<LocateIn, LocateOut>, Buf<u8>) {
    let mut i = Loans::<LocateIn>::new();
    let authority = i.target(TARGET).authority_buf(64);
    match t.call::<{ slot::LOCATE }>(i) {
        Called::Pending(p) => (p, authority),
        Called::Ready(a) => panic!(
            "the fixture's first locate answers SHORT, not {:?}: {:?}",
            a.outcome(),
            a.error()
        ),
    }
}

#[test]
fn a_pending_crossing_moved_between_containers_resumes_with_the_buffers_it_was_lent() {
    both::<Transport>("transport_fixture", transport_door::door, |image, img| {
        let h = host();
        let mut t = h
            .open(img, "host-fixture-transport", b"{}")
            .unwrap_or_else(|e| panic!("{image}: {e:?}"));
        let (p, authority) = short_locate(&mut t);
        // A pending crossing owns its loans (each a heap allocation) and its boxed frame, so
        // moving it moves no byte the plugin was lent: the fixture refuses a re-call lent another
        // authority buffer than its SHORT call was.
        let mut queued = vec![p];
        let mut by_name = std::collections::HashMap::new();
        by_name.insert("locate", queued.pop().expect("the one queued crossing"));
        let p = by_name.remove("locate").expect("the one named crossing");
        match p.resume(&mut t) {
            Called::Ready(a) => {
                assert_eq!(a.outcome(), Outcome::Ready, "{image}: {:?}", a.error());
                let written = usize::try_from(a.get(|o| o.authority_written)).expect("a length");
                assert_eq!(
                    a.read(&authority).get(..written),
                    Some(TARGET),
                    "{image}: the re-call wrote the target into the buffer the SHORT call was lent"
                );
            }
            Called::Pending(p) => {
                p.leak_loans();
                panic!("{image}: the re-call never answers SHORT again");
            }
        };
    });
}

#[test]
#[should_panic(expected = "resumed on another instance")]
fn a_pending_crossing_resumed_on_another_instance_panics() {
    let h = host();
    let mut first = h
        .open(
            Image::<Transport>::linked(transport_door::door),
            "host-fixture-transport",
            b"{}",
        )
        .expect("the first instance opens");
    let mut second = h
        .open(
            Image::<Transport>::linked(transport_door::door),
            "host-fixture-transport-2",
            b"{}",
        )
        .expect("the second instance opens");
    let (p, _) = short_locate(&mut first);
    drop(p.resume(&mut second));
}

#[test]
#[should_panic(expected = "a pending crossing is still in flight on this instance")]
fn a_call_while_the_short_re_call_is_outstanding_panics() {
    let h = host();
    let mut t = h
        .open(
            Image::<Transport>::linked(transport_door::door),
            "host-fixture-transport",
            b"{}",
        )
        .expect("the instance opens");
    let (_pending, _) = short_locate(&mut t);
    let mut i = Loans::<WriteIn>::new();
    i.bytes(b"hello").conn(7);
    drop(t.call::<{ slot::WRITE }>(i));
}

/// An EMIT of `bytes` on `t`: the wire the fixture echoed them to, as the host read it.
fn emit(t: &mut Opened<Transport>, bytes: &[u8], image: &str) -> Vec<u8> {
    let mut i = Loans::<EmitIn>::new();
    let mut wire = None;
    i.bytes(bytes).stream(1).sink(|s| wire = Some(s.wire(64)));
    let wire = wire.expect("the sink lends a wire buffer");
    match t.call::<{ slot::EMIT }>(i) {
        Called::Ready(a) => {
            assert_eq!(a.outcome(), Outcome::Ready, "{image}: {:?}", a.error());
            let len = usize::try_from(a.get(|o| o.yielded.wire_len)).expect("a length");
            a.read(&wire)
                .get(..len)
                .expect("the wire written lies within the wire buffer")
                .to_vec()
        }
        Called::Pending(p) => {
            p.leak_loans();
            panic!("{image}: emit never answers SHORT");
        }
    }
}

#[test]
fn the_fixture_s_emit_echoes_its_bytes_whole_through_both_images() {
    both::<Transport>("transport_fixture", transport_door::door, |image, img| {
        let h = host();
        let mut t = h
            .open(img, "host-fixture-transport", b"{}")
            .unwrap_or_else(|e| panic!("{image}: {e:?}"));
        assert_eq!(emit(&mut t, b"hello", image), b"hello", "{image}");
        assert_eq!(emit(&mut t, b"again", image), b"again", "{image}");
    });
}

#[test]
fn a_corrupting_mutant_flips_one_byte_of_the_nth_emit_s_wire() {
    let h = host();
    let mut t = h
        .open(
            Image::<Transport>::mutant(Mutant::corrupting(transport_door::door, slot::EMIT, 1)),
            "host-fixture-transport",
            b"{}",
        )
        .expect("a corrupting mutant states what its door states, so it opens");
    let first = emit(&mut t, b"hello", "mutant");
    let second = emit(&mut t, b"hello", "mutant");
    assert_ne!(
        first, b"hello",
        "the echo check sees the first EMIT's wire corrupted"
    );
    assert_eq!(
        (first.len(), first.first().copied(), first.get(1..)),
        (5, Some(!b'h'), Some(&b"ello"[..])),
        "exactly the first wire byte is flipped, nothing else"
    );
    assert_eq!(second, b"hello", "only the nth EMIT is corrupted");
}

#[test]
#[should_panic(expected = "this row corrupts a framer op that writes a sink")]
fn a_corrupting_row_refuses_a_slot_with_no_sink() {
    let _ = Mutant::corrupting(transport_door::door, slot::WRITE, 1);
}

/// An EMIT on the media fixture `t`: the datagrams the host reads back (each route's lane and
/// bytes, in order), once the answer has passed the host's own datagram check.
fn emit_datagrams(t: &mut Opened<Transport>) -> Vec<(u32, Vec<u8>)> {
    let mut i = Loans::<EmitIn>::new();
    let (mut wire, mut routes) = (None, None);
    i.bytes(b"media")
        .stream(1)
        .sink(|s| wire = Some(s.wire(64)))
        .lane(|l| {
            l.push(|lane| {
                let size = u32::try_from(std::mem::size_of::<DatagramLane>()).expect("a size");
                lane.size(size).bound(media_door::PATH).verified(1);
                routes = Some(lane.routes(8));
            });
        });
    let wire = wire.expect("the sink lends a wire buffer");
    let routes = routes.expect("the lane lends a routes buffer");
    match t.call::<{ slot::EMIT }>(i) {
        Called::Ready(a) => {
            assert_eq!(a.outcome(), Outcome::Ready, "{:?}", a.error());
            let mut out: FramerOut = blank_out();
            out.yielded = a.get(|o| o.yielded);
            out.datagram = a.get(|o| o.datagram);
            let lent = a.read(&routes);
            let cap = u64::try_from(lent.len()).expect("a capacity");
            check_datagram(a.outcome(), &out, lent, cap)
                .unwrap_or_else(|f| panic!("the answer passes the host's datagram check: {f:?}"));
            let n = usize::try_from(out.datagram.routes_len).expect("a count");
            let wire = a.read(&wire);
            lent.get(..n)
                .expect("the routes answered lie within the routes buffer")
                .iter()
                .map(|r| {
                    let at = usize::try_from(r.offset).expect("an offset");
                    let len = usize::try_from(r.len).expect("a length");
                    let bytes = wire
                        .get(at..at + len)
                        .expect("each route lies within the wire buffer");
                    (r.lane, bytes.to_vec())
                })
                .collect()
        }
        Called::Pending(p) => {
            p.leak_loans();
            panic!("emit never answers SHORT");
        }
    }
}

/// The fixture's datagrams at these (0-based) positions of [`media_door::DATAGRAMS`].
fn datagrams(at: &[usize]) -> Vec<(u32, Vec<u8>)> {
    at.iter()
        .map(|&k| {
            let (bytes, lane) = media_door::DATAGRAMS[k];
            (lane, bytes.to_vec())
        })
        .collect()
}

#[test]
fn a_dropping_media_mutant_drops_rtp_and_keeps_stun_dtls_and_secured_routes() {
    let h = host();
    let mut real = h
        .open(
            Image::<Transport>::linked(media_door::door),
            "host-fixture-media",
            b"{}",
        )
        .expect("the media fixture opens");
    assert_eq!(
        emit_datagrams(&mut real),
        datagrams(&[0, 1, 2, 3, 4, 5]),
        "the real door answers STUN, RTP, RTP, DTLS, RTP and a secured route"
    );
    drop(real);

    // The only case in this binary that sends media through a dropping mutant, so the
    // process-wide count moves only here.
    let before = Mutant::dropped_media();
    let mut all = h
        .open(
            Image::<Transport>::mutant(Mutant::dropping_media(media_door::door, 1)),
            "host-fixture-media-all",
            b"{}",
        )
        .expect("a dropping mutant states what its door states, so it opens");
    assert_eq!(
        emit_datagrams(&mut all),
        datagrams(&[0, 3, 5]),
        "every = 1: all three RTP routes go; STUN, DTLS and the secured route (first byte 0x90) stay"
    );
    assert_eq!(
        Mutant::dropped_media() - before,
        3,
        "three media routes dropped"
    );
    drop(all);

    let mut half = h
        .open(
            Image::<Transport>::mutant(Mutant::dropping_media(media_door::door, 2)),
            "host-fixture-media-half",
            b"{}",
        )
        .expect("a dropping mutant states what its door states, so it opens");
    assert_eq!(
        emit_datagrams(&mut half),
        datagrams(&[0, 1, 3, 4, 5]),
        "every = 2: routes 1, 2, 4, 5 and 6 reach the host; RTP number 2 is dropped"
    );
    assert_eq!(
        emit_datagrams(&mut half),
        datagrams(&[0, 2, 3, 5]),
        "the count runs on across answers: this mutant's media 4 and 6 are dropped"
    );
    assert_eq!(
        Mutant::dropped_media() - before,
        6,
        "each forged mutant counts its own media"
    );
}

#[test]
fn a_dropping_media_mutant_forwards_a_stream_framer_s_answer_untouched() {
    let h = host();
    let mut t = h
        .open(
            Image::<Transport>::mutant(Mutant::dropping_media(transport_door::door, 1)),
            "host-fixture-transport",
            b"{}",
        )
        .expect("a dropping mutant states what its door states, so it opens");
    assert_eq!(
        emit(&mut t, b"hello", "mutant"),
        b"hello",
        "a stream framer is lent no lane (NULL), so its answer passes as the door wrote it"
    );
}

#[test]
#[should_panic(expected = "the first media route is number 1")]
fn a_dropping_media_row_refuses_every_zero() {
    let _ = Mutant::dropping_media(media_door::door, 0);
}

/// The fixture secret's RESOLVE answer: the first secret its OPEN was lent.
fn resolved(t: &mut Opened<busbar_plugin_test::Secret>) -> Vec<u8> {
    use busbar_contract::abi::secret::{slot as secret_slot, ResolveIn};
    let mut i = Loans::<ResolveIn>::new();
    let k = i.secret_buf(64);
    match t.call::<{ secret_slot::RESOLVE }>(i) {
        Called::Ready(a) => {
            assert_eq!(a.outcome(), Outcome::Ready, "RESOLVE answers");
            let len = a.get(|o| o.secret.len);
            a.read(&k)
                .get(..len)
                .expect("inside the lent buffer")
                .to_vec()
        }
        Called::Pending(p) => {
            p.leak_loans();
            panic!("the fixture's RESOLVE does not pend");
        }
    }
}

#[test]
fn an_open_lends_the_plugin_the_secrets_the_test_states() {
    let secrets: [&[u8]; 2] = [b"lent-secret-0", b"lent-secret-1"];
    let mut t = host()
        .open_lent(
            Image::<busbar_plugin_test::Secret>::linked(secret_door::door),
            "host-fixture-secret",
            b"{}",
            &secrets,
        )
        .expect("the secret fixture opens");
    assert_eq!(
        resolved(&mut t),
        b"lent-secret-0",
        "OPEN lent the first secret the test stated"
    );
}

/// STH-ROWS D-1a/D-1b: the secret fixture opened through `open_lent`, lent `secret`.
fn open_secret(h: &Host, secret: &[u8]) -> Opened<busbar_plugin_test::Secret> {
    h.open_lent(
        Image::<busbar_plugin_test::Secret>::linked(secret_door::door),
        "host-fixture-secret",
        b"{}",
        &[secret],
    )
    .expect("the secret fixture opens")
}

/// CLOSE crossings the secret fixture answered so far.
fn closes() -> u64 {
    secret_door::CLOSES.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn validate_answers_before_open_and_a_refused_open_sends_no_close() {
    let h = host();
    let mut loaded = h
        .load(
            Image::<busbar_plugin_test::Secret>::linked(secret_door::door),
            "host-fixture-secret",
        )
        .expect("the secret fixture loads");
    let valid = loaded.validate(b"{}");
    assert_eq!(
        valid.outcome,
        Outcome::Ready,
        "VALIDATE answers before any OPEN: {:?}",
        valid.error
    );
    let invalid = loaded.validate(b"[]");
    assert_ne!(
        invalid.outcome,
        Outcome::Ready,
        "a JSON list is not settings"
    );
    assert!(invalid.error.is_some(), "a refused VALIDATE states why");
    let before = closes();
    let (why, loaded) = match loaded.open(b"[]", &[]) {
        Err(back) => back,
        Ok(_) => panic!("the fixture's OPEN refuses a JSON list"),
    };
    assert!(matches!(why, Refused::Open(_)), "{why:?}");
    drop(loaded);
    assert_eq!(
        closes(),
        before,
        "an OPEN that did not answer READY opened nothing, so nothing is CLOSEd"
    );
}

#[test]
fn an_opening_closes_once_when_dropped_and_readies_into_an_open_instance() {
    let h = host();
    let image = || Image::<busbar_plugin_test::Secret>::linked(secret_door::door);
    let before = closes();
    let opening = h
        .load(image(), "host-fixture-secret")
        .expect("the secret fixture loads")
        .open(b"{}", &[b"lent-secret-0".as_slice()])
        .map_err(|(why, _)| why)
        .expect("the secret fixture opens");
    drop(opening);
    assert_eq!(
        closes() - before,
        1,
        "an instance dropped between OPEN and READY CLOSEs once"
    );
    let mut t = h
        .load(image(), "host-fixture-secret")
        .expect("the secret fixture loads")
        .open(b"{}", &[b"lent-secret-0".as_slice()])
        .map_err(|(why, _)| why)
        .expect("the secret fixture opens")
        .ready()
        .map_err(|(why, _)| why)
        .expect("the secret fixture readies");
    assert_eq!(
        resolved(&mut t),
        b"lent-secret-0",
        "the readied instance serves"
    );
}

#[test]
fn the_lifecycle_slots_cross_an_open_instance_and_close_answers_once() {
    let h = host();
    let mut t = open_secret(&h, b"lent-secret-0");
    let id = t.instance_id();
    let valid = t.validate(b"{}");
    assert_eq!(valid.outcome, Outcome::Ready, "{:?}", valid.error);
    let refreshed = t.refresh(b"{}", &[b"refreshed-secret".as_slice()], 2);
    assert_eq!(refreshed.outcome, Outcome::Ready, "{:?}", refreshed.error);
    assert_eq!(
        resolved(&mut t),
        b"refreshed-secret",
        "REFRESH lent the plugin its new secret"
    );
    let refused = t.refresh(b"[]", &[], 3);
    assert_ne!(
        refused.outcome,
        Outcome::Ready,
        "the fixture refuses a list"
    );
    assert!(refused.error.is_some(), "a refused REFRESH states why");
    assert_eq!(t.instance_id(), id, "REFRESH keeps the instance");
    let ticked = t.tick(100);
    assert_eq!(ticked.outcome, Outcome::Ready, "{:?}", ticked.error);
    assert_eq!(
        ticked.next_tick_ns,
        Some(105),
        "TICK answers the plugin's next tick"
    );
    let retired = t.retire(1);
    assert_eq!(retired.outcome, Outcome::Ready, "{:?}", retired.error);
    let before = closes();
    let closed = t.close();
    assert_eq!(closed.outcome, Outcome::Ready, "{:?}", closed.error);
    assert_eq!(
        closes() - before,
        1,
        "close() CLOSEs once, and the drop after it sends no second CLOSE"
    );
}

#[test]
fn the_host_builders_keep_each_other_s_settings() {
    use busbar_contract::services::HostServices;
    use busbar_plugin_loader::dispatch::DispatchConfig;
    use busbar_plugin_test::Services;

    let base = host().dispatcher().workers();
    let wider = DispatchConfig {
        workers: 2,
        ..DispatchConfig::default()
    };
    let svc: std::sync::Arc<dyn HostServices> = std::sync::Arc::new(Services::new());
    let config_first = host().config(wider).services(std::sync::Arc::clone(&svc));
    assert_eq!(
        config_first.dispatcher().workers(),
        base + 1,
        "services() keeps the stated config"
    );
    assert!(config_first.dispatcher().host_services().is_some());
    let services_first = host().services(svc).config(wider);
    assert_eq!(services_first.dispatcher().workers(), base + 1);
    assert!(
        services_first.dispatcher().host_services().is_some(),
        "config() keeps the stated services"
    );
}

/// STH-ROWS D-6: how long a submission's answer is waited for.
const WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

/// A RESOLVE `in` lending a `cap`-byte secret buffer, and its key.
fn resolve_in(cap: usize) -> (Loans<busbar_contract::abi::secret::ResolveIn>, Buf<u8>) {
    let mut i = Loans::<busbar_contract::abi::secret::ResolveIn>::new();
    let k = i.secret_buf(cap);
    (i, k)
}

#[test]
fn a_short_answer_regrows_its_buffer_before_the_one_re_call() {
    use busbar_contract::abi::secret::slot as secret_slot;
    let h = host();
    let mut t = open_secret(&h, b"lent-secret-0");
    let (i, _small) = resolve_in(4);
    let pending = match t.call::<{ secret_slot::RESOLVE }>(i) {
        Called::Pending(p) => p,
        Called::Ready(a) => panic!(
            "a 4-byte buffer is SHORT for a 13-byte secret: {:?}",
            a.outcome()
        ),
    };
    let mut grown = None;
    let pending = pending.regrow(|i| grown = Some(i.secret_buf(64)));
    let key = grown.expect("regrow ran its closure");
    let called = pending.resume(&mut t);
    match called {
        Called::Ready(a) => {
            assert_eq!(a.outcome(), Outcome::Ready, "{:?}", a.error());
            let len = a.get(|o| o.secret.len);
            assert_eq!(
                a.read(&key).get(..len),
                Some(b"lent-secret-0".as_slice()),
                "the re-call was lent the grown buffer"
            );
        }
        Called::Pending(p) => {
            p.leak_loans();
            panic!("the one re-call, lent 64 bytes, answers");
        }
    }
}

#[test]
fn submitted_ops_answer_through_wait_each_with_its_own_moved_loans() {
    use busbar_contract::abi::secret::slot as secret_slot;
    let h = host();
    let t = open_secret(&h, b"lent-secret-0");
    let mut flying = Vec::new();
    let mut keys = Vec::new();
    for _ in 0..2 {
        let (i, k) = resolve_in(64);
        keys.push(k);
        flying.push(t.submit::<{ secret_slot::RESOLVE }>(i));
    }
    for (submitted, key) in flying.into_iter().zip(keys) {
        let done = submitted.wait(WITHIN).unwrap_or_else(|late| {
            late.leak_loans();
            panic!("RESOLVE answers within the wait")
        });
        assert_eq!(done.outcome(), Outcome::Ready, "{:?}", done.error());
        let len = done.get(|o| o.secret.len);
        assert_eq!(
            done.read(&key).get(..len),
            Some(b"lent-secret-0".as_slice()),
            "each moved submission reads back its own buffer"
        );
    }
}

#[test]
fn a_short_submission_is_resubmitted_once_on_its_ticket_with_grown_loans() {
    use busbar_contract::abi::secret::slot as secret_slot;
    let h = host();
    let t = open_secret(&h, b"lent-secret-0");
    let (i, _small) = resolve_in(4);
    let short = t
        .submit::<{ secret_slot::RESOLVE }>(i)
        .wait(WITHIN)
        .unwrap_or_else(|late| {
            late.leak_loans();
            panic!("RESOLVE answers within the wait")
        });
    assert!(
        short.short(),
        "a 4-byte buffer is SHORT for a 13-byte secret: {:?}",
        short.outcome()
    );
    let mut grown = None;
    let done = short
        .resubmit(|i| grown = Some(i.secret_buf(64)))
        .wait(WITHIN)
        .unwrap_or_else(|late| {
            late.leak_loans();
            panic!("the resubmission answers within the wait")
        });
    assert_eq!(done.outcome(), Outcome::Ready, "{:?}", done.error());
    let key = grown.expect("resubmit ran its closure");
    let len = done.get(|o| o.secret.len);
    assert_eq!(
        done.read(&key).get(..len),
        Some(b"lent-secret-0".as_slice()),
        "the resubmission was lent the grown buffer"
    );
}

#[test]
fn a_cancelled_pending_submission_answers_the_kind_s_disposition() {
    use busbar_contract::abi::secret::{cancel, slot as secret_slot};
    let h = host();
    let t = open_secret(&h, secret_door::PENDS);
    let (i, _k) = resolve_in(64);
    let pending = match t
        .submit::<{ secret_slot::RESOLVE }>(i)
        .wait(std::time::Duration::from_millis(200))
    {
        Err(pending) => pending,
        Ok(done) => panic!("RESOLVE pends until cancelled: {:?}", done.outcome()),
    };
    let done = pending.cancel(WITHIN).unwrap_or_else(|late| {
        late.leak_loans();
        panic!("a cancelled op answers within the wait")
    });
    assert_eq!(
        done.disposition(),
        Some(cancel::ABORTED),
        "the fixture's CANCEL disposition: {:?} {:?}",
        done.outcome(),
        done.error()
    );
    assert_ne!(
        done.outcome(),
        Outcome::Ready,
        "a cancelled op did not answer"
    );
}

#[test]
fn an_instance_with_a_forgotten_submission_is_poisoned_not_closed() {
    use busbar_contract::abi::secret::slot as secret_slot;
    let h = host();
    let t = open_secret(&h, secret_door::PENDS);
    let (i, _k) = resolve_in(64);
    std::mem::forget(t.submit::<{ secret_slot::RESOLVE }>(i));
    let before = closes();
    drop(t);
    assert_eq!(
        closes(),
        before,
        "a poisoned instance skips CLOSE: the plugin may still hold the leaked loans"
    );
}

#[test]
fn a_mutant_renders_what_its_door_states_and_a_tailless_or_cut_tail_is_refused() {
    use busbar_plugin_test::{rendering, rendering_of};
    assert_eq!(
        rendering(Mutant::of(transport_door::door)),
        rendering_of(transport_door::door),
        "an unchanged mutant renders exactly what its door states"
    );
    for (name, mutant) in [
        ("mutant-no-tail", Mutant::of(transport_door::door).no_tail()),
        (
            "mutant-cut-tail",
            Mutant::of(transport_door::door).tail_size(4),
        ),
    ] {
        let refused = host().open(Image::<Transport>::mutant(mutant), name, b"{}");
        assert!(
            matches!(refused, Err(Refused::Load(_))),
            "{name}: a transport whose tail is missing or cut below its head is refused at load: {:?}",
            refused.err()
        );
    }
}

#[test]
#[should_panic(expected = "beyond the tail's own size")]
fn a_tail_row_never_grows_a_tail() {
    let _ = Mutant::of(transport_door::door).tail_size(u32::MAX);
}

#[test]
#[should_panic(expected = "this row edits a Plane tail only")]
fn the_media_row_refuses_a_transport_s_door() {
    let _ = Mutant::of(transport_door::door).no_streaming_types();
}

#[test]
fn an_images_declared_diagnostic_reaches_the_hosts_sink_once() {
    let env = busbar_plugin_test::Envelopes::new();
    let h = host().sink(env.clone());
    let mut t = open_secret(&h, secret_door::NOTES);
    assert_eq!(resolved(&mut t), secret_door::NOTES, "RESOLVE answers");
    assert_eq!(
        env.diags(),
        vec![busbar_plugin_test::DiagRecord {
            id: 0,
            name: b"fixture-note".to_vec(),
            severity: 1,
            text: b"the fixture was asked to note".to_vec(),
        }],
        "the declared diagnostic is recorded once, as production's sink sees it"
    );
    assert!(env.metrics().is_empty() && env.dropped().is_empty());
}

#[test]
fn a_linked_door_is_refused_when_it_states_another_plugins_statement() {
    // Another plugin of the SAME kind: a statement of another kind is refused earlier, as a manifest kind
    // mismatch, before the statement is ever compared with the door.
    let other =
        busbar_plugin_test::rendering(Mutant::of(transport_door::door).version("0.0.0-other"))
            .expect("the other transport renders");
    let wrong = host().open(
        Image::<Transport>::linked_stated(transport_door::door, &other),
        "linked-stated",
        b"{}",
    );
    assert!(
        matches!(wrong, Err(Refused::Load(LoadError::StatementMismatch))),
        "{:?}",
        wrong.err()
    );
}

/// STH-ROWS D-7: a plugin repository's `busbar-plugin-test` dev edge, with `test-seal` on it,
/// opens a host with no second `busbar-contract` edge and no seal in its own code.
#[cfg(feature = "test-seal")]
#[test]
fn the_facade_hands_out_a_sealed_host_only_under_test_seal() {
    let h = busbar_plugin_test::host();
    let t = h
        .open(
            Image::<Transport>::linked(transport_door::door),
            "facade-host",
            b"{}",
        )
        .expect("the facade's host opens a linked fixture");
    drop(t);
}
