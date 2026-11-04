// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FINISH is a bounded synchronous drain, including when a destructor discards its output.

use super::*;
use busbar_contract::abi::transport::YIELD_MORE;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Ending {
    Batches(usize),
    EmptyForever,
    WireForever,
    BadSink,
    BadRoute,
    BadFlags,
    FailSecond,
    Pend,
    PanicSecond,
}

#[derive(Default)]
struct Finished {
    tokens: Vec<u64>,
    lanes: Vec<Seen>,
    pointers: Vec<(usize, usize, usize)>,
    errors: Vec<crate::framer::Refused>,
}

type Callback = Arc<dyn Fn() + Send + Sync>;

struct Finishing {
    inner: Arc<Scripted>,
    ending: Ending,
    calls: AtomicUsize,
    finished: Mutex<Finished>,
    callback: Mutex<Option<Callback>>,
}

impl Finishing {
    fn install(host: &mut DatagramFraming, inner: Arc<Scripted>, ending: Ending) -> Arc<Self> {
        let door = Arc::new(Self {
            inner,
            ending,
            calls: AtomicUsize::new(0),
            finished: Mutex::new(Finished::default()),
            callback: Mutex::new(None),
        });
        host.door = door.clone();
        door
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl FramerDoor for Finishing {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn incomplete_retirement(&self, error: &crate::framer::Refused) {
        self.finished.lock().unwrap().errors.push(error.clone());
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let Call::Finish(input, out) = call else {
            return self.inner.cross(call);
        };
        assert_eq!(out.yielded.wire_len, 0);
        assert_eq!(out.yielded.frame_len, 0);
        assert_eq!(out.yielded.flags, 0);
        assert!(raw(input.sink.wire, input.sink.wire_cap)
            .iter()
            .all(|byte| *byte == 0));
        assert!(raw(input.sink.frame, input.sink.frame_cap)
            .iter()
            .all(|byte| *byte == 0));
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let lane = {
            let mut st = self.inner.st.lock().unwrap();
            read_lane(&mut st, input.lane).unwrap();
            st.seen.pop().unwrap()
        };
        {
            let mut finished = self.finished.lock().unwrap();
            finished.tokens.push(input.framing);
            finished.lanes.push(lane);
            // SAFETY: the host lends the lane and its keying/path pointers for this crossing.
            let lane = unsafe { &*input.lane };
            finished.pointers.push((
                input.lane as usize,
                lane.keying as usize,
                lane.paths as usize,
            ));
        }
        let callback = self.callback.lock().unwrap().clone();
        if let Some(callback) = callback {
            callback();
        }
        let mut outcome = Outcome::Ready;
        match self.ending {
            Ending::EmptyForever => out.yielded.flags = YIELD_MORE,
            Ending::WireForever => {
                // SAFETY: the host lends this initialized output buffer at its stated capacity.
                unsafe { std::ptr::write_bytes(input.sink.wire, 1, input.sink.wire_cap) };
                out.yielded.wire_len = input.sink.wire_cap as u64;
                out.yielded.flags = YIELD_MORE;
            }
            Ending::BadSink => out.yielded.frame_len = input.sink.frame_cap as u64 + 1,
            Ending::BadFlags => out.yielded.flags = 1 << 31,
            Ending::BadRoute => out.datagram.routes_len = 1,
            Ending::FailSecond if call == 2 => outcome = Outcome::Failed,
            Ending::Pend => outcome = Outcome::Pending,
            Ending::PanicSecond if call == 2 => panic!("FINISH unwind witness"),
            ending => {
                let bytes = [b'c', u8::try_from(call).unwrap()];
                assert!(input.sink.wire_cap >= bytes.len());
                // SAFETY: both host loans have sufficient capacity; the route references only
                // the two bytes initialized in this crossing.
                unsafe {
                    let lane = &*input.lane;
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), input.sink.wire, bytes.len());
                    lane.routes.write(DatagramRoute {
                        path: lane.bound.max(1),
                        lane: LANE_SECURED,
                        offset: 0,
                        len: bytes.len() as u64,
                    });
                }
                out.yielded.wire_len = bytes.len() as u64;
                out.datagram.routes_len = 1;
                if !matches!(ending, Ending::Batches(last) if call == last) {
                    out.yielded.flags = YIELD_MORE;
                }
            }
        }
        Crossed {
            outcome,
            error: (outcome == Outcome::Failed).then(|| b"FINISH failed".to_vec()),
        }
    }
}

fn framing(ending: Ending) -> (DatagramFraming, Arc<Finishing>) {
    let inner = scripted(Knobs::default());
    let mut host = settled(inner.clone());
    let door = Finishing::install(&mut host, inner, ending);
    (host, door)
}

#[test]
fn datagram_finish_drains_partial_batches_with_the_same_token_and_borrowed_lane() {
    let mut rig = rig(Knobs::default());
    rig.first_check();
    rig.pump(200);
    assert!(rig.host.verified());
    let keyed = rig
        .far
        .ups
        .iter()
        .position(|up| matches!(up, Up::Keyed(_)))
        .unwrap();
    let Up::Keyed(keying) = rig.far.ups.remove(keyed) else {
        unreachable!()
    };
    let material = keying.material().to_vec();
    rig.host.keying = Some(keying);
    let extra = p("203.0.113.44:4444");
    rig.host.book.number(extra, |_| true).unwrap();
    let door = Finishing::install(&mut rig.host, rig.door.clone(), Ending::Batches(3));
    let sent = Mutex::new(Vec::new());
    rig.host
        .close(&|to, bytes| sent.lock().unwrap().push((to, bytes.to_vec())))
        .unwrap();
    assert_eq!(rig.host.retirement(), Some(&Ok(())));
    assert!(rig
        .host
        .bufs
        .wire_written(2)
        .unwrap()
        .iter()
        .all(|byte| *byte == 0));
    rig.host
        .close(&|_, _| panic!("duplicate close sent output"))
        .unwrap();
    drop(rig.host);
    assert_eq!(door.calls(), 3);
    let finished = door.finished.lock().unwrap();
    assert_eq!(finished.tokens, [7, 7, 7]);
    assert!(finished.errors.is_empty());
    assert!(finished.pointers.iter().all(|p| p == &finished.pointers[0]));
    assert_ne!(
        finished.pointers[0].1, 0,
        "keying remains borrowed through the final call"
    );
    for lane in &finished.lanes {
        assert!(lane.verified);
        assert_eq!(lane.local, rig.host_addr.to_string());
        assert_eq!(lane.keying.as_ref().unwrap().1, material);
        assert!(lane.told.iter().any(|(_, addr)| addr == &extra.to_string()));
    }
    drop(finished);
    let mut plain = Vec::new();
    for (to, bytes) in sent.into_inner().unwrap() {
        assert_eq!(to, rig.far.addr);
        rig.far.a.ingest(rig.host_addr, &bytes, rig.now);
        while let Some(up) = rig.far.a.poll_up() {
            if let Up::Plaintext(bytes) = up {
                plain.push(bytes);
            }
        }
    }
    assert_eq!(plain, [vec![b'c', 1], vec![b'c', 2], vec![b'c', 3]]);
}

#[test]
fn datagram_finish_empty_more_is_bounded_and_incomplete_without_a_destructor_retry() {
    let (mut host, door) = framing(Ending::EmptyForever);
    let error = host.close(&|_, _| {}).unwrap_err();
    assert_eq!(error.outcome, Outcome::Fault);
    assert!(error.error.contains("wrote nothing"));
    assert_eq!(door.calls(), crate::framer::MORE_STALLS);
    assert_eq!(host.retirement(), Some(&Err(error.clone())));
    assert_eq!(host.close(&|_, _| {}), Err(error.clone()));
    drop(host);
    assert_eq!(door.calls(), crate::framer::MORE_STALLS);
    assert_eq!(door.finished.lock().unwrap().errors, [error]);
}

#[test]
fn datagram_finish_nonempty_more_uses_the_existing_output_work_bound() {
    let (mut host, door) = framing(Ending::WireForever);
    host.bufs = crate::framer::Buffers::new(1024 * 1024, 1, 1);
    let error = host.close(&|_, _| {}).unwrap_err();
    assert!(error.error.contains("output/control work"));
    assert_eq!(door.calls(), 65);
    drop(host);
    assert_eq!(door.calls(), 65);
    assert_eq!(door.finished.lock().unwrap().errors, [error]);
}

#[test]
fn datagram_finish_rejects_malformed_sinks_routes_flags_and_pending() {
    for ending in [
        Ending::BadSink,
        Ending::BadRoute,
        Ending::BadFlags,
        Ending::Pend,
    ] {
        let (mut host, door) = framing(ending);
        let error = host
            .close(&|_, _| panic!("unchecked closing output escaped"))
            .unwrap_err();
        assert_eq!(error.outcome, Outcome::Fault);
        assert_eq!(host.retirement(), Some(&Err(error.clone())));
        drop(host);
        assert_eq!(door.calls(), 1);
        assert_eq!(door.finished.lock().unwrap().errors, [error]);
    }
}

#[test]
fn datagram_finish_failure_after_partial_output_preserves_the_failure_and_stops() {
    let mut rig = rig(Knobs::default());
    rig.first_check();
    rig.pump(200);
    assert!(rig.host.verified());
    let door = Finishing::install(&mut rig.host, rig.door.clone(), Ending::FailSecond);
    let sent = Mutex::new(Vec::new());
    let error = rig
        .host
        .close(&|to, bytes| sent.lock().unwrap().push((to, bytes.to_vec())))
        .unwrap_err();
    assert_eq!(error.outcome, Outcome::Failed);
    assert_eq!(door.calls(), 2);
    assert_eq!(rig.host.retirement(), Some(&Err(error.clone())));
    let sent = sent.into_inner().unwrap();
    assert_eq!(sent.len(), 1, "only the first checked batch was sent");
    assert_eq!(sent[0].0, rig.far.addr);
    rig.far.a.ingest(rig.host_addr, &sent[0].1, rig.now);
    assert!(matches!(rig.far.a.poll_up(), Some(Up::Plaintext(bytes)) if bytes == [b'c', 1]));
    assert!(rig.far.a.poll_up().is_none());
    drop(rig.host);
    assert_eq!(door.calls(), 2);
    assert_eq!(door.finished.lock().unwrap().errors, [error]);
}

#[test]
fn datagram_finish_drop_drains_and_discards_closing_output() {
    let (host, door) = framing(Ending::Batches(3));
    drop(host);
    assert_eq!(door.calls(), 3);
    assert!(door.finished.lock().unwrap().errors.is_empty());
}

#[test]
fn datagram_finish_unwind_never_recurses_into_the_broken_door() {
    let (mut host, door) = framing(Ending::PanicSecond);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.close(&|_, _| {})));
    assert!(result.is_err());
    assert!(matches!(host.retirement(), Some(Err(_))));
    drop(host);
    assert_eq!(door.calls(), 2);
}

#[test]
fn datagram_finish_reentrant_removal_runs_all_batches_outside_the_port_lock_once() {
    let (host, door) = framing(Ending::Batches(3));
    let port = Arc::new(super::super::PortAssociations::new());
    let id = port.add(host).unwrap();
    let weak = Arc::downgrade(&port);
    *door.callback.lock().unwrap() = Some(Arc::new(move || {
        let port = weak.upgrade().unwrap();
        assert!(port.assocs.try_lock().is_ok());
        port.remove(id);
    }));
    port.remove_sending(id, &|_, _| {});
    port.remove_sending(id, &|_, _| panic!("duplicate close sent"));
    assert!(port.is_empty());
    drop(port);
    assert_eq!(door.calls(), 3);
    assert!(door.finished.lock().unwrap().errors.is_empty());
}
