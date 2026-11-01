// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO PLUGIN CODE RUNS UNDER A HOST LOCK (`BUSBAR-1.6.0.md` §11), on a framed stream: a write has
//! the stream out of its slot while its framer is crossed, so a framer `emit` that hangs holds no
//! lock, and the unit's close beside it never waits on it. The close is the write's to make, as it
//! puts the stream back.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_core_connector::framed_stream::FramedStream;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_kernel::plane_driver::CallerEnd;

use super::{refused, shared, FramedCaller, IngressCaller};

/// A framer that answers every op with nothing, and whose `emit` HANGS once armed: it says it is
/// inside the crossing, then does not come back until the test lets it. Every crossing is recorded
/// with the thread it ran on.
struct Hanging {
    facts: DoorFacts,
    gate: Mutex<Option<(mpsc::Sender<ThreadId>, mpsc::Receiver<()>)>>,
    crossed: Mutex<Vec<(&'static str, ThreadId)>>,
}

impl FramerDoor for Hanging {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let op = match call {
            Call::Begin(..) => "begin",
            Call::Emit(..) => "emit",
            Call::Refuse(..) => "refuse",
            Call::Finish(..) => "finish",
            _ => "other",
        };
        self.crossed
            .lock()
            .unwrap()
            .push((op, thread::current().id()));
        if op == "emit" {
            let gate = self.gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(thread::current().id()).unwrap();
                release.recv().unwrap();
            }
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

/// RED before a write had the stream out of its slot: the slot's lock was held across the framer's
/// `emit`, so the unit's close (its final status) beside a hung emit waited on the plugin for as
/// long as it hung, and so did the answer's refusal. Now both return while the emit still hangs,
/// and the write makes the close itself, on its own thread, as it puts the stream back.
#[test]
fn a_close_beside_a_hung_framer_emit_never_waits_and_the_write_makes_it() {
    let door = Arc::new(Hanging {
        facts: DoorFacts {
            name: "lp".into(),
            claims: vec!["lp"],
            role: busbar_contract::abi::transport::ROLE_FRAMER,
            composes_over: Vec::new(),
            ported: false,
            status_rows: Vec::new(),
            duplex: vec!["lp"],
            datagram: false,
        },
        gate: Mutex::new(None),
        crossed: Mutex::new(Vec::new()),
    });
    let stream = FramedStream::open(
        Arc::clone(&door) as Arc<dyn FramerDoor>,
        "lp",
        "/",
        &[],
        busbar_contract::abi::host::service::SCHEME_PLAIN,
    )
    .expect("the stream opens");
    let stream = shared(stream);
    let (inner, _reply) = IngressCaller::new();
    let (trailers, _trailed) = tokio::sync::oneshot::channel();
    let caller = Arc::new(FramedCaller::new(inner, Arc::clone(&stream), trailers));

    let (entered_tx, entered) = mpsc::channel();
    let (release, held_back) = mpsc::channel();
    *door.gate.lock().unwrap() = Some((entered_tx, held_back));
    let writing = Arc::clone(&caller);
    let writer = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(writing.framed(b"reply", true))
    });
    let owner = entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the write reaches the framer");

    // BESIDE IT, on another thread: the answer's refusal and the unit's final status.
    let (done_tx, done) = mpsc::channel();
    let closing = Arc::clone(&caller);
    let answered = Arc::clone(&stream);
    let closer = thread::spawn(move || {
        let response = refused(&answered, None);
        closing.final_status(200, b"", b"");
        done_tx.send(response.status().as_u16()).unwrap();
    });
    done.recv_timeout(Duration::from_secs(5))
        .expect("a close beside a hung framer emit returned while it still hangs");
    let closed_early = door
        .crossed
        .lock()
        .unwrap()
        .iter()
        .any(|(op, _)| matches!(*op, "finish" | "refuse"));
    assert!(
        !closed_early,
        "the close was handed to the write: nothing crossed beside its hung emit"
    );

    release.send(()).unwrap();
    assert!(writer.join().unwrap(), "the write went through");
    closer.join().unwrap();
    let crossed = door.crossed.lock().unwrap().clone();
    let emit = crossed
        .iter()
        .rposition(|(op, _)| *op == "emit")
        .expect("the emit crossed");
    assert!(
        crossed[emit + 1..]
            .iter()
            .any(|(op, on)| matches!(*op, "finish" | "refuse") && *on == owner),
        "the write closed the stream as it put it back, on its own thread: {crossed:?}"
    );
}
