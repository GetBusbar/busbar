// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retirement cannot forget a supervision key before in-flight carrier work and close finish.

use super::*;
use std::sync::{mpsc, Mutex};

#[derive(Default)]
struct Gate(Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>);

impl Gate {
    fn arm(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered) = mpsc::channel();
        let (release, held) = mpsc::channel();
        *self.0.lock().unwrap() = Some((entered_tx, held));
        (entered, release)
    }

    fn cross(&self) {
        let gate = self.0.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            let _ = entered.send(());
            let _ = release.recv();
        }
    }
}

struct RetirementDoor {
    inner: TestDoor,
    read: Gate,
    dial: Gate,
    shut: Gate,
    events: Mutex<Vec<&'static str>>,
}

impl crate::framer::FramerDoor for RetirementDoor {
    fn facts(&self) -> &crate::framer::DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: crate::framer::Call<'_>) -> crate::framer::Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.side()
    }

    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        resume: bool,
        call: crate::carrier::Carry<'_>,
    ) -> crate::framer::Crossed {
        use crate::carrier::Carry;
        let closing = matches!(&call, Carry::Shut(..));
        let retired_before = self.inner.retired_keys.lock().unwrap().len();
        match &call {
            Carry::Read(..) => self.read.cross(),
            Carry::Shut(..) => self.shut.cross(),
            // Only the first dial is gated; the retirement notification comes later.
            Carry::Dial(..) => self.dial.cross(),
            _ => {}
        }
        let result = self.inner.carry(side, resume, call);
        if self.inner.retired_keys.lock().unwrap().len() != retired_before {
            self.events.lock().unwrap().push("retired");
        }
        if closing {
            self.events.lock().unwrap().push("shut returned");
        }
        result
    }
}

async fn retirement_waits_for_crossing_and_close(during_spawn: bool) {
    let handle = tokio::runtime::Handle::current();
    let door = Arc::new(RetirementDoor {
        inner: TestDoor::identity("bytes"),
        read: Gate::default(),
        dial: Gate::default(),
        shut: Gate::default(),
        events: Mutex::new(Vec::new()),
    });
    let c = Arc::new(Connector::serving(
        Transports::new(vec![Entry {
            door: Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
            alpn: Vec::new(),
        }])
        .unwrap(),
        Arc::new(crate::LiteralsOnly(crate::guard::Guard::default())),
        None,
        Arc::new(|_, _| {}),
    ));
    declare(&c, &[("m", sh(ECHO_PID, &[]))]).unwrap();
    let existing = if during_spawn {
        None
    } else {
        let id = open(&c, "m", b"").unwrap();
        assert_eq!(generation(&c, id).await, 1);
        pid_of(&c, id, "warm").await;
        Some(id)
    };
    let (entered, release) = if during_spawn {
        door.dial.arm()
    } else {
        door.read.arm()
    };
    let (shutting, release_shut) = door.shut.arm();
    let crossing = Arc::clone(&c);
    let on = handle.clone();
    let in_flight = std::thread::spawn(move || {
        let _runtime = on.enter();
        if let Some(id) = existing {
            let mut buf = [0_u8; 64];
            let _ = crossing.read(OWNER, id, 7, &mut buf);
            None
        } else {
            Some(open(&crossing, "m", b""))
        }
    });
    let reached = entered.recv_timeout(Duration::from_secs(10));
    let (done_tx, done) = mpsc::channel();
    let retiring = Arc::clone(&c);
    let on = handle.clone();
    let retire = std::thread::spawn(move || {
        let _runtime = on.enter();
        let declared = declare(&retiring, &[("m", sh("exec cat", &[]))]);
        let closed = existing.map(|id| retiring.close(OWNER, id));
        let _ = done_tx.send((declared, closed));
    });
    let answered = done.recv_timeout(Duration::from_secs(5));
    let before_crossing_return = door.inner.retired_keys.lock().unwrap().clone();
    // Release every gate and join both threads before asserting, including on the old red code.
    let _ = release.send(());
    let close_reached = shutting.recv_timeout(Duration::from_secs(10));
    let before_close_return = door.inner.retired_keys.lock().unwrap().clone();
    let _ = release_shut.send(());
    let crossed = in_flight.join();
    let retired = retire.join();
    reached.expect("the requested carrier crossing entered");
    close_reached.expect("the retired program reaches its carrier close");
    retired.unwrap();
    let opened = crossed.unwrap();
    let (declared, closed) = answered.expect("retire and close return while carrier work hangs");
    assert_eq!(declared, Ok(()));
    assert_eq!(closed, existing.map(|_| Ok(())));
    if during_spawn {
        assert!(
            matches!(opened, Some(Err(ConnError::Refused))),
            "retired spawn: {opened:?}"
        );
    }
    assert!(
        before_crossing_return.is_empty(),
        "key retired during carrier work"
    );
    assert!(
        before_close_return.is_empty(),
        "key retired before close returned"
    );
    let keys = door.inner.dialled_keys.lock().unwrap().clone();
    assert_eq!(keys.len(), 1);
    assert_eq!(*door.inner.retired_keys.lock().unwrap(), keys);
    assert_eq!(*door.events.lock().unwrap(), ["shut returned", "retired"]);
}

#[test]
fn retiring_a_member_waits_for_its_read_and_then_its_close_before_forgetting_its_key() {
    worker().block_on(retirement_waits_for_crossing_and_close(false));
}

#[test]
fn retiring_a_member_waits_for_its_spawn_and_then_its_close_before_forgetting_its_key() {
    worker().block_on(retirement_waits_for_crossing_and_close(true));
}
