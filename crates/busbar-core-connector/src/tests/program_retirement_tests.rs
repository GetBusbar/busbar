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
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
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

fn handoff_declare(
    c: &Connector,
    predecessor: InstanceId,
    owner: InstanceId,
    spec: &ReadNeed,
    name: &str,
    program: Program,
) {
    c.declare_member_programs_from(
        predecessor,
        owner,
        NEED,
        spec,
        &[(name.to_owned(), program)],
    )
    .expect("the candidate declares its own program need");
}

async fn handoff_read(
    c: &Connector,
    owner: InstanceId,
    id: ConnId,
    buf: &mut [u8],
) -> busbar_contract::conn::Piece {
    handoff_read_before(
        c,
        owner,
        id,
        buf,
        std::time::Instant::now() + Duration::from_secs(10),
    )
    .await
}

async fn handoff_read_before(
    c: &Connector,
    owner: InstanceId,
    id: ConnId,
    buf: &mut [u8],
    deadline: std::time::Instant,
) -> busbar_contract::conn::Piece {
    loop {
        match c.read(owner, id, 7, buf) {
            Err(ConnError::Pending) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            answer => return answer.expect("the actual child's bounded read succeeds"),
        }
    }
}

async fn handoff_open(c: &Connector, owner: InstanceId, name: &str) -> ConnId {
    let id = c
        .open(
            owner,
            NEED,
            &OpenDesc {
                target: name,
                ..OpenDesc::default()
            },
        )
        .unwrap();
    let mut head = [0_u8; 512];
    assert_eq!(
        handoff_read(c, owner, id, &mut head).await.kind,
        PieceKind::Fields
    );
    id
}

async fn handoff_pid(c: &Connector, owner: InstanceId, id: ConnId, text: &str) -> String {
    handoff_pid_after_broadcasts(c, owner, id, text, &[]).await
}

async fn handoff_pid_after_broadcasts(
    c: &Connector,
    owner: InstanceId,
    id: ConnId,
    text: &str,
    pending: &[(&str, &str)],
) -> String {
    let message = format!("{text}\n");
    assert_eq!(
        c.write(owner, id, message.as_bytes(), false, false),
        Ok(message.len())
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut held = Vec::new();
    let mut seen = 0;
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "correlated child reply deadline"
        );
        let mut buf = [0_u8; 256];
        let piece = handoff_read_before(c, owner, id, &mut buf, deadline).await;
        assert_eq!(piece.kind, PieceKind::Body);
        held.extend_from_slice(&buf[..piece.len]);
        while let Some(at) = held.iter().position(|b| *b == b'\n') {
            let bytes: Vec<u8> = held.drain(..=at).collect();
            let line = std::str::from_utf8(&bytes[..at]).unwrap();
            let (pid, echoed) = line.split_once(' ').unwrap();
            assert!(pid.parse::<u32>().is_ok_and(|pid| pid > 0));
            if let Some((expected_pid, expected_text)) = pending.get(seen) {
                assert_eq!(
                    (pid, echoed),
                    (*expected_pid, *expected_text),
                    "exact previously emitted broadcast, in order"
                );
                seen += 1;
            } else {
                assert_eq!(echoed, text);
                assert!(held.is_empty(), "no unrequested trailing child data");
                return pid.to_owned();
            }
        }
    }
}

#[test]
fn program_custody_survives_two_owner_refreshes_candidate_rollback_and_old_owner_forget() {
    worker().block_on(async {
        let c = connector();
        let spec = need(EGRESS_OPERATOR_INFRASTRUCTURE);
        let program = sh(ECHO_PID, &[]);
        declare(&c, &[("m", program.clone())]).unwrap();
        let old = handoff_open(&c, OWNER, "m").await;
        let pid = handoff_pid(&c, OWNER, old, "initial").await;
        let second = InstanceId(2);
        handoff_declare(&c, OWNER, second, &spec, "m", program.clone());
        let middle = handoff_open(&c, second, "m").await;
        assert_eq!(handoff_pid(&c, second, middle, "second").await, pid);
        assert_eq!(
            handoff_pid_after_broadcasts(&c, OWNER, old, "retained-old", &[(&pid, "second")]).await,
            pid
        );
        let third = InstanceId(3);
        handoff_declare(&c, second, third, &spec, "m", program.clone());
        let current = handoff_open(&c, third, "m").await;
        assert_eq!(handoff_pid(&c, third, current, "third").await, pid);
        let rejected = InstanceId(4);
        handoff_declare(&c, third, rejected, &spec, "m", program);
        c.forget(rejected); // The candidate never publishes.
        assert_eq!(handoff_pid(&c, third, current, "after-rollback").await, pid);
        c.forget(second);
        c.forget(OWNER);
        assert_eq!(
            handoff_pid(&c, third, current, "after-old-forget").await,
            pid
        );
        c.forget(third);
        assert!(
            until_gone(&pid).await,
            "the final declaring owner retires its actual child"
        );
    });
}

#[test]
fn program_handoff_requires_the_same_need_member_and_program_and_is_not_global() {
    worker().block_on(async {
        let c = connector();
        let spec = need(EGRESS_OPERATOR_INFRASTRUCTURE);
        let program = sh(ECHO_PID, &[]);
        declare(&c, &[("m", program.clone())]).unwrap();
        let old = handoff_open(&c, OWNER, "m").await;
        let original_pid = handoff_pid(&c, OWNER, old, "original").await;
        let mut changed_need = spec.clone();
        changed_need.timeout_ms = 1234;
        let changes = [
            (InstanceId(2), changed_need, "m", program.clone()),
            (InstanceId(3), spec.clone(), "renamed", program.clone()),
            (
                InstanceId(4),
                spec.clone(),
                "m",
                sh(ECHO_PID, &[("CHANGED", "1")]),
            ),
        ];
        let mut separate = Vec::new();
        for (owner, changed, name, program) in changes {
            handoff_declare(&c, OWNER, owner, &changed, name, program);
            let id = handoff_open(&c, owner, name).await;
            let pid = handoff_pid(&c, owner, id, "separate").await;
            assert_ne!(
                pid, original_pid,
                "a changed declaration starts its own actual child"
            );
            separate.push((owner, pid));
        }
        let unrelated = InstanceId(5);
        c.declare_member_programs(unrelated, NEED, &spec, &[("m".to_owned(), program)])
            .unwrap();
        let id = handoff_open(&c, unrelated, "m").await;
        let unrelated_pid = handoff_pid(&c, unrelated, id, "unrelated").await;
        assert_ne!(
            unrelated_pid, original_pid,
            "normal declarations never search other owners"
        );
        separate.push((unrelated, unrelated_pid));
        // Removing the original member retires only its declaration, even while its lease exists.
        c.declare_member_programs(OWNER, NEED, &spec, &[]).unwrap();
        assert!(
            !gone(&original_pid),
            "a retained lease keeps its removed child alive"
        );
        assert_eq!(
            handoff_pid(&c, OWNER, old, "retained-after-removal").await,
            original_pid
        );
        assert!(
            c.open(
                OWNER,
                NEED,
                &OpenDesc {
                    target: "m",
                    ..OpenDesc::default()
                }
            )
            .is_err(),
            "removal admits no new member lease"
        );
        c.close(OWNER, old).unwrap();
        assert!(
            until_gone(&original_pid).await,
            "the removed child's final lease closes before retirement"
        );
        for (owner, pid) in separate {
            assert!(
                !gone(&pid),
                "removing another declaration leaves this child live"
            );
            c.forget(owner);
            assert!(until_gone(&pid).await, "forget retires each distinct child");
        }
        c.forget(OWNER);
    });
}
