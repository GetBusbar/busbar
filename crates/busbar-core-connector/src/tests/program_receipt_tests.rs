// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::framer::{Call, DoorFacts};
use crate::support::{worker, TestDoor, OWNER};
use busbar_contract::io_host::{IoHost as _, Spawn};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug)]
enum Answer {
    NoSpawn,
    WrongOwner,
    WrongTicket,
    Closed,
    Spawned,
    FailedAfterSpawn,
}

struct ProgramDoor {
    inner: TestDoor,
    io: Arc<HostIo>,
    answer: Answer,
    owner: Option<u64>,
    attempts: AtomicUsize,
    shuts: AtomicUsize,
}

impl FramerDoor for ProgramDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }
    fn io_owner(&self) -> Option<u64> {
        self.owner
    }

    fn carry(&self, side: &dyn Side, _resume: bool, call: Carry<'_>) -> Crossed {
        match call {
            Carry::Dial(_, out) => {
                self.attempts.fetch_add(1, Ordering::Relaxed);
                let ticket = if matches!(self.answer, Answer::WrongTicket) {
                    let mut ticket = side.ticket();
                    ticket.generation += 1;
                    ticket
                } else {
                    side.ticket()
                };
                let owner = if matches!(self.answer, Answer::WrongOwner) {
                    OWNER + 1
                } else {
                    OWNER
                };
                if !matches!(self.answer, Answer::NoSpawn) {
                    if let Ok(handle) = self.io.spawn(
                        owner,
                        ticket,
                        &Spawn {
                            program: "/bin/cat",
                            args: &[],
                            env: &[],
                        },
                    ) {
                        out.conn = handle;
                        if matches!(self.answer, Answer::Closed) {
                            self.io.close(owner, handle).unwrap();
                        }
                    }
                }
                Crossed {
                    outcome: if matches!(self.answer, Answer::FailedAfterSpawn) {
                        Outcome::Failed
                    } else {
                        Outcome::Ready
                    },
                    error: None,
                }
            }
            Carry::Shut(input, _) => {
                self.shuts.fetch_add(1, Ordering::Relaxed);
                let _ = self.io.close(OWNER, input.conn);
                Crossed {
                    outcome: Outcome::Ready,
                    error: None,
                }
            }
            _ => Crossed {
                outcome: Outcome::Ready,
                error: None,
            },
        }
    }
}

#[test]
fn a_program_ready_requires_its_actual_live_same_ticket_supplier_spawn() {
    worker().block_on(async {
        for answer in [
            Answer::NoSpawn,
            Answer::WrongOwner,
            Answer::WrongTicket,
            Answer::Closed,
            Answer::Spawned,
            Answer::FailedAfterSpawn,
        ] {
            let io = Arc::new(HostIo::new());
            let door = Arc::new(ProgramDoor {
                inner: TestDoor::identity("program-proof"),
                io: Arc::clone(&io),
                answer,
                owner: Some(OWNER),
                attempts: AtomicUsize::new(0),
                shuts: AtomicUsize::new(0),
            });
            let program = busbar_contract::conn::Program::from_settings(
                &serde_json::json!({"command": "/bin/cat", "cwd": "/"}),
            )
            .unwrap();
            let result = Carried::dial(
                Arc::clone(&door) as Arc<dyn FramerDoor>,
                Arc::clone(&io),
                &Dest::Program(program, crate::spawn_env::HeldEnv::written_only(), 1),
            );
            assert_eq!(door.attempts.load(Ordering::Relaxed), 1);
            if matches!(answer, Answer::Spawned) {
                let carried = result.expect("an actual successful host spawn is admitted");
                assert_eq!(io.held(), 1);
                drop(carried);
            } else {
                assert!(result.is_err(), "{answer:?} forged a program connection");
            }
            assert_eq!(io.held(), 0, "{answer:?} left a host handle behind");
            if !matches!(answer, Answer::FailedAfterSpawn) {
                assert_eq!(door.shuts.load(Ordering::Relaxed), 1);
            }
        }
    });
}

#[test]
fn a_program_carrier_without_a_checked_supplier_owner_never_crosses() {
    worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let door = Arc::new(ProgramDoor {
            inner: TestDoor::identity("program-proof"),
            io: Arc::clone(&io),
            answer: Answer::Spawned,
            owner: None,
            attempts: AtomicUsize::new(0),
            shuts: AtomicUsize::new(0),
        });
        let program = busbar_contract::conn::Program::from_settings(
            &serde_json::json!({"command": "/bin/cat"}),
        )
        .unwrap();
        assert!(Carried::dial(
            Arc::clone(&door) as Arc<dyn FramerDoor>,
            Arc::clone(&io),
            &Dest::Program(program, crate::spawn_env::HeldEnv::written_only(), 1)
        )
        .is_err());
        assert_eq!(door.attempts.load(Ordering::Relaxed), 0);
        assert_eq!(io.held(), 0);
    });
}
