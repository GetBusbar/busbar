// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A dial that does not end READY leaves nothing of the host's behind. The carrier's `dial` opens

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::io_host::IoHost as _;
use tokio::io::AsyncReadExt as _;

use super::{Carried, Dest, DialFailure};
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::hostio::HostIo;
use crate::support::{self, TestDoor, OWNER};

/// How the scripted carrier answers its `dial`.
#[derive(Clone, Copy)]
enum Answer {
    Ready,
    Refused,
    Failed,
    Fault,
    Pending,
}

/// The test carrier entry, its `dial` scripted. It makes the host handle through the `HostIo`
struct Dialer {
    inner: TestDoor,
    io: Arc<HostIo>,
    /// The address the dial opens (the one the connector admitted).
    addr: String,
    answer: Answer,
    /// Open the host socket during `dial`, before answering.
    open: bool,
    /// Close that handle itself before answering, as a carrier that cleans up after itself does.
    close_own: bool,
    /// Open the host socket only when the dial is CANCELLED (the cancel makes the handle).
    open_on_cancel: bool,
    /// Every handle the carrier made, in order.
    made: Mutex<Vec<u64>>,
    cancels: AtomicUsize,
    shuts: AtomicUsize,
    /// Whether the open made inside `cancel` was admitted by the host.
    cancel_open_ok: AtomicBool,
}

impl Dialer {
    fn new(io: &Arc<HostIo>, addr: &str, answer: Answer) -> Self {
        Self {
            inner: TestDoor::identity("retire-dial"),
            io: Arc::clone(io),
            addr: addr.to_owned(),
            answer,
            open: true,
            close_own: false,
            open_on_cancel: false,
            made: Mutex::new(Vec::new()),
            cancels: AtomicUsize::new(0),
            shuts: AtomicUsize::new(0),
            cancel_open_ok: AtomicBool::new(false),
        }
    }

    fn made(&self) -> Vec<u64> {
        self.made.lock().unwrap().clone()
    }
}

impl FramerDoor for Dialer {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }

    fn carry(&self, side: &dyn Side, _resume: bool, call: Carry<'_>) -> Crossed {
        let ready = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        match call {
            Carry::Dial(_, out) => {
                if self.open {
                    if let Ok(handle) = self.io.open(OWNER, side.ticket(), &self.addr) {
                        self.made.lock().unwrap().push(handle);
                        out.conn = handle;
                        if self.close_own {
                            let _ = self.io.close(OWNER, handle);
                        }
                    }
                }
                match self.answer {
                    Answer::Ready => ready,
                    Answer::Pending => Crossed {
                        outcome: Outcome::Pending,
                        error: None,
                    },
                    Answer::Refused => Crossed {
                        outcome: Outcome::Refused,
                        error: Some(b"the carrier refused after opening".to_vec()),
                    },
                    Answer::Failed => Crossed {
                        outcome: Outcome::Failed,
                        error: Some(b"the carrier failed after opening".to_vec()),
                    },
                    Answer::Fault => Crossed {
                        outcome: Outcome::Fault,
                        error: None,
                    },
                }
            }
            Carry::Cancel(..) => {
                self.cancels.fetch_add(1, Ordering::SeqCst);
                if self.open_on_cancel {
                    let opened = self.io.open(OWNER, side.ticket(), &self.addr);
                    self.cancel_open_ok.store(opened.is_ok(), Ordering::SeqCst);
                    if let Ok(handle) = opened {
                        self.made.lock().unwrap().push(handle);
                    }
                }
                ready
            }
            Carry::Shut(shut, _) => {
                self.shuts.fetch_add(1, Ordering::SeqCst);
                let _ = self.io.close(OWNER, shut.conn);
                ready
            }
            _ => ready,
        }
    }
}

/// A far end on loopback, and the `ip:port` the connector admits for it.
async fn far() -> (tokio::net::TcpListener, String) {
    let far = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = far.local_addr().unwrap().to_string();
    (far, at)
}

/// The host really closed the socket its dial made: the far end that accepted it reads the end of
async fn far_sees_the_close(far: &tokio::net::TcpListener) {
    let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), far.accept())
        .await
        .expect("the dial reached the far end")
        .unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut rest))
        .await
        .expect("the host closed the socket the failed dial made")
        .unwrap();
    assert!(rest.is_empty());
}

fn dial(door: &Arc<Dialer>, io: &Arc<HostIo>, at: &str) -> Result<Carried, DialFailure> {
    Carried::dial(
        Arc::clone(door) as Arc<dyn FramerDoor>,
        Arc::clone(io),
        &Dest::Authority(at.to_owned()),
    )
}

#[test]
fn a_failed_dial_retires_the_socket_it_made_and_keeps_the_carriers_words() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let door = Arc::new(Dialer::new(&io, &at, Answer::Failed));
        let error = dial(&door, &io, &at).unwrap_err();
        assert_eq!(
            error,
            DialFailure::Failed("the carrier failed after opening".into())
        );
        assert_eq!(door.made().len(), 1, "the dial really made a host handle");
        assert_eq!(
            io.held(),
            0,
            "and it was retired, not held for the instance"
        );
        assert_eq!(door.cancels.load(Ordering::SeqCst), 0, "nothing pended");
        far_sees_the_close(&far).await;
    });
}

#[test]
fn a_refused_dial_retires_the_socket_it_made_and_stays_refused() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let door = Arc::new(Dialer::new(&io, &at, Answer::Refused));
        let error = dial(&door, &io, &at).unwrap_err();
        assert_eq!(
            error,
            DialFailure::Refused("the carrier refused after opening".into())
        );
        assert_eq!(door.made().len(), 1);
        assert_eq!(io.held(), 0);
        far_sees_the_close(&far).await;
    });
}

#[test]
fn a_faulted_dial_retires_the_socket_it_made() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let door = Arc::new(Dialer::new(&io, &at, Answer::Fault));

        assert_eq!(
            dial(&door, &io, &at).unwrap_err(),
            DialFailure::Failed(String::new())
        );
        assert_eq!(door.made().len(), 1);
        assert_eq!(io.held(), 0);
        far_sees_the_close(&far).await;
    });
}

#[test]
fn a_carrier_that_closed_its_own_handle_before_failing_leaves_nothing_to_retire_twice() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (_far, at) = far().await;
        let mut dialer = Dialer::new(&io, &at, Answer::Failed);
        dialer.close_own = true;
        let door = Arc::new(dialer);
        assert!(matches!(
            dial(&door, &io, &at).unwrap_err(),
            DialFailure::Failed(_)
        ));
        assert_eq!(door.made().len(), 1);
        assert_eq!(
            io.held(),
            0,
            "the stale handle names nothing and closes nothing"
        );
    });
}

#[test]
fn the_hosts_own_open_failure_still_outranks_the_carriers_answer() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());

        let at = "not-an-ip-literal";
        let door = Arc::new(Dialer::new(&io, at, Answer::Failed));
        match dial(&door, &io, at).unwrap_err() {
            DialFailure::Refused(why) => {
                assert!(why.contains("without resolving a name"), "{why}");
            }
            other => panic!("the host's recorded failure is the dial's words: {other:?}"),
        }
        assert!(door.made().is_empty(), "the host made no handle");
        assert_eq!(io.held(), 0);
    });
}

#[test]
fn a_pending_dial_is_cancelled_once_and_its_socket_retired() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let door = Arc::new(Dialer::new(&io, &at, Answer::Pending));
        assert_eq!(
            dial(&door, &io, &at).unwrap_err(),
            DialFailure::Failed("a dial may not pend".into())
        );
        assert_eq!(
            door.cancels.load(Ordering::SeqCst),
            1,
            "cancelled exactly once"
        );
        assert_eq!(door.made().len(), 1);
        assert_eq!(io.held(), 0, "the pended dial's socket is retired");
        far_sees_the_close(&far).await;
    });
}

#[test]
fn a_handle_the_cancel_itself_makes_is_still_collected_and_retired() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let mut dialer = Dialer::new(&io, &at, Answer::Pending);

        dialer.open = false;
        dialer.open_on_cancel = true;
        let door = Arc::new(dialer);
        assert_eq!(
            dial(&door, &io, &at).unwrap_err(),
            DialFailure::Failed("a dial may not pend".into())
        );
        assert_eq!(door.cancels.load(Ordering::SeqCst), 1);

        assert!(door.cancel_open_ok.load(Ordering::SeqCst));
        assert_eq!(door.made().len(), 1);
        assert_eq!(
            io.held(),
            0,
            "the handle made during the cancel is retired too"
        );
        far_sees_the_close(&far).await;
    });
}

#[test]
fn a_ready_dial_keeps_its_handle_until_the_connections_own_close() {
    support::worker().block_on(async {
        let io = Arc::new(HostIo::new());
        let (far, at) = far().await;
        let door = Arc::new(Dialer::new(&io, &at, Answer::Ready));
        let mut carried = dial(&door, &io, &at).expect("a ready dial is a connection");
        let made = door.made();
        assert_eq!(made.len(), 1);
        assert_eq!(
            carried.handle(),
            Some(made[0]),
            "ownership moved to the connection"
        );
        assert_eq!(io.held(), 1, "held for as long as the connection lives");
        assert_eq!(door.cancels.load(Ordering::SeqCst), 0);
        let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), far.accept())
            .await
            .expect("the dial reached the far end")
            .unwrap();
        carried.close();
        assert_eq!(door.shuts.load(Ordering::SeqCst), 1);
        assert_eq!(io.held(), 0, "the connection's close releases it");
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut rest))
            .await
            .expect("the close ends the stream")
            .unwrap();
        assert!(rest.is_empty());
        drop(carried);
        assert_eq!(
            door.shuts.load(Ordering::SeqCst),
            1,
            "closed once, however it ends"
        );
    });
}
