// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::io_host::IoHost;

struct DialAfterForget {
    inner: TestDoor,
    gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    made: AtomicU64,
}

impl FramerDoor for DialAfterForget {
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
        match call {
            crate::carrier::Carry::Dial(i, o) => {
                let gate = self.gate.lock().unwrap().take();
                if let Some((entered, release)) = gate {
                    entered.send(()).unwrap();
                    release.recv().unwrap();
                }
                let crossed = self
                    .inner
                    .carry(side, resume, crate::carrier::Carry::Dial(i, o));
                self.made.store(o.conn, Ordering::SeqCst);
                crossed
            }
            other => self.inner.carry(side, resume, other),
        }
    }
}

#[test]
fn a_dial_that_finishes_after_forget_retires_its_refused_insert() {
    let runtime = worker();
    let on = runtime.handle().clone();
    runtime.block_on(async {
        let (far, address) = far_end().await;
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, held_back) = std::sync::mpsc::channel();
        let carrier = Arc::new(DialAfterForget {
            inner: TestDoor::identity("carrier"),
            gate: Mutex::new(Some((entered_tx, held_back))),
            made: AtomicU64::new(0),
        });
        let c = Arc::new(
            Connector::serving(
                Transports::new(vec![
                    Entry {
                        door: Arc::new(TestDoor::new(
                            "messages",
                            &["messages"],
                            &[],
                            crate::support::Knobs {
                                messages: Some(crate::compose::EXCHANGE_STREAM),
                                ..crate::support::Knobs::default()
                            },
                        )),
                        alpn: Vec::new(),
                    },
                    Entry {
                        door: Arc::clone(&carrier) as Arc<dyn FramerDoor>,
                        alpn: Vec::new(),
                    },
                ])
                .unwrap(),
                loopback_literals(),
                None,
                Arc::new(|_, _| {}),
            )
            .pooling(crate::pool::PoolPosture {
                max_idle_per_host: 8,
                idle_timeout: std::time::Duration::from_secs(60),
            }),
        );
        c.declare_over(OWNER, NeedId(0), "messages").unwrap();
        let opening = Arc::clone(&c);
        let opened = std::thread::spawn(move || {
            let _entered = on.enter();
            opening.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &address,
                    ..OpenDesc::default()
                },
            )
        });
        entered.recv().unwrap();
        c.forget(OWNER);
        release.send(()).unwrap();
        let result = opened.join().unwrap();
        let made = carrier.made.load(Ordering::SeqCst);
        let io = crate::hostio::process();
        let retired = matches!(
            io.ends(crate::support::OWNER, made),
            Err(busbar_contract::io_host::IoRefusal::Refused(_))
        );

        c.pools.forget(OWNER);
        let _ = io.close(crate::support::OWNER, made);
        drop(far);
        assert_eq!(result, Err(ConnError::UndeclaredNeed));
        assert!(
            made != 0 && retired,
            "the refused insert left its pooled dial live"
        );
    });
}
