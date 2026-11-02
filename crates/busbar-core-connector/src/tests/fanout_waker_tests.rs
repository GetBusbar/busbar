// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Public reader wakers can run user code when their last Arc is dropped. Replacing or removing

use super::*;
use std::sync::{atomic::AtomicBool, Mutex, Weak};
use std::task::{Context, Wake, Waker};

#[path = "fanout_wake_tests.rs"]
#[allow(unsafe_code)]
mod wake_callbacks;

const FRAMER_CLAIM: &str = "fan-waker-frames";
const CARRIER_CLAIM: &str = "fan-waker-carrier";
const NEED: NeedId = NeedId(0);
/// RFC 9113 section 3.1's h2 identifier, length-prefixed as RFC 7301's ProtocolNameList.
const H2_OFFER: &[u8] = b"\x02h2";
/// The existing TestDoor carrier observation vocabulary records Carry::Dial as this label.
const DIAL_CROSSING: &str = "dial";
/// Only a bounded test wait: the old destructor returns after it so the blocked call can join.
const CALLBACK_WAIT: Duration = Duration::from_secs(5);
/// Enable live-line sharing for this one-connection fixture; no idle reuse is under test.
const SHARED_LINE_POOL: crate::pool::PoolPosture = crate::pool::PoolPosture {
    max_idle_per_host: 1,
    idle_timeout: CALLBACK_WAIT,
};

#[derive(Default)]
struct Observed {
    timely: AtomicBool,
    calls: Mutex<Vec<std::thread::JoinHandle<Result<usize, ConnError>>>>,
}

struct ReenterOnDrop {
    connector: Weak<Connector>,
    conn: ConnId,
    runtime: tokio::runtime::Handle,
    observed: Arc<Observed>,
}

#[allow(clippy::manual_noop_waker)]
impl Wake for ReenterOnDrop {
    fn wake(self: Arc<Self>) {}
}

impl Drop for ReenterOnDrop {
    fn drop(&mut self) {
        let connector = self.connector.upgrade().expect("connector still live");
        let conn = self.conn;
        let runtime = self.runtime.clone();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (done_tx, done) = std::sync::mpsc::channel();
        let call = std::thread::spawn(move || {
            let _entered = runtime.enter();
            entered_tx.send(()).unwrap();
            let result = connector.wait(OWNER, &[conn], NO_TICKET);
            let _ = done_tx.send(());
            result
        });
        entered.recv().unwrap();

        self.observed
            .timely
            .store(done.recv_timeout(CALLBACK_WAIT).is_ok(), Ordering::SeqCst);
        self.observed.calls.lock().unwrap().push(call);
    }
}

fn fan_waker_retirement(removal: bool) {
    worker().block_on(async {
        let (listener, far) = far_end().await;
        let carrier = Arc::new(TestDoor::identity(CARRIER_CLAIM));
        let c = Arc::new(
            Connector::serving(
                Transports::new(vec![
                    Entry {
                        door: Arc::new(TestDoor::new(
                            FRAMER_CLAIM,
                            &[FRAMER_CLAIM],
                            &[],
                            crate::support::Knobs {
                                offer: Some(H2_OFFER),
                                ..Default::default()
                            },
                        )),
                        alpn: Vec::new(),
                    },
                    Entry {
                        door: carrier.clone(),
                        alpn: Vec::new(),
                    },
                ])
                .unwrap(),
                loopback_literals(),
                None,
                Arc::new(|_, _| {}),
            )
            .pooling(SHARED_LINE_POOL),
        );
        c.declare_over(OWNER, NEED, FRAMER_CLAIM).unwrap();
        let desc = OpenDesc {
            target: &far,
            ..Default::default()
        };
        let first = c.open(OWNER, NEED, &desc).unwrap();
        let (socket, _) = listener.accept().await.unwrap();

        let second = removal.then(|| c.open(OWNER, NEED, &desc).unwrap());
        assert_eq!(
            carrier
                .carried
                .lock()
                .unwrap()
                .iter()
                .filter(|op| **op == DIAL_CROSSING)
                .count(),
            1
        );
        let target = second.unwrap_or(first);
        let observed = Arc::new(Observed::default());
        let retired = Arc::new(ReenterOnDrop {
            connector: Arc::downgrade(&c),
            conn: target,
            runtime: tokio::runtime::Handle::current(),
            observed: observed.clone(),
        });
        let weak = Arc::downgrade(&retired);
        let waker = Waker::from(retired);
        let mut buf = [0; 1];
        let first_poll = c.poll_read(OWNER, first, &mut Context::from_waker(&waker), &mut buf);
        let same_poll = c.poll_read(OWNER, first, &mut Context::from_waker(&waker), &mut buf);
        assert!(
            observed.calls.lock().unwrap().is_empty(),
            "same-waker registration retains it"
        );
        drop(waker);
        assert_eq!(
            weak.strong_count(),
            1,
            "the registered fan owns the last reader waker"
        );

        let replacement = if removal {
            c.close(OWNER, first).unwrap();
            None
        } else {
            Some(c.poll_read(
                OWNER,
                first,
                &mut Context::from_waker(Waker::noop()),
                &mut buf,
            ))
        };
        let timely = observed.timely.load(Ordering::SeqCst);
        let retired_before_cleanup = weak.strong_count() == 0;
        let calls = std::mem::take(&mut *observed.calls.lock().unwrap());
        let answers: Vec<_> = calls.into_iter().map(|call| call.join().unwrap()).collect();
        c.close(OWNER, target).unwrap();
        drop(socket);

        assert!(first_poll.is_pending() && same_poll.is_pending());
        assert!(replacement.is_none_or(|poll| poll.is_pending()));
        assert!(
            retired_before_cleanup,
            "replacement/removal exercised the destructor"
        );
        assert!(timely, "reader waker destructor reentered a locked fan");
        assert_eq!(
            answers,
            vec![Err(ConnError::Pending)],
            "the same live line was reached"
        );
    });
}

#[test]
fn replacing_a_public_reader_waker_drops_it_outside_the_fan_lock() {
    fan_waker_retirement(false);
}

#[test]
fn closing_an_exchange_drops_its_reader_waker_outside_the_shared_fan_lock() {
    fan_waker_retirement(true);
}
