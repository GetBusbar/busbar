// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut};
use busbar_contract::secret::SecretAxis;

use crate::dispatch::{DispatchConfig, Dispatcher};
use crate::secret_calls::SecretRows;

const NAME: &str = "shared-secret-close-race";
const WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Gate {
    asks: usize,
    release_open: bool,
    closes: usize,
    release_close: bool,
}

static GATE: (Mutex<Gate>, Condvar) = (
    Mutex::new(Gate {
        asks: 0,
        release_open: false,
        closes: 0,
        release_close: false,
    }),
    Condvar::new(),
);

struct Release;

impl Drop for Release {
    fn drop(&mut self) {
        let mut gate = GATE.0.lock().unwrap();
        gate.release_open = true;
        gate.release_close = true;
        GATE.1.notify_all();
    }
}

fn wait_for(predicate: impl Fn(&Gate) -> bool) {
    let (gate, _) = GATE
        .1
        .wait_timeout_while(GATE.0.lock().unwrap(), WAIT, |g| !predicate(g))
        .unwrap();
    let reached = predicate(&gate);
    drop(gate);
    assert!(reached, "the controlled plugin boundary was not reached");
}

fn dispatcher() -> Arc<Dispatcher> {
    let mut gate = GATE.0.lock().unwrap();
    gate.asks += 1;
    GATE.1.notify_all();
    if gate.asks == 1 {
        while !gate.release_open {
            gate = GATE.1.wait(gate).unwrap();
        }
    }
    drop(gate);
    static ONE: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    ONE.get_or_init(|| Arc::new(Dispatcher::new(DispatchConfig::default())))
        .clone()
}

pub struct Closing;

impl Life for Closing {
    const CANCEL: u32 = cancel::ABORTED;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }

    fn close(&self, _: Option<&busbar_contract::abi::sdk::conn::Host>) {
        let mut gate = GATE.0.lock().unwrap();
        gate.closes += 1;
        GATE.1.notify_all();
        while !gate.release_close {
            gate = GATE.1.wait(gate).unwrap();
        }
    }
}

pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Closing>;

    fn call(_: Instance<'_, Self::State>, _: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
        Outcome::Ready
    }
}

mod fixture {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::NAME, "1.6.0", 8),
        lifecycle: life(super::Closing),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

#[test]
fn a_losing_shared_instances_plugin_close_holds_no_cache_caller() {
    *GATE.0.lock().unwrap() = Gate::default();
    let release = Release;
    let mut rows = SecretRows::new(dispatcher, || None);
    rows.link(fixture::door)
        .expect("the controlled secret door links");
    let rows = Arc::new(rows);
    let losing = {
        let rows = rows.clone();
        std::thread::spawn(move || rows.shared(NAME))
    };
    wait_for(|g| g.asks == 1);
    let winner = rows
        .shared(NAME)
        .expect("the second open installs its instance");
    GATE.0.lock().unwrap().release_open = true;
    GATE.1.notify_all();
    wait_for(|g| g.closes == 1);

    let (sent, answered) = mpsc::channel();
    let lookup = {
        let rows = rows.clone();
        std::thread::spawn(move || {
            let _ = sent.send(rows.shared(NAME));
        })
    };
    let during_close = answered.recv_timeout(WAIT);
    let closes = GATE.0.lock().unwrap().closes;
    drop(release);
    let losing = losing
        .join()
        .expect("the losing caller returns")
        .expect("the losing open succeeds");
    lookup.join().expect("the lookup caller returns");
    let during_close = during_close
        .expect("a blocked plugin CLOSE held the shared cache")
        .expect("the installed instance is available during CLOSE");
    assert!(Arc::ptr_eq(&winner, &during_close));
    assert!(Arc::ptr_eq(&winner, &losing));
    assert_eq!(closes, 1, "exactly the losing instance closed");
}
