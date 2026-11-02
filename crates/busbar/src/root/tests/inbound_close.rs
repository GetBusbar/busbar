// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::marker::PhantomData;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::loader::hook_door::HookRows;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_kernel_testkit::test_support::{rows, TestApp};

const NAME: &str = "inbound-retirement-hook";
const WAIT: Duration = Duration::from_secs(5);
struct Gate {
    closes: usize,
    release: bool,
}
static GATE: (Mutex<Gate>, Condvar) = (
    Mutex::new(Gate {
        closes: 0,
        release: true,
    }),
    Condvar::new(),
);
struct Release;
impl Drop for Release {
    fn drop(&mut self) {
        GATE.0.lock().unwrap().release = true;
        GATE.1.notify_all();
    }
}

pub struct Closing;
impl Life for Closing {
    const CANCEL: u32 = busbar_contract::abi::hook::cancel::ABORTED;
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
        while !gate.release {
            gate = GATE.1.wait(gate).unwrap();
        }
    }
}
pub struct Unused<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Unused<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Closing>;
    fn call(_: Instance<'_, Self::State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}
mod fixture {
    use busbar_contract::abi::{
        hook as h,
        mechanism::call::{InHead, OutHead},
    };
    busbar_contract::plugin_door! {
        ops: h::Ops,
        statement: busbar_contract::abi::sdk::hook::statement_with_tail(
            busbar_contract::abi::sdk::door::statement(super::NAME, "1.6.0", 8),
            &busbar_contract::abi::sdk::hook::tail(h::CLASS_GATE, h::PROMPT_NO, h::USER_NO),
        ),
        lifecycle: life(super::Closing),
        kind_ops: {
            decide: busbar_contract::abi::sdk::Safe<super::Unused<h::DecideIn, h::DecideOut>>,
            transform: busbar_contract::abi::sdk::Safe<super::Unused<h::DecideIn, h::TransformOut>>,
            notify: busbar_contract::abi::sdk::Safe<super::Unused<h::NotifyIn, OutHead>>,
            configure: busbar_contract::abi::sdk::Safe<super::Unused<h::ConfigureIn, h::ConfigureOut>>,
            status: busbar_contract::abi::sdk::Safe<super::Unused<InHead, h::StatusOut>>,
            describe: busbar_contract::abi::sdk::Safe<super::Unused<InHead, h::DescribeOut>>,
            serve: busbar_contract::abi::sdk::Safe<super::Unused<h::ServeIn, h::ServeOut>>,
        },
    }
}

struct FixtureResolver;
impl busbar_contract::secret::SecretResolve for FixtureResolver {
    fn resolve(
        &self,
        _: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        Ok(busbar_contract::redacted::Secret::new(b"fixture".to_vec()))
    }
    fn resolve_string(
        &self,
        _: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        Ok(busbar_contract::redacted::Secret::new(
            "fixture".to_string(),
        ))
    }
}

fn hooked_app() -> Arc<busbar_kernel::state::App> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let axis = Arc::new(HookRows::new(&[fixture::door], None, dispatcher).unwrap());
    let registry = rows::Rows::default()
        .with_dropped_reference_slots(
            rows::row(NAME, NAME, busbar_contract::abi::mechanism::kind::HOOK),
            &["uncached"],
        )
        .into_rows();
    let env = busbar_kernel::hooks::HookEnv::with_axis(registry, axis, Arc::new(FixtureResolver));
    let cfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": NAME,
        "settings": { "uncached": { "env": "INBOUND_CLOSE_UNUSED" } }
    }))
    .unwrap();

    let app = TestApp::new()
        .hook_env(env)
        .hook("retiring-close", cfg)
        .global_hook("retiring-close")
        .resolve_global_gates()
        .build();
    assert_eq!(app.global_gates.len(), 1);
    app
}

fn listener(app: Arc<busbar_kernel::state::App>) -> kin::Listener {
    let mut open = line(NATIVE, METHOD_POST);
    open.auth = LineAuth::None;
    let guests = GuestList::seal(vec![open]).unwrap();
    let ids = guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(RefSpace::Line))
        .collect();
    kin::Listener {
        guests,
        auths: Default::default(),
        body_limit: 16,
        app,
        door_refusals: Vec::new(),
        ids,
        signed_ingress: busbar_kernel_testkit::test_support::inbound::signed_by_dialect(),
        scope: None,
    }
}

#[test]
fn retiring_or_replacing_a_generation_closes_its_real_hook_outside_the_table_lock() {
    for replace in [false, true] {
        *GATE.0.lock().unwrap() = Gate {
            closes: 0,
            release: true,
        };
        let inbound = Inbound::new(
            kin::Seals {
                mint: Arc::new(|| 1),
                mac: Arc::new(|_| Some(1)),
            },
            Arc::new(|_| {}),
            Arc::new(|_| {}),
        );
        inbound.install(OWNER, 1, listener(hooked_app())).unwrap();
        if !replace {
            inbound
                .install(OWNER, 2, listener(TestApp::new().build()))
                .unwrap();
        }
        let generation = if replace { 1 } else { 3 };
        let next = listener(TestApp::new().build());
        let expected = next.specs();
        let release = Release;
        {
            let mut gate = GATE.0.lock().unwrap();
            gate.closes = 0;
            gate.release = false;
        }
        let retiring = {
            let inbound = inbound.clone();
            std::thread::spawn(move || inbound.install(OWNER, generation, next).unwrap())
        };
        let (gate, _) = GATE
            .1
            .wait_timeout_while(GATE.0.lock().unwrap(), WAIT, |g| g.closes == 0)
            .unwrap();
        let entered = gate.closes != 0;
        drop(gate);
        assert!(entered, "retirement must reach the actual hook CLOSE");
        let (answer, result) = std::sync::mpsc::channel();
        let lookup = {
            let inbound = inbound.clone();
            std::thread::spawn(move || {
                answer.send(inbound.specs(OWNER, generation)).unwrap();
            })
        };
        let during_close = result.recv_timeout(WAIT);
        drop(release);
        retiring.join().unwrap();
        lookup.join().unwrap();
        assert_eq!(
            during_close
                .expect("hook CLOSE blocked an independent table lookup")
                .expect("the new table is installed"),
            expected
        );
        assert_eq!(
            GATE.0.lock().unwrap().closes,
            1,
            "one old plugin instance closed"
        );
    }
}
