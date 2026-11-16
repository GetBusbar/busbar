// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DEPLOYMENT-ID (ABI-MIN3-INTERFACE §14 rounds 28, 29). Arm (e), never torn, is W1-H0's (merged). (a) and (d)
//! need the kernel's boot identity (K9 owns boot.rs in wave 1); (c) is a C-PANIC-HOST injection arm (W1-H1); (f),
//! the 2a/2b re-check, is the registry's (W1-L2). (b), the C fixture's `bb_host.deployment`, runs in
//! busbar-secret-c's CI.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::{Arc, Barrier};

use busbar_plugin_abi::host_side::host_vt::{set_deployment, vt};

const ID: [u8; 16] = *b"deployment-id-16";

#[test]
fn every_read_is_all_zero_or_exactly_the_id() {
    let start = Arc::new(Barrier::new(9));
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..125_000 {
                    let read = vt::deployment().0;
                    assert!(read == [0; 16] || read == ID, "torn: {read:?}");
                }
            })
        })
        .collect();
    start.wait();
    set_deployment(ID);
    for reader in readers {
        reader.join().expect("reader");
    }
    assert_eq!(vt::deployment().0, ID);
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn step_2b_reads_none_and_2c_reads_the_stored_id() {
    todo!("owner: W1-K9 (C-DEPLOYMENT-ID)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn the_conformance_injection_answers_all_zero_without_unwinding() {
    todo!("owner: W1-H1 (C-DEPLOYMENT-ID)")
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn the_id_never_equals_a_run_of_the_keyset_seed() {
    todo!("owner: W1-K9 (C-DEPLOYMENT-ID)")
}

/// (f), over the kernel's boot walk (`busbar_kernel::appbuild::boot_walk::walk` with its `RegistryBoot`, the
/// steps the root's boot runs) and a real registry: a 2a secret probe, the 2b inline store and a 2c secret probe,
/// each recording what `Host::deployment_id` answered in `open` and in `check`. The 2a and 2b opens see None;
/// after the walk publishes the id (`set_deployment`), the re-check of 2a then 2b sees Some(id), and only then
/// does the 2c instance open (seeing Some(id)). Then a 2b store whose install binding names another deployment
/// refuses its re-check: the boot is refused naming the store, with the store's text scrubbed by core (the URL
/// userinfo masked), and no 2c instance opens. The id here is the walk's `deployment` read answered with a fixed
/// id: the `busbar.deployment.v1`/`id` row through a store is (a)'s (W1-K9). `set_deployment` is process-wide
/// and keep-once, so the refusal runs second (its 2a/2b opens already see the id) and the arm relies on each test
/// running in its own process (nextest).
#[test]
fn the_2a_and_2b_recheck_sees_the_id_before_any_2c_open() {
    use std::sync::Mutex;

    use busbar_kernel::appbuild::boot_walk::{
        walk, BootRefused, BootSteps, DeploymentRead, RegistryBoot,
    };
    use busbar_plugin_abi::fail::refused::R_CONFIG;
    use busbar_plugin_abi::host_side::caller::BoxFut;
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_loader::instance::{BootPhase, BootPlan, OpenError, OpenedPort};
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_plugin_test::suites::harness::Harness;
    use busbar_ports::store::StoreHandle;

    use crate::{min3_second as probe, min3_store as store};

    /// The registry's boot steps, with every call the walk makes recorded in order.
    struct Watched<'r> {
        inner: RegistryBoot<'r, FakeNeeds>,
        calls: Mutex<Vec<String>>,
    }

    impl Watched<'_> {
        fn call(&self, what: String) {
            self.calls.lock().expect("calls").push(what);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls").clone()
        }
    }

    impl BootSteps for Watched<'_> {
        type Opened = OpenedPort;

        fn open(&self, index: u32) -> BoxFut<'_, Result<OpenedPort, OpenError>> {
            self.call(format!("open {index}"));
            self.inner.open(index)
        }

        fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>> {
            self.call(format!("check {index}"));
            self.inner.check(index)
        }

        fn deployment<'a>(&'a self, store: &'a OpenedPort) -> BoxFut<'a, Result<[u8; 16], String>> {
            self.call("deployment".to_owned());
            self.inner.deployment(store)
        }

        fn publish(&self, id: [u8; 16]) {
            self.call("publish".to_owned());
            self.inner.publish(id);
        }
    }

    /// What the probe of `tag` recorded as `what` (`open.deployment` or `check.deployment`), in order.
    fn probe_saw(tag: &str, what: &str) -> Vec<Vec<u8>> {
        probe::inputs(tag)
            .into_iter()
            .filter(|(w, _)| *w == what)
            .map(|(_, bytes)| bytes)
            .collect()
    }

    let read: &DeploymentRead =
        &|_store: &StoreHandle| -> BoxFut<'static, Result<[u8; 16], String>> {
            Box::pin(core::future::ready(Ok(ID)))
        };
    let plan = BootPlan {
        steps: vec![
            (0, BootPhase::StoreSecrets),
            (1, BootPhase::Store),
            (2, BootPhase::Rest),
        ],
    };
    let mut h = Harness::admit(probe::probe::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("{r:?}"));
    h.add(store::inline::PLUGIN.plugin())
        .unwrap_or_else(|r| panic!("{r:?}"));
    h.registry().set_store_seal(Box::new(|| {
        Box::new(busbar_contract::plugin::TestKernelSeal)
    }));
    let inline = "fixture-store-inline";
    assert_eq!(vt::deployment().0, [0; 16], "no id before the walk");

    let instances = [
        (
            KindCode::Secret,
            h.spec_for(
                probe::PROBE,
                "vault-2a",
                br#"{"tag":"dep-2a","deployment":true}"#,
            ),
        ),
        (
            KindCode::Store,
            h.spec_for(inline, "store-2b", br#"{"id":"dep-2b","deployment":true}"#),
        ),
        (
            KindCode::Secret,
            h.spec_for(
                probe::PROBE,
                "late-2c",
                br#"{"tag":"dep-2c","deployment":true}"#,
            ),
        ),
    ];
    let steps = Watched {
        inner: RegistryBoot {
            registry: h.registry(),
            instances: &instances,
            deployment: read,
        },
        calls: Mutex::new(Vec::new()),
    };
    let booted = h
        .block_on(walk(&plan, &steps))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(booted.deployment, ID);
    assert_eq!(
        steps.calls(),
        [
            "open 0",
            "open 1",
            "deployment",
            "publish",
            "check 0",
            "check 1",
            "open 2"
        ],
        "the id is published and 2a then 2b re-checked before the 2c open"
    );
    let (none, some) = (Vec::new(), ID.to_vec());
    assert_eq!(probe_saw("dep-2a", "open.deployment"), [none.clone()]);
    assert_eq!(probe_saw("dep-2a", "check.deployment"), [some.clone()]);
    let store_saw = store::counts("dep-2b");
    assert_eq!(store_saw.opens_saw, [none]);
    assert_eq!(store_saw.checks_saw, [some.clone()]);
    assert_eq!(probe_saw("dep-2c", "open.deployment"), [some]);
    assert!(
        probe_saw("dep-2c", "check.deployment").is_empty(),
        "a 2c instance is not re-checked"
    );
    drop(booted);

    let instances = [
        (
            KindCode::Secret,
            h.spec_for(probe::PROBE, "bind-vault-2a", br#"{"tag":"bind-2a"}"#),
        ),
        (
            KindCode::Store,
            h.spec_for(
                inline,
                "bind-store-2b",
                br#"{"id":"bind-2b","install":"another-deploy16"}"#,
            ),
        ),
        (
            KindCode::Secret,
            h.spec_for(probe::PROBE, "bind-late-2c", br#"{"tag":"bind-2c"}"#),
        ),
    ];
    let steps = Watched {
        inner: RegistryBoot {
            registry: h.registry(),
            instances: &instances,
            deployment: read,
        },
        calls: Mutex::new(Vec::new()),
    };
    match h.block_on(walk(&plan, &steps)) {
        Err(BootRefused::Recheck { index: 1, error }) => match *error {
            OpenError::Config { code, text, .. } => {
                assert_eq!(code, R_CONFIG);
                assert!(
                    text.starts_with("the install binding https://***@licence.example"),
                    "the store's text, scrubbed: {text}"
                );
                assert!(!text.contains(store::INSTALL_PASSWORD), "{text}");
            }
            other => panic!("the re-check refused its config: {other:?}"),
        },
        Err(other) => panic!("the 2b re-check refuses the boot: {other}"),
        Ok(_) => panic!("a wrong install binding booted"),
    }
    assert_eq!(
        steps.calls(),
        [
            "open 0",
            "open 1",
            "deployment",
            "publish",
            "check 0",
            "check 1"
        ],
        "no 2c open after the refused re-check"
    );
    assert!(
        probe::inputs("bind-2c").is_empty(),
        "the 2c instance never opened"
    );
}
