// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUTO-TRAITS (ABI-MIN3-INTERFACE §14 round 26; the IF names it `tests/auto_traits.rs`): compile-time asserts
//! that the host-side handles keep their auto traits, so a missing `unsafe impl` fails here and not in A4's, L1's
//! or L2's code. W1-T1's arms hold over today's types. `ChainGuard` is crate-private (W1-H1 asserts it through the driver future), and
//! `Admitted` holds a `&'static Plugin` (raw pointers) until W1-L1's impls (UNSAFE-MIN), so those two arms wait.
//! The macro side (A4) keeps these green when the real fields land.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::{auth, export, hook, plane, secret, store, transport};
use busbar_plugin_loader::instance::{InstanceSpec, Registry, SlotLease};
use busbar_plugin_test::FakeNeeds;
use busbar_ports::plane::PlaneSession;

fn send_sync<T: Send + Sync>() {}

fn send<T: Send>() {}

fn sent<T: Send>(value: &T) {
    let _ = value;
}

#[test]
fn every_kind_proxy_is_send_and_sync() {
    send_sync::<store::Proxy>();
    send_sync::<secret::Proxy>();
    send_sync::<auth::Proxy>();
    send_sync::<hook::Proxy>();
    send_sync::<export::Proxy>();
    send_sync::<plane::Proxy>();
    send_sync::<transport::Proxy>();
}

#[test]
fn session_handles_are_send() {
    send::<plane::SessionHandle>();
    send::<transport::SessionHandle>();
}

#[test]
fn the_slot_lease_is_send_and_sync() {
    send_sync::<SlotLease>();
}

#[test]
fn the_registrys_open_and_check_futures_are_send() {
    fn opens(
        registry: &Registry,
        needs: &std::sync::Arc<FakeNeeds>,
        refs: &std::sync::Arc<dyn busbar_ports::binder::RefSource>,
        seal: busbar_plugin_loader::instance::StoreSeal,
        spec: &InstanceSpec<'_>,
    ) {
        sent(&registry.open_store(spec, needs, refs, seal));
        sent(&registry.open_secret(spec, needs, refs));
        sent(&registry.open_auth(spec, needs, refs));
        sent(&registry.open_hook(spec, needs, refs));
        sent(&registry.open_export(spec, needs, refs));
        sent(&registry.open_plane(spec, needs, refs));
        sent(&registry.open_transport(spec, needs, refs));
        sent(&registry.check(spec));
    }
    let _ = opens;
}

#[test]
fn a_spawned_task_can_own_a_plane_session() {
    fn spawn(session: PlaneSession) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { drop(session) })
    }
    let _ = spawn;
}

/// `ChainGuard` is crate-private; it lives inside the driver's step-loop future for the whole chain, so that
/// future being `Send` over a `FakeNeeds` is the guard being `Send` (with its parked busbar-ffi chain, its
/// borrowed Needs and Caller and its pooled buffers). Built, never polled.
#[test]
fn chain_guard_is_send_for_a_needs_fake() {
    use std::time::{Duration, Instant};

    use busbar_plugin_abi::host::{CallStack, Caller, Driver, First, InstanceLimits, Pool};
    use busbar_plugin_abi::types::KindCode;

    use crate::bridge_fixture as fx;

    fn first<'i>(started: fx::Started<'i, fx::Secret>) -> First<'i, fx::Secret> {
        started.into()
    }
    let instance = fx::instance();
    let needs = FakeNeeds::new();
    let caller = Caller {
        plugin: "bridge-fixture",
        kind: KindCode::Secret,
        name: "fixture",
        instance: 1,
        slot: 1,
        chain: 0,
        deadline: Instant::now() + Duration::from_secs(60),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    };
    let mut drv = Driver::new(&needs, caller);
    let req = Pool::global().acquire(1 << 20);
    let fut = drv.run(0, 1 << 20, req, |_, lease| {
        first(fx::start(&instance, b"secret", lease))
    });
    sent(&fut);
}

/// W1-L1: `Admitted` holds busbar-ffi's checked header address (UNSAFE-MIN r3.1), its verified stamp and the
/// `Arc<Image>` that keeps it mapped, so it is `Send + Sync` with no `unsafe impl`; the registry holds one across
/// the awaits of its describe and open futures.
#[test]
fn admitted_is_send_and_sync() {
    send_sync::<busbar_plugin_loader::admit::Admitted>();
}
