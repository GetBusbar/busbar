// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUTO-TRAITS (ABI-MIN3-INTERFACE §14 round 26; the IF names it `tests/auto_traits.rs`): compile-time asserts
//! that the host-side handles keep their auto traits, so a missing `unsafe impl` fails here and not in A4's, L1's
//! or L2's code. W1-T1's arms hold over today's types. `ChainGuard` is crate-private until W1-H1 lands it, and
//! `Admitted` holds a `&'static Plugin` (raw pointers) until W1-L1's impls (UNSAFE-MIN), so those two arms wait.
//! The macro side (A4) keeps these green when the real fields land.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::{auth, export, hook, plane, secret, store, transport};
use busbar_plugin_loader::instance::{InstanceSpec, Registry, SlotLease};
use busbar_plugin_loader::ports::plane::PlaneSession;
use busbar_plugin_test::FakeNeeds;

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
    fn opens(registry: &Registry<FakeNeeds>, spec: &InstanceSpec<'_>) {
        sent(&registry.open_store(spec));
        sent(&registry.open_secret(spec));
        sent(&registry.open_auth(spec));
        sent(&registry.open_hook(spec));
        sent(&registry.open_export(spec));
        sent(&registry.open_plane(spec));
        sent(&registry.open_transport(spec));
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

#[test]
#[ignore = "owner: W1-H1"]
fn chain_guard_is_send_for_a_needs_fake() {
    todo!("owner: W1-H1 (C-AUTO-TRAITS)")
}

#[test]
#[ignore = "owner: W1-L1"]
fn admitted_is_send_and_sync() {
    todo!("owner: W1-L1 (C-AUTO-TRAITS)")
}
