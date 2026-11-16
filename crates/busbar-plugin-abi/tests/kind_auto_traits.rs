// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUTO-TRAITS, the kind module side (IF §10.4 round 26): the auto-trait claims about the host handles are
//! stated, not inferred. A `Proxy` is `Send + Sync` (every async proxy future borrows it and every port adapter is
//! `Send + Sync`); a `SessionHandle` is `Send` and not `Sync` (so two entries on one token need two `&mut`
//! borrows); the kind-erased `Instance` that both hold is `Send + Sync`.

use std::sync::Arc;

use busbar_plugin_abi::host_side::driver::{Instance, SlotCell};
use busbar_plugin_abi::{auth, export, hook, plane, secret, store, transport};

fn send_sync<T: Send + Sync>() {}
fn send<T: Send>() {}

/// `AmbiguousIfSync<_>` has one blanket impl and a second only for `Sync` types, so naming
/// `<T as AmbiguousIfSync<_>>::some_item` compiles exactly when `T` is not `Sync`.
trait AmbiguousIfSync<A> {
    fn some_item() {}
}
impl<T: ?Sized> AmbiguousIfSync<()> for T {}
impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

macro_rules! not_sync {
    ($t:ty) => {
        let _ = <$t as AmbiguousIfSync<_>>::some_item;
    };
}

#[test]
fn every_proxy_and_the_instance_are_send_and_sync() {
    send_sync::<Instance>();
    send_sync::<Arc<Instance>>();
    send_sync::<SlotCell>();
    send_sync::<store::Proxy>();
    send_sync::<secret::Proxy>();
    send_sync::<auth::Proxy>();
    send_sync::<hook::Proxy>();
    send_sync::<export::Proxy>();
    send_sync::<plane::Proxy>();
    send_sync::<transport::Proxy>();
}

#[test]
fn a_session_handle_is_send_and_not_sync() {
    send::<plane::SessionHandle>();
    send::<transport::SessionHandle>();
    not_sync!(plane::SessionHandle);
    not_sync!(transport::SessionHandle);
}
