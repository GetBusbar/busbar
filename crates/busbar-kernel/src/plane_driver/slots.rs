// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SLOTS THE DRIVER HANDS A PLANE: the type-erased per-generation slot a plane reads its own
//! runtime object from ([`PlaneSlots`]), the `&mut` sink its hook gates are re-resolved into on a
//! config swap ([`ContainerGateSink`]), and `PlaneSlots` through a pointer.
//!
//! Kind-level: a slot is keyed by the plane's declared key and holds an opaque object; the kernel
//! never reads what is inside it.
//!
//! ## `PlaneSlots` through a pointer
//!
//! The snapshot is almost always held behind a pointer — an `Arc` off the handle, a lock-free load
//! guard, a plain borrow — and a plane's slot readers take `&impl PlaneSlots`. The blanket impl
//! below makes a `Deref` to a slot holder itself a slot holder, forwarding both reads to the target.
//! It adds no behaviour; the borrow it hands back is the target's own.

use std::ops::Deref;
use std::sync::Arc;

/// THE NEUTRAL TYPE-ERASED SLOT-READ SEAM the core-owned `PlaneDecl` callbacks that today force a
/// `&busbar_kernel::state::App` are neutralised over — so a plane's `on_swap` / `registry_contains` /
/// `retain_verify_gates` hook reads its own per-generation runtime object off the snapshot WITHOUT
/// the callback fn-pointer signature naming a core type. Core `impl`s it for `App` as a thin delegate
/// to the inherent `App::plane_slot`; an EXTRACTED plane reaches only [`Self::plane_slot`] and
/// stays neutral. [`Self::as_any`] is the recovery hatch the kernel's own readers use to downcast
/// back to its concrete snapshot for a field that does not live in `plane_slots`; a plane never calls
/// it.
pub trait PlaneSlots {
    /// The plane's type-erased runtime object for THIS generation, keyed by the plane's decl key —
    /// a pure `plane_slots` map read, borrowed (mirrors the inherent `App::plane_slot`).
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>>;

    /// Recover the concrete snapshot as `&dyn Any` — the hatch the kernel's own readers downcast
    /// through to reach the snapshot fields that are not `plane_slots` entries. A plane never names a
    /// concrete type through this, so it never calls it.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// THE NEUTRAL `&mut` GATE-REBUILD SINK the core-owned `PlaneDecl::reresolve_gates` callback is
/// neutralised over — the config-swap re-resolution of a plane's per-registration hook gates, moved
/// behind a trait so the fn-pointer signature names no `&mut busbar_kernel::state::App`. A `PlaneSlots`
/// (its supertrait) so the plane can read its own registry object off the same `&mut` receiver before
/// it writes the resolved gates back. The resolve-and-store is ONE method (rather than the spec's
/// `resolve` + `set` pair) because the resolved gate map value type is core-owned
/// (`Vec<(u16, busbar_kernel::hooks::ResolvedPolicy)>`) and cannot be named in this crate — so the map
/// never crosses the seam; it is built and stored entirely core-side, keyed by `plane_key`.
pub trait ContainerGateSink: PlaneSlots {
    /// Resolve `containers` (each `(name, its-own-hooks)`) unioned with `section_hooks` against this
    /// snapshot's hook registry, and store the resolved per-container gates under the opaque registry
    /// `plane_key` (the plane's stable decl key) in the generic `App::plane_gates` map. Byte-identical
    /// to the old inline `next.plane_gates.insert(plane_key, next.resolve_container_gates(...))`.
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    );
}

impl<P> PlaneSlots for P
where
    P: Deref,
    P::Target: PlaneSlots,
{
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        (**self).plane_slot(key)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        (**self).as_any()
    }
}
