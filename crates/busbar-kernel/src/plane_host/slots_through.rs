// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `PlaneSlots` THROUGH A POINTER: any smart pointer or borrow whose target reads plane slots reads
//! them too.
//!
//! The engine snapshot is almost always held behind a pointer — an `Arc` off the handle, a
//! lock-free load guard, a plain borrow — and a plane's slot reads (`resource(app)`,
//! `runtime(app)`) used to take the concrete snapshot type by reference so that every one of those
//! pointer shapes auto-dereferenced to it. Once a plane names no concrete snapshot type, its readers
//! take `&impl PlaneSlots` instead, and this blanket impl is what keeps every pointer-shaped caller
//! compiling unchanged: a `Deref` to a slot holder is itself a slot holder, forwarding both reads to
//! the target. It adds no behaviour; the borrow it hands back is the target's own.

use super::PlaneSlots;
use std::ops::Deref;
use std::sync::Arc;

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
