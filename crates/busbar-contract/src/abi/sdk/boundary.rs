// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT BOUNDARY'S ONE CATCH: every slot a plugin image exports runs under a mandatory
//! `catch_unwind`, so no panic (from user code or a user `Drop`) unwinds out of the image. What is
//! left here is the one reviewed choke point the memory ABI's connection table
//! (`abi::host::conn`) and the HOT lane's transport slots (`super::transport`) cross; the COLD/JSON
//! lane's `open`/`call`/`free`/`close` bodies that also lived here are gone with that lane.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f` under the MANDATORY `catch_unwind` every export boundary shares, answering `None` for a
/// caught panic: the HOT lane's transport slots (`super::transport`) cross here, so a panicking
/// carrier or framer answers its fault byte instead of unwinding out of the image, through the one
/// reviewed choke point rather than a second one. No hold is in scope on either side of the call.
pub fn caught<T>(f: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(f)).ok()
}
