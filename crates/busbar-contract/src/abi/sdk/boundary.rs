// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT BOUNDARY'S ONE CATCH: every slot a plugin image exports runs under a mandatory

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f` under the MANDATORY `catch_unwind` every export boundary shares, answering `None` for a

pub fn caught<T>(f: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(f)).ok()
}
