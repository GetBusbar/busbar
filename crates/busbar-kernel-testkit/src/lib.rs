// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

pub mod app;

pub mod limits {
    pub use crate::test_support::fixture_limits::*;
}

pub mod routes;

use busbar_kernel::*;
pub mod ingress;
pub mod test_support;
pub mod testkit;

/// Real socket upgrade adaptation for tests of the kernel's neutral session handoff.
pub mod websocket;
