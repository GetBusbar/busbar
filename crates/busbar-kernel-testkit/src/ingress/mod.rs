// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The production ingress types plus the external kit's own fixture protocol registry.

pub use busbar_kernel::ingress::*;

#[path = "protocols_legacy.rs"]
pub mod protocols;
