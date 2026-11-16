// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive Store adapter and shared native connection mechanics.

pub mod v4;
pub mod wire;

mod op;
pub use op::{Checkout, Op, Services, Step};
