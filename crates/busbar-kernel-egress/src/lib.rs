// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # busbar-kernel-egress — the egress unit

pub mod attempt;
pub mod exhaustion;
pub mod pool;
pub mod ports;
pub mod race;
pub mod select;

pub mod trust;
pub mod upstream;
pub mod walk;
pub mod wire;

pub use pool::{
    Failover, Member, OnExhausted, Pool, DEFAULT_FAILOVER_CAP, DEFAULT_FAILOVER_DEADLINE_SECS,
};
pub use select::{RequestCtx, WeightedFloor};
pub use walk::{Shape, Step, Taken, Walk, WalkPorts};
pub use wire::Shed;

#[cfg(test)]
mod tests;
