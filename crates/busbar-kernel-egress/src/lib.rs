// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// busbar:request-path
#![cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
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
