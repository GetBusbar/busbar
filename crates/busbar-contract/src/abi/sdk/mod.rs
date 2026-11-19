// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the host still reads of the old SDK: digests, the sealed spool cipher, secret bytes and
//! their wipe, expiry counting, the recovery and plane record shapes, the generation mark, the
//! inspection wire, the boundary guard, the store slot row, and the Statement helpers.

#![allow(unsafe_op_in_unsafe_fn)]

pub mod aead;
pub mod boundary;
pub mod digest;
pub mod door;
pub mod expiry;
pub mod generation;
pub mod inspection_wire;
pub mod plane;
pub mod recovery;
pub(crate) mod secret_bytes;
pub mod store;
pub mod wipe;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
