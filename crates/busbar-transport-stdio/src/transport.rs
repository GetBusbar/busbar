// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio row's shared framing bound.
//!
//! The stdio transport is carried on the memory-ABI line-framer DOOR ([`crate::door`], the
//! `transport-door` axis the composition root links) and, in-process, the [`crate::carrier`]; both
//! frame one opaque line per `0x0A`. This module holds the one line bound they share. (The crate's
//! single kind entry is its exported door — there is no in-process `impl Transport` here; the host
//! reaches this row only over the ABI, as every plugin does.)

/// The largest line (a frame) the stdio framing accepts, in bytes, before it is a framing error.
pub(crate) const MAX_LINE_BYTES: usize = busbar_contract::MAX_CURSOR_BYTES;
