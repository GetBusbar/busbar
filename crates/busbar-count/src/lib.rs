// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact decimal quantities and the shared byte-span grammar that reads them.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod count;
pub mod json_span;

pub use count::*;
