// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-seams — the kernel's seams that are not the plugin contract
//!
//! The types and traits the kernel, its member crates and the plugin loader trade with each other.
//! No plugin names them, so they are not in `busbar-contract`; the loader must not depend on the
//! kernel, so they are not in `busbar-kernel`. This crate depends on `busbar-contract` alone.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

// THE MIGRATION SEAMS: the legacy-row shapes and the three traits the store adapter implements and
// the ledger's migration consumes (the same division `slice` makes).
pub mod migration;
pub mod slice;
pub mod verb_store;
