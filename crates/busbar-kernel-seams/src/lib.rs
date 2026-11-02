// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-seams — the kernel's seams that are not the plugin contract

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod migration;
pub mod slice;
pub mod verb_store;
