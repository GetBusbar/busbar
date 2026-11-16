// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// The linked-table generator as a library: core's own source, mounted as this crate's root, so a build
// script reaches it as a dependency and carries no `include!` of it. Plain and dependency-free.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

include!("../../busbar/src/linked_gen.rs");
