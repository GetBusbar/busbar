// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Futures over the serving App's credential custody graph prove Send through more than the
// default 128 auto-trait steps (see busbar-kernel's lib.rs); the graph is acyclic.
#![recursion_limit = "256"]

use busbar_kernel::persistence;

#[path = "support/plane_driver_actual.rs"]
mod suite;
