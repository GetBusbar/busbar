// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Send proofs over busbar-kernel futures exceed the default 128 (see busbar-kernel lib.rs).
#![recursion_limit = "256"]

use busbar_kernel::persistence;

#[path = "support/plane_driver_actual.rs"]
mod suite;
