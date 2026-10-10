// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTRACT'S TEST KIT: pure shapes and in-memory doubles a plugin's own tests use to observe what
//! it did through the contract, without reaching any crate above it. Nothing here opens a file, a
//! socket or a process, reads the environment or the clock. It is compiled only under `cfg(test)` or
//! the dev-only `test-seal` feature (Locked Decision #33: no testkit ships), so a release build has
//! none of it and a plugin reaches it only on its `[dev-dependencies]` edge.

pub mod store_v3;
pub mod warn_capture;

pub use warn_capture::WarnCapture;
