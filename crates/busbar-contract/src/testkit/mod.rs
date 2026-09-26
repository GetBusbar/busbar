// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTRACT'S TEST KIT: pure shapes and in-memory doubles a plugin's own tests use to observe what
//! it did through the contract, without reaching any crate above it. Nothing here opens a file, a
//! socket or a process, reads the environment or the clock, and nothing is behind a feature: it is the
//! same module in every build, so a plugin tested against it is tested against the contract it ships
//! on.

pub mod warn_capture;

pub use warn_capture::WarnCapture;
