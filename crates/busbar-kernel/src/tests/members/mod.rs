// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel member crates' minting tests (ARCHITECT ruling A, GATE-GREEN): a test that mints a
//! token lives where minting is legal, and drives the member crate through its public API.

mod audit;
mod breaker;
mod egress;
mod ledger;
mod wal;
