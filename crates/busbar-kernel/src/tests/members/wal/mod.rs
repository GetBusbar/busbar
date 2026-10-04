// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar-kernel-wal batteries that mint their tokens.

mod bounds_tests;
mod corruption_verdict_tests;
mod fixtures;
mod idempotence_tests;
mod journal_chain_tests;
mod kill_at_every_offset_tests;
mod no_disk_tests;
mod poison_tests;
mod restart_after_a_roll_tests;
