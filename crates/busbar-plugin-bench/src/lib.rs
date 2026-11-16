// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 plugin interface benches (ABI-MIN3-INTERFACE §6.5, §14, §16). Each named bench is one file under
//! `benches/`, registered in this crate's manifest and written by the task that owns it: B-SLOTS and B-OPEN
//! (W1-A3), B-SYNC (W1-H0), B-STORE-LANE (W1-L3), B-CHAIN and B-HOLD (wave 4). Wave 0 lands the empty files.

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
