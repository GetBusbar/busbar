// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-owned persistence coordination over the neutral Store kind contract.
//!
//! Staged beside the existing runtime while domains move to canonical records.
//! Only this host layer assigns domain namespaces, prepares mutations, and owns
//! uncertain operation recovery; backend adapters supply atomic opaque storage.

pub mod boot_identity;
pub(crate) mod candidate_codec;
pub mod plugin_floor;
pub mod undrained;
// Staged host-service owner; the old caller port removes this allowance.
pub(crate) mod claims;
pub mod commit;
pub mod facade;
pub mod fences;
// Staged history owner; removed with its asynchronous caller port.
pub(crate) mod history;
// Staged owner; removed with the asynchronous host-service caller port.
pub(crate) mod host_records;
// Staged journal owner; removed with its asynchronous recovery caller port.
pub mod first_start;
// The record-format migration owner (#319 r4): the only handle before ordinary admission.
pub mod format_migration;
pub mod import_target;
pub mod journal;
pub(crate) mod keys;
pub mod lifecycle;
pub mod observations;
pub(crate) mod partition;
pub mod record_ops;
pub mod recovery_api;
pub mod restore;
pub mod restore_tail;
pub(crate) mod scan;
pub mod scoped;
mod slot_seal;
pub mod startup;
#[cfg(any(test, feature = "test-support"))]
pub mod test_backend;
// The store kit: kernel-level Startup conformance run against a store (DES-STOREKIT r2: the
// harness build's `--store-kit` runner, through the `store-kit` feature).
#[cfg(any(test, feature = "test-support", feature = "store-kit"))]
pub mod store_kit;
