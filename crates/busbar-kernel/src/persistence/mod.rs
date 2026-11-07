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
// Staged host-service owner; the old caller port removes this allowance.
#[allow(dead_code)]
pub(crate) mod claims;
pub mod commit;
pub mod facade;
pub mod fences;
// Staged history owner; removed with its asynchronous caller port.
#[allow(dead_code)]
pub(crate) mod history;
// Staged owner; removed with the asynchronous host-service caller port.
#[allow(dead_code)]
pub(crate) mod host_records;
// Staged journal owner; removed with its asynchronous recovery caller port.
pub mod import_target;
#[allow(dead_code)]
pub mod journal;
pub(crate) mod keys;
pub mod objects;
pub(crate) mod partition;
pub mod recovery_api;
pub(crate) mod scan;
pub mod scoped;
pub mod startup;
