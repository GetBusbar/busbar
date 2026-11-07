// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Historical conversion and resumable upgrades driven by ordinary Busbar startup.
//!
//! The Store checkpoint is authoritative; exported manifests contain only public
//! identities and evidence digests. Protected intent must be durable before a send.
//! Recovery reconciles outstanding intent against its original native authority;
//! a new process cannot reset the replay horizon or declare old operation debt safe.

#![deny(unsafe_code)]

mod activation;
pub mod archive_source;
mod completion;
pub mod config;
mod coordinator;
pub mod documents;
mod fence;
mod intent;
pub mod legacy;
mod manifest;
pub mod native_source;
mod provenance;
pub mod routes;
pub(crate) mod seal;
mod startup;
mod verification;
mod witness;
pub use activation::{BootstrapIds, BootstrapProgress, CoreActivation, TargetBootstrap};
pub use completion::CompletionReceipt;
pub use coordinator::*;
pub use fence::NativeSourceFence;
pub use intent::{ColdWriterRegistration, OutstandingIntent, StoreIntent};
pub use manifest::*;
pub use provenance::{CheckedNativeFence, ReleasedProfile, ReleasedSourceProof};
pub use startup::{
    DocumentCustody, FrozenBindingResolver, FrozenResolution, Preparation, RecoveryPending,
    StartupUpgrade,
};
pub use verification::{ArchiveVerifier, NativeReadback, TargetRecoveryProbe};

#[cfg(test)]
mod tests;
