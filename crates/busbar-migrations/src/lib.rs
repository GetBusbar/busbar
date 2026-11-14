// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Historical conversion and resumable upgrades driven by ordinary Busbar startup.
//!
//! The Store checkpoint is authoritative; exported manifests contain only public
//! identities and evidence digests. Protected intent must be durable before a send.
//! Recovery reconciles outstanding intent against its original native authority;
//! a new process cannot declare old operation debt safe.
//!
//! Every store commit this crate makes is self-fenced (STORE-TRANSACTIONS R9): it
//! cannot reach the kernel's slot queue. These must not compile here:
//!
//! ```compile_fail
//! fn bypass(
//!     candidate: busbar_contract::persistence::PreparedCandidate,
//!     key: busbar_contract::persistence::CommitKey,
//!     backend: std::sync::Arc<dyn busbar_contract::persistence::PersistenceBackend>,
//! ) {
//!     // `Attempt::slotted` is crate-private to busbar-kernel.
//!     let _ = busbar_kernel::persistence::commit::Attempt::slotted(candidate, key, backend);
//! }
//! ```
//!
//! ```compile_fail
//! // The slotted-key root token cannot be constructed outside busbar-contract.
//! let seal = busbar_contract::caps::SlotSeal(());
//! let _ = busbar_contract::persistence::CommitKey::slotted(0, 1, &seal);
//! ```

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
pub mod source_facts;
pub mod source_interpretation;
mod startup;
mod verification;
mod witness;
pub use activation::{BootstrapIds, BootstrapProgress, CoreActivation, TargetBootstrap};
pub use completion::CompletionReceipt;
pub use coordinator::*;
pub use fence::NativeSourceFence;
pub use intent::{ColdWriterRegistration, OutstandingIntent, StoreIntent};
pub use manifest::*;
pub use provenance::{CheckedNativeFence, ReleasedSourceProof};
pub use startup::{
    DocumentCustody, FrozenBindingResolver, FrozenResolution, Preparation, RecoveryPending,
    StartupUpgrade,
};
pub use verification::{ArchiveVerifier, NativeReadback, TargetRecoveryProbe};

#[cfg(test)]
mod tests;
