// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trusted original-journal migration capability. Implemented only by the
//! compiled frozen-source bridge after complete run verification; manifests
//! cannot construct it. It emits original R/H records, never custody O records.
use super::{archive::Provenance, CanonicalRows};

#[derive(Clone, Copy)]
pub struct Part<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}
pub trait JournalMigration: Send + Sync {
    fn provenance(&self) -> Provenance;
    /// Bound original node inventory, each verified run checksum, exact source
    /// identity and derived ordinal mapping. Nonzero, deterministic, no payload
    /// reinterpretation and no business verdict or append-custody grant.
    fn descriptor_digest(&self) -> [u8; 32];
    /// Authorize only an inventory address derived from a stored complete run proof.
    fn inventory_authorizes(&self, address: &busbar_contract::persistence::Address) -> bool;
    /// Visit opaque complete run proofs for read-only target inventory.
    /// No raw caller-supplied node IDs can replace this verified capability.
    fn visit_verified_nodes(
        &self,
        visitor: &mut dyn FnMut(
            &busbar_kernel::persistence::import_target::journal::VerifiedNode,
        ) -> Result<(), super::super::Error>,
    ) -> Result<(), super::super::Error>;
    /// Project one verified frozen original directly from streamed source rows.
    /// Physical evidence is copied independently; this never creates custody.
    fn copy_source_group(
        &self,
        node: u64,
        sequence: u64,
        max_frame_bytes: usize,
    ) -> Result<CanonicalRows, super::super::Error>;
    fn copy_group(
        &self,
        parts: &[Part<'_>],
        max_frame_bytes: usize,
    ) -> Result<CanonicalRows, super::super::Error>;
}
pub(super) fn matches(plan: &dyn JournalMigration, source: Provenance) -> bool {
    let actual = plan.provenance();
    actual.dataset == source.dataset
        && actual.catalogue == source.catalogue
        && plan.descriptor_digest() != [0; 32]
}
