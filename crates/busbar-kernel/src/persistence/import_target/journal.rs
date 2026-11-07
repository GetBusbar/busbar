// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current journal and candidate codecs for trusted offline import owners.
//! Original-run verification grants no append custody or business replay rights.

use crate::governance::{
    persistence::recovery as recovery_owner,
    recovery::{RecoveryError, RecoverySelection},
};
use crate::persistence::journal::migration as codec;
use busbar_contract::{
    persistence::{Address, InvalidCandidate, PreparedCandidate},
    Secret,
};
use busbar_kernel_wal::{JournalRecord, Record};

/// Content-free original journal verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The caller supplied an invalid identity or ordinal.
    Invalid,
    /// Original framing, identity, chain or bridge evidence differs.
    Corrupt,
    /// Explicit memory or read work admission was exceeded.
    Budget,
    /// An ordinal or length could not be represented.
    Overflow,
    /// Required current authority was unavailable.
    Authority,
}
fn journal_error(error: crate::persistence::journal::Error) -> Error {
    use crate::persistence::journal::Error as Inner;
    match error {
        Inner::Invalid => Error::Invalid,
        Inner::Budget => Error::Budget,
        Inner::Overflow => Error::Overflow,
        Inner::Authority | Inner::Access(_) => Error::Authority,
        _ => Error::Corrupt,
    }
}

/// Stable indexed originals from an admitted frozen source, one frame at a time.
pub trait IndexedFrames {
    /// Number of retained original records, including recorded bridge notes.
    fn count(&self) -> u64;
    /// Reassemble the complete original frame at a one-based ordinal.
    fn frame(&mut self, ordinal: u64) -> Result<Vec<u8>, Error>;
}
/// Explicit original-frame memory and bridge-lookahead work bounds.
#[derive(Debug, Clone, Copy)]
pub struct SourceBudget {
    /// Maximum bytes in one original frame.
    pub max_frame_bytes: usize,
    /// Maximum frame reads, including bridge lookahead.
    pub max_reads: u64,
}
/// An opaque proof of one completely verified original run.
pub struct VerifiedNode {
    pub(crate) inner: codec::VerifiedNode,
}
impl std::fmt::Debug for VerifiedNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedNode")
            .field("node", &self.node())
            .field("count", &self.count())
            .finish_non_exhaustive()
    }
}
impl VerifiedNode {
    /// Original node identity.
    pub fn node(&self) -> u64 {
        self.inner.node()
    }
    /// Number of verified retained original frames.
    pub fn count(&self) -> u64 {
        self.inner.count()
    }
    /// Original final sequence and chain hash, never reconstructed.
    pub fn tail(&self) -> (u64, [u8; 32]) {
        self.inner.tail()
    }
    /// Inventory checksum over original bytes; never a replacement chain hash.
    pub fn original_digest(&self) -> [u8; 32] {
        self.inner.original_digest()
    }
}
struct Frames<'a, S>(&'a mut S);
impl<S: IndexedFrames> codec::IndexedFrames for Frames<'_, S> {
    fn count(&self) -> u64 {
        self.0.count()
    }
    fn frame(&mut self, ordinal: u64) -> Result<Vec<u8>, crate::persistence::journal::Error> {
        self.0.frame(ordinal).map_err(|error| match error {
            Error::Budget => crate::persistence::journal::Error::Budget,
            Error::Overflow => crate::persistence::journal::Error::Overflow,
            Error::Invalid => crate::persistence::journal::Error::Invalid,
            Error::Authority => crate::persistence::journal::Error::Authority,
            Error::Corrupt => crate::persistence::journal::Error::Corrupt,
        })
    }
}
/// Verify a complete original run using the current journal's bridge rules.
pub fn verify_source<S: IndexedFrames>(
    node: u64,
    source: &mut S,
    budget: SourceBudget,
) -> Result<VerifiedNode, Error> {
    codec::verify_source(
        node,
        &mut Frames(source),
        codec::SourceBudget {
            max_frame_bytes: budget.max_frame_bytes,
            max_reads: budget.max_reads,
        },
    )
    .map(|inner| VerifiedNode { inner })
    .map_err(journal_error)
}
/// Recognize only canonical immutable R rows and selected H rows, never custody O.
pub fn authorizes(address: &Address) -> bool {
    codec::authorizes(address)
}
/// Encode one unchanged canonical original at its verified run ordinal.
pub fn record(
    node: u64,
    ordinal: u64,
    original: &Record,
) -> Result<(Address, Secret<Vec<u8>>), Error> {
    codec::record(node, ordinal, original).map_err(journal_error)
}
/// Encode the original selected head from a complete run proof.
pub fn head(node: &VerifiedNode) -> (Address, Secret<Vec<u8>>) {
    codec::head(&node.inner)
}

/// Prepare read-only discovery of one completely verified imported node.
/// This reserves its identity for audit inventory and future allocation; it
/// creates no assignment, lease, journal owner or business replay authority.
/// The verified import owner publishes it only in the admitted inactive target.
pub fn inventory_row(node: &VerifiedNode) -> Result<(Address, Secret<Vec<u8>>), Error> {
    if node.node() == 0 || node.count() == 0 || node.tail().0 == 0 {
        return Err(Error::Invalid);
    }
    let address = crate::persistence::boot_identity::journal_inventory_address(node.node())
        .map_err(|_| Error::Budget)?;
    let bytes = crate::persistence::boot_identity::journal_inventory_bytes(
        node.node(),
        node.count(),
        node.tail(),
        node.original_digest(),
    );
    Ok((address, Secret::new(bytes)))
}
/// Recognize only the boot owner's reserved journal-inventory address class.
/// Recognition grants no source proof, assignment, lease or write authority.
pub fn inventory_address_class(address: &Address) -> bool {
    crate::persistence::boot_identity::journal_inventory_address_class(address)
}
/// Match only the exact read-only inventory derived from this complete proof.
pub fn inventory_matches(node: &VerifiedNode, address: &Address, value: &Secret<Vec<u8>>) -> bool {
    inventory_row(node).is_ok_and(|(expected_address, expected_value)| {
        expected_address == *address && expected_value == *value
    })
}

/// Content-free protected candidate codec failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateError {
    /// Unsupported retained candidate version.
    Version,
    /// Invalid framing.
    Malformed,
    /// Unrepresentable length.
    Overflow,
    /// Explicit allocation admission was exceeded.
    Budget,
    /// An admitted allocation failed.
    Allocation,
    /// The current native candidate is invalid.
    Invalid(InvalidCandidate),
    /// The original fingerprint differs.
    Fingerprint,
}
/// Preserve an immutable native candidate in the current protected codec.
pub fn encode_candidate(
    candidate: &PreparedCandidate,
    allocation_budget: usize,
) -> Result<Secret<Vec<u8>>, CandidateError> {
    super::candidate_codec::encode(candidate, allocation_budget, &crate::seal::lend())
}
/// Decode the exact retained candidate under explicit aggregate allocation admission.
pub fn decode_candidate(
    encoded: &Secret<Vec<u8>>,
    allocation_budget: usize,
) -> Result<PreparedCandidate, CandidateError> {
    super::candidate_codec::decode(encoded, allocation_budget, &crate::seal::lend())
}

/// Trusted frozen-source access for current recovery ancestry verification.
pub trait RecoveryHistory {
    /// Complete original run proof for the named node.
    fn verified_node(&self, node: u64) -> Option<&VerifiedNode>;
    /// Exact verified original selected by its historical node and sequence.
    fn original(&mut self, node: u64, sequence: u64) -> Result<JournalRecord, RecoveryError>;
    /// Exact original selected recovery head of another referenced operation.
    fn selected_head(
        &mut self,
        operation: &[u8; 16],
    ) -> Result<Option<Secret<Vec<u8>>>, RecoveryError>;
}
struct History<'a, S>(&'a mut S);
impl<S: RecoveryHistory> recovery_owner::LegacyRecoveryHistory for History<'_, S> {
    fn verified_node(&self, node: u64) -> Option<&codec::VerifiedNode> {
        self.0.verified_node(node).map(|proof| &proof.inner)
    }
    fn original(&mut self, node: u64, sequence: u64) -> Result<JournalRecord, RecoveryError> {
        self.0.original(node, sequence)
    }
    fn selected_head(
        &mut self,
        operation: &[u8; 16],
    ) -> Result<Option<Secret<Vec<u8>>>, RecoveryError> {
        self.0.selected_head(operation)
    }
}
/// Verify original selected ancestry and adoption proofs without granting a writer.
pub fn inspect_recovery_operation<S: RecoveryHistory>(
    operation: [u8; 16],
    head: &[u8],
    history: &mut S,
) -> Result<RecoverySelection, RecoveryError> {
    recovery_owner::inspect_legacy_recovery_operation(operation, head, &mut History(history))
}
