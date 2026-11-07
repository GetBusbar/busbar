// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protected custody of exact current native candidates for offline import.

pub use super::journal::CandidateError;
use busbar_contract::{persistence::PreparedCandidate, plugin::KernelSeal, Secret};

/// Encode the immutable candidate with the current guarded codec and explicit
/// allocation admission. The result retains secret custody.
pub fn encode<S: KernelSeal + ?Sized>(
    candidate: &PreparedCandidate,
    allocation_budget: usize,
    seal: &S,
) -> Result<Secret<Vec<u8>>, CandidateError> {
    crate::persistence::candidate_codec::encode(candidate, allocation_budget, seal)
        .map_err(content_free)
}

/// Recover the exact retained candidate without translating its version,
/// fingerprint, identity, values, or time predicates.
pub fn decode<S: KernelSeal + ?Sized>(
    encoded: &Secret<Vec<u8>>,
    allocation_budget: usize,
    seal: &S,
) -> Result<PreparedCandidate, CandidateError> {
    crate::persistence::candidate_codec::decode(encoded, allocation_budget, seal)
        .map_err(content_free)
}

fn content_free(error: crate::persistence::candidate_codec::CodecError) -> CandidateError {
    use crate::persistence::candidate_codec::CodecError;
    match error {
        CodecError::Version => CandidateError::Version,
        CodecError::Malformed => CandidateError::Malformed,
        CodecError::Overflow => CandidateError::Overflow,
        CodecError::Budget => CandidateError::Budget,
        CodecError::Allocation => CandidateError::Allocation,
        CodecError::Invalid(error) => CandidateError::Invalid(error),
        CodecError::Fingerprint => CandidateError::Fingerprint,
    }
}
