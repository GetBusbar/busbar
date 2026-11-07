// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ownership-preserving marshalling for the staged primitive Store ABI.
//!
//! A returned raw frame borrows its marshaller, which retains shared source ownership.
//! The marshaller must live until the native operation, including a pending ticket,
//! releases it. Scan frames additionally require their source request to stay alive.

pub mod backend;
pub mod bootstrap;
pub mod decode;
pub mod door;
pub mod encode;
pub mod metadata;
pub mod response;
pub mod retirement;

use crate::abi::mechanism::call::{Blob, InHead, BLOB_OCTETS, BLOB_SECRET};
use crate::abi::store::{v4 as wire, HostBuf};
use crate::persistence::{self as owned, ExpectedValue, Mutation};

/// Failure before any native submission; no backend mutation has been attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarshalError {
    /// Descriptor arithmetic overflow or host descriptor budget exceeded.
    Budget,
    /// Descriptor storage could not be reserved.
    Allocation,
}

fn reserve<T>(count: usize, budget: &mut usize) -> Result<Vec<T>, MarshalError> {
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(MarshalError::Budget)?;
    if bytes > isize::MAX as usize {
        return Err(MarshalError::Budget);
    }
    *budget = budget.checked_sub(bytes).ok_or(MarshalError::Budget)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| MarshalError::Allocation)?;
    Ok(result)
}

fn bytes(value: &[u8]) -> wire::Bytes {
    wire::Bytes {
        ptr: if value.is_empty() {
            std::ptr::null()
        } else {
            value.as_ptr()
        },
        len: value.len(),
    }
}

fn blob(value: &[u8]) -> Blob {
    Blob {
        ptr: bytes(value).ptr,
        len: value.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

fn address(value: &owned::Address) -> wire::Address {
    wire::Address {
        namespace: value.namespace,
        key: bytes(&value.key),
    }
}

fn time(value: Option<owned::TimeGuard>) -> wire::TimeGuard {
    let value = value.unwrap_or(owned::TimeGuard {
        not_before: None,
        before: None,
    });
    wire::TimeGuard {
        flags: if value.not_before.is_some() {
            wire::TIME_NOT_BEFORE
        } else {
            0
        } | if value.before.is_some() {
            wire::TIME_BEFORE
        } else {
            0
        },
        _reserved: 0,
        not_before: value.not_before.unwrap_or(0),
        before: value.before.unwrap_or(0),
    }
}

/// Stable descriptor storage retaining one sealed candidate without payload copies.
#[derive(Debug)]
pub struct Commit {
    candidate: owned::PreparedCandidate,
    predicates: Vec<wire::Predicate>,
    mutations: Vec<wire::Mutation>,
}

// SAFETY: all raw pointers borrow immutable source allocations retained by the
// shared candidate owner. Descriptor vectors never resize after construction. Native
// input consumers may only read these descriptors and bytes while this owner lives.
unsafe impl Send for Commit {}
unsafe impl Sync for Commit {}

impl Commit {
    /// Reserve descriptors within the host budget; values remain in original custody.
    pub fn new(
        candidate: &owned::PreparedCandidate,
        mut descriptor_budget: usize,
    ) -> Result<Self, MarshalError> {
        let source = candidate.candidate();
        let mut predicates = reserve(source.predicates.len(), &mut descriptor_budget)?;
        let mut mutations = reserve(source.mutations.len(), &mut descriptor_budget)?;
        for item in &source.predicates {
            let (tag, expected) = match &item.expected {
                ExpectedValue::Absent => (wire::PREDICATE_ABSENT, Blob::ABSENT),
                ExpectedValue::Exact(value) => (wire::PREDICATE_EXACT, blob(&value.0)),
            };
            predicates.push(wire::Predicate {
                address: address(&item.address),
                tag,
                _reserved: 0,
                expected,
            });
        }
        for item in &source.mutations {
            let (at, tag, exact_length, value) = match item {
                Mutation::Put { address: at, value } => {
                    (address(at), wire::MUTATION_PUT, 0, blob(&value.0))
                }
                Mutation::Delete(at) => (address(at), wire::MUTATION_DELETE, 0, Blob::ABSENT),
                Mutation::DeleteRange {
                    namespace,
                    prefix,
                    exact_key_length,
                } => (
                    wire::Address {
                        namespace: namespace.0,
                        key: bytes(prefix),
                    },
                    wire::MUTATION_DELETE_RANGE,
                    *exact_key_length,
                    Blob::ABSENT,
                ),
            };
            mutations.push(wire::Mutation {
                address: at,
                tag,
                _reserved: 0,
                exact_length,
                value,
            });
        }
        Ok(Self {
            candidate: candidate.clone(),
            predicates,
            mutations,
        })
    }

    /// Borrow a raw input frame; this owner must outlive its execution/ticket.
    pub fn frame(&self, head: InHead, result: HostBuf) -> wire::CommitIn {
        let source = self.candidate.candidate();
        let id = source.id;
        wire::CommitIn {
            head,
            candidate: wire::Candidate {
                id: wire::AttemptId {
                    dataset: id.dataset.0,
                    writer: id.writer,
                    operation: id.operation,
                    writer_epoch: id.writer_epoch,
                    execution_epoch: id.execution_epoch,
                },
                codec: source.codec,
                _reserved: 0,
                time: time(source.time),
                predicates: self.predicates.as_ptr(),
                predicates_len: self.predicates.len(),
                mutations: self.mutations.as_ptr(),
                mutations_len: self.mutations.len(),
                result: blob(&source.result.0),
            },
            result,
        }
    }
}

/// Stable address descriptors retaining a consistent read request.
#[derive(Debug)]
pub struct Read {
    request: std::sync::Arc<owned::Read>,
    addresses: Vec<wire::Address>,
}

// SAFETY: descriptors contain only immutable pointers into the shared request;
// neither the request nor descriptor vector may change while this owner lives.
unsafe impl Send for Read {}
unsafe impl Sync for Read {}

impl Read {
    /// Allocate address descriptors within the host's explicit descriptor budget.
    pub fn new(
        request: std::sync::Arc<owned::Read>,
        mut descriptor_budget: usize,
    ) -> Result<Self, MarshalError> {
        let mut addresses = reserve(request.addresses.len(), &mut descriptor_budget)?;
        addresses.extend(request.addresses.iter().map(address));
        Ok(Self { request, addresses })
    }

    /// Borrow the raw frame, retaining this owner through any pending operation.
    pub fn frame(&self, head: InHead, values: wire::HostValues) -> wire::ReadIn {
        wire::ReadIn {
            head,
            dataset: self.request.dataset.0,
            addresses: self.addresses.as_ptr(),
            addresses_len: self.addresses.len(),
            time: time(self.request.time),
            values,
        }
    }
}

/// Borrow a scan frame without allocating or copying key material.
/// The source request and output buffers must outlive native execution.
pub fn scan(request: &owned::Scan, head: InHead, rows: wire::HostRows) -> wire::ScanIn {
    wire::ScanIn {
        head,
        dataset: request.dataset.0,
        namespace: request.namespace.0,
        prefix: bytes(&request.prefix),
        after: bytes(request.after.as_deref().unwrap_or_default()),
        generation: request.generation.unwrap_or(0),
        flags: if request.after.is_some() {
            wire::SCAN_AFTER
        } else {
            0
        } | if request.generation.is_some() {
            wire::SCAN_GENERATION
        } else {
            0
        } | if request.allow_change {
            wire::SCAN_ALLOW_CHANGE
        } else {
            0
        },
        _reserved: 0,
        max_items: request.max_items as u64,
        max_bytes: request.max_bytes as u64,
        rows,
    }
}

#[cfg(test)]
#[path = "tests/marshal_tests.rs"]
mod tests;
