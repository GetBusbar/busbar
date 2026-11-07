// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral asynchronous persistence boundary shared by core and the loader.
//!
//! Domain records and policy do not cross this interface. Implementations must
//! evaluate conditions, epoch admission, mutations and receipts atomically. These
//! types do not enable a backend: ABI admission and qualification remain required.

use std::future::Future;
use std::pin::Pin;

use crate::redacted::{Kernel, Secret};

pub mod archive;
pub mod axis;
pub mod control;
pub mod legacy_row;
pub mod lifecycle;
pub mod source_fence;

/// A persistence call whose input remains owned until completion or cancellation.
pub type Call<'a, T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + Send + 'a>>;

/// Dataset identity, independent of display names and process incarnations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatasetId(pub [u8; 16]);

/// Core-assigned namespace; a backend never interprets its domain meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamespaceId(pub [u8; 16]);

/// Acknowledgement guarantee verified by the adapter for its opened configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// State and receipts are lost with the process.
    Ephemeral,
    /// Acknowledgement requires persistence on the authoritative local storage.
    Local,
    /// Acknowledgement requires a durable quorum in the declared atomic domain.
    Quorum,
}

/// Generic facts about one opened backend, never business-feature capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendInfo {
    /// Persistent identity of the selected dataset.
    pub dataset: DatasetId,
    /// One native atomicity domain covering all namespaces in this dataset.
    pub atomic_domain: [u8; 16],
    /// Authority used by all time-bearing operations on this dataset.
    pub clock_authority: [u8; 16],
    /// Adapter-owned physical format, independent of core logical schema.
    pub physical_version: u32,
    /// Effective acknowledgement guarantee; asynchronous replicas are not a quorum.
    pub durability: Durability,
}

/// A record address; key bytes are ordered lexicographically, without text collation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    /// Core-assigned namespace bytes.
    pub namespace: [u8; 16],
    /// Opaque instance-local key.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("namespace", &self.namespace)
            .field("key_bytes", &self.key.len())
            .finish()
    }
}

/// Persistence-authoritative UTC interval, in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeGuard {
    /// Inclusive lower bound; absent means no lower bound.
    pub not_before: Option<u64>,
    /// Exclusive upper bound; absent means no upper bound.
    pub before: Option<u64>,
}

/// An authoritative clock observation; identity is stable across compatible writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockObservation {
    /// Identity of the declared clock authority, not the calling node's clock.
    pub authority: [u8; 16],
    /// UTC seconds since the Unix epoch.
    pub unix_seconds: u64,
}

impl TimeGuard {
    /// Whether the authoritative observation satisfies both bounds.
    #[must_use]
    pub fn permits(self, now: u64) -> bool {
        self.not_before.is_none_or(|lower| now >= lower)
            && self.before.is_none_or(|upper| now < upper)
    }
}

/// Identity binding an immutable attempt to its permitted execution epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptId {
    /// Target dataset; reload must not retarget an attempt.
    pub dataset: DatasetId,
    /// Admitted dataset writer generation.
    pub writer_epoch: u64,
    /// Registered writer identity; never reused after restore.
    pub writer: [u8; 16],
    /// Writer execution epoch, fenced before receipt collection.
    pub execution_epoch: u64,
    /// Unique operation identity within the registered writer.
    pub operation: [u8; 16],
}

/// Required pre-mutation value. Exact values retain wiping, redacted custody.
#[derive(Debug)]
pub enum ExpectedValue<O = Kernel> {
    /// The address must not contain a live value.
    Absent,
    /// The address must contain exactly these bytes.
    Exact(Secret<Vec<u8>, O>),
}

/// One condition evaluated against the transaction's pre-mutation state.
#[derive(Debug)]
pub struct Predicate<O = Kernel> {
    /// Compared address.
    pub address: Address,
    /// Required state.
    pub expected: ExpectedValue<O>,
}

/// An opaque mutation; overlapping selectors must be refused before execution.
#[derive(Debug)]
pub enum Mutation<O = Kernel> {
    /// Replace a value; its size is governed by storage bounds, not plane bounds.
    Put {
        /// Destination address.
        address: Address,
        /// Owned, wiping payload, including confidential envelopes.
        value: Secret<Vec<u8>, O>,
    },
    /// Remove the live value at an address.
    Delete(Address),
    /// Atomically remove all matching keys, without visible page-by-page deletion.
    DeleteRange {
        /// Namespace containing the range.
        namespace: NamespaceId,
        /// Raw key prefix; equality is byte-based.
        prefix: Vec<u8>,
        /// Only keys with this exact byte length match.
        exact_key_length: u64,
    },
}

/// Owned transaction input. A submitted instance must remain immutable for replay.
#[derive(Debug)]
pub struct Candidate<O = Kernel> {
    /// Exact replay authority and operation identity.
    pub id: AttemptId,
    /// Candidate codec version, preserved through recovery and migration.
    pub codec: u32,
    /// Conditions evaluated before any mutation.
    pub predicates: Vec<Predicate<O>>,
    /// Effects committed atomically with the applied receipt.
    pub mutations: Vec<Mutation<O>>,
    /// Evaluated at serialization, after checking for an existing receipt.
    pub time: Option<TimeGuard>,
    /// Original result/reference bytes; never a plaintext secret response.
    pub result: Secret<Vec<u8>, O>,
}

/// Version of the immutable candidate representation, separate from the kind ABI.
pub const CANDIDATE_VERSION: u32 = 1;

/// Invalid candidate structure. Diagnostics intentionally carry no record contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCandidate {
    /// Validation scratch allocation could not be reserved.
    Allocation,
    /// The candidate codec is unknown.
    Version,
    /// Dataset, writer or operation identity is zero, or its epoch is unregistered.
    Identity,
    /// A transaction must contain at least one mutation.
    Empty,
    /// Two conditions name the same address.
    DuplicatePredicate,
    /// Mutation selectors overlap or repeat.
    Overlap,
    /// A range has an impossible key length.
    RangeLength,
    /// A storage value exceeds its carrier's byte dimension.
    ValueLength,
    /// The temporal interval is empty or inverted.
    TimeInterval,
}

impl<O> Candidate<O> {
    /// Checked payload storage for the temporary borrowed validation vectors.
    /// Allocator bookkeeping and fixed stack/header sizes are separate host overhead.
    #[must_use]
    pub fn validation_workspace_bytes(predicates: usize, mutations: usize) -> Option<usize> {
        let predicates = predicates.checked_mul(std::mem::size_of::<&Address>())?;
        let selectors = mutations
            .checked_mul(std::mem::size_of::<([u8; 16], usize, &[u8])>())?
            .checked_mul(2)?;
        predicates.checked_add(selectors)
    }

    /// Validate structure without imposing a plane-size or batch-count limit.
    ///
    /// This does not authorize execution or establish resource admission. The host
    /// checks its allocation budget before constructing wire arrays; the backend
    /// checks epoch admission and predicates atomically with receipt publication.
    pub fn validate(&self) -> Result<(), InvalidCandidate> {
        use InvalidCandidate as E;

        if self.codec != CANDIDATE_VERSION {
            return Err(E::Version);
        }
        if self.id.dataset.0 == [0; 16]
            || self.id.writer == [0; 16]
            || self.id.operation == [0; 16]
            || self.id.writer_epoch == 0
            || self.id.execution_epoch == 0
        {
            return Err(E::Identity);
        }
        if self.mutations.is_empty() {
            return Err(E::Empty);
        }
        if let Some(TimeGuard {
            not_before: Some(lower),
            before: Some(upper),
        }) = self.time
        {
            if lower >= upper {
                return Err(E::TimeInterval);
            }
        }
        let fits = |bytes: &Secret<Vec<u8>, O>| u32::try_from(bytes.0.len()).is_ok();
        if !fits(&self.result) {
            return Err(E::ValueLength);
        }
        let mut predicates = Vec::new();
        predicates
            .try_reserve_exact(self.predicates.len())
            .map_err(|_| E::Allocation)?;
        for predicate in &self.predicates {
            predicates.push(&predicate.address);
            if let ExpectedValue::Exact(bytes) = &predicate.expected {
                if !fits(bytes) {
                    return Err(E::ValueLength);
                }
            }
        }
        predicates.sort_unstable();
        if predicates.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(E::DuplicatePredicate);
        }
        let mut points = Vec::new();
        let mut ranges = Vec::new();
        points
            .try_reserve_exact(self.mutations.len())
            .map_err(|_| E::Allocation)?;
        ranges
            .try_reserve_exact(self.mutations.len())
            .map_err(|_| E::Allocation)?;
        for mutation in &self.mutations {
            match mutation {
                Mutation::Put { address, value } => {
                    if !fits(value) {
                        return Err(E::ValueLength);
                    }
                    points.push((address.namespace, address.key.len(), address.key.as_slice()));
                }
                Mutation::Delete(address) => {
                    points.push((address.namespace, address.key.len(), address.key.as_slice()));
                }
                Mutation::DeleteRange {
                    namespace,
                    prefix,
                    exact_key_length,
                } => {
                    let length = usize::try_from(*exact_key_length).map_err(|_| E::RangeLength)?;
                    if length < prefix.len() {
                        return Err(E::RangeLength);
                    }
                    ranges.push((namespace.0, length, prefix.as_slice()));
                }
            }
        }
        points.sort_unstable();
        ranges.sort_unstable();
        if points.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(E::Overlap);
        }
        let mut previous: Option<([u8; 16], usize, &[u8])> = None;
        for &(namespace, length, prefix) in &ranges {
            if let Some(&(point_ns, point_len, key)) =
                points.get(points.partition_point(|point| *point < (namespace, length, prefix)))
            {
                if point_ns == namespace && point_len == length && key.starts_with(prefix) {
                    return Err(E::Overlap);
                }
            }
            if let Some((old_ns, old_len, old_prefix)) = previous {
                if old_ns == namespace && old_len == length && prefix.starts_with(old_prefix) {
                    return Err(E::Overlap);
                }
            }
            previous = Some((namespace, length, prefix));
        }
        Ok(())
    }
}

/// An immutable, validated candidate with an exact content fingerprint.
///
/// Cloning shares custody; it neither regenerates an identity nor copies secret
/// payloads. The fingerprint covers semantic bytes, not addresses or buffer sizes.
#[derive(Debug)]
pub struct PreparedCandidate<O = Kernel> {
    candidate: std::sync::Arc<Candidate<O>>,
    fingerprint: [u8; 32],
}

impl<O> Clone for PreparedCandidate<O> {
    fn clone(&self) -> Self {
        Self {
            candidate: self.candidate.clone(),
            fingerprint: self.fingerprint,
        }
    }
}

impl<O> PreparedCandidate<O> {
    /// Validate and seal ownership before any submission or durable custody write.
    pub fn new(candidate: Candidate<O>) -> Result<Self, InvalidCandidate> {
        candidate.validate()?;
        let fingerprint = candidate_fingerprint(&candidate);
        Ok(Self {
            candidate: std::sync::Arc::new(candidate),
            fingerprint,
        })
    }

    /// Original immutable candidate, retained through unknown outcomes.
    #[must_use]
    pub fn candidate(&self) -> &Candidate<O> {
        &self.candidate
    }

    /// Domain-separated digest of the complete original candidate.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

fn candidate_fingerprint<O>(candidate: &Candidate<O>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    fn bytes(hash: &mut Sha256, value: &[u8]) {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    fn address(hash: &mut Sha256, address: &Address) {
        hash.update(address.namespace);
        bytes(hash, &address.key);
    }
    fn timestamp(hash: &mut Sha256, value: Option<u64>) {
        hash.update([u8::from(value.is_some())]);
        if let Some(value) = value {
            hash.update(value.to_le_bytes());
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"busbar.persistence.candidate/1\0");
    hash.update(candidate.codec.to_le_bytes());
    hash.update(candidate.id.dataset.0);
    hash.update(candidate.id.writer_epoch.to_le_bytes());
    hash.update(candidate.id.writer);
    hash.update(candidate.id.execution_epoch.to_le_bytes());
    hash.update(candidate.id.operation);
    let time = candidate.time.unwrap_or(TimeGuard {
        not_before: None,
        before: None,
    });
    timestamp(&mut hash, time.not_before);
    timestamp(&mut hash, time.before);
    hash.update((candidate.predicates.len() as u64).to_le_bytes());
    for predicate in &candidate.predicates {
        address(&mut hash, &predicate.address);
        match &predicate.expected {
            ExpectedValue::Absent => hash.update([0]),
            ExpectedValue::Exact(value) => {
                hash.update([1]);
                bytes(&mut hash, &value.0);
            }
        }
    }
    hash.update((candidate.mutations.len() as u64).to_le_bytes());
    for mutation in &candidate.mutations {
        match mutation {
            Mutation::Put { address: at, value } => {
                hash.update([0]);
                address(&mut hash, at);
                bytes(&mut hash, &value.0);
            }
            Mutation::Delete(at) => {
                hash.update([1]);
                address(&mut hash, at);
            }
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => {
                hash.update([2]);
                hash.update(namespace.0);
                bytes(&mut hash, prefix);
                hash.update(exact_key_length.to_le_bytes());
            }
        }
    }
    bytes(&mut hash, &candidate.result.0);
    hash.finalize().into()
}

/// Definitive or unresolved execution decision; transport errors remain separate.
#[derive(Debug)]
pub enum Decision<O = Kernel> {
    /// Matching applied receipt, whether newly committed or replayed.
    Applied(Secret<Vec<u8>, O>),
    /// This execution applied nothing because a predicate failed.
    ConditionConflict,
    /// This execution applied nothing because its temporal guard failed.
    TimeGuardFailed {
        /// Store-authoritative observation at serialization.
        observed_at: ClockObservation,
    },
    /// The operation identity is bound to different immutable candidate bytes.
    OpIdConflict,
    /// Execution authority retired and the result is unavailable; never execute anew.
    ExpiredUnknown,
}

/// Failure classification does not erase an earlier uncertain execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// This call was refused before any mutation.
    Refused,
    /// The host did not submit this call because admission was exhausted.
    Overloaded,
    /// Execution may have occurred; retain exact identity and candidate.
    Unknown,
    /// Read observation unavailable; never substitute missing or empty state.
    Unavailable,
    /// Read data is malformed or inconsistent.
    Corrupt,
    /// A continued scan's observed namespace generation changed.
    StaleScan,
}

/// Consistent multi-address read with optional serialization-time guard.
#[derive(Debug)]
pub struct Read {
    /// Target dataset.
    pub dataset: DatasetId,
    /// Exact addresses, returned in request order.
    pub addresses: Vec<Address>,
    /// Optional time condition evaluated with the read.
    pub time: Option<TimeGuard>,
}

/// One consistent read result.
#[derive(Debug)]
pub enum ReadResult<O = Kernel> {
    /// Values in request order; absence is distinct from any read failure.
    Values {
        /// Store-authoritative observation time.
        observed_at: ClockObservation,
        /// Wiping values, one per requested address.
        values: Vec<Option<Secret<Vec<u8>, O>>>,
    },
    /// The interval did not include serialization time.
    TimeGuardFailed {
        /// Store-authoritative observation time.
        observed_at: ClockObservation,
    },
}

/// Ordered, bounded scan request; continuation checks the same generation.
#[derive(Debug)]
pub struct Scan {
    /// Target dataset.
    pub dataset: DatasetId,
    /// Core-assigned namespace.
    pub namespace: NamespaceId,
    /// Raw key prefix.
    pub prefix: Vec<u8>,
    /// Exclusive raw key cursor, absent on the first page.
    pub after: Option<Vec<u8>>,
    /// Expected namespace generation, absent on the first page.
    pub generation: Option<u64>,
    /// Explicit display-only mode allowing changes between pages; no snapshot claim.
    pub allow_change: bool,
    /// Maximum number of rows in this page.
    pub max_items: usize,
    /// Maximum key and value payload bytes in this page.
    pub max_bytes: usize,
}

/// Coherent page with explicit exhaustion and a generation for subsequent calls.
#[derive(Debug)]
pub struct Page<O = Kernel> {
    /// Namespace generation observed atomically with this page.
    pub generation: u64,
    /// Ordered addresses and owned wiping values.
    pub rows: Vec<(Address, Secret<Vec<u8>, O>)>,
    /// Exclusive continuation cursor; absent means exhausted.
    pub next: Option<Vec<u8>>,
}

/// Mandatory primitive interface implemented by an admitted loader binding.
///
/// Core owns business interpretation. Implementations preserve pending leases and
/// candidate custody and never convert cancellation or malformed replies to rollback.
pub trait PersistenceBackend: Send + Sync {
    /// Facts verified for this specific opened instance, fixed for its lifetime.
    fn info(&self) -> BackendInfo;
    /// Read a coherent set of values and evaluate an optional time guard.
    fn read(&self, request: std::sync::Arc<Read>) -> Call<'_, ReadResult>;
    /// Scan one coherent generation-checked page.
    fn scan(&self, request: std::sync::Arc<Scan>) -> Call<'_, Page>;
    /// Commit all effects and their receipt, or return a truthful decision.
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision>;
    /// Observe authoritative UTC seconds; not a substitute for atomic time guards.
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation>;
}

#[cfg(test)]
#[path = "tests/persistence_tests.rs"]
mod tests;
