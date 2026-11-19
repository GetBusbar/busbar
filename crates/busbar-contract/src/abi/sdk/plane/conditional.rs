// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Logical conditional record publication. The guest names no physical key or operation id.

use crate::abi::mechanism::{extensions, ticket::Ticket};
use crate::abi::sdk::secret_bytes::SecretBytes;
use crate::abi::sdk::wipe::wipe_bytes;
use crate::host_records::{Decision, Expected};
use crate::secure::SecureVec;
use zeroize::Zeroize;

/// Host capability, present only with a supporting configured store.
pub const CAPABILITY: &str = "busbar.plane.record-transaction/1";
/// Statement-only guarded record kind indices: count followed by little-endian u32 indices.
pub const REQUIRED_KINDS: &str = "busbar.plane.record-transaction.required-kinds/1";
/// Statement-only opt-in: unrelated operations may run without transactional storage.
/// Guarded kinds still forbid ordinary writes; each conditional operation requires
/// the actual host capability before any dependent external effect.
pub const OPTIONAL: &str = "busbar.plane.record-transaction.optional/1";
/// Pending logical intent.
pub const INTENT: &str = "busbar.plane.record-transaction";
/// Definitive result of the exact pending intent.
pub const RESULT: &str = "busbar.plane.record-transaction.result";
/// Outcome-only receipt for an original submitted commit whose normal operation ended.
pub const SETTLEMENT: &str = "busbar.plane.record-transaction.settlement";
/// Acknowledgement that the exact original receipt's local obligations were consumed.
pub const SETTLEMENT_ACK: &str = "busbar.plane.record-transaction.settlement-ack";
/// Read-only chain incarnation observation, issued before planning reads.
pub const OBSERVE: &str = "busbar.plane.record-transaction.observe";
/// The immutable original chain incarnation.
pub const OBSERVED: &str = "busbar.plane.record-transaction.observed";
/// Malformed or unsupported exchange.
pub const INVALID: &str = "invalid conditional record exchange";

/// One logical comparison under the instance's declared record kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPredicate {
    /// Declared kind index.
    pub kind: u32,
    /// Logical key.
    pub key: Vec<u8>,
    /// Required pre-state.
    pub expected: Expected,
}
/// One logical record mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordMutation {
    /// Put nonempty bytes.
    Put {
        /// Declared record kind index.
        kind: u32,
        /// Logical key.
        key: Vec<u8>,
        /// Nonempty bytes.
        value: Vec<u8>,
    },
    /// Remove a record.
    Delete {
        /// Declared record kind index.
        kind: u32,
        /// Logical key.
        key: Vec<u8>,
    },
}
/// One logical chain operation, sealed by the kernel inside the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMutation {
    /// Assert the original incarnation without changing the chain.
    Check {
        /// Declared chained record kind index.
        kind: u32,
        /// Logical chain scope.
        scope: Vec<u8>,
        /// Original incarnation observed before fresh state reads.
        life: Expected,
    },
    /// Append content.
    Append {
        /// Declared chained record kind index.
        kind: u32,
        /// Logical chain scope.
        scope: Vec<u8>,
        /// Original incarnation observed before fresh state reads; never recaptured at commit.
        life: Expected,
        /// Content for the host to frame and sign.
        content: Vec<u8>,
    },
    /// Drop a scope.
    Drop {
        /// Declared chained record kind index.
        kind: u32,
        /// Logical chain scope.
        scope: Vec<u8>,
        /// Original incarnation observed before fresh state reads.
        life: Expected,
    },
}
/// Immutable guest intent; correlation is local to the current host ticket epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalCandidate {
    /// Nonzero monotonically increasing candidate identity within an epoch.
    pub correlation: u64,
    /// Exact comparisons.
    pub predicates: Vec<RecordPredicate>,
    /// Record changes.
    pub mutations: Vec<RecordMutation>,
    /// Chain changes.
    pub chains: Vec<ChainMutation>,
}
/// Definitive failure; uncertain storage outcomes never produce a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalFailure {
    /// Authority, capability or storage refusal.
    Refused(&'static str),
    /// Kernel operation identity conflict.
    OpIdConflict,
    /// The replay horizon ended without a definitive answer. Never replan this candidate.
    Indeterminate,
}
/// The exact candidate's definitive result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalResult {
    /// Original candidate correlation.
    pub correlation: u64,
    /// Definitive decision.
    pub decision: Result<Decision, ConditionalFailure>,
}
/// Host-issued authority for this operation. Never transferable between tickets or epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// Actual host ticket.
    pub ticket: Ticket,
    /// Host service epoch.
    pub epoch: u64,
}
/// Fully owned intent copied while the answer lease lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Capability read from this crossing.
    pub capability: Capability,
    /// Immutable logical candidate.
    pub candidate: ConditionalCandidate,
}

// Each impl below does exactly what its field-by-field `Zeroize` calls did: a `Vec<u8>` wipes its
// whole capacity and empties, an `Expected` wipes its bytes, a list wipes each element, empties and
// volatile-zeroes its spare capacity (`Zeroize for Vec<T>`).
impl Zeroize for RecordPredicate {
    fn zeroize(&mut self) {
        wipe_predicate(self);
    }
}
impl Zeroize for RecordMutation {
    fn zeroize(&mut self) {
        wipe_mutation(self);
    }
}
impl Zeroize for ChainMutation {
    fn zeroize(&mut self) {
        wipe_chain(self);
    }
}
impl Zeroize for ConditionalCandidate {
    fn zeroize(&mut self) {
        wipe_candidate(self);
    }
}
impl Zeroize for Request {
    fn zeroize(&mut self) {
        wipe_candidate(&mut self.candidate);
    }
}

/// `Zeroize for Expected`: its bytes, if any, wiped whole.
fn wipe_expected(expected: &mut Expected) {
    if let Expected::Bytes(bytes) = expected {
        wipe_bytes(bytes);
    }
}
fn wipe_predicate(p: &mut RecordPredicate) {
    wipe_bytes(&mut p.key);
    wipe_expected(&mut p.expected);
}
fn wipe_mutation(m: &mut RecordMutation) {
    match m {
        RecordMutation::Put { key, value, .. } => {
            wipe_bytes(key);
            wipe_bytes(value);
        }
        RecordMutation::Delete { key, .. } => wipe_bytes(key),
    }
}
fn wipe_chain(m: &mut ChainMutation) {
    match m {
        ChainMutation::Check { scope, life, .. } | ChainMutation::Drop { scope, life, .. } => {
            wipe_bytes(scope);
            wipe_expected(life);
        }
        ChainMutation::Append {
            scope,
            life,
            content,
            ..
        } => {
            wipe_bytes(scope);
            wipe_expected(life);
            wipe_bytes(content);
        }
    }
}
fn wipe_candidate(c: &mut ConditionalCandidate) {
    wipe_list(&mut c.predicates, wipe_predicate);
    wipe_list(&mut c.mutations, wipe_mutation);
    wipe_list(&mut c.chains, wipe_chain);
}

/// `Zeroize for Vec<T>`: wipe every element, drop them all, then volatile-zero every byte of the
/// spare capacity (which now holds the dropped elements' bytes) and fence.
fn wipe_list<T>(items: &mut Vec<T>, wipe: fn(&mut T)) {
    for item in items.iter_mut() {
        wipe(item);
    }
    items.clear();
    let spare = items.spare_capacity_mut();
    let len = core::mem::size_of_val(spare);
    // SAFETY: `spare` is `len` bytes of the live allocation, borrowed exclusively, and
    // `MaybeUninit<u8>` carries no validity invariant and has alignment 1.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            spare.as_mut_ptr().cast::<core::mem::MaybeUninit<u8>>(),
            len,
        )
    };
    for byte in bytes {
        // SAFETY: an exclusive, aligned reference into the live allocation.
        unsafe { core::ptr::write_volatile(byte, core::mem::MaybeUninit::new(0)) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// A read-only chain incarnation observation bound to the host's current operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Capability read from this crossing.
    pub capability: Capability,
    /// Nonzero identity, increasing across both observations and publications.
    pub correlation: u64,
    /// Declared chained record kind index.
    pub kind: u32,
    /// Logical scope.
    pub scope: Vec<u8>,
}

/// Original chain life, to retain before fresh reads and carry into the candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationResult {
    /// Original observation identity.
    pub correlation: u64,
    /// Absent or exact incarnation bytes; never inferred from task contents.
    pub result: Result<Expected, ConditionalFailure>,
}

/// An immutable original observation, retaining the logical address with its CAS bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedChain {
    /// Declared chained record kind index.
    pub kind: u32,
    /// Original logical scope.
    pub scope: Vec<u8>,
    /// Original incarnation, never refreshed while preparing or replaying a candidate.
    pub life: Expected,
}

impl Observation {
    /// Associate a decoded result with the exact logical address that requested it.
    pub fn observed(&self, result: ObservationResult) -> Result<ObservedChain, ConditionalFailure> {
        if result.correlation != self.correlation {
            return Err(ConditionalFailure::Refused(INVALID));
        }
        Ok(ObservedChain {
            kind: self.kind,
            scope: self.scope.clone(),
            life: result.result?,
        })
    }
}

trait Encode {
    fn extend_from_slice(&mut self, bytes: &[u8]);
    fn push(&mut self, byte: u8);
}

impl Encode for SecretBytes {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        SecretBytes::extend_from_slice(self, bytes);
    }
    fn push(&mut self, byte: u8) {
        SecretBytes::push(self, byte);
    }
}

fn expected(out: &mut impl Encode, value: &Expected) -> Result<(), &'static str> {
    match value {
        Expected::Absent => out.push(0),
        Expected::Bytes(bytes) => {
            out.push(1);
            blob(out, bytes)?;
        }
    }
    Ok(())
}

fn blob(out: &mut impl Encode, value: &[u8]) -> Result<(), &'static str> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| INVALID)?
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}
fn count(out: &mut impl Encode, n: usize) -> Result<(), &'static str> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| INVALID)?.to_le_bytes());
    Ok(())
}
fn authority(out: &mut impl Encode, c: Capability) {
    out.extend_from_slice(&authority_bytes(c));
}
/// The capability's wire form: version 1, ticket slot and generation, epoch.
fn authority_bytes(c: Capability) -> [u8; 20] {
    let mut out = [0; 20];
    out[..4].copy_from_slice(&1_u32.to_le_bytes());
    out[4..8].copy_from_slice(&c.ticket.slot.to_le_bytes());
    out[8..12].copy_from_slice(&c.ticket.generation.to_le_bytes());
    out[12..].copy_from_slice(&c.epoch.to_le_bytes());
    out
}
/// A blob's `u32` length prefix.
fn blob_len(value: &[u8]) -> Result<[u8; 4], &'static str> {
    Ok(u32::try_from(value.len())
        .map_err(|_| INVALID)?
        .to_le_bytes())
}
/// One extension entry whose value is `parts` in order, written once into the returned buffer:
/// the bytes `extensions::encode(&[(key, value)])` writes for the joined value, and nothing when
/// the key or value outgrows its length prefix (an entry `encode` skips).
fn entry_of(key: &str, parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|part| part.len()).sum::<usize>();
    let (Ok(key_len), Ok(value_len)) = (u16::try_from(key.len()), u32::try_from(len)) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(extensions::entry_len(key, &[]) + len);
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&value_len.to_le_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}
struct Read<'a>(&'a [u8]);
impl<'a> Read<'a> {
    fn expected(&mut self) -> Result<Expected, &'static str> {
        match self.take(1)?[0] {
            0 => Ok(Expected::Absent),
            1 => Ok(Expected::Bytes(self.bytes()?)),
            _ => Err(INVALID),
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let (a, b) = self.0.split_at_checked(n).ok_or(INVALID)?;
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| INVALID)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| INVALID)?,
        ))
    }
    /// A length-prefixed blob, borrowed from the lent bytes.
    fn slice(&mut self) -> Result<&'a [u8], &'static str> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// A length-prefixed blob, copied out: the one copy an owned public field (`key`, `scope`,
    /// `Expected::Bytes`) takes while the lease lives.
    fn bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        Ok(self.slice()?.to_vec())
    }
    fn capability(&mut self) -> Result<Capability, &'static str> {
        if self.u32()? != 1 {
            return Err(INVALID);
        }
        let c = Capability {
            ticket: Ticket {
                slot: self.u32()?,
                generation: self.u32()?,
            },
            epoch: self.u64()?,
        };
        if c.ticket.is_none() || c.epoch == 0 {
            return Err(INVALID);
        }
        Ok(c)
    }
    fn end(self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}
/// Read a unique feature entry, rejecting truncated or duplicate feature envelopes.
pub fn entry<'a>(bytes: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, &'static str> {
    extensions::unique(bytes, key).map_err(|_| INVALID)
}
/// Whether any feature key occurs, including a truncated feature value.
pub fn present(bytes: &[u8]) -> bool {
    extensions::present(
        bytes,
        &[
            CAPABILITY,
            REQUIRED_KINDS,
            OPTIONAL,
            INTENT,
            RESULT,
            SETTLEMENT,
            SETTLEMENT_ACK,
            OBSERVE,
            OBSERVED,
        ],
    )
}
/// Encode the host capability as an extension entry.
pub fn encode_capability(c: Capability) -> Vec<u8> {
    entry_of(CAPABILITY, &[&authority_bytes(c)])
}
/// Read the Statement's guarded kind set; duplicate indices are invalid.
pub fn required_kinds(bytes: &[u8]) -> Result<Vec<u32>, &'static str> {
    let Some(value) = entry(bytes, REQUIRED_KINDS)? else {
        return Ok(Vec::new());
    };
    let mut r = Read(value);
    let n = r.u32()?;
    let mut kinds = Vec::new();
    for _ in 0..n {
        kinds.push(r.u32()?);
    }
    r.end()?;
    // A handful of kinds: each is compared with those before it, in place.
    if (1..kinds.len()).any(|i| kinds[..i].contains(&kinds[i])) {
        return Err(INVALID);
    }
    Ok(kinds)
}
/// Encode the Statement's protocol support and guarded kind set together.
pub fn statement(kinds: &[u32]) -> Result<Vec<u8>, &'static str> {
    let n = u32::try_from(kinds.len()).map_err(|_| INVALID)?;
    // The kinds entry's value (count, then each index) is written straight into the returned
    // buffer; a value past its `u32` length prefix is skipped, as `extensions::encode` skips it.
    let value_len = kinds
        .len()
        .checked_mul(4)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| u32::try_from(len).ok());
    let kinds_len = value_len.map_or(0, |len| {
        extensions::entry_len(REQUIRED_KINDS, &[]) + len as usize
    });
    let mut encoded = Vec::with_capacity(extensions::entry_len(CAPABILITY, b"1") + kinds_len);
    extensions::encode_into(&mut encoded, &[(CAPABILITY, b"1")]);
    if let Some(len) = value_len {
        encoded.extend_from_slice(&(REQUIRED_KINDS.len() as u16).to_le_bytes());
        encoded.extend_from_slice(REQUIRED_KINDS.as_bytes());
        encoded.extend_from_slice(&len.to_le_bytes());
        encoded.extend_from_slice(&n.to_le_bytes());
        for k in kinds {
            encoded.extend_from_slice(&k.to_le_bytes());
        }
    }
    required_kinds(&encoded)?;
    Ok(encoded)
}
/// Declare an optional transactional feature without weakening its guarded kinds.
/// Older hosts conservatively keep the original mandatory storage requirement.
pub fn optional_statement(kinds: &[u32]) -> Result<Vec<u8>, &'static str> {
    let mut encoded = statement(kinds)?;
    extensions::encode_into(&mut encoded, &[(OPTIONAL, b"1")]);
    Ok(encoded)
}
/// Read the strict optional-storage marker; absence preserves mandatory admission.
pub fn optional(bytes: &[u8]) -> Result<bool, &'static str> {
    match entry(bytes, OPTIONAL)? {
        None => Ok(false),
        Some(b"1") => Ok(true),
        Some(_) => Err(INVALID),
    }
}

#[cfg(test)]
#[test]
fn optional_statement_preserves_guards_and_rejects_ambiguous_markers() {
    let encoded = optional_statement(&[1, 4]).unwrap();
    assert_eq!(entry(&encoded, CAPABILITY), Ok(Some(b"1".as_slice())));
    assert_eq!(required_kinds(&encoded), Ok(vec![1, 4]));
    assert_eq!(optional(&encoded), Ok(true));
    assert_eq!(optional(&statement(&[1, 4]).unwrap()), Ok(false));
    assert!(optional_statement(&[1, 1]).is_err());
    assert!(optional(&extensions::encode(&[(OPTIONAL, b"0")])).is_err());
    let mut duplicated = encoded;
    duplicated.extend_from_slice(&extensions::encode(&[(OPTIONAL, b"1")]));
    assert!(optional(&duplicated).is_err());
}
/// Read the host capability. Absence means unsupported, never a fallback to ordinary writes.
pub fn read_capability(bytes: &[u8]) -> Result<Option<Capability>, &'static str> {
    let Some(value) = entry(bytes, CAPABILITY)? else {
        return Ok(None);
    };
    let mut r = Read(value);
    let c = r.capability()?;
    r.end()?;
    Ok(Some(c))
}
/// Encode one immutable pending candidate, bound to this crossing's capability.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, &'static str> {
    Ok(encode_request_held(request)?.into_vec())
}

pub(crate) fn encode_request_held(request: &Request) -> Result<SecureVec, &'static str> {
    let mut out = SecretBytes::default();
    authority(&mut out, request.capability);
    let c = &request.candidate;
    if c.correlation == 0 {
        return Err(INVALID);
    }
    out.extend_from_slice(&c.correlation.to_le_bytes());
    count(&mut out, c.predicates.len())?;
    for p in &c.predicates {
        out.extend_from_slice(&p.kind.to_le_bytes());
        blob(&mut out, &p.key)?;
        match &p.expected {
            Expected::Absent => out.push(0),
            Expected::Bytes(b) => {
                out.push(1);
                blob(&mut out, b)?;
            }
        }
    }
    count(&mut out, c.mutations.len())?;
    for m in &c.mutations {
        match m {
            RecordMutation::Put { kind, key, value } => {
                out.push(1);
                out.extend_from_slice(&kind.to_le_bytes());
                blob(&mut out, key)?;
                blob(&mut out, value)?;
            }
            RecordMutation::Delete { kind, key } => {
                out.push(0);
                out.extend_from_slice(&kind.to_le_bytes());
                blob(&mut out, key)?;
            }
        }
    }
    count(&mut out, c.chains.len())?;
    for m in &c.chains {
        match m {
            ChainMutation::Check { kind, scope, life } => {
                out.push(2);
                out.extend_from_slice(&kind.to_le_bytes());
                blob(&mut out, scope)?;
                expected(&mut out, life)?;
            }
            ChainMutation::Append {
                kind,
                scope,
                life,
                content,
            } => {
                out.push(1);
                out.extend_from_slice(&kind.to_le_bytes());
                blob(&mut out, scope)?;
                expected(&mut out, life)?;
                blob(&mut out, content)?;
            }
            ChainMutation::Drop { kind, scope, life } => {
                out.push(0);
                out.extend_from_slice(&kind.to_le_bytes());
                blob(&mut out, scope)?;
                expected(&mut out, life)?;
            }
        }
    }
    if extensions::entry_len(INTENT, &out) > crate::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err(INVALID);
    }

    let mut encoded = SecretBytes::with_capacity(extensions::entry_len(INTENT, &out));
    encoded.extend_from_slice(&(INTENT.len() as u16).to_le_bytes());
    encoded.extend_from_slice(INTENT.as_bytes());
    encoded.extend_from_slice(&u32::try_from(out.len()).map_err(|_| INVALID)?.to_le_bytes());
    encoded.extend_from_slice(&out);
    Ok(encoded.into_secure())
}

fn request_digest(request: &Request) -> Result<[u8; 32], &'static str> {
    let encoded = encode_request_held(request)?;
    Ok(crate::abi::sdk::digest::sha256(&encoded))
}

fn held_bytes(bytes: Vec<u8>) -> SecureVec {
    let bytes = SecureVec::from(bytes);
    #[cfg(test)]
    crate::abi::sdk::secret_bytes::watch(&bytes);
    bytes
}

struct HeldExpected(Expected);
impl HeldExpected {
    fn new(expected: Expected) -> Self {
        #[cfg(test)]
        if let Expected::Bytes(bytes) = &expected {
            crate::abi::sdk::secret_bytes::watch(bytes);
        }
        Self(expected)
    }
    fn take(&mut self) -> Expected {
        std::mem::replace(&mut self.0, Expected::Absent)
    }
}
impl Drop for HeldExpected {
    fn drop(&mut self) {
        wipe_expected(&mut self.0);
    }
}

struct Decoding(Request);
impl Decoding {
    fn take(mut self) -> Request {
        let candidate = &mut self.0.candidate;
        Request {
            capability: self.0.capability,
            candidate: ConditionalCandidate {
                correlation: candidate.correlation,
                predicates: std::mem::take(&mut candidate.predicates),
                mutations: std::mem::take(&mut candidate.mutations),
                chains: std::mem::take(&mut candidate.chains),
            },
        }
    }
}
impl Drop for Decoding {
    fn drop(&mut self) {
        wipe_candidate(&mut self.0.candidate);
    }
}
/// Decode and own every candidate byte before returning the plugin's answer lease.
pub fn read_request(bytes: &[u8]) -> Result<Option<Request>, &'static str> {
    if bytes.len() > crate::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err(INVALID);
    }
    let Some(value) = entry(bytes, INTENT)? else {
        return Ok(None);
    };
    let mut r = Read(value);
    let capability = r.capability()?;
    let correlation = r.u64()?;
    if correlation == 0 {
        return Err(INVALID);
    }
    let mut decoded = Decoding(Request {
        capability,
        candidate: ConditionalCandidate {
            correlation,
            predicates: Vec::new(),
            mutations: Vec::new(),
            chains: Vec::new(),
        },
    });
    for _ in 0..r.u32()? {
        let kind = r.u32()?;
        let key = held_bytes(r.bytes()?);
        let mut expected = HeldExpected::new(r.expected()?);

        decoded.0.candidate.predicates.reserve(1);
        decoded.0.candidate.predicates.push(RecordPredicate {
            kind,
            key: key.into_vec(),
            expected: expected.take(),
        });
    }
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let key = held_bytes(r.bytes()?);
        let value = match tag {
            0 => held_bytes(Vec::new()),
            1 => held_bytes(r.bytes()?),
            _ => return Err(INVALID),
        };
        decoded.0.candidate.mutations.reserve(1);
        decoded.0.candidate.mutations.push(match tag {
            0 => RecordMutation::Delete {
                kind,
                key: key.into_vec(),
            },
            1 => RecordMutation::Put {
                kind,
                key: key.into_vec(),
                value: value.into_vec(),
            },
            _ => unreachable!("the mutation tag was checked before handoff"),
        });
    }
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let scope = held_bytes(r.bytes()?);
        let mut life = HeldExpected::new(r.expected()?);
        let content = match tag {
            0 | 2 => held_bytes(Vec::new()),
            1 => held_bytes(r.bytes()?),
            _ => return Err(INVALID),
        };
        decoded.0.candidate.chains.reserve(1);
        let scope = scope.into_vec();
        let life = life.take();
        decoded.0.candidate.chains.push(match tag {
            2 => ChainMutation::Check { kind, scope, life },
            0 => ChainMutation::Drop { kind, scope, life },
            1 => ChainMutation::Append {
                kind,
                scope,
                life,
                content: content.into_vec(),
            },
            _ => unreachable!("the chain tag was checked before handoff"),
        });
    }
    r.end()?;
    Ok(Some(decoded.take()))
}
/// Encode a definitive result bound to its actual ticket and epoch.
pub fn encode_result(
    request: &Request,
    result: &ConditionalResult,
) -> Result<Vec<u8>, &'static str> {
    Ok(entry_of(RESULT, &[&result_body(request, result)?]))
}
/// A result's fixed-size body: authority, correlation, request digest, decision.
fn result_body(request: &Request, result: &ConditionalResult) -> Result<[u8; 61], &'static str> {
    let mut out = [0; 61];
    out[..20].copy_from_slice(&authority_bytes(request.capability));
    out[20..28].copy_from_slice(&result.correlation.to_le_bytes());
    out[28..60].copy_from_slice(&request_digest(request)?);
    out[60] = match result.decision {
        Ok(Decision::Applied) => 0,
        Ok(Decision::ConditionConflict) => 1,
        Err(ConditionalFailure::Refused(_)) => 2,
        Err(ConditionalFailure::OpIdConflict) => 3,
        Err(ConditionalFailure::Indeterminate) => 4,
    };
    Ok(out)
}
/// Accept only the exact outstanding candidate's result; a missing result remains pending.
pub fn read_result(
    bytes: &[u8],
    request: &Request,
) -> Result<Option<ConditionalResult>, &'static str> {
    let Some(value) = entry(bytes, RESULT)? else {
        return Ok(None);
    };
    let mut r = Read(value);
    if r.capability()? != request.capability {
        return Err(INVALID);
    }
    let correlation = r.u64()?;
    if correlation != request.candidate.correlation {
        return Err(INVALID);
    }
    if r.take(32)? != request_digest(request)? {
        return Err(INVALID);
    }
    let decision = match r.take(1)?[0] {
        0 => Ok(Decision::Applied),
        1 => Ok(Decision::ConditionConflict),
        2 => Err(ConditionalFailure::Refused(
            "conditional record transaction refused",
        )),
        3 => Err(ConditionalFailure::OpIdConflict),
        4 => Err(ConditionalFailure::Indeterminate),
        _ => return Err(INVALID),
    };
    r.end()?;
    Ok(Some(ConditionalResult {
        correlation,
        decision,
    }))
}

/// A receipt delivered only to settle an original canceled commit. It grants no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The original operation's ticket and epoch, never the delivery driver's authority.
    pub capability: Capability,
    /// The immutable original commit result.
    pub result: ConditionalResult,
    /// Digest of the exact original request, as in ordinary result receipts.
    pub request_digest: [u8; 32],
}

impl Settlement {
    /// Match an existing retained request without reconstructing or resubmitting a candidate.
    pub fn matches(&self, request: &Request) -> Result<bool, &'static str> {
        Ok(self.capability == request.capability
            && self.result.correlation == request.candidate.correlation
            && self.request_digest == request_digest(request)?)
    }
}

/// The exact original identity acknowledged after outcome-only local settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAck {
    /// Original operation identity, not the delivery driver.
    pub capability: Capability,
    /// Original commit correlation.
    pub correlation: u64,
    /// Digest of the exact original request.
    pub request_digest: [u8; 32],
}
impl SettlementAck {
    /// Validate this acknowledgement against the original retained commit.
    pub fn matches(&self, request: &Request) -> Result<bool, &'static str> {
        Ok(self.capability == request.capability
            && self.correlation == request.candidate.correlation
            && self.request_digest == request_digest(request)?)
    }
}

/// Encode a host-only settlement receipt using the existing immutable result body.
pub fn encode_settlement(
    request: &Request,
    result: &ConditionalResult,
) -> Result<Vec<u8>, &'static str> {
    Ok(entry_of(SETTLEMENT, &[&result_body(request, result)?]))
}

/// Decode an outcome-only receipt; match it to retained Request custody before local effects.
pub fn read_settlement(bytes: &[u8]) -> Result<Option<Settlement>, &'static str> {
    let Some(body) = entry(bytes, SETTLEMENT)? else {
        return Ok(None);
    };
    let mut reader = Read(body);
    let capability = reader.capability()?;
    let correlation = reader.u64()?;
    if correlation == 0 {
        return Err(INVALID);
    }
    let request_digest = reader.take(32)?.try_into().map_err(|_| INVALID)?;
    let decision = match reader.take(1)?[0] {
        0 => Ok(Decision::Applied),
        1 => Ok(Decision::ConditionConflict),
        2 => Err(ConditionalFailure::Refused(
            "conditional record transaction refused",
        )),
        3 => Err(ConditionalFailure::OpIdConflict),
        4 => Err(ConditionalFailure::Indeterminate),
        _ => return Err(INVALID),
    };
    reader.end()?;
    Ok(Some(Settlement {
        capability,
        result: ConditionalResult {
            correlation,
            decision,
        },
        request_digest,
    }))
}

/// Acknowledge only an exact receipt consumed by outcome-only settlement. This is not a request.
pub fn encode_settlement_ack(settlement: &Settlement) -> Vec<u8> {
    entry_of(
        SETTLEMENT_ACK,
        &[
            &authority_bytes(settlement.capability),
            &settlement.result.correlation.to_le_bytes(),
            &settlement.request_digest,
        ],
    )
}

/// Decode an outcome-only acknowledgement for the host's retained original request.
pub fn read_settlement_ack(bytes: &[u8]) -> Result<Option<SettlementAck>, &'static str> {
    let Some(body) = entry(bytes, SETTLEMENT_ACK)? else {
        return Ok(None);
    };
    let mut reader = Read(body);
    let capability = reader.capability()?;
    let correlation = reader.u64()?;
    if correlation == 0 {
        return Err(INVALID);
    }
    let request_digest = reader.take(32)?.try_into().map_err(|_| INVALID)?;
    reader.end()?;
    Ok(Some(SettlementAck {
        capability,
        correlation,
        request_digest,
    }))
}

/// Encode an observation. Pend before any planning read; retain the result unchanged.
pub fn encode_observation(request: &Observation) -> Result<Vec<u8>, &'static str> {
    if request.correlation == 0 {
        return Err(INVALID);
    }
    Ok(entry_of(
        OBSERVE,
        &[
            &authority_bytes(request.capability),
            &request.correlation.to_le_bytes(),
            &request.kind.to_le_bytes(),
            &blob_len(&request.scope)?,
            &request.scope,
        ],
    ))
}
/// Copy a read-only observation request while its answer lease lives.
pub fn read_observation(bytes: &[u8]) -> Result<Option<Observation>, &'static str> {
    let Some(bytes) = entry(bytes, OBSERVE)? else {
        return Ok(None);
    };
    let mut r = Read(bytes);
    let capability = r.capability()?;
    let correlation = r.u64()?;
    if correlation == 0 {
        return Err(INVALID);
    }
    let kind = r.u32()?;
    let scope = r.bytes()?;
    r.end()?;
    Ok(Some(Observation {
        capability,
        correlation,
        kind,
        scope,
    }))
}
/// Encode the exact observation's result.
pub fn encode_observed(
    request: &Observation,
    result: &ObservationResult,
) -> Result<Vec<u8>, &'static str> {
    // The result: `1` refused; `0` then the incarnation, `0` absent or `1` and its blob.
    const ZERO: &[u8] = &[0];
    const ONE: &[u8] = &[1];
    const NONE: &[u8] = &[];
    let len_bytes;
    let (tag, life_tag, life_len, life) = match &result.result {
        Ok(Expected::Absent) => (ZERO, ZERO, NONE, NONE),
        Ok(Expected::Bytes(bytes)) => {
            len_bytes = blob_len(bytes)?;
            (ZERO, ONE, &len_bytes[..], bytes.as_slice())
        }
        Err(_) => (ONE, NONE, NONE, NONE),
    };
    Ok(entry_of(
        OBSERVED,
        &[
            &authority_bytes(request.capability),
            &result.correlation.to_le_bytes(),
            &request.kind.to_le_bytes(),
            &blob_len(&request.scope)?,
            &request.scope,
            tag,
            life_tag,
            life_len,
            life,
        ],
    ))
}
/// Read the original observation only on its actual ticket, epoch and correlation.
pub fn read_observed(
    bytes: &[u8],
    request: &Observation,
) -> Result<Option<ObservationResult>, &'static str> {
    let Some(bytes) = entry(bytes, OBSERVED)? else {
        return Ok(None);
    };
    let mut r = Read(bytes);
    if r.capability()? != request.capability || r.u64()? != request.correlation {
        return Err(INVALID);
    }
    if r.u32()? != request.kind || r.slice()? != request.scope.as_slice() {
        return Err(INVALID);
    }
    let result = match r.take(1)?[0] {
        0 => Ok(r.expected()?),
        1 => Err(ConditionalFailure::Refused("chain observation refused")),
        _ => return Err(INVALID),
    };
    if result
        .as_ref()
        .is_ok_and(|v| matches!(v,Expected::Bytes(bytes) if bytes.len()!=8))
    {
        return Err(INVALID);
    }
    r.end()?;
    Ok(Some(ObservationResult {
        correlation: request.correlation,
        result,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap() -> Capability {
        Capability {
            ticket: Ticket {
                slot: 9,
                generation: 7,
            },
            epoch: 13,
        }
    }
    #[test]
    fn logical_wire_copies_original_life_and_refuses_truncation_duplicates_and_wrong_receipts() {
        let request = Request {
            capability: cap(),
            candidate: ConditionalCandidate {
                correlation: 2,
                predicates: vec![RecordPredicate {
                    kind: 0,
                    key: vec![0, 255],
                    expected: Expected::Absent,
                }],
                mutations: vec![RecordMutation::Delete {
                    kind: 0,
                    key: vec![0, 255],
                }],
                chains: vec![ChainMutation::Check {
                    kind: 1,
                    scope: b"task".to_vec(),
                    life: Expected::Bytes(3_u64.to_le_bytes().to_vec()),
                }],
            },
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(read_request(&bytes), Ok(Some(request.clone())));
        for n in 1..bytes.len() {
            assert!(read_request(&bytes[..n]).is_err());
        }
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(read_request(&duplicate).is_err());
        let result = ConditionalResult {
            correlation: 2,
            decision: Err(ConditionalFailure::Indeterminate),
        };
        let bytes = encode_result(&request, &result).unwrap();
        assert_eq!(read_result(&bytes, &request), Ok(Some(result)));
        let mut changed = request.clone();
        changed.candidate.predicates.clear();
        assert!(read_result(&bytes, &changed).is_err());
        let mut changed = request;
        changed.capability.epoch += 1;
        assert!(read_result(&bytes, &changed).is_err());
    }
    #[test]
    fn settlement_and_ack_bind_the_original_request_without_submission_authority() {
        let request = Request {
            capability: cap(),
            candidate: ConditionalCandidate {
                correlation: 17,
                predicates: vec![RecordPredicate {
                    kind: 1,
                    key: b"original".to_vec(),
                    expected: Expected::Absent,
                }],
                mutations: vec![RecordMutation::Delete {
                    kind: 1,
                    key: b"original".to_vec(),
                }],
                chains: Vec::new(),
            },
        };
        for decision in [
            Ok(Decision::Applied),
            Ok(Decision::ConditionConflict),
            Err(ConditionalFailure::Indeterminate),
        ] {
            let result = ConditionalResult {
                correlation: 17,
                decision,
            };
            let bytes = encode_settlement(&request, &result).unwrap();
            let receipt = read_settlement(&bytes).unwrap().unwrap();
            assert_eq!(receipt.result, result);
            assert!(receipt.matches(&request).unwrap());
            assert!(read_request(&bytes).unwrap().is_none());
            assert!(read_capability(&bytes).unwrap().is_none());
            assert!(read_result(&bytes, &request).unwrap().is_none());
            let ack_bytes = encode_settlement_ack(&receipt);
            let ack = read_settlement_ack(&ack_bytes).unwrap().unwrap();
            assert!(ack.matches(&request).unwrap());
            assert!(read_request(&ack_bytes).unwrap().is_none());
            assert!(read_settlement(&ack_bytes).unwrap().is_none());
            let mut changed = request.clone();
            changed.candidate.mutations.push(RecordMutation::Delete {
                kind: 1,
                key: b"another".to_vec(),
            });
            assert!(!receipt.matches(&changed).unwrap());
            assert!(!ack.matches(&changed).unwrap());
            for n in 1..bytes.len() {
                assert!(read_settlement(&bytes[..n]).is_err());
            }
            for n in 1..ack_bytes.len() {
                assert!(read_settlement_ack(&ack_bytes[..n]).is_err());
            }
            let mut duplicate = bytes.clone();
            duplicate.extend_from_slice(&bytes);
            assert!(read_settlement(&duplicate).is_err());
            let mut duplicate = ack_bytes.clone();
            duplicate.extend_from_slice(&ack_bytes);
            assert!(read_settlement_ack(&duplicate).is_err());
        }
    }

    #[test]
    fn observations_preserve_scope_and_life_and_are_distinct_from_commit_receipts() {
        let request = Observation {
            capability: cap(),
            correlation: 1,
            kind: 2,
            scope: b"original".to_vec(),
        };
        assert_eq!(
            read_observation(&encode_observation(&request).unwrap()),
            Ok(Some(request.clone()))
        );
        let result = ObservationResult {
            correlation: 1,
            result: Ok(Expected::Bytes(11_u64.to_le_bytes().to_vec())),
        };
        let bytes = encode_observed(&request, &result).unwrap();
        let decoded = read_observed(&bytes, &request).unwrap().unwrap();
        assert_eq!(
            request.observed(decoded).unwrap(),
            ObservedChain {
                kind: 2,
                scope: b"original".to_vec(),
                life: Expected::Bytes(11_u64.to_le_bytes().to_vec())
            }
        );
        let mut changed = request;
        changed.correlation += 1;
        assert!(read_observed(&bytes, &changed).is_err());
        assert_eq!(required_kinds(&statement(&[1, 4]).unwrap()), Ok(vec![1, 4]));
        assert!(statement(&[1, 1]).is_err());
    }
}
