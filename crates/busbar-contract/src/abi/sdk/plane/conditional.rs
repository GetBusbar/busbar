// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Logical conditional record publication. The guest names no physical key or operation id.

use crate::abi::mechanism::{extensions, ticket::Ticket};
use crate::abi::sdk::secret_bytes::SecretBytes;
use crate::abi::sdk::store::conditional::{Decision, Expected};
use zeroize::{Zeroize, Zeroizing};

/// Host capability, present only with a supporting configured store.
pub const CAPABILITY: &str = "busbar.plane.record-transaction/1";
/// Statement-only guarded record kind indices: count followed by little-endian u32 indices.
pub const REQUIRED_KINDS: &str = "busbar.plane.record-transaction.required-kinds/1";
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

impl Zeroize for RecordPredicate {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.expected.zeroize();
    }
}
impl Zeroize for RecordMutation {
    fn zeroize(&mut self) {
        match self {
            Self::Put { key, value, .. } => {
                key.zeroize();
                value.zeroize();
            }
            Self::Delete { key, .. } => key.zeroize(),
        }
    }
}
impl Zeroize for ChainMutation {
    fn zeroize(&mut self) {
        match self {
            Self::Check { scope, life, .. } | Self::Drop { scope, life, .. } => {
                scope.zeroize();
                life.zeroize();
            }
            Self::Append {
                scope,
                life,
                content,
                ..
            } => {
                scope.zeroize();
                life.zeroize();
                content.zeroize();
            }
        }
    }
}
impl Zeroize for ConditionalCandidate {
    fn zeroize(&mut self) {
        self.predicates.zeroize();
        self.mutations.zeroize();
        self.chains.zeroize();
    }
}
impl Zeroize for Request {
    fn zeroize(&mut self) {
        self.candidate.zeroize();
    }
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

impl Encode for Vec<u8> {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }
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
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&c.ticket.slot.to_le_bytes());
    out.extend_from_slice(&c.ticket.generation.to_le_bytes());
    out.extend_from_slice(&c.epoch.to_le_bytes());
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
    fn bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
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
    let mut rest = bytes;
    let mut found = None;
    while !rest.is_empty() {
        let mut r = Read(rest);
        let n = u16::from_le_bytes(r.take(2)?.try_into().map_err(|_| INVALID)?) as usize;
        let name = r.take(n)?;
        let n = r.u32()? as usize;
        let value = r.take(n)?;
        if name == key.as_bytes() {
            if found.is_some() {
                return Err(INVALID);
            }
            found = Some(value);
        }
        rest = r.0;
    }
    Ok(found)
}
/// Whether any feature key occurs, including a truncated feature value.
pub fn present(mut bytes: &[u8]) -> bool {
    while bytes.len() >= 2 {
        let n = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let Some(key) = bytes.get(2..2 + n) else {
            return false;
        };
        if [
            CAPABILITY,
            REQUIRED_KINDS,
            INTENT,
            RESULT,
            SETTLEMENT,
            SETTLEMENT_ACK,
            OBSERVE,
            OBSERVED,
        ]
        .iter()
        .any(|k| key == k.as_bytes())
        {
            return true;
        }
        let Some(v) = bytes.get(2 + n..6 + n) else {
            return false;
        };
        let nvalue = u32::from_le_bytes(v.try_into().expect("four bytes")) as usize;
        let Some(rest) = (6 + n).checked_add(nvalue).and_then(|n| bytes.get(n..)) else {
            return false;
        };
        bytes = rest;
    }
    false
}
/// Encode the host capability as an extension entry.
pub fn encode_capability(c: Capability) -> Vec<u8> {
    let mut out = Vec::new();
    authority(&mut out, c);
    extensions::encode(&[(CAPABILITY, &out)])
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
        let k = r.u32()?;
        if kinds.contains(&k) {
            return Err(INVALID);
        }
        kinds.push(k);
    }
    r.end()?;
    Ok(kinds)
}
/// Encode the Statement's protocol support and guarded kind set together.
pub fn statement(kinds: &[u32]) -> Result<Vec<u8>, &'static str> {
    let mut value = Vec::new();
    count(&mut value, kinds.len())?;
    for k in kinds {
        value.extend_from_slice(&k.to_le_bytes());
    }
    let encoded = extensions::encode(&[(CAPABILITY, b"1"), (REQUIRED_KINDS, &value)]);
    required_kinds(&encoded)?;
    Ok(encoded)
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
    let mut bytes = encode_request_held(request)?;
    Ok(std::mem::take(&mut *bytes))
}

pub(crate) fn encode_request_held(request: &Request) -> Result<Zeroizing<Vec<u8>>, &'static str> {
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
    if out.len() > crate::abi::mechanism::check::HARD_MAX_BYTES as usize {
        return Err(INVALID);
    }

    let mut encoded = SecretBytes::with_capacity(extensions::entry_len(INTENT, &out));
    encoded.extend_from_slice(&(INTENT.len() as u16).to_le_bytes());
    encoded.extend_from_slice(INTENT.as_bytes());
    encoded.extend_from_slice(&u32::try_from(out.len()).map_err(|_| INVALID)?.to_le_bytes());
    encoded.extend_from_slice(&out);
    Ok(encoded.into_zeroizing())
}

fn request_digest(request: &Request) -> Result<[u8; 32], &'static str> {
    let encoded = encode_request_held(request)?;
    Ok(crate::abi::sdk::digest::sha256(&encoded))
}

fn held_bytes(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(bytes);
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
        if let Expected::Bytes(bytes) = &mut self.0 {
            bytes.zeroize();
        }
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
        self.0.zeroize();
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
        let mut key = held_bytes(r.bytes()?);
        let mut expected = HeldExpected::new(r.expected()?);

        decoded.0.candidate.predicates.reserve(1);
        decoded.0.candidate.predicates.push(RecordPredicate {
            kind,
            key: std::mem::take(&mut *key),
            expected: expected.take(),
        });
    }
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let mut key = held_bytes(r.bytes()?);
        let mut value = match tag {
            0 => held_bytes(Vec::new()),
            1 => held_bytes(r.bytes()?),
            _ => return Err(INVALID),
        };
        decoded.0.candidate.mutations.reserve(1);
        decoded.0.candidate.mutations.push(match tag {
            0 => RecordMutation::Delete {
                kind,
                key: std::mem::take(&mut *key),
            },
            1 => RecordMutation::Put {
                kind,
                key: std::mem::take(&mut *key),
                value: std::mem::take(&mut *value),
            },
            _ => unreachable!("the mutation tag was checked before handoff"),
        });
    }
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let mut scope = held_bytes(r.bytes()?);
        let mut life = HeldExpected::new(r.expected()?);
        let mut content = match tag {
            0 | 2 => held_bytes(Vec::new()),
            1 => held_bytes(r.bytes()?),
            _ => return Err(INVALID),
        };
        decoded.0.candidate.chains.reserve(1);
        let scope = std::mem::take(&mut *scope);
        let life = life.take();
        decoded.0.candidate.chains.push(match tag {
            2 => ChainMutation::Check { kind, scope, life },
            0 => ChainMutation::Drop { kind, scope, life },
            1 => ChainMutation::Append {
                kind,
                scope,
                life,
                content: std::mem::take(&mut *content),
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
    let mut out = Vec::new();
    authority(&mut out, request.capability);
    out.extend_from_slice(&result.correlation.to_le_bytes());
    out.extend_from_slice(&request_digest(request)?);
    out.push(match result.decision {
        Ok(Decision::Applied) => 0,
        Ok(Decision::ConditionConflict) => 1,
        Err(ConditionalFailure::Refused(_)) => 2,
        Err(ConditionalFailure::OpIdConflict) => 3,
        Err(ConditionalFailure::Indeterminate) => 4,
    });
    Ok(extensions::encode(&[(RESULT, &out)]))
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
    let encoded = encode_result(request, result)?;
    let body = entry(&encoded, RESULT)?.ok_or(INVALID)?;
    Ok(extensions::encode(&[(SETTLEMENT, body)]))
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
    let mut body = Vec::new();
    authority(&mut body, settlement.capability);
    body.extend_from_slice(&settlement.result.correlation.to_le_bytes());
    body.extend_from_slice(&settlement.request_digest);
    extensions::encode(&[(SETTLEMENT_ACK, &body)])
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
    let mut out = Vec::new();
    authority(&mut out, request.capability);
    out.extend_from_slice(&request.correlation.to_le_bytes());
    out.extend_from_slice(&request.kind.to_le_bytes());
    blob(&mut out, &request.scope)?;
    Ok(extensions::encode(&[(OBSERVE, &out)]))
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
    let mut out = Vec::new();
    authority(&mut out, request.capability);
    out.extend_from_slice(&result.correlation.to_le_bytes());
    out.extend_from_slice(&request.kind.to_le_bytes());
    blob(&mut out, &request.scope)?;
    match &result.result {
        Ok(value) => {
            out.push(0);
            expected(&mut out, value)?;
        }
        Err(_) => out.push(1),
    }
    Ok(extensions::encode(&[(OBSERVED, &out)]))
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
    if r.u32()? != request.kind || r.bytes()? != request.scope {
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
    fn inspection_cannot_append_to_an_existing_conditional_output() {
        use crate::abi::mechanism::call::{OutHead, Outcome};
        use crate::abi::mechanism::inspection::{
            InspectionError, InspectionQuery, InspectionRequest,
        };
        use crate::abi::sdk::{life::Leases, Out};
        let request = Request {
            capability: cap(),
            candidate: ConditionalCandidate {
                correlation: 18,
                predicates: Vec::new(),
                mutations: Vec::new(),
                chains: Vec::new(),
            },
        };
        let observation = Observation {
            capability: cap(),
            correlation: 19,
            kind: 0,
            scope: b"scope".to_vec(),
        };
        let inspection = InspectionRequest {
            ticket: cap().ticket,
            epoch: cap().epoch,
            id: 20,
            query: InspectionQuery::Work {
                reference: b"work".to_vec(),
            },
        };
        for observe in [false, true] {
            let leases = Leases::default();
            // SAFETY: OutHead contains only integers and raw pointers, all valid when zero.
            let mut out: OutHead = unsafe { std::mem::zeroed() };
            if observe {
                Out::new(&mut out)
                    .conditional_observation(&leases, &observation)
                    .unwrap();
            } else {
                Out::new(&mut out)
                    .conditional_request(&leases, &request)
                    .unwrap();
            }
            let original = (out.extensions.ptr, out.lease);
            assert_eq!(
                Out::new(&mut out).inspection_request(&leases, &inspection),
                Err(InspectionError::Busy)
            );
            assert_eq!((out.extensions.ptr, out.lease), original);
            assert_eq!(leases.release(out.lease), Outcome::Ready);
        }
    }

    #[test]
    fn settlement_ack_writer_owns_its_lease_and_refuses_mixed_or_changed_identity() {
        use crate::abi::mechanism::call::{OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET};
        use crate::abi::sdk::{life::Leases, Out};
        let request = Request {
            capability: cap(),
            candidate: ConditionalCandidate {
                correlation: 18,
                predicates: Vec::new(),
                mutations: Vec::new(),
                chains: Vec::new(),
            },
        };
        let settlement = read_settlement(
            &encode_settlement(
                &request,
                &ConditionalResult {
                    correlation: 18,
                    decision: Ok(Decision::Applied),
                },
            )
            .unwrap(),
        )
        .unwrap()
        .unwrap();
        let leases = Leases::default();
        let holders = crate::abi::sdk::out::Holders::default();
        // SAFETY: OutHead contains only integers and raw pointers, all valid when zero.
        let mut out: OutHead = unsafe { std::mem::zeroed() };
        Out::new(&mut out).lease_secret(
            |o| &o.extensions,
            &leases,
            extensions::encode(&[("unrelated", b"kept secret")]),
            BLOB_OCTETS,
        );
        assert_eq!(
            Out::witnessed(&mut out, &holders).conditional_settlement_ack(&leases, &settlement),
            Ok(())
        );
        assert!(crate::abi::sdk::out::holders_live(&holders));
        let (pointer, lease) = (out.extensions.ptr, out.lease);
        assert_eq!(out.extensions.flags, BLOB_SECRET);
        // SAFETY: the SDK lease retains every byte until release below.
        let bytes = unsafe { std::slice::from_raw_parts(out.extensions.ptr, out.extensions.len) };
        assert_eq!(
            extensions::get(bytes, "unrelated"),
            Some(b"kept secret".as_slice())
        );
        assert!(read_settlement_ack(bytes)
            .unwrap()
            .unwrap()
            .matches(&request)
            .unwrap());
        assert_eq!(
            Out::new(&mut out).conditional_settlement_ack(&leases, &settlement),
            Ok(())
        );
        assert_eq!((out.extensions.ptr, out.lease), (pointer, lease));
        let mut changed = settlement.clone();
        changed.request_digest[0] ^= 1;
        assert!(Out::new(&mut out)
            .conditional_settlement_ack(&leases, &changed)
            .is_err());
        assert!(Out::new(&mut out)
            .conditional_request(&leases, &request)
            .is_err());
        let observation = Observation {
            capability: cap(),
            correlation: 19,
            kind: 0,
            scope: b"scope".to_vec(),
        };
        assert!(Out::new(&mut out)
            .conditional_observation(&leases, &observation)
            .is_err());
        let inspection = crate::abi::mechanism::inspection::InspectionRequest {
            ticket: cap().ticket,
            epoch: cap().epoch,
            id: 20,
            query: crate::abi::mechanism::inspection::InspectionQuery::Work {
                reference: b"work".to_vec(),
            },
        };
        assert_eq!(
            Out::new(&mut out).inspection_request(&leases, &inspection),
            Err(crate::abi::mechanism::inspection::InspectionError::Busy)
        );
        assert_eq!((out.extensions.ptr, out.lease), (pointer, lease));
        assert_eq!(leases.release(lease), Outcome::Ready);
        assert_eq!(leases.release(lease), Outcome::Refused);
        drop(leases);
        assert!(!crate::abi::sdk::out::holders_live(&holders));
        for key in [
            INTENT,
            OBSERVE,
            RESULT,
            OBSERVED,
            CAPABILITY,
            SETTLEMENT,
            crate::abi::mechanism::inspection::EXT_REQUEST,
        ] {
            let leases = Leases::default();
            // SAFETY: the same pointer/integer-only output frame.
            let mut out: OutHead = unsafe { std::mem::zeroed() };
            Out::new(&mut out).lease(
                |o| &o.extensions,
                &leases,
                extensions::encode(&[(key, b"occupied")]),
                BLOB_OCTETS,
            );
            let original = (out.extensions.ptr, out.lease);
            assert!(Out::new(&mut out)
                .conditional_settlement_ack(&leases, &settlement)
                .is_err());
            assert_eq!((out.extensions.ptr, out.lease), original);
            assert_eq!(leases.release(out.lease), Outcome::Ready);
        }
        let mut invalid = settlement;
        invalid.result.correlation = 0;
        // SAFETY: an empty output frame, no memory borrowed from it.
        let mut empty: OutHead = unsafe { std::mem::zeroed() };
        assert!(Out::new(&mut empty)
            .conditional_settlement_ack(&Leases::default(), &invalid)
            .is_err());
        assert_eq!(empty.extensions.len, 0);
        assert_eq!(empty.lease, 0);
        let leases = Leases::default();
        assert_eq!(
            Out::new(&mut empty).inspection_request(&leases, &inspection),
            Ok(())
        );
        let original = (empty.extensions.ptr, empty.lease);
        assert!(Out::new(&mut empty)
            .conditional_settlement_ack(&leases, &changed)
            .is_err());
        assert_eq!((empty.extensions.ptr, empty.lease), original);
        assert_eq!(leases.release(empty.lease), Outcome::Ready);
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

    #[test]
    fn output_helpers_preserve_secret_extensions_and_release_every_copy_wiped() {
        use crate::abi::mechanism::call::{OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET};
        use crate::abi::sdk::{life::Leases, Out};
        use crate::alloc_counter::InitializedPayloadProbe;
        let secret = [0xA7; 32];
        for helper in 0..3 {
            // SAFETY: every registered owned blob stays on this thread through lease release.
            let probe =
                unsafe { InitializedPayloadProbe::start().expect("open the memory observer") };
            let leases = Leases::default();
            // SAFETY: OutHead contains only integers and raw pointers, all valid when zero.
            let mut out: OutHead = unsafe { std::mem::zeroed() };
            Out::new(&mut out).lease_secret(
                |o| &o.extensions,
                &leases,
                extensions::encode(&[("unrelated", &secret)]),
                BLOB_OCTETS,
            );
            let mut expected_lengths = vec![out.extensions.len];
            let request = Request {
                capability: cap(),
                candidate: ConditionalCandidate {
                    correlation: 2,
                    predicates: Vec::new(),
                    mutations: Vec::new(),
                    chains: Vec::new(),
                },
            };
            let observation = Observation {
                capability: cap(),
                correlation: 1,
                kind: 0,
                scope: b"scope".to_vec(),
            };
            let settlement = read_settlement(
                &encode_settlement(
                    &request,
                    &ConditionalResult {
                        correlation: 2,
                        decision: Ok(Decision::Applied),
                    },
                )
                .unwrap(),
            )
            .unwrap()
            .unwrap();
            let put = |out: &mut OutHead| match helper {
                0 => Out::new(out).conditional_request(&leases, &request),
                1 => Out::new(out).conditional_observation(&leases, &observation),
                _ => Out::new(out).conditional_settlement_ack(&leases, &settlement),
            };
            assert_eq!(put(&mut out), Ok(()));
            expected_lengths.push(out.extensions.len);
            let pointer = out.extensions.ptr;
            let lease = out.lease;
            assert_eq!(out.extensions.flags, BLOB_SECRET);
            // SAFETY: the output's lease owns these bytes until its release below.
            let bytes =
                unsafe { std::slice::from_raw_parts(out.extensions.ptr, out.extensions.len) };
            assert_eq!(extensions::get(bytes, "unrelated"), Some(secret.as_slice()));
            assert_eq!(put(&mut out), Ok(()));
            assert_eq!((out.extensions.ptr, out.lease), (pointer, lease));
            let mut changed = request.clone();
            changed.candidate.correlation += 1;
            assert!(Out::new(&mut out)
                .conditional_request(&leases, &changed)
                .is_err());
            let mut changed = observation.clone();
            changed.scope.push(b'x');
            assert!(Out::new(&mut out)
                .conditional_observation(&leases, &changed)
                .is_err());
            let mut changed = settlement.clone();
            changed.request_digest[0] ^= 1;
            assert!(Out::new(&mut out)
                .conditional_settlement_ack(&leases, &changed)
                .is_err());
            assert_eq!((out.extensions.ptr, out.lease), (pointer, lease));
            assert_eq!(leases.release(lease), Outcome::Ready);
            assert_eq!(leases.release(lease), Outcome::Refused);
            drop(leases);
            let observations = probe.finish();
            assert!(
                !observations.reentered,
                "OS memory reader reentered the allocator"
            );
            for len in expected_lengths {
                assert!(
                    observations.payloads.iter().any(|record| record.len == len),
                    "observe the original secret blob and the final composed copy"
                );
            }

            for record in &observations.payloads {
                assert!(record.freed, "secret allocation was not freed: {record:?}");
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(record.read_error, None, "OS memory read failed: {record:?}");
                    assert!(
                        record.complete_read,
                        "OS memory read was incomplete: {record:?}"
                    );
                    assert_eq!(record.bytes_read, record.len);
                    assert!(
                        record.wiped,
                        "original and composed secret blobs must be wiped: {record:?}"
                    );
                }
                #[cfg(not(target_os = "linux"))]
                {
                    assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
                    assert!(!record.complete_read);
                    assert_eq!(record.bytes_read, 0);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        eprintln!("Secret blobs and frees checked; memory proof requires Linux /proc/self/mem");
    }
}

#[cfg(test)]
#[path = "../tests/conditional_custody_tests.rs"]
mod custody_tests;
