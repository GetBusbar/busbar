// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Logical conditional record publication. The guest names no physical key or operation id.
//! Publish intent only with PENDING and no other output. Retain the candidate until its exact
//! receipt arrives on RESUME/DRIVE. ConditionConflict permits replanning that operation;
//! Applied permits the next independent publication. Refused and Indeterminate permit neither.

use crate::abi::mechanism::{extensions, ticket::Ticket};
use crate::abi::sdk::store::conditional::{Decision, Expected};

/// Host capability, present only with a supporting configured store.
pub const CAPABILITY: &str = "busbar.plane.record-transaction/1";
/// Statement-only guarded record kind indices: count followed by little-endian u32 indices.
pub const REQUIRED_KINDS: &str = "busbar.plane.record-transaction.required-kinds/1";
/// Pending logical intent.
pub const INTENT: &str = "busbar.plane.record-transaction";
/// Definitive result of the exact pending intent.
pub const RESULT: &str = "busbar.plane.record-transaction.result";
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

fn expected(out: &mut Vec<u8>, value: &Expected) -> Result<(), &'static str> {
    match value {
        Expected::Absent => out.push(0),
        Expected::Bytes(bytes) => {
            out.push(1);
            blob(out, bytes)?;
        }
    }
    Ok(())
}

fn blob(out: &mut Vec<u8>, value: &[u8]) -> Result<(), &'static str> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| INVALID)?
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}
fn count(out: &mut Vec<u8>, n: usize) -> Result<(), &'static str> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| INVALID)?.to_le_bytes());
    Ok(())
}
fn authority(out: &mut Vec<u8>, c: Capability) {
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
    let mut out = Vec::new();
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
    Ok(extensions::encode(&[(INTENT, &out)]))
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
    let mut predicates = Vec::new();
    for _ in 0..r.u32()? {
        let kind = r.u32()?;
        let key = r.bytes()?;
        let expected = match r.take(1)?[0] {
            0 => Expected::Absent,
            1 => Expected::Bytes(r.bytes()?),
            _ => return Err(INVALID),
        };
        predicates.push(RecordPredicate {
            kind,
            key,
            expected,
        });
    }
    let mut mutations = Vec::new();
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let key = r.bytes()?;
        mutations.push(match tag {
            0 => RecordMutation::Delete { kind, key },
            1 => RecordMutation::Put {
                kind,
                key,
                value: r.bytes()?,
            },
            _ => return Err(INVALID),
        });
    }
    let mut chains = Vec::new();
    for _ in 0..r.u32()? {
        let tag = r.take(1)?[0];
        let kind = r.u32()?;
        let scope = r.bytes()?;
        let life = r.expected()?;
        chains.push(match tag {
            2 => ChainMutation::Check { kind, scope, life },
            0 => ChainMutation::Drop { kind, scope, life },
            1 => ChainMutation::Append {
                kind,
                scope,
                life,
                content: r.bytes()?,
            },
            _ => return Err(INVALID),
        });
    }
    r.end()?;
    Ok(Some(Request {
        capability,
        candidate: ConditionalCandidate {
            correlation,
            predicates,
            mutations,
            chains,
        },
    }))
}
/// Encode a definitive result bound to its actual ticket and epoch.
pub fn encode_result(
    request: &Request,
    result: &ConditionalResult,
) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    authority(&mut out, request.capability);
    out.extend_from_slice(&result.correlation.to_le_bytes());
    out.extend_from_slice(&crate::abi::sdk::digest::sha256(&encode_request(request)?));
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
    if r.take(32)? != crate::abi::sdk::digest::sha256(&encode_request(request)?) {
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
        use crate::alloc_counter::{freed_unzeroed, marked_key};
        // The allocation witness's own controls reserve IDs 1..=7 in this test binary.
        let secret = marked_key::<32>(0);
        let before = freed_unzeroed(0);
        for observation_first in [false, true] {
            let leases = Leases::default();
            // SAFETY: OutHead contains only integers and raw pointers, all valid when zero.
            let mut out: OutHead = unsafe { std::mem::zeroed() };
            Out::new(&mut out).lease_secret(
                |o| &o.extensions,
                &leases,
                extensions::encode(&[("unrelated", &secret)]),
                BLOB_OCTETS,
            );
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
            let put = |out: &mut OutHead| {
                if observation_first {
                    Out::new(out).conditional_observation(&leases, &observation)
                } else {
                    Out::new(out).conditional_request(&leases, &request)
                }
            };
            assert_eq!(put(&mut out), Ok(()));
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
            assert_eq!((out.extensions.ptr, out.lease), (pointer, lease));
            assert_eq!(leases.release(lease), Outcome::Ready);
            assert_eq!(leases.release(lease), Outcome::Refused);
            drop(leases);
        }
        assert_eq!(
            freed_unzeroed(0),
            before,
            "original and composed secret blobs must be wiped before release frees them"
        );
    }
}
