// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::connections::grant::{GrantPurpose, GrantState, GrantVersion};
use crate::governance::at_rest::{CallerRecordContext, CallerRecordKind};
use busbar_contract::persistence::{AttemptId, DatasetId};
use busbar_contract::secure::SecureVec;

const MAGIC: &[u8; 8] = b"BBGINT01";
const HEADER: usize = 147;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Pending,
    Applied,
    NoEffect,
}
impl Phase {
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Applied => 2,
            Self::NoEffect => 3,
        }
    }
    pub(super) fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Applied),
            3 => Ok(Self::NoEffect),
            _ => Err(Error::Corrupt),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Header {
    pub(super) generation: u64,
    pub(super) origin: AttemptId,
    pub(super) purpose: u8,
    pub(super) before: Option<GrantVersion>,
    pub(super) after: GrantVersion,
    pub(super) transition: [u8; 32],
}
impl Header {
    pub(super) fn for_change(
        origin: AttemptId,
        generation: u64,
        change: &ValidatedGrantChange,
    ) -> Self {
        let mut header = Self {
            generation,
            origin,
            purpose: purpose(change.purpose()),
            before: change.before(),
            after: change.after(),
            transition: [0; 32],
        };
        header.transition = *transition(
            &header,
            change.encoded_key(),
            change.previous(),
            change.successor(),
        )
        .as_bytes();
        header
    }
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.origin.dataset.0);
        out.extend_from_slice(&self.origin.writer_epoch.to_be_bytes());
        out.extend_from_slice(&self.origin.writer);
        out.extend_from_slice(&self.origin.execution_epoch.to_be_bytes());
        out.extend_from_slice(&self.origin.operation);
        out.push(self.purpose);
        for version in [self.before, Some(self.after)] {
            out.extend_from_slice(&version.map_or(0, |v| v.epoch).to_be_bytes());
            out.extend_from_slice(&version.map_or(0, |v| v.revision).to_be_bytes());
            out.push(version.map_or(0, |v| v.state as u8));
        }
        out.extend_from_slice(&self.transition);
        out
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HEADER || &bytes[..8] != MAGIC {
            return Err(Error::Corrupt);
        }
        fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], Error> {
            bytes
                .get(start..start + N)
                .ok_or(Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)
        }
        fn number(bytes: &[u8], start: usize) -> Result<u64, Error> {
            Ok(u64::from_be_bytes(array(bytes, start)?))
        }
        fn version(bytes: &[u8], start: usize) -> Result<Option<GrantVersion>, Error> {
            let epoch = number(bytes, start)?;
            let revision = number(bytes, start + 8)?;
            let state = match bytes[start + 16] {
                0 if epoch == 0 && revision == 0 => return Ok(None),
                1 => GrantState::Live,
                2 => GrantState::Minting,
                3 => GrantState::ReconnectRequired,
                4 => GrantState::Revoked,
                _ => return Err(Error::Corrupt),
            };
            if epoch == 0 || revision == 0 {
                return Err(Error::Corrupt);
            }
            Ok(Some(GrantVersion {
                epoch,
                revision,
                state,
            }))
        }
        let header = Self {
            generation: number(bytes, 8)?,
            origin: AttemptId {
                dataset: DatasetId(array(bytes, 16)?),
                writer_epoch: number(bytes, 32)?,
                writer: array(bytes, 40)?,
                execution_epoch: number(bytes, 56)?,
                operation: array(bytes, 64)?,
            },
            purpose: bytes[80],
            before: version(bytes, 81)?,
            after: version(bytes, 98)?.ok_or(Error::Corrupt)?,
            transition: array(bytes, 115)?,
        };
        if header.generation == 0
            || header.origin.dataset.0 == [0; 16]
            || header.origin.writer_epoch == 0
            || header.origin.writer == [0; 16]
            || header.origin.execution_epoch == 0
            || header.origin.operation == [0; 16]
            || !(1..=8).contains(&header.purpose)
        {
            return Err(Error::Corrupt);
        }
        Ok(header)
    }
}
fn purpose(p: GrantPurpose) -> u8 {
    match p {
        GrantPurpose::Install => 1,
        GrantPurpose::Refresh => 2,
        GrantPurpose::RevokeCurrent => 3,
        GrantPurpose::RevokeExplicit => 4,
        GrantPurpose::Delivery => 5,
        GrantPurpose::Rewrap => 6,
        GrantPurpose::MintStart => 7,
        GrantPurpose::MintFinish => 8,
    }
}

fn transition(
    header: &Header,
    key: &[u8],
    previous: Option<&Secret<Vec<u8>>>,
    next: &Secret<Vec<u8>>,
) -> crate::hashing::SecretDigest {
    let mut hash = crate::hashing::Sha256::new();
    hash.update(b"busbar.caller.transition/1\0");
    let encoded = header.encode();
    hash.update(&encoded[..115]);
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key);
    hash.update([u8::from(previous.is_some())]);
    let seal = crate::seal::lend();
    for value in previous.into_iter().chain(std::iter::once(next)) {
        let bytes = value.expose(&seal);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hash.finalize_secret()
}

fn context<'a>(
    owner: &CallerIntents,
    key: &'a [u8],
    header: &Header,
    binding: &'a [u8],
    kind: CallerRecordKind,
) -> Result<CallerRecordContext<'a>, Error> {
    if header.origin.dataset != owner.store.info().dataset {
        return Err(Error::Authority);
    }
    CallerRecordContext::new(
        kind,
        owner.store.info().dataset.0,
        owner.store.info().atomic_domain,
        key,
        header.generation,
        header.origin.operation,
        binding,
    )
    .map_err(|_| Error::Invalid)
}
fn seal(
    owner: &CallerIntents,
    key: &[u8],
    header: &Header,
    kind: CallerRecordKind,
    plain: &[u8],
) -> Result<Secret<Vec<u8>>, Error> {
    if plain
        .len()
        .checked_add(HEADER + 128)
        .ok_or(Error::Overflow)?
        > owner.store.limits().scan_bytes
    {
        return Err(Error::Budget);
    }
    let binding = header.encode();
    let encrypted = owner
        .records
        .seal(&context(owner, key, header, &binding, kind)?, plain)
        .map_err(|_| Error::Corrupt)?;
    let mut bytes =
        SecureVec::with_capacity(HEADER + encrypted.len()).map_err(|_| Error::Budget)?;
    bytes.extend_from_slice(&binding);
    bytes.extend_from_slice(&encrypted);
    Ok(Secret::new(bytes.into_vec()))
}
fn open(
    owner: &CallerIntents,
    key: &[u8],
    kind: CallerRecordKind,
    value: &Secret<Vec<u8>>,
) -> Result<(Header, SecureVec), Error> {
    let seal = crate::seal::lend();
    let bytes = value.expose(&seal);
    if bytes.len() > owner.store.limits().scan_bytes {
        return Err(Error::Budget);
    }
    let binding = bytes.get(..HEADER).ok_or(Error::Corrupt)?;
    let header = Header::decode(binding)?;
    let plain = owner
        .records
        .open(
            &context(owner, key, &header, binding, kind)?,
            &bytes[HEADER..],
        )
        .map_err(|_| Error::Corrupt)?;
    Ok((header, plain))
}
pub(super) fn seal_guard(
    owner: &CallerIntents,
    key: &[u8],
    header: &Header,
    phase: Phase,
) -> Result<Secret<Vec<u8>>, Error> {
    seal(owner, key, header, CallerRecordKind::Guard, &[phase.tag()])
}
pub(super) fn seal_terminal(
    owner: &CallerIntents,
    key: &[u8],
    header: &Header,
    phase: Phase,
) -> Result<Secret<Vec<u8>>, Error> {
    if phase == Phase::Pending {
        return Err(Error::Invalid);
    }
    seal(
        owner,
        key,
        header,
        CallerRecordKind::Terminal,
        &[phase.tag()],
    )
}
pub(super) fn seal_prepared(
    owner: &CallerIntents,
    key: &[u8],
    header: &Header,
    candidate: &PreparedCandidate,
) -> Result<Secret<Vec<u8>>, Error> {
    let snapshot = super::super::candidate_codec::encode(
        candidate,
        owner.store.limits().scan_bytes,
        &crate::seal::lend(),
    )
    .map_err(|_| Error::Budget)?;
    let snapshot = snapshot.expose(&crate::seal::lend());
    let mut bytes = SecureVec::with_capacity(snapshot.len() + 1).map_err(|_| Error::Budget)?;
    bytes.extend_from_slice(&[Phase::Pending.tag()]);
    bytes.extend_from_slice(snapshot);
    seal(owner, key, header, CallerRecordKind::Prepared, &bytes)
}
pub(super) fn validate_pair(
    owner: &CallerIntents,
    key: &[u8],
    guard: &Secret<Vec<u8>>,
    intent: &Secret<Vec<u8>>,
) -> Result<(Header, Phase), Error> {
    let (header, guard_plain) = open(owner, key, CallerRecordKind::Guard, guard)?;
    if guard_plain.len() != 1 {
        return Err(Error::Corrupt);
    }
    let phase = Phase::decode(guard_plain[0])?;
    if phase == Phase::Pending {
        let (found, _) = prepared(owner, key, guard, intent)?;
        if found != header {
            return Err(Error::Corrupt);
        }
    } else {
        let (found, plain) = open(owner, key, CallerRecordKind::Terminal, intent)?;
        if found != header || plain.as_slice() != [phase.tag()] {
            return Err(Error::Corrupt);
        }
    }
    Ok((header, phase))
}
pub(super) fn prepared(
    owner: &CallerIntents,
    key: &[u8],
    guard: &Secret<Vec<u8>>,
    intent: &Secret<Vec<u8>>,
) -> Result<(Header, PreparedCandidate), Error> {
    let (header, mut plain) = open(owner, key, CallerRecordKind::Prepared, intent)?;
    if plain.first() != Some(&Phase::Pending.tag()) {
        return Err(Error::Corrupt);
    }
    plain.consume(1);
    let snapshot = Secret::new(plain.into_vec());
    let candidate = super::super::candidate_codec::decode(
        &snapshot,
        owner.store.limits().scan_bytes / 4,
        &crate::seal::lend(),
    )
    .map_err(|_| Error::Corrupt)?;
    let body = candidate.candidate();
    if body.id != header.origin
        || body.time.is_some()
        || !body.result.expose(&crate::seal::lend()).is_empty()
        || body.predicates.len() != 2
        || body.mutations.len() != 3
    {
        return Err(Error::Corrupt);
    }
    let guard_at = owner.address(GUARD, key)?;
    let grant_at = owner.address(GRANT, key)?;
    let intent_at = owner.address(INTENT, key)?;
    if body.predicates[0].address != guard_at || body.predicates[1].address != grant_at {
        return Err(Error::Corrupt);
    }
    if !matches!(&body.predicates[0].expected,ExpectedValue::Exact(v) if v==guard) {
        return Err(Error::Corrupt);
    }
    let mut values = Vec::with_capacity(3);
    for (mutation, expected) in body
        .mutations
        .iter()
        .zip([&grant_at, &guard_at, &intent_at])
    {
        match mutation {
            Mutation::Put { address, value } if address == expected => values.push(value),
            _ => return Err(Error::Corrupt),
        }
    }
    let previous = match &body.predicates[1].expected {
        ExpectedValue::Absent => None,
        ExpectedValue::Exact(value) => Some(value),
    };
    if previous.is_some() != header.before.is_some()
        || !transition(&header, key, previous, values[0]).matches(&header.transition)
    {
        return Err(Error::Corrupt);
    }
    // Validate the terminal directly: malformed nested Prepared envelopes must
    // not turn decoding one fixed-shape intent into recursive work.
    let (terminal, guard_plain) = open(owner, key, CallerRecordKind::Guard, values[1])?;
    let (terminal_intent, intent_plain) = open(owner, key, CallerRecordKind::Terminal, values[2])?;
    if terminal != header
        || terminal_intent != header
        || guard_plain.as_slice() != [Phase::Applied.tag()]
        || intent_plain.as_slice() != [Phase::Applied.tag()]
    {
        return Err(Error::Corrupt);
    }
    Ok((header, candidate))
}
