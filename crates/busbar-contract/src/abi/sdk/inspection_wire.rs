// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opt-in, read-only host facts through the existing main-call extensions. These are Rust

use crate::abi::mechanism::{extensions, ticket::Ticket};

/// Negotiated capability, carrying this ticket's current host result epoch.
pub const EXT_CAPABILITY: &str = "host_inspection_v1";
/// One request, on a ticketed PENDING answer.
pub const EXT_REQUEST: &str = "host_inspection_request_v1";
/// The immutable correlated receipt, lent on RESUME or the driver's DRIVE.
pub const EXT_REPLY: &str = "host_inspection_reply_v1";
/// The supported wire version.
pub const VERSION: u8 = 1;
/// The existing mechanism's hard byte bound, also applied to the whole extended blob.
pub const MAX_BYTES: usize = crate::abi::mechanism::check::HARD_MAX_BYTES as usize;

/// An inspection refusal or an invalid local/wire exchange. Unknown is never unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionError {
    /// This host does not serve the negotiated inspection feature.
    Unsupported,
    /// The admitted caller has no such current work-book entry.
    NotFound,
    /// The host refused the caller's authority for the requested fact.
    Refused,
    /// The request, value, or byte budget is invalid.
    Invalid,
    /// A receipt did not name the current full request and result epoch.
    Correlation,
    /// A negotiated resumed crossing carried no receipt.
    MissingReceipt,
    /// Another query already owns this crossing or inspection state.
    Busy,
    /// Inspection requires a real ticket and nonzero result epoch.
    Unticketed,
}

impl std::fmt::Display for InspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "host inspection unsupported",
            Self::NotFound => "host inspection work not found",
            Self::Refused => "host inspection refused",
            Self::Invalid => "invalid host inspection",
            Self::Correlation => "host inspection correlation mismatch",
            Self::MissingReceipt => "host inspection receipt missing",
            Self::Busy => "host inspection already pending",
            Self::Unticketed => "host inspection requires a ticket",
        })
    }
}
impl std::error::Error for InspectionError {}

/// The only two generic host facts negotiated by version one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionQuery {
    /// Current admitted work already present in the host's work book. Does not import storage.
    Work { reference: Vec<u8> },
    /// Liveness of known opaque carrier IDs, in order; IDs are nonzero and unique.
    CarrierSessions { sessions: Vec<u64> },
}

/// Host work lifetime facts at one observation, all in integer milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkObservation {
    /// Host wall clock when these facts were read.
    pub observed_ms: u64,
    /// The host's actual work creation time.
    pub opened_ms: u64,
    /// The current instance policy's terminal retention duration.
    pub retain_ms: u64,
    /// Actual terminal settlement time. None means live: an expiry is not established.
    pub settled_ms: Option<u64>,
}

/// One known carrier's liveness, scoped to the admitted calling instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionObservation {
    /// The opaque ID supplied in the query.
    pub session: u64,
    /// Whether that caller still owns a live carrier with this ID.
    pub live: bool,
}

/// A copied observation; no borrowed plugin or host memory escapes the crossing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionObservation {
    Work(WorkObservation),
    CarrierSessions(Vec<SessionObservation>),
}

/// The optional host provider's synchronous read-only answer.
pub type InspectionResult = Result<InspectionObservation, InspectionError>;

/// The current host result epoch advertised to this ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectionCapability {
    pub epoch: u64,
}

/// One outstanding request per caller instance, ticket and epoch. IDs strictly increase within
/// an epoch; an identical ID can only replay the identical request. Never wrap an exhausted ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionRequest {
    pub ticket: Ticket,
    pub epoch: u64,
    pub id: u64,
    pub query: InspectionQuery,
}

/// The full request is repeated so neither a new query nor a reused ticket accepts an old answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionReceipt {
    pub request: InspectionRequest,
    pub result: InspectionResult,
}

/// Maximum carrier IDs fitting BOTH request and full correlated receipt, with the existing

#[must_use]
pub fn max_carrier_sessions(existing_extension_bytes: usize) -> usize {
    let request_overhead = 30 + extensions::entry_len(EXT_REQUEST, &[]);
    let reply_overhead =
        40 + extensions::entry_len(EXT_REPLY, &[]) + extensions::entry_len(EXT_CAPABILITY, &[0; 9]);
    let request =
        MAX_BYTES.saturating_sub(existing_extension_bytes.saturating_add(request_overhead)) / 8;
    let reply =
        MAX_BYTES.saturating_sub(existing_extension_bytes.saturating_add(reply_overhead)) / 17;
    request.min(reply)
}

/// Whether the query and its largest correlated receipt fit while retaining existing bytes.
#[must_use]
pub fn query_fits(query: &InspectionQuery, existing_extension_bytes: usize) -> bool {
    match query {
        InspectionQuery::Work { reference } => {
            let request = 30 + extensions::entry_len(EXT_REQUEST, &[]);
            let reply = 69
                + extensions::entry_len(EXT_REPLY, &[])
                + extensions::entry_len(EXT_CAPABILITY, &[0; 9]);
            let available = MAX_BYTES
                .saturating_sub(existing_extension_bytes.saturating_add(request.max(reply)));
            !reference.is_empty() && reference.len() <= available
        }
        InspectionQuery::CarrierSessions { sessions } => {
            !sessions.is_empty() && sessions.len() <= max_carrier_sessions(existing_extension_bytes)
        }
    }
}

fn valid_query(query: &InspectionQuery) -> Result<(), InspectionError> {
    match query {
        InspectionQuery::Work { .. } if query_fits(query, 0) => Ok(()),
        InspectionQuery::CarrierSessions { sessions }
            if !sessions.is_empty() && sessions.len() <= max_carrier_sessions(0) =>
        {
            let mut seen = std::collections::HashSet::with_capacity(sessions.len());
            if sessions.iter().all(|id| *id != 0 && seen.insert(*id)) {
                Ok(())
            } else {
                Err(InspectionError::Invalid)
            }
        }
        _ => Err(InspectionError::Invalid),
    }
}

fn valid_request(request: &InspectionRequest) -> Result<(), InspectionError> {
    if request.ticket.is_none() || request.epoch == 0 {
        return Err(InspectionError::Unticketed);
    }
    if request.id == 0 {
        return Err(InspectionError::Invalid);
    }
    valid_query(&request.query)
}

/// Encode a negotiated epoch. Epoch zero is never a usable capability.
pub fn encode_capability(epoch: u64) -> Result<Vec<u8>, InspectionError> {
    if epoch == 0 {
        return Err(InspectionError::Unticketed);
    }
    let mut bytes = vec![VERSION];
    bytes.extend_from_slice(&epoch.to_le_bytes());
    Ok(bytes)
}

/// Decode exactly one supported capability, refusing trailing bytes and unknown versions.
pub fn decode_capability(bytes: &[u8]) -> Result<InspectionCapability, InspectionError> {
    let mut read = Reader::new(bytes)?;
    let epoch = read.u64()?;
    read.end()?;
    if epoch == 0 {
        return Err(InspectionError::Unticketed);
    }
    Ok(InspectionCapability { epoch })
}

/// Encode one validated request.
pub fn encode_request(request: &InspectionRequest) -> Result<Vec<u8>, InspectionError> {
    valid_request(request)?;
    let mut out = vec![VERSION];
    out.extend_from_slice(&request.ticket.slot.to_le_bytes());
    out.extend_from_slice(&request.ticket.generation.to_le_bytes());
    out.extend_from_slice(&request.epoch.to_le_bytes());
    out.extend_from_slice(&request.id.to_le_bytes());
    match &request.query {
        InspectionQuery::Work { reference } => {
            out.push(1);
            put_bytes(&mut out, reference)?;
        }
        InspectionQuery::CarrierSessions { sessions } => {
            out.push(2);
            put_len(&mut out, sessions.len())?;
            for id in sessions {
                out.extend_from_slice(&id.to_le_bytes());
            }
        }
    }
    bounded(out)
}

/// Decode a validated request; no incomplete or extra data is accepted.
pub fn decode_request(bytes: &[u8]) -> Result<InspectionRequest, InspectionError> {
    let mut read = Reader::new(bytes)?;
    let ticket = Ticket {
        slot: read.u32()?,
        generation: read.u32()?,
    };
    let epoch = read.u64()?;
    let id = read.u64()?;
    let query = match read.byte()? {
        1 => {
            let reference = read.bytes()?;
            let overhead = 69
                + extensions::entry_len(EXT_REPLY, &[])
                + extensions::entry_len(EXT_CAPABILITY, &[0; 9]);
            if reference.is_empty() || reference.len() > MAX_BYTES - overhead {
                return Err(InspectionError::Invalid);
            }
            InspectionQuery::Work {
                reference: reference.to_vec(),
            }
        }
        2 => {
            let count = read.count(8)?;
            if count == 0 || count > max_carrier_sessions(0) {
                return Err(InspectionError::Invalid);
            }
            let mut sessions = Vec::with_capacity(count);
            for _ in 0..count {
                sessions.push(read.u64()?);
            }
            InspectionQuery::CarrierSessions { sessions }
        }
        _ => return Err(InspectionError::Invalid),
    };
    read.end()?;
    let request = InspectionRequest {
        ticket,
        epoch,
        id,
        query,
    };
    valid_request(&request)?;
    Ok(request)
}

fn matching(request: &InspectionRequest, result: &InspectionResult) -> Result<(), InspectionError> {
    match (&request.query, result) {
        (_, Err(_)) | (InspectionQuery::Work { .. }, Ok(InspectionObservation::Work(_))) => Ok(()),
        (
            InspectionQuery::CarrierSessions { sessions },
            Ok(InspectionObservation::CarrierSessions(found)),
        ) if sessions.len() == found.len()
            && sessions
                .iter()
                .zip(found)
                .all(|(id, found)| *id == found.session) =>
        {
            Ok(())
        }
        _ => Err(InspectionError::Correlation),
    }
}

/// Encode an immutable receipt, including the full request and exact ordered response shape.
pub fn encode_receipt(receipt: &InspectionReceipt) -> Result<Vec<u8>, InspectionError> {
    matching(&receipt.request, &receipt.result)?;
    let request = encode_request(&receipt.request)?;
    let mut out = vec![VERSION];
    put_bytes(&mut out, &request)?;
    match &receipt.result {
        Ok(InspectionObservation::Work(work)) => {
            out.push(0);
            for n in [work.observed_ms, work.opened_ms, work.retain_ms] {
                out.extend_from_slice(&n.to_le_bytes());
            }
            out.push(u8::from(work.settled_ms.is_some()));
            if let Some(n) = work.settled_ms {
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        Ok(InspectionObservation::CarrierSessions(found)) => {
            out.push(0);
            put_len(&mut out, found.len())?;
            for session in found {
                out.extend_from_slice(&session.session.to_le_bytes());
                out.push(u8::from(session.live));
            }
        }
        Err(error) => out.push(match error {
            InspectionError::Unsupported => 1,
            InspectionError::NotFound => 2,
            InspectionError::Refused => 3,
            InspectionError::Invalid => 4,
            _ => return Err(InspectionError::Invalid),
        }),
    }
    bounded(out)
}

/// Decode a receipt, rejecting wrong result types, changed session order, and trailing bytes.
pub fn decode_receipt(bytes: &[u8]) -> Result<InspectionReceipt, InspectionError> {
    let mut read = Reader::new(bytes)?;
    let request = decode_request(read.bytes()?)?;
    let result = match read.byte()? {
        0 => Ok(match &request.query {
            InspectionQuery::Work { .. } => {
                let observed_ms = read.u64()?;
                let opened_ms = read.u64()?;
                let retain_ms = read.u64()?;
                let settled_ms = match read.byte()? {
                    0 => None,
                    1 => Some(read.u64()?),
                    _ => return Err(InspectionError::Invalid),
                };
                InspectionObservation::Work(WorkObservation {
                    observed_ms,
                    opened_ms,
                    retain_ms,
                    settled_ms,
                })
            }
            InspectionQuery::CarrierSessions { sessions } => {
                let count = read.count(9)?;
                if count != sessions.len() {
                    return Err(InspectionError::Correlation);
                }
                let mut found = Vec::with_capacity(count);
                for _ in 0..count {
                    let session = read.u64()?;
                    let live = match read.byte()? {
                        0 => false,
                        1 => true,
                        _ => return Err(InspectionError::Invalid),
                    };
                    found.push(SessionObservation { session, live });
                }
                InspectionObservation::CarrierSessions(found)
            }
        }),
        1 => Err(InspectionError::Unsupported),
        2 => Err(InspectionError::NotFound),
        3 => Err(InspectionError::Refused),
        4 => Err(InspectionError::Invalid),
        _ => return Err(InspectionError::Invalid),
    };
    read.end()?;
    matching(&request, &result)?;
    Ok(InspectionReceipt { request, result })
}

fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, InspectionError> {
    if bytes.len() <= MAX_BYTES {
        Ok(bytes)
    } else {
        Err(InspectionError::Invalid)
    }
}
fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), InspectionError> {
    out.extend_from_slice(
        &u32::try_from(len)
            .map_err(|_| InspectionError::Invalid)?
            .to_le_bytes(),
    );
    Ok(())
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), InspectionError> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, InspectionError> {
        if bytes.len() > MAX_BYTES {
            return Err(InspectionError::Invalid);
        }
        let mut read = Self { bytes, at: 0 };
        if read.byte()? != VERSION {
            return Err(InspectionError::Unsupported);
        }
        Ok(read)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], InspectionError> {
        let end = self.at.checked_add(n).ok_or(InspectionError::Invalid)?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or(InspectionError::Invalid)?;
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, InspectionError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, InspectionError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| InspectionError::Invalid)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, InspectionError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| InspectionError::Invalid)?,
        ))
    }
    fn count(&mut self, width: usize) -> Result<usize, InspectionError> {
        let count = usize::try_from(self.u32()?).map_err(|_| InspectionError::Invalid)?;
        if count > self.bytes.len().saturating_sub(self.at) / width {
            return Err(InspectionError::Invalid);
        }
        Ok(count)
    }
    fn bytes(&mut self) -> Result<&'a [u8], InspectionError> {
        let n = self.count(1)?;
        self.take(n)
    }
    fn end(self) -> Result<(), InspectionError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(InspectionError::Invalid)
        }
    }
}

fn value<'a>(blob: &'a [u8], key: &str) -> Result<Option<&'a [u8]>, InspectionError> {
    if blob.len() > MAX_BYTES {
        return Err(InspectionError::Invalid);
    }
    let mut at = 0usize;
    let mut found = None;
    for (k, v) in extensions::entries(blob) {
        at = at
            .checked_add(2 + k.len() + 4 + v.len())
            .ok_or(InspectionError::Invalid)?;
        if k == key.as_bytes() {
            if found.is_some() {
                return Err(InspectionError::Invalid);
            }
            found = Some(v);
        }
    }
    if at != blob.len() {
        return Err(InspectionError::Invalid);
    }
    Ok(found)
}
fn append(blob: &[u8], key: &str, bytes: &[u8]) -> Result<Vec<u8>, InspectionError> {
    if let Some(existing) = value(blob, key)? {
        return if existing == bytes {
            Ok(blob.to_vec())
        } else {
            Err(InspectionError::Correlation)
        };
    }
    let entry_len = extensions::entry_len(key, bytes);
    if blob
        .len()
        .checked_add(entry_len)
        .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(InspectionError::Invalid);
    }
    let mut out = Vec::with_capacity(blob.len() + entry_len);
    out.extend_from_slice(blob);
    out.extend_from_slice(&extensions::encode(&[(key, bytes)]));
    Ok(out)
}

/// Read the unique negotiated capability without changing any other extension.
pub fn read_capability(blob: &[u8]) -> Result<Option<InspectionCapability>, InspectionError> {
    value(blob, EXT_CAPABILITY)?
        .map(decode_capability)
        .transpose()
}
/// Read the unique request while its main reply is still leased.
pub fn read_request(blob: &[u8]) -> Result<Option<InspectionRequest>, InspectionError> {
    value(blob, EXT_REQUEST)?.map(decode_request).transpose()
}
/// Read and copy the unique receipt while its main input is lent.
pub fn read_receipt(blob: &[u8]) -> Result<Option<InspectionReceipt>, InspectionError> {
    value(blob, EXT_REPLY)?.map(decode_receipt).transpose()
}
/// Append a capability, preserving unrelated extension bytes exactly.
pub fn append_capability(blob: &[u8], epoch: u64) -> Result<Vec<u8>, InspectionError> {
    append(blob, EXT_CAPABILITY, &encode_capability(epoch)?)
}
/// Append a request, preserving unrelated extension bytes exactly.
pub fn append_request(
    blob: &[u8],
    request: &InspectionRequest,
) -> Result<Vec<u8>, InspectionError> {
    append(blob, EXT_REQUEST, &encode_request(request)?)
}
/// Append a receipt, preserving unrelated extension bytes exactly.
pub fn append_receipt(
    blob: &[u8],
    receipt: &InspectionReceipt,
) -> Result<Vec<u8>, InspectionError> {
    append(blob, EXT_REPLY, &encode_receipt(receipt)?)
}

#[cfg(test)]
#[path = "../mechanism/tests/inspection_tests.rs"]
mod tests;
