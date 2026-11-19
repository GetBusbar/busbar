// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native request facts shared by authentication and resource selection.
//! Logical copied bytes and live ABI view slots are charged; allocator/Arc bookkeeping is not RSS accounting.

use std::ops::Range;
use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_ports::auth::AuthIn;
use busbar_ports::PortError;

use crate::limits::process_admission::{ByteCredit, CapacityDenied, RequestLease};

/// Borrowed original facts. Physical callers map their existing header array without allocating Pair views.
/// Every field borrows or is a scalar, so the input is `Copy` whenever its header source is.
#[derive(Clone, Copy)]
pub struct SnapshotInput<'a, H> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub query_present: bool,
    pub authority: &'a str,
    pub headers: H,
    pub peer: &'a str,
    pub tls_peer_cert: &'a [u8],
    pub body: &'a [u8],
    pub now_s: u64,
}

#[derive(Debug)]
pub enum SnapshotError {
    Invalid,
    Overflow,
    Capacity(CapacityDenied),
    Allocation,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid original request snapshot",
            Self::Overflow => "request snapshot extent overflow",
            Self::Capacity(_) => "request snapshot capacity exhausted",
            Self::Allocation => "request snapshot allocation failed",
        })
    }
}
impl std::error::Error for SnapshotError {}

impl From<SnapshotError> for PortError {
    fn from(_: SnapshotError) -> Self {
        Self::Failed {
            code: busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
            text: "request snapshot unavailable".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        }
    }
}

/// Custody only, never authentication or physical-request authority. Legacy snapshots cannot construct this.
pub struct ChargedRequestSnapshot {
    // Declaration-order destruction wipes and frees the payload before its credit retires.
    bytes: SecureVec,
    method: Range<usize>,
    target: Range<usize>,
    path: Range<usize>,
    query: Range<usize>,
    authority: Range<usize>,
    peer: Range<usize>,
    certificate: Range<usize>,
    body: Range<usize>,
    headers: Range<usize>,
    header_count: usize,
    query_present: bool,
    now_s: u64,
    credit: ByteCredit,
    /// A restated head ([`Self::restate_headers`]): the original whose method, target, authority,
    /// peer, certificate and body this view shares, charged once by the original. `bytes` then
    /// holds only the restated header block, and every other range indexes the original's bytes.
    original: Option<Arc<ChargedRequestSnapshot>>,
}

impl std::fmt::Debug for ChargedRequestSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChargedRequestSnapshot")
            .field("bytes", &self.bytes.len())
            .field("headers", &self.header_count)
            .finish_non_exhaustive()
    }
}

fn add(extent: usize, more: usize) -> Result<usize, SnapshotError> {
    extent.checked_add(more).ok_or(SnapshotError::Overflow)
}

fn append(
    bytes: &mut SecureVec,
    value: &[u8],
    extent: usize,
) -> Result<Range<usize>, SnapshotError> {
    let start = bytes.len();
    let end = add(start, value.len())?;
    if end > extent {
        return Err(SnapshotError::Invalid);
    }
    bytes.extend(value).map_err(|_| SnapshotError::Allocation)?;
    Ok(start..end)
}

impl ChargedRequestSnapshot {
    /// Reserve the complete independent copy before allocating, without an intermediate Pair vector.
    pub fn capture<'a, H>(
        input: SnapshotInput<'a, H>,
        request: &RequestLease,
    ) -> Result<Arc<Self>, SnapshotError>
    where
        H: Clone + ExactSizeIterator<Item = (&'a str, &'a [u8])>,
    {
        let count = input.headers.len();
        let measure = input.headers.clone();
        Self::capture_passes(input, measure, count, request)
    }

    /// The existing HTTP adapter can recreate borrowed HeaderMap iterators, which are neither
    /// Clone nor ExactSizeIterator. Both passes use the same checked capture implementation.
    pub fn capture_header_map<'a>(
        input: SnapshotInput<'a, &'a http::HeaderMap>,
        request: &RequestLease,
    ) -> Result<Arc<Self>, SnapshotError> {
        fn field<'h>(
            (name, value): (&'h http::HeaderName, &'h http::HeaderValue),
        ) -> (&'h str, &'h [u8]) {
            (name.as_str(), value.as_bytes())
        }
        let count = input.headers.len();
        let measure = input.headers.iter().map(field);
        let input = SnapshotInput {
            method: input.method,
            path: input.path,
            query: input.query,
            query_present: input.query_present,
            authority: input.authority,
            headers: input.headers.iter().map(field),
            peer: input.peer,
            tls_peer_cert: input.tls_peer_cert,
            body: input.body,
            now_s: input.now_s,
        };
        Self::capture_passes(input, measure, count, request)
    }

    fn capture_passes<'a, H>(
        input: SnapshotInput<'a, H>,
        measure: H,
        count: usize,
        request: &RequestLease,
    ) -> Result<Arc<Self>, SnapshotError>
    where
        H: Iterator<Item = (&'a str, &'a [u8])>,
    {
        if !input.query_present && !input.query.is_empty() {
            return Err(SnapshotError::Invalid);
        }
        let mut extent = add(
            usize::from(input.query_present),
            count.checked_mul(16).ok_or(SnapshotError::Overflow)?,
        )?;
        for len in [
            input.method.len(),
            input.path.len(),
            input.query.len(),
            input.authority.len(),
            input.peer.len(),
            input.tls_peer_cert.len(),
            input.body.len(),
        ] {
            extent = add(extent, len)?;
        }
        extent = add(extent, header_extent(measure, count)?)?;
        // The credit is acquired before either backing or content is allocated.
        let credit = request
            .try_reserve(extent)
            .map_err(SnapshotError::Capacity)?;
        let mut bytes = SecureVec::with_capacity(extent).map_err(|_| SnapshotError::Allocation)?;
        let method = append(&mut bytes, input.method.as_bytes(), extent)?;
        let path = append(&mut bytes, input.path.as_bytes(), extent)?;
        if input.query_present {
            append(&mut bytes, b"?", extent)?;
        }
        let query = append(&mut bytes, input.query.as_bytes(), extent)?;
        let target = path.start..query.end;
        let authority = append(&mut bytes, input.authority.as_bytes(), extent)?;
        let peer = append(&mut bytes, input.peer.as_bytes(), extent)?;
        let certificate = append(&mut bytes, input.tls_peer_cert, extent)?;
        let body = append(&mut bytes, input.body, extent)?;
        let start = bytes.len();
        pack_headers(&mut bytes, input.headers, count, extent)?;
        Ok(Arc::new(Self {
            bytes,
            method,
            target,
            path,
            query,
            authority,
            peer,
            certificate,
            body,
            headers: start..extent,
            header_count: count,
            query_present: input.query_present,
            now_s: input.now_s,
            credit,
            original: None,
        }))
    }

    /// The same request with its headers restated (`headers`, in order): method, target,
    /// authority, peer, certificate and body are the original's own bytes, shared and never
    /// charged again; only the restated header block is a new copy, reserved on the original's
    /// request before it is allocated. A request that cannot pay for that block is refused.
    pub fn restate_headers<'a, H>(
        original: &Arc<Self>,
        headers: H,
    ) -> Result<Arc<Self>, SnapshotError>
    where
        H: Clone + ExactSizeIterator<Item = (&'a str, &'a [u8])>,
    {
        // A view of a view shares the one original: the body is never charged twice.
        let original = original.original.as_ref().unwrap_or(original);
        let count = headers.len();
        let extent = header_extent(headers.clone(), count)?;
        let credit = original
            .request()
            .try_reserve(extent)
            .map_err(SnapshotError::Capacity)?;
        let mut bytes = SecureVec::with_capacity(extent).map_err(|_| SnapshotError::Allocation)?;
        pack_headers(&mut bytes, headers, count, extent)?;
        Ok(Arc::new(Self {
            bytes,
            method: original.method.clone(),
            target: original.target.clone(),
            path: original.path.clone(),
            query: original.query.clone(),
            authority: original.authority.clone(),
            peer: original.peer.clone(),
            certificate: original.certificate.clone(),
            body: original.body.clone(),
            headers: 0..extent,
            header_count: count,
            query_present: original.query_present,
            now_s: original.now_s,
            credit,
            original: Some(Arc::clone(original)),
        }))
    }

    /// The snapshot whose bytes hold this request's method, target, authority, peer,
    /// certificate and body: the original for a restated head, else this one.
    fn facts(self: &Arc<Self>) -> &Arc<Self> {
        self.original.as_ref().unwrap_or(self)
    }
    fn fact(&self, range: &Range<usize>) -> &[u8] {
        match &self.original {
            Some(original) => original.slice(range),
            None => self.slice(range),
        }
    }
    fn fact_text(&self, range: &Range<usize>) -> &str {
        std::str::from_utf8(self.fact(range)).expect("snapshot text was copied from str")
    }

    fn slice(&self, range: &Range<usize>) -> &[u8] {
        &self.bytes[range.clone()]
    }
    fn text(&self, range: &Range<usize>) -> &str {
        std::str::from_utf8(self.slice(range)).expect("snapshot text was copied from str")
    }
    pub fn method(&self) -> &str {
        self.text(&self.method)
    }
    pub fn target(&self) -> &str {
        self.text(&self.target)
    }
    pub fn path(&self) -> &str {
        self.text(&self.path)
    }
    pub fn query(&self) -> &str {
        self.text(&self.query)
    }
    pub fn query_present(&self) -> bool {
        self.query_present
    }
    pub fn authority(&self) -> &str {
        self.text(&self.authority)
    }
    pub fn peer(&self) -> &str {
        self.text(&self.peer)
    }
    pub fn tls_peer_cert(&self) -> &[u8] {
        self.slice(&self.certificate)
    }
    pub fn body(&self) -> &[u8] {
        self.slice(&self.body)
    }
    /// Share the body without copying; every nonempty Bytes clone/slice retains the full snapshot.
    /// Empty operations must additionally retain the original request admission explicitly.
    pub fn body_bytes(self: &Arc<Self>) -> bytes::Bytes {
        self.owned_bytes(self.body.clone())
    }
    /// Share the exact path and query, including an originally present empty query.
    /// Passing these Bytes to `http::Uri::from_maybe_shared` avoids a second payload copy.
    pub fn target_bytes(self: &Arc<Self>) -> bytes::Bytes {
        self.owned_bytes(self.target.clone())
    }
    /// Share long HTTP methods through the maintained parser and its independent clones.
    pub fn method_bytes(self: &Arc<Self>) -> bytes::Bytes {
        self.owned_bytes(self.method.clone())
    }
    fn owned_bytes(self: &Arc<Self>, range: Range<usize>) -> bytes::Bytes {
        bytes::Bytes::from_owner(SnapshotSpan {
            snapshot: Arc::clone(self),
            range,
        })
    }
    /// Original ordered headers with snapshot-owned values, without a temporary header array.
    /// `http::HeaderValue::from_maybe_shared` retains each Bytes backing through value clones.
    /// Header-name parsing and HeaderMap storage are separate allocations, not funded by this view.
    pub fn header_values(
        self: &Arc<Self>,
    ) -> impl Clone + ExactSizeIterator<Item = (&str, bytes::Bytes)> {
        let mut offset = self.headers.start;
        self.headers().map(move |(name, value)| {
            // Capture validated every packed extent; these immutable ranges cannot overflow.
            let start = offset + 16 + name.len();
            offset = start + value.len();
            (name, self.owned_bytes(start..offset))
        })
    }
    /// Original name/value spans for the maintained HTTP projection, with no field-array copy.
    pub fn header_fields(
        self: &Arc<Self>,
    ) -> impl Clone + ExactSizeIterator<Item = (bytes::Bytes, bytes::Bytes)> + '_ {
        let mut offset = self.headers.start;
        self.headers().map(move |(name, value)| {
            let name_start = offset + 16;
            let value_start = name_start + name.len();
            offset = value_start + value.len();
            (
                self.owned_bytes(name_start..value_start),
                self.owned_bytes(value_start..offset),
            )
        })
    }
    pub fn now_s(&self) -> u64 {
        self.now_s
    }
    pub fn request(&self) -> &RequestLease {
        self.credit.request()
    }
    pub fn headers(&self) -> impl Clone + ExactSizeIterator<Item = (&str, &[u8])> {
        Headers {
            bytes: self.slice(&self.headers),
            remaining: self.header_count,
        }
    }

    /// Each simultaneous ABI view owns a separate reservation. A denied view never calls `f`.
    /// Reservations here never call metrics/recorders: policy may view beneath a publication guard.
    /// The outer admission boundary reports capacity failures after releasing that guard.
    pub fn with_auth_input<R>(&self, f: impl FnOnce(&AuthIn<'_>) -> R) -> Result<R, SnapshotError> {
        let extent = self
            .header_count
            .checked_mul(std::mem::size_of::<Pair<'_>>())
            .ok_or(SnapshotError::Overflow)?;
        let credit = self
            .request()
            .try_reserve_unreported(extent)
            .map_err(SnapshotError::Capacity)?;
        // Local destruction is reversed: the Pair allocation retires before its credit on every exit.
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(self.header_count)
            .map_err(|_| SnapshotError::Allocation)?;
        for (name, value) in self.headers() {
            headers.push(Pair {
                name: Str::new(name),
                value: Bytes::new(value),
            });
        }
        let result = f(&AuthIn {
            method: self.method(),
            path: self.path(),
            query: self.query(),
            authority: self.authority(),
            headers: &headers,
            peer: self.peer(),
            tls_peer_cert: self.tls_peer_cert(),
            body: self.body(),
            now_s: self.now_s,
        });
        drop(headers);
        drop(credit);
        Ok(result)
    }
}

struct SnapshotSpan {
    snapshot: Arc<ChargedRequestSnapshot>,
    range: Range<usize>,
}
impl AsRef<[u8]> for SnapshotSpan {
    fn as_ref(&self) -> &[u8] {
        self.snapshot.slice(&self.range)
    }
}

#[derive(Clone)]
struct Headers<'a> {
    bytes: &'a [u8],
    remaining: usize,
}
impl<'a> Iterator for Headers<'a> {
    type Item = (&'a str, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let name_len = usize::try_from(u64::from_le_bytes(
            self.bytes[..8].try_into().expect("snapshot header length"),
        ))
        .expect("snapshot length came from usize");
        let value_len = usize::try_from(u64::from_le_bytes(
            self.bytes[8..16].try_into().expect("snapshot value length"),
        ))
        .expect("snapshot length came from usize");
        let (name, rest) = self.bytes[16..].split_at(name_len);
        let (value, rest) = rest.split_at(value_len);
        self.bytes = rest;
        self.remaining -= 1;
        Some((
            std::str::from_utf8(name).expect("snapshot header name came from str"),
            value,
        ))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Headers<'_> {}

#[cfg(test)]
#[path = "tests/request_snapshot.rs"]
mod tests;
