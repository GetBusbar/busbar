// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `http` transport: request in, response frames out.
//!
//! `http` carries no session (`SESSION = false`) and its per-frame `WireStatusClass` rides the first
//! response frame (`STATUS_CLASS = Some(FirstFrame)`) — the kernel-derived leg of the fee decision
//! the design's settlement table reads. It composes over `tcp` for its byte stream;
//! TLS on that stream is core's connection security, never a layer.
//!
//! ## Dialling is not this transport's
//!
//! This transport serves: it binds, accepts and frames what arrives. It does not open a connection
//! to an upstream. [`Transport::dial`](busbar_contract::Transport::dial) answers
//! `AddressRefused` for every destination, before any name is resolved or any socket is opened.
//! An upstream request leaves through the connector, which dials only an IP literal the kernel's
//! one destination judge has passed (`DialJudge`), with this crate's [`door`] framing it. A client
//! of its own here would resolve a name the judge never saw, and would resolve it again on every
//! pooled reconnect (TODO #145).
//!
//! ## Bodies larger than one call
//!
//! A body is not one read's worth of bytes: an accepted request arrives as a HEAD frame followed by
//! body-chunk frames, and is accepted up to the configured maximum however many chunks it took.
//! That maximum is [`ClientSettings::request_body_max_bytes`], carried here from the operator's own
//! `limits.request_body_max_bytes`, the SAME knob the served door's body limit is built from, so
//! the two caps cannot disagree about what this gateway accepts. The ingress reader refuses a
//! declared length past it without reading the body behind it.
//!
//! A request that asks to be told before it uploads is told. `Expect: 100-continue` is what a
//! client sets when it would rather be refused than send a body — `curl` sets it itself past about
//! a kibibyte — and it then waits for the interim answer before writing a byte, so a reader that
//! only parks on the body leaves both sides waiting on each other. The interim answer goes out once
//! the head has passed its framing checks and before the body is waited for.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::transport::wire::ConnHandle;
use busbar_contract::transport::wire::Direction;
use busbar_contract::transport::wire::FrameMeta;
use busbar_contract::transport::wire::ListenerHandle;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::{Frame, SlabBytes, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;

mod claims;
// THE ABI BOUNDARY: the door reads and writes the host's C buffers through the SDK's safe surface
// (`busbar_contract::abi::sdk::{SafeSlot, Lent, HostBuf}`), so it holds no `unsafe` either.
pub mod door;
mod meta;
mod raw;
mod transport;

pub mod mount;

// THE FOLD: gRPC is HTTP/2 framing, a dialect of this wire, so its
// transport is a module of this crate rather than a crate beside it. It still registers as its own
// transport under its own key (`grpc`), so the registry and boot matching see what they saw before.
pub mod grpc;

// THE SAME FOLD for SSE, which IS an HTTP response body: `sse` is composed over this crate's own
// `HttpTransport` and registers as its own transport under its own key (`sse`), unchanged.
pub mod sse;

pub use raw::{RawMessage, RawStartLine};

/// Bytes read per syscall on the ingress side, and the cap this crate scans a header prefix
/// against — the same "scanned prefix, at most the cursor cap" shape `MAX_CURSOR_BYTES` names.
pub const READ_CHUNK_BYTES: usize = busbar_contract::MAX_CURSOR_BYTES;

/// The settings this transport is built from — the contract's
/// [`TransportSettings`](busbar_contract::transport::TransportSettings), the one shape the
/// composition root resolves off the deployment's `limits:` and hands every transport's build. Named
/// here too so this crate's own callers read the name they always did.
pub use busbar_contract::transport::TransportSettings as ClientSettings;
pub use busbar_contract::transport::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for each wire this crate
/// carries — its key, the layers it declares, and how it is built. The root names none of them.
pub mod linked {
    use std::sync::Arc;

    use busbar_contract::transport::{Transport, TransportMeta, TransportSettings};

    use crate::HttpTransport;

    /// The `http` row's registry key.
    pub const KEY: &str = <HttpTransport as TransportMeta>::KEY;
    /// The layers `http` declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = <HttpTransport as TransportMeta>::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = <HttpTransport as TransportMeta>::SESSION;

    /// `http` opens its own socket, so it takes no lower layer; it holds the deployment's settings.
    #[must_use]
    pub fn build(
        _: Option<Arc<dyn Transport>>,
        settings: &TransportSettings,
    ) -> Arc<dyn Transport> {
        Arc::new(HttpTransport::new(*settings))
    }

    /// The `sse` row: an HTTP response body, composed over the `http` the root built below it.
    pub mod sse {
        use super::{Arc, HttpTransport, Transport, TransportMeta, TransportSettings};
        use crate::sse::SseTransport;

        /// The `sse` row's registry key.
        pub const KEY: &str = <SseTransport as TransportMeta>::KEY;
        /// The layers `sse` declares it can be built over.
        pub const COMPOSES_OVER: &[&str] = <SseTransport as TransportMeta>::COMPOSES_OVER;
        /// Whether this wire carries sessions.
        pub const SESSION: bool = <SseTransport as TransportMeta>::SESSION;

        /// Built over `lower`; with none (a composition the boot check refuses, `http` unlinked) it
        /// is built over an `http` of its own from the same settings.
        #[must_use]
        pub fn build(
            lower: Option<Arc<dyn Transport>>,
            settings: &TransportSettings,
        ) -> Arc<dyn Transport> {
            let lower = lower.unwrap_or_else(|| Arc::new(HttpTransport::new(*settings)));
            Arc::new(SseTransport::over(lower))
        }
    }

    /// The `grpc` row: HTTP/2 framing, composed over the `http` the root built below it.
    pub mod grpc {
        use super::{Arc, Transport, TransportMeta, TransportSettings};
        use crate::grpc::GrpcTransport;

        /// The `grpc` row's registry key.
        pub const KEY: &str = <GrpcTransport as TransportMeta>::KEY;
        /// The layers `grpc` declares it can be built over.
        pub const COMPOSES_OVER: &[&str] = <GrpcTransport as TransportMeta>::COMPOSES_OVER;
        /// Whether this wire carries sessions.
        pub const SESSION: bool = <GrpcTransport as TransportMeta>::SESSION;

        /// Built over `lower` — never over nothing, which yields a transport that refuses every
        /// connection; with no lower layer the boot check has already refused the composition.
        #[must_use]
        pub fn build(
            lower: Option<Arc<dyn Transport>>,
            _: &TransportSettings,
        ) -> Arc<dyn Transport> {
            Arc::new(lower.map_or_else(GrpcTransport::new, GrpcTransport::over))
        }
    }
}

/// An accepted connection: the raw framing lives here, one request per connection in this delivery
/// (no HTTP/1.1 keep-alive pipelining — see the crate doc).
struct Inner {
    read: AsyncMutex<ReadSide>,
    write: AsyncMutex<OwnedWriteHalf>,
    leftover: AsyncMutex<Vec<u8>>,
    /// Set once this connection has been finalised. A frame stream captured its own clone of
    /// this state before the close, and a request the peer half-wrote parks that stream on a
    /// read the peer may never answer; the registry removal alone would never reach it. This is
    /// the flag it checks, so it ends and the socket halves actually drop.
    closed: AtomicBool,
    /// What WAKES that pump. The flag is only ever read once a read has returned, and the read
    /// a half-written request parks on returns when the peer sends more — which is precisely
    /// what a peer that has gone quiet never does. Against that peer the flag alone leaves the
    /// pump parked for the life of the process, holding the last clone of the socket: one
    /// leaked descriptor per closed connection and a drain that never finishes. The close
    /// notifies this, every read is raced against it, and the stream ends where it was parked.
    /// The sibling `tcp` crate closes the same way.
    closing: tokio::sync::Notify,
    /// The local port this connection was accepted on.
    ///
    /// `Port` is one of the selector forms this transport declares, and a claim by port reads
    /// the arrival record: zero there made every arrival on every listener look alike. It is
    /// taken off the ACCEPTED SOCKET rather than off the bind string, which is the only place
    /// the fact exists at all on an ephemeral (`:0`) bind — the sibling `tcp` and `ws`
    /// crates record it the same way.
    local_port: u16,
}

/// A connection's read half and the buffer every read on it fills.
///
/// The buffer is allocated once, when the connection is accepted, and reused for the life of the
/// connection: a fresh `READ_CHUNK_BYTES` vector per read syscall is an allocation and a zero-fill
/// on the frame path, for every read of every header, every body chunk and every trailer — and a
/// message dribbled in arbitrarily small pieces pays it once per piece. Keeping it behind the same
/// lock as the read half is what makes the reuse sound: a connection is read by one pump at a time,
/// so there is never a second reader to see a half-filled buffer. The sibling `tcp` crate
/// reads the same way.
struct ReadSide {
    half: OwnedReadHalf,
    scratch: Vec<u8>,
}

struct HttpConnHandle {
    id: u64,
    peer: String,
}
impl ConnHandle for HttpConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

struct HttpListenerHandle {
    addr: String,
}
impl ListenerHandle for HttpListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

/// The `http` transport.
pub struct HttpTransport {
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<Inner>>>,
    listeners: Mutex<HashMap<String, Arc<TcpListener>>>,
    /// The operator's body cap, carried from [`ClientSettings`] and applied to both accumulators.
    max_body_bytes: usize,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport").finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Build the transport. It holds no client: it serves, and never dials (see the crate doc).
    #[must_use]
    pub fn new(settings: ClientSettings) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            max_body_bytes: settings.request_body_max_bytes,
        }
    }

    /// The body ceiling this instance was built with, in bytes — the operator's
    /// `limits.request_body_max_bytes` as it reached this transport.
    ///
    /// Readable because the composition that hands it here is a boot-time wiring a caller must be
    /// able to prove: a root that built its transports from a `Default` instead of from the
    /// deployment's limits looks identical from the outside until a body of the wrong size arrives.
    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns.lock().expect("poisoned").get(&id).cloned()
    }

    /// The address of the buffer an accepted connection reads through, for the cell that pins one
    /// buffer per connection rather than one per read.
    #[cfg(test)]
    pub(crate) async fn scratch_addr(&self, id: u64) -> Option<usize> {
        let inner = self.inner(id)?;
        let guard = inner.read.lock().await;
        Some(guard.scratch.as_ptr() as usize)
    }

    fn map_io_err(e: &io::Error) -> TransportError {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => TransportError::Refused,
            io::ErrorKind::TimedOut => TransportError::Timeout,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                TransportError::Reset
            }
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => {
                TransportError::AddressRefused
            }
            _ => TransportError::Closed,
        }
    }
}

/// Read the upstream's `Retry-After` off a response head and resolve it to whole seconds.
///
/// The header is optional, appears at most once in any answer that means it, and a value this
/// parser cannot read is treated as absent — a wait nobody can compute is not a wait, and guessing
/// one would park a lane on a header nobody wrote.
fn retry_after_secs(headers: &http::HeaderMap, now_secs: u64) -> Option<u64> {
    let raw = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after(raw, now_secs)
}

/// Parse an RFC 9110 `Retry-After` header VALUE against `now` (a Unix timestamp in seconds). Both
/// normative forms are accepted: `delay-seconds` (an integer, which ignores `now`) and an
/// HTTP-date, converted to the seconds remaining until that instant and floored at 0 when it is
/// already in the past.
///
/// The arithmetic is the one the breaker's own classifier does, and it is duplicated here rather
/// than shared: this crate sits on the transport axis and may not name a unit crate, and the unit
/// crate's own dependency policy names the capability crate as the only workspace crate it may see.
/// Neither can reach the other, so there is no shared home for four lines of date parsing. The forms
/// accepted and the flooring rule are pinned by the tests below against the same values.
///
/// (The capability crate is deliberately not spelled here. `tests/no_plane_names.rs` refuses that
/// name anywhere in this crate's source, and a rule with an exception for prose is a rule with an
/// exception — the sentence says the same thing without one.)
fn parse_retry_after(value: &str, now: u64) -> Option<u64> {
    let s = value.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    parse_imf_fixdate_retry_after(s, now)
}

/// Parse the value as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, the sole HTTP-date form RFC
/// 9110 recommends generating) and return the whole seconds remaining until it, floored at 0 for a
/// date already in the past.
fn parse_imf_fixdate_retry_after(s: &str, now: u64) -> Option<u64> {
    // "Www, dd Mon yyyy HH:MM:SS GMT" — fixed-width, so a byte-length check plus field slicing is
    // enough; no general calendar library is warranted for one wire format.
    if s.len() != 29 || !s.ends_with(" GMT") {
        return None;
    }
    if s.as_bytes().get(3) != Some(&b',') || s.as_bytes().get(4) != Some(&b' ') {
        return None;
    }
    let day: u64 = s.get(5..7)?.parse().ok()?;
    let month = month_from_abbrev(s.get(8..11)?)?;
    let year: u64 = s.get(12..16)?.parse().ok()?;
    let hour: u64 = s.get(17..19)?.parse().ok()?;
    let minute: u64 = s.get(20..22)?.parse().ok()?;
    let second: u64 = s.get(23..25)?.parse().ok()?;
    let epoch_secs = civil_to_epoch_secs(year, month, day, hour, minute, second)?;
    Some(epoch_secs.saturating_sub(now))
}

fn month_from_abbrev(m: &str) -> Option<u64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days-from-civil (Howard Hinnant's public-domain algorithm), giving a UTC Unix timestamp for a
/// UTC calendar date and time with no external date/time dependency.
fn civil_to_epoch_secs(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> Option<u64> {
    let y = year as i64 - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146_097 + doe - 719_468;
    let days_since_epoch = u64::try_from(days_since_epoch).ok()?;
    Some(days_since_epoch * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Where an egress request actually goes: the dialled scheme and authority, carrying the path the
/// ENVELOPE named.
///
/// A dial pins a destination — scheme, host, port. It does not pin a request: one connection to an
/// upstream carries many requests, and on an API whose surface is its path they are different
/// requests only because their paths differ. So the path travels with the message, and the dial
/// URI's own path stands in only when the message names none (`/` or empty), which is the shape a
/// caller writes when the dial URI already spells the whole target.
fn request_target(dial: &http::Uri, path: &str) -> Result<http::Uri, TransportError> {
    if path.is_empty() || path == "/" {
        return Ok(dial.clone());
    }
    let mut parts = dial.clone().into_parts();
    parts.path_and_query = Some(
        path.parse::<http::uri::PathAndQuery>()
            .map_err(|_| TransportError::Framing)?,
    );
    http::Uri::from_parts(parts).map_err(|_| TransportError::Framing)
}

/// Take a connection out of the registry and mark it finalised, so a pump that already holds a
/// clone of its state ends rather than staying parked on a socket nobody is going to write to.
fn finalise(conns: &Mutex<HashMap<u64, Arc<Inner>>>, id: u64) {
    let removed = conns.lock().expect("poisoned").remove(&id);
    if let Some(Inner {
        closed, closing, ..
    }) = removed.as_deref()
    {
        // The flag FIRST, then the wake: a pump that arms its wait and then re-reads the flag can
        // never miss both the store and the notification, whichever order the two tasks interleave
        // in. Reversed, a pump between the two sees neither and stays parked.
        closed.store(true, Ordering::Release);
        closing.notify_waiters();
    }
}

/// Read into this connection's own buffer, RACED against this connection's close.
///
/// `None` means the close won, and the caller ends its stream where it stood. The flag alone is
/// read only once a read has RETURNED, and the read a half-written request parks on returns when
/// the peer sends more — exactly what a peer that has gone quiet never does. So the close has to be
/// a wake as well as a flag. The wait is armed BEFORE the flag is re-read, so a close landing
/// between the two is seen as the flag and one landing after it as the notification; neither order
/// leaves this parked. The sibling `tcp` crate reads the same way.
async fn read_or_closed(
    r: &mut ReadSide,
    closed: &AtomicBool,
    closing: &tokio::sync::Notify,
) -> Option<io::Result<usize>> {
    let mut wait = Box::pin(closing.notified());
    wait.as_mut().enable();
    if closed.load(Ordering::Acquire) {
        return None;
    }
    let reading = std::pin::pin!(r.half.read(&mut r.scratch));
    match futures::future::select(reading, wait).await {
        futures::future::Either::Left((read, _)) => Some(read),
        // The close won: the read is dropped where it stood.
        futures::future::Either::Right(((), _)) => None,
    }
}

/// Put a Unit 0 refusal's bytes on the wire and report whether they actually left.
///
/// `write_all` only proves the bytes reached the writer's own buffer. The kernel is told a refusal
/// was delivered, and a refusal is the client-visible answer to an authentication failure, so the
/// flush is the evidence and its failure is reported the same way the ordinary write path reports
/// one rather than being swallowed. The sibling `tcp` crate already answers this way.
async fn deliver_refusal<W>(w: &mut W, bytes: &[u8]) -> Result<(), TransportError>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    w.write_all(bytes)
        .await
        .map_err(|e| HttpTransport::map_io_err(&e))?;
    w.flush().await.map_err(|e| HttpTransport::map_io_err(&e))
}

/// A message this transport has been handed enough of to send, or `None` for a prefix of one.
///
/// The three endings are the wire's own: a declared `Content-Length` reached, the terminal chunk of
/// a chunked body seen, or a message that declares neither coding and therefore carries no body at
/// all. A chunked message is decoded here, so what comes back always carries the body itself rather
/// than a framing of it.
fn complete_message(
    buffered: &[u8],
    cache: &mut EgressHead,
    max_body_bytes: usize,
) -> Result<Option<raw::RawMessage>, TransportError> {
    if cache.head.is_none() {
        let Some(header_end) = find_header_end(buffered) else {
            return Ok(None);
        };
        let message = raw::parse_message(&buffered[..header_end]).ok_or(TransportError::Framing)?;
        cache.parses += 1;
        if raw::has_transfer_encoding(&message.headers) {
            if !raw::is_chunked(&message.headers) {
                // A declared coding this transport cannot frame. Falling through to
                // `Content-Length` would be answering a question the sender did not ask.
                return Err(TransportError::Framing);
            }
            if raw::header(&message.headers, "content-length").is_some() {
                // Two headers describing two framings of the same bytes. The coding wins the
                // reading, but forwarding the pair on — as this used to do — hands the next hop a
                // length the bytes do not have, the smuggling shape itself. Refused rather than
                // silently disambiguated, mirroring the ingress reader's identical refusal.
                return Err(TransportError::Framing);
            }
        }
        cache.head = Some(CachedHead {
            end: header_end,
            start: message.start,
            headers: message.headers,
        });
    }
    // Read what the head says before touching the cache again: the decoder lives beside it, and
    // feeding it is a mutation of the same cell this borrow reads.
    let (head_end, chunked, declared) = {
        let head = cache.head.as_ref().expect("set just above");
        (
            head.end,
            raw::is_chunked(&head.headers),
            raw::content_length(&head.headers),
        )
    };
    let rest = &buffered[head_end..];

    let (body, trailers) = if chunked {
        // ONE decoder across the calls, fed only what arrived with this one. A fresh decoder per
        // call re-decodes every byte received so far and re-allocates the decoded chunks each
        // time — quadratic in the body, which for the megabyte bodies this path exists to carry is
        // the difference between a transport and a stall. The ingress reader already reads this
        // way; this is the same reading on the side that accumulates.
        let decoder = cache
            .decoder
            .get_or_insert_with(|| Box::new(raw::ChunkedDecoder::default()));
        let fresh = &rest[cache.fed.min(rest.len())..];
        cache.feeds += fresh.len();
        decoder.feed(fresh).map_err(|_| TransportError::Framing)?;
        cache.fed = rest.len();
        if !decoder.is_done() {
            return Ok(None);
        }
        let (chunks, trailers) = cache.decoder.take().expect("set just above").take();
        (chunks.concat(), trailers)
    } else {
        let declared = declared.map_err(|()| TransportError::Framing)?.unwrap_or(0);
        if declared > max_body_bytes {
            return Err(TransportError::Framing);
        }
        if rest.len() < declared {
            return Ok(None);
        }
        (rest[..declared].to_vec(), Vec::new())
    };

    // Whole: the head is spent with the message it belonged to, so the next one parses its own,
    // and the decoder that read this body is spent with it too.
    let mut head = cache.head.take().expect("set just above");
    cache.decoder = None;
    cache.fed = 0;
    // A trailer is a header that arrived late; it goes where every other header went, so
    // nothing downstream has to know which side of the body it was written on.
    head.headers.extend(trailers);
    Ok(Some(raw::RawMessage {
        start: head.start,
        headers: head.headers,
        body,
    }))
}

/// The parsed header block of the message the door's `emit` is still accumulating.
///
/// `emit` asks whether the message is whole on EVERY chunk, and the header prefix does not change
/// between those asks. Parsing it each time allocates a fresh vector and two strings per header and
/// throws them away — the same waste the chunked decoder was written incrementally to avoid. Held
/// beside the pending bytes, and taken when the message completes so it can never outlive it.
struct CachedHead {
    end: usize,
    start: raw::RawStartLine,
    headers: Vec<(String, String)>,
}

/// [`CachedHead`], plus this connection's own count of how many times it has parsed one — the cell
/// that pins the egress side to one parse per message rather than one per `emit` call. Per
/// instance rather than a crate-global counter, so a test reading it back sees only its own
/// connection's work, never a sibling test's sharing the same binary.
#[derive(Default)]
struct EgressHead {
    head: Option<CachedHead>,
    parses: usize,
    /// The chunked decoder this message is being decoded by, kept across `emit` calls so each
    /// call feeds only the bytes that arrived with it — the same discipline the ingress reader
    /// keeps across reads. Behind a box because it is a per-message working set that most
    /// connections never allocate, and inline it would be carried by every connection ever dialled.
    decoder: Option<Box<raw::ChunkedDecoder>>,
    /// How many bytes past the header block have already been fed to `decoder`.
    fed: usize,
    /// This connection's own tally of bytes fed to a decoder, per instance for the same reason
    /// `parses` is: a test reading it back sees only its own connection's work.
    feeds: usize,
}

/// Read one HTTP/1.1 request off an ingress connection.
///
/// The scanned header prefix (bounded by [`READ_CHUNK_BYTES`], mirroring the design's cursor cap)
/// becomes the HEAD frame. The body follows as body-chunk frames: one frame for a declared
/// `Content-Length` body, and for a chunked one, one frame per chunk the sender wrote — the sender's
/// own framing, kept rather than flattened, so a megabyte body arrives as the chunks it was sent as
/// however the reads happened to fall. A trailer section becomes one final frame carrying it in
/// wire form, which is where a reader that folded it into the body would have lost it.
///
/// Between the head and the body sits the one thing this reader WRITES: the interim answer a
/// request carrying `Expect: 100-continue` is waiting for. See the crate doc.
async fn read_ingress_message(
    inner: &Inner,
    max_body_bytes: usize,
) -> Result<Option<Vec<(StreamId, Frame)>>, TransportError> {
    let Inner {
        read,
        write,
        leftover,
        closed,
        closing,
        ..
    } = inner;
    if closed.load(Ordering::Acquire) {
        return Ok(None);
    }
    let mut buf = leftover.lock().await;
    let mut guard = read.lock().await;
    let r = &mut *guard;
    let mut scan = HeaderScan::default();
    let header_end = loop {
        if let Some(pos) = scan.find(&buf) {
            break pos;
        }
        if buf.len() >= READ_CHUNK_BYTES {
            return Err(TransportError::Framing);
        }
        let Some(read) = read_or_closed(r, closed, closing).await else {
            return Ok(None);
        };
        let n = read.map_err(|e| HttpTransport::map_io_err(&e))?;
        if n == 0 {
            if buf.is_empty() {
                // Nothing was ever begun: the peer opened a connection and closed it. That is the
                // end of the stream, not a broken message.
                return Ok(None);
            }
            // A header block the peer stopped in the middle of. Taking it for end-of-stream would
            // silently discard bytes that were already read and call a truncated request no
            // request at all — the same guess the body branches refuse to make.
            return Err(TransportError::Framing);
        }
        // Between reads, because a half-written request parks this loop for as long as the peer
        // stays quiet, and a connection closed under it must not go on reading toward a message
        // nobody is waiting for any more.
        if closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        buf.extend_from_slice(&r.scratch[..n]);
    };

    let header_bytes = buf[..header_end].to_vec();
    // A block this reader cannot parse is a message it cannot read. Taking it for an empty header
    // list would invent a framing — declared length zero, no body — out of a parse failure, while
    // the same unreadable bytes still went up as the HEAD frame.
    let headers = raw::parse_message(&header_bytes)
        .ok_or(TransportError::Framing)?
        .headers;
    let mut rest = buf[header_end..].to_vec();
    buf.clear();
    drop(buf);

    if raw::has_transfer_encoding(&headers) {
        if !raw::is_chunked(&headers) {
            // A declared coding this transport cannot frame. Falling through to `Content-Length`
            // would be answering a question the sender did not ask.
            return Err(TransportError::Framing);
        }
        if raw::header(&headers, "content-length").is_some() {
            // Two headers describing two framings of the same bytes. The coding wins the reading,
            // but this reader hands the VERBATIM header prefix up as the HEAD frame, so forwarding
            // it would hand the next reader a length the bytes do not have — the smuggling shape
            // itself. Refused rather than forwarded.
            return Err(TransportError::Framing);
        }
    }

    // The head passed its framing checks, so this request IS accepted for a body — and a client
    // that asked to be told so is WAITING to be told before it sends one. `curl` sets the header
    // itself for any body past about a kibibyte; against a reader that only parks on the body,
    // both sides then wait on each other until the client's own timeout fires, and what the client
    // sees is a hang rather than an answer. `hyper` served this surface in 1.5.5 and answered the
    // header, so the answer is the parity bar. Nothing is written where the client did not ask, and
    // an interim answer that cannot be written is not fatal on its own: the body may already be in
    // flight, and the read below is the one that decides.
    if raw::header(&headers, "expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        let mut w = write.lock().await;
        let _ = w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        let _ = w.flush().await;
    }

    let (bodies, trailers) = if raw::is_chunked(&headers) {
        let mut decoder = raw::ChunkedDecoder::default();
        // A chunked sender declares no total, so the cap is held against the bytes that have
        // actually arrived rather than against a number the peer supplied.
        let mut read_so_far = rest.len();
        decoder.feed(&rest).map_err(|_| TransportError::Framing)?;
        loop {
            // The cap is checked before the done test, not only around the next read, so a whole
            // chunked message that already sits in the buffer is held to it the same as one that
            // arrives across reads — the mirror of the `Content-Length` branch, which caps every
            // body whether or not it had to read past the head.
            if read_so_far > max_body_bytes {
                return Err(TransportError::Framing);
            }
            if decoder.is_done() {
                break;
            }
            let Some(read) = read_or_closed(r, closed, closing).await else {
                return Ok(None);
            };
            let n = read.map_err(|e| HttpTransport::map_io_err(&e))?;
            read_so_far += n;
            if n == 0 {
                // The peer stopped before the terminal chunk: the declared framing did not happen,
                // and guessing where the body ended is the one thing a transport must not do.
                return Err(TransportError::Framing);
            }
            decoder
                .feed(&r.scratch[..n])
                .map_err(|_| TransportError::Framing)?;
        }
        decoder.take()
    } else {
        let declared = raw::content_length(&headers)
            .map_err(|()| TransportError::Framing)?
            .unwrap_or(0);
        if declared > max_body_bytes {
            // Refused on the declaration, before a byte of the body behind it is read: reading a
            // megabyte only to discard it is the resource cost the cap exists to avoid.
            return Err(TransportError::Framing);
        }
        while rest.len() < declared {
            let Some(read) = read_or_closed(r, closed, closing).await else {
                return Ok(None);
            };
            let n = read.map_err(|e| HttpTransport::map_io_err(&e))?;
            if n == 0 {
                // The peer stopped before the length it declared: the same answer the chunked
                // branch gives a peer that stops before the terminal chunk. A body short of its
                // declared length is a message that never arrived, not a smaller one that did.
                return Err(TransportError::Framing);
            }
            rest.extend_from_slice(&r.scratch[..n]);
        }
        rest.truncate(declared);
        (
            if rest.is_empty() {
                Vec::new()
            } else {
                vec![rest]
            },
            Vec::new(),
        )
    };

    let mut frames = vec![body_frame(header_bytes)];
    frames.extend(bodies.into_iter().filter(|b| !b.is_empty()).map(body_frame));
    if !trailers.is_empty() {
        let mut rendered = String::new();
        for (name, value) in &trailers {
            rendered.push_str(name);
            rendered.push_str(": ");
            rendered.push_str(value);
            rendered.push_str("\r\n");
        }
        frames.push(body_frame(rendered.into_bytes()));
    }
    Ok(Some(frames))
}

/// One inbound frame over bytes this connection read, with honest meta: the byte count is what
/// actually moved, and there is no status leg on the ingress side.
fn body_frame(bytes: Vec<u8>) -> (StreamId, Frame) {
    let len = bytes.len() as u64;
    let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
    (
        StreamId(0),
        Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(arc),
            meta: FrameMeta {
                bytes: len,
                transport_units: None,
                status: None,
                status_code: None,
                retry_after_secs: None,
            },
        },
    )
}

/// The offset just past the blank line that ends a header block, searching from `start`, alongside
/// how many bytes of `buf` this call examined — the pair a caller uses to pin the scan's own
/// complexity class without a process-global counter racing every other test in the binary.
///
/// The search JUMPS between line feeds rather than stepping a four-byte window over every position;
/// the terminator's last byte is one, so no candidate is skipped. `start` may sit anywhere in the
/// buffer: the match looks BACKWARD from the line feed it found, so a caller resuming a scan never
/// has to have kept the three bytes before it in view.
fn find_header_end_from(buf: &[u8], start: usize) -> (Option<usize>, usize) {
    let mut i = start.min(buf.len());
    let scanned = buf.len() - i;
    let found = loop {
        let Some(rel) = memchr::memchr(b'\n', &buf[i..]) else {
            break None;
        };
        let at = i + rel;
        if at >= 3 && &buf[at - 3..=at] == b"\r\n\r\n" {
            break Some(at + 1);
        }
        i = at + 1;
    };
    (found, scanned)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    find_header_end_from(buf, 0).0
}

/// What the header scan remembers between reads: how much of the buffer has already been proven
/// not to hold the terminator, and how many bytes it has examined in total.
///
/// Without the cursor the reader rescans the whole growing buffer on every read, which for a header
/// dribbled a byte at a time is quadratic in the header size. The cursor is rewound by three
/// bytes, because that is the most of a four-byte terminator a previous read can have left behind.
/// `scanned` is this instance's own tally, not a crate-global one, so a test reading it back sees
/// only the work its own scan did — never a sibling test's, running in the same binary.
#[derive(Default)]
struct HeaderScan {
    proven: usize,
    scanned: usize,
}

impl HeaderScan {
    fn find(&mut self, buf: &[u8]) -> Option<usize> {
        let (found, scanned) = find_header_end_from(buf, self.proven);
        self.scanned += scanned;
        if found.is_none() {
            self.proven = buf.len().saturating_sub(3);
        }
        found
    }
}

#[cfg(test)]
mod tests;
