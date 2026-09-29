// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SESSION STATE FOR THE SESSION REVISIONS: plane state, bounded, and bound to its owner.
//!
//! The `2025-06-18`, `2025-11-25` and `2024-11-05` revisions open a conversation with `initialize`
//! and keep it in a session the server names. That state belongs to this plane and to no other
//! kind, and it is held here as a plain value with `&mut` methods: the caller owns the one table per
//! plane instance and serialises access to it. Nothing here is process-global (no statics), reads a
//! clock (the caller passes `now_ms`), or draws randomness (the caller passes the entropy).
//!
//! ## Bounded, in count and in bytes, with eviction
//!
//! A session costs memory for as long as it lives, and a client that never sends DELETE never gives
//! it back. So every dimension has a ceiling in [`Bounds`]:
//!
//! - `max_sessions`: opening one more evicts the LEAST RECENTLY USED session.
//! - `idle_ms`: a session untouched for this long is gone at the next lookup or sweep.
//! - `max_session_bytes`: a session's buffered events are trimmed OLDEST FIRST to fit. A trimmed
//!   event can no longer be replayed; the replay says so instead of pretending the tail is whole.
//! - `max_total_bytes`: the whole table is held under this by evicting least-recently-used OTHER
//!   sessions first, then trimming the session being written.
//! - `max_streams`: a session's resumable streams are capped; opening one more drops the oldest.
//!
//! An evicted or expired session answers exactly as an unknown one does. The spec's rule for that
//! (404, and the client re-initialises) is what makes eviction safe to do at all.
//!
//! ## Per-process memory, deliberately
//!
//! Sessions are not shared between replicas. A client whose next request lands on another replica
//! is told its session is unknown and re-initialises, which is the spec's own recovery path. A
//! shared session store would make every replica a reader of every other replica's conversation
//! for no gain the protocol does not already give.
//!
//! ## Bound to the principal that opened it
//!
//! A session id is a bearer of nothing. The table records the [`Owner`] (principal and tenant) that
//! opened each session, and a lookup under any other owner answers "unknown", indistinguishable from
//! a session that never existed, so a leaked id is not a probe. The id is 128 bits from the caller's
//! CSPRNG, and an all-zero entropy buffer (the failure shape of a refused entropy source) is refused
//! rather than minted. Log only [`log_prefix`] of an id, never the whole of it.

use std::collections::{BTreeMap, VecDeque};

use crate::revision::Revision;

/// The ceilings on the session table. See the module header for what each one evicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// Most sessions held at once.
    pub max_sessions: usize,
    /// Most bytes of buffered events one session may hold.
    pub max_session_bytes: usize,
    /// Most bytes the whole table may hold.
    pub max_total_bytes: usize,
    /// A session untouched for this many milliseconds is expired.
    pub idle_ms: u64,
    /// Most resumable streams one session may hold.
    pub max_streams: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_session_bytes: 1 << 20,
            max_total_bytes: 64 << 20,
            idle_ms: 30 * 60 * 1000,
            max_streams: 16,
        }
    }
}

/// The fixed cost charged to a session for its own bookkeeping, so a table of empty sessions is
/// still bounded by `max_total_bytes`.
const SESSION_OVERHEAD: usize = 256;
/// The fixed cost charged per buffered event over its data.
const EVENT_OVERHEAD: usize = 32;

/// The principal and tenant a session is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    /// The authenticated principal that opened the session.
    pub principal: String,
    /// The tenant that principal was authenticated in.
    pub tenant: String,
}

/// How a session's messages are carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carriage {
    /// The single endpoint: POST, the GET stream and DELETE.
    Endpoint,
    /// The `2024-11-05` event stream, with messages POSTed to the address it named.
    EventStream,
}

/// A minted session id: 32 lowercase hex digits, 128 bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    /// The id as the wire carries it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The part of a session id that may be logged: its first eight characters, or nothing when the
/// value is not a well-formed id at all (so a hostile header is never echoed into a log).
#[must_use]
pub fn log_prefix(id: &str) -> &str {
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        &id[..8]
    } else {
        ""
    }
}

/// Why a session could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRefused {
    /// The entropy was all zeroes: the entropy source failed, and an id minted from it would be
    /// guessable and would repeat.
    NoEntropy,
    /// The id already names a live session. The caller draws fresh entropy and tries again.
    Collision,
}

#[derive(Debug)]
struct Event {
    seq: u64,
    /// Session-wide write order, so the oldest event across streams is found without a clock.
    order: u64,
    data: String,
}

#[derive(Debug)]
struct Stream {
    id: u32,
    next_seq: u64,
    /// The highest seq ever trimmed away, or 0 when nothing was trimmed.
    trimmed_through: u64,
    events: VecDeque<Event>,
}

#[derive(Debug)]
struct Session {
    owner: Owner,
    revision: Revision,
    carriage: Carriage,
    initialized: bool,
    last_ms: u64,
    streams: Vec<Stream>,
    next_stream: u32,
    next_order: u64,
    bytes: usize,
}

impl Session {
    fn base_bytes(owner: &Owner) -> usize {
        SESSION_OVERHEAD + owner.principal.len() + owner.tenant.len()
    }

    /// Drops the oldest buffered event in the session. Returns the bytes freed (0 when empty).
    fn trim_oldest(&mut self) -> usize {
        let Some(stream) = self
            .streams
            .iter_mut()
            .filter(|s| !s.events.is_empty())
            .min_by_key(|s| s.events.front().map_or(u64::MAX, |e| e.order))
        else {
            return 0;
        };
        let Some(event) = stream.events.pop_front() else {
            return 0;
        };
        stream.trimmed_through = stream.trimmed_through.max(event.seq);
        let freed = event.data.len() + EVENT_OVERHEAD;
        self.bytes -= freed;
        freed
    }
}

/// What a `Last-Event-ID` resumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// The stream the cursor named, which the resumed connection continues.
    pub stream: u32,
    /// `(event id, data)` for every buffered event after the cursor, in order.
    pub events: Vec<(String, String)>,
    /// `false` when events after the cursor were trimmed and cannot be replayed.
    pub complete: bool,
}

/// The session table for one plane instance.
#[derive(Debug)]
pub struct SessionTable {
    bounds: Bounds,
    sessions: BTreeMap<String, Session>,
    total_bytes: usize,
}

/// Formats an event id: `<stream>-<seq>`, unique within the session.
fn event_id(stream: u32, seq: u64) -> String {
    format!("{stream}-{seq}")
}

/// Reads an event id back. `None` for anything this table did not write.
fn parse_event_id(raw: &str) -> Option<(u32, u64)> {
    let (s, q) = raw.split_once('-')?;
    Some((s.parse().ok()?, q.parse().ok()?))
}

impl SessionTable {
    /// An empty table under `bounds`.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            sessions: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    /// The ceilings this table enforces.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// Live sessions (expired ones not yet swept included).
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the table holds no session.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Bytes charged to the table.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Opens a session for `owner`. `entropy` is 16 bytes from the caller's CSPRNG.
    ///
    /// # Errors
    /// [`OpenRefused::NoEntropy`] for an all-zero buffer, [`OpenRefused::Collision`] when the id is
    /// already live.
    pub fn open(
        &mut self,
        entropy: [u8; 16],
        owner: Owner,
        revision: Revision,
        carriage: Carriage,
        now_ms: u64,
    ) -> Result<SessionId, OpenRefused> {
        if entropy.iter().all(|b| *b == 0) {
            return Err(OpenRefused::NoEntropy);
        }
        let mut id = String::with_capacity(32);
        for b in entropy {
            id.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            id.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
        }
        self.sweep(now_ms);
        if self.sessions.contains_key(&id) {
            return Err(OpenRefused::Collision);
        }
        while self.sessions.len() >= self.bounds.max_sessions.max(1) {
            if !self.evict_lru(None) {
                break;
            }
        }
        let bytes = Session::base_bytes(&owner);
        self.total_bytes += bytes;
        self.sessions.insert(
            id.clone(),
            Session {
                owner,
                revision,
                carriage,
                initialized: false,
                last_ms: now_ms,
                streams: Vec::new(),
                next_stream: 0,
                next_order: 0,
                bytes,
            },
        );
        self.enforce_total(&id);
        Ok(SessionId(id))
    }

    /// Finds `id` for `owner`, refreshing its idle clock. Unknown, expired and foreign sessions all
    /// read `None`.
    fn find(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<&mut Session> {
        let last_ms = self.sessions.get(id)?.last_ms;
        let expired = now_ms.saturating_sub(last_ms) >= self.bounds.idle_ms;
        if expired {
            self.remove(id);
            return None;
        }
        let s = self.sessions.get_mut(id)?;
        if s.owner != *owner {
            return None;
        }
        s.last_ms = now_ms;
        Some(s)
    }

    /// The revision `id` negotiated, when `owner` holds it.
    pub fn revision(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<Revision> {
        self.find(id, owner, now_ms).map(|s| s.revision)
    }

    /// How `id` is carried, when `owner` holds it.
    pub fn carriage(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<Carriage> {
        self.find(id, owner, now_ms).map(|s| s.carriage)
    }

    /// Records `notifications/initialized`. `false` when `owner` does not hold `id`.
    pub fn mark_initialized(&mut self, id: &str, owner: &Owner, now_ms: u64) -> bool {
        self.find(id, owner, now_ms)
            .map(|s| s.initialized = true)
            .is_some()
    }

    /// Whether `id` has seen `notifications/initialized`.
    pub fn is_initialized(&mut self, id: &str, owner: &Owner, now_ms: u64) -> bool {
        self.find(id, owner, now_ms).is_some_and(|s| s.initialized)
    }

    /// Ends `id` (DELETE). `false` when `owner` does not hold it.
    pub fn close(&mut self, id: &str, owner: &Owner, now_ms: u64) -> bool {
        if self.find(id, owner, now_ms).is_none() {
            return false;
        }
        self.remove(id);
        true
    }

    /// Opens a resumable stream in `id`. When the session is at `max_streams`, the oldest stream
    /// and its buffered events are dropped first.
    pub fn open_stream(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<u32> {
        let max_streams = self.bounds.max_streams.max(1);
        let s = self.find(id, owner, now_ms)?;
        let mut freed = 0;
        while s.streams.len() >= max_streams {
            let dropped = s.streams.remove(0);
            freed += dropped
                .events
                .iter()
                .map(|e| e.data.len() + EVENT_OVERHEAD)
                .sum::<usize>();
        }
        s.bytes -= freed;
        let stream = s.next_stream;
        s.next_stream = s.next_stream.wrapping_add(1);
        s.streams.push(Stream {
            id: stream,
            next_seq: 1,
            trimmed_through: 0,
            events: VecDeque::new(),
        });
        self.total_bytes -= freed;
        Some(stream)
    }

    /// Buffers `data` as the next event on `stream` and returns its event id. The buffer is then
    /// trimmed to the session and table bounds. `None` when `owner` does not hold `id` or the stream
    /// is not open.
    pub fn push(
        &mut self,
        id: &str,
        owner: &Owner,
        stream: u32,
        data: &str,
        now_ms: u64,
    ) -> Option<String> {
        let max_session = self.bounds.max_session_bytes;
        let s = self.find(id, owner, now_ms)?;
        let order = s.next_order;
        let st = s.streams.iter_mut().find(|st| st.id == stream)?;
        let seq = st.next_seq;
        st.next_seq += 1;
        let cost = data.len() + EVENT_OVERHEAD;
        st.events.push_back(Event {
            seq,
            order,
            data: data.to_string(),
        });
        s.next_order += 1;
        s.bytes += cost;
        let base = Session::base_bytes(&s.owner);
        let mut freed = 0;
        while s.bytes > base + max_session {
            let f = s.trim_oldest();
            if f == 0 {
                break;
            }
            freed += f;
        }
        self.total_bytes = self.total_bytes + cost - freed;
        self.enforce_total(id);
        Some(event_id(stream, seq))
    }

    /// Resumes after `last_event_id`. `None` when `owner` does not hold `id`, or the cursor names a
    /// stream the session does not hold (a cursor from another stream is never replayed here: the
    /// spec forbids replaying one stream's messages on another).
    pub fn replay(
        &mut self,
        id: &str,
        owner: &Owner,
        last_event_id: &str,
        now_ms: u64,
    ) -> Option<Replay> {
        let (stream, cursor) = parse_event_id(last_event_id)?;
        let s = self.find(id, owner, now_ms)?;
        let st = s.streams.iter().find(|st| st.id == stream)?;
        let events: Vec<(String, String)> = st
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .map(|e| (event_id(stream, e.seq), e.data.clone()))
            .collect();
        Some(Replay {
            stream,
            events,
            complete: st.trimmed_through <= cursor,
        })
    }

    /// Drops every expired session. Returns how many.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let idle = self.bounds.idle_ms;
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.last_ms) >= idle)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            self.remove(k);
        }
        expired.len()
    }

    fn remove(&mut self, id: &str) {
        if let Some(s) = self.sessions.remove(id) {
            self.total_bytes -= s.bytes;
        }
    }

    /// Evicts the least recently used session other than `keep`. `false` when there is none.
    fn evict_lru(&mut self, keep: Option<&str>) -> bool {
        let victim = self
            .sessions
            .iter()
            .filter(|(k, _)| Some(k.as_str()) != keep)
            .min_by_key(|(k, s)| (s.last_ms, (*k).clone()))
            .map(|(k, _)| k.clone());
        match victim {
            Some(v) => {
                self.remove(&v);
                true
            }
            None => false,
        }
    }

    /// Holds the table under `max_total_bytes`: other sessions go first, then `keep`'s oldest
    /// events.
    fn enforce_total(&mut self, keep: &str) {
        while self.total_bytes > self.bounds.max_total_bytes {
            if self.evict_lru(Some(keep)) {
                continue;
            }
            let freed = self.sessions.get_mut(keep).map_or(0, Session::trim_oldest);
            if freed == 0 {
                break;
            }
            self.total_bytes -= freed;
        }
    }
}

/// WHAT BUSBAR REMEMBERS ABOUT ONE UPSTREAM, as a client: the revision it negotiated and, on a
/// session revision, the upstream's session and the message address it named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remembered {
    /// The negotiated revision.
    pub revision: Revision,
    /// The upstream's session id, on a session revision.
    pub session: Option<String>,
    /// The `2024-11-05` message address the upstream's event stream named.
    pub message_address: Option<String>,
}

impl Remembered {
    fn bytes(&self, key: &str) -> usize {
        SESSION_OVERHEAD
            + key.len()
            + self.session.as_ref().map_or(0, String::len)
            + self.message_address.as_ref().map_or(0, String::len)
    }
}

/// The client's per-upstream memory, bounded in count and bytes with least-recently-used eviction.
/// Forgetting an upstream costs one renegotiation and nothing else.
#[derive(Debug)]
pub struct UpstreamTable {
    max_entries: usize,
    max_bytes: usize,
    entries: BTreeMap<String, (Remembered, u64)>,
    bytes: usize,
    tick: u64,
}

impl UpstreamTable {
    /// An empty table holding at most `max_entries` upstreams and `max_bytes`.
    #[must_use]
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_bytes,
            entries: BTreeMap::new(),
            bytes: 0,
            tick: 0,
        }
    }

    /// Upstreams remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes charged.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// What is remembered about `upstream`, refreshing its recency.
    pub fn get(&mut self, upstream: &str) -> Option<Remembered> {
        self.tick += 1;
        let tick = self.tick;
        self.entries.get_mut(upstream).map(|(r, t)| {
            *t = tick;
            r.clone()
        })
    }

    /// Remembers `value` for `upstream`, evicting least-recently-used upstreams to fit.
    pub fn put(&mut self, upstream: &str, value: Remembered) {
        self.forget(upstream);
        let cost = value.bytes(upstream);
        if cost > self.max_bytes {
            return;
        }
        while self.entries.len() >= self.max_entries || self.bytes + cost > self.max_bytes {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.forget(&victim);
        }
        self.tick += 1;
        self.bytes += cost;
        self.entries
            .insert(upstream.to_string(), (value, self.tick));
    }

    /// Forgets `upstream` (its session ended, or it answered 404 for it).
    pub fn forget(&mut self, upstream: &str) {
        if let Some((r, _)) = self.entries.remove(upstream) {
            self.bytes -= r.bytes(upstream);
        }
    }
}

#[cfg(test)]
#[path = "tests/session_tests.rs"]
mod tests;
