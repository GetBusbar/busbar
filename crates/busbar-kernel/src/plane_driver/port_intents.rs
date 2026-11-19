// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The intents a plane answers with, resolved by core (IF §8.6, §12.5, §12.9, §12.19, §12.24; PLANE-DRIVER.md
//! slice 6). A plane states LOOKUP, STORE, DELETE, COMMIT, WORK, PUSH, SIGNAL, WAKE_AT and DETACH inside an answer;
//! it never calls the store. [`Task::resolve`] takes one answer, applies its intents in answer order (STORE, DELETE
//! and COMMIT before LOOKUP and WORK are resolved), and delivers each result kind back as one `piece(FROM_CORE)`
//! before any other call on the session. The answer to such a piece can carry intents of its own, which resolve the
//! same way; a plane that never settles is a [`Violation::IntentStorm`].
//!
//! [`IntentHost`] is the seam: [`KernelIntents`] is its production form over [`PluginRecords`], the push queue and
//! the session signal registry; a test fakes it. A caller-scoped record (`LK_CALLER`, `REC_CALLER`), a WORK and a
//! caller-scoped SIGNAL all need a verified subject: without one core answers the refusal itself and the host is
//! never asked (it would otherwise answer from the shared namespace).
//!
//! The grant, trust, media and custody intents (`Entitle`, `Judge`, `Mint`, `Sign`, `Connect`, `Sight`, `Trust*`,
//! `Rendezvous`, `Obs*`) are driven the same way, each onto its kernel service (`port_services::Services`); a service
//! not installed answers its fail-closed value. WORK is decided by [`DurableDecider`] over [`DurableWork`]; with no
//! decider installed [`NoWork`] answers `R_UNSUPPORTED`, the fail-closed answer the IF defines, so a plane refuses
//! paid dispatch as it does without a recovery runtime. The store-backed [`DurableWork`] over `host_work/` and
//! `host_recovery.rs` is the next piece (it needs the recovery binding the governance standing captures).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::fail::refused::{R_DENIED, R_INVALID, R_RATE_LIMITED, R_UNSUPPORTED};
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{
    CONNECT_BEGIN, CONNECT_REVOKE, CONNECT_STATUS, CONN_NONE, CONN_PENDING, CONN_REFUSED,
    DEST_INTERNAL, DISTRUST_UNKNOWN, FROM_CORE, LK_CALLER, LK_CHAIN, LK_PREFIX, MINT_ONCE,
    OBS_REFUSED, P_CHANNEL, P_COMMITTED, P_CONNECT, P_ENTITLE, P_ERROR, P_JUDGED, P_LOOKUP,
    P_MINTED, P_OBSERVED, P_RENDEZVOUS, P_RV_FAILED, P_SIGNAL, P_SIGNED, P_STORE_FAILED, P_TRUST,
    P_WORK, RV_ACCEPT, RV_REMOTE, SIGNED_MALFORMED_ROOT, SIGN_JWS_DETACHED, TRUST_SERVES,
    TRUST_STATE, WORK_FIND, WORK_LIVE, WORK_OPEN, WORK_SETTLE, WORK_SETTLED,
};
use busbar_plugin_abi::records::{commit, tag, RecDelRec, RecPredRec, RecPutRec, Records, Reply};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::codec::plane::{
    encode_chain_state, encode_chan_attach, encode_committed, encode_connect_answers,
    encode_entitle_answers, encode_judged, encode_lookup_hits, encode_minted, encode_observed,
    encode_refusal, encode_signed, encode_trust_answers, encode_work_answers, SignedAnswer,
};
use busbar_ports::plane::{ObservedAnswer, TrustAnswer, TrustItem, WorkAnswer};

use super::plane_judge::PlaneJudge;
use super::port_channels::{ChannelAttach, ChannelHost, Channels, Held};
use super::port_services::{MediaHeld, ObservationIn, Services};
use super::port_session::{Answer, Calls, Effects, SessionError, Task, Violation};
use crate::channels::SessionSignals;
use crate::hashing::Sha256;
use crate::plane_grants::{SignedJws, TicketMint};
use crate::plugin_records::{
    CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, MAX_KEY, MAX_VALUE,
};
use crate::push::StorePushQueue;

/// How many rounds of intents one answer may chain (an answer's pieces answering with more intents) before the
/// session is cut. A plane's real chains are two or three deep (LOOKUP, then COMMIT, then WORK).
const MAX_ROUNDS: u32 = 64;

/// Where one intent field's bytes sit in its answer's [`Lent`] buffer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Span {
    at: u32,
    len: u32,
}

/// The bytes an answer's intents name: one buffer per answer, appended as the plane's items are read (the plane's
/// output buffer is reused by its next call, so each item is copied once, here, and never again).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lent {
    bytes: Vec<u8>,
}

impl Lent {
    /// Appends `bytes` and names them. An answer is bounded by the plane's output cap, far below 4 GiB.
    pub fn put(&mut self, bytes: &[u8]) -> Span {
        let at = u32::try_from(self.bytes.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(bytes);
        Span {
            at,
            len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        }
    }

    /// The bytes `span` names (empty for a span of another buffer).
    #[must_use]
    pub fn bytes(&self, span: Span) -> &[u8] {
        let at = span.at as usize;
        self.bytes
            .get(at..at.saturating_add(span.len as usize))
            .unwrap_or_default()
    }

    /// The text `span` names: what [`Lent::put`] was given as `&str` reads back as it (empty otherwise).
    #[must_use]
    pub fn text(&self, span: Span) -> &str {
        std::str::from_utf8(self.bytes(span)).unwrap_or_default()
    }

    /// The validated nested records `span` names.
    #[must_use]
    pub fn records(&self, span: Span) -> Records<'_> {
        Records::new(self.bytes(span))
    }
}

/// The OBS_REQUIRE classes of an OBS_SCOPE, read back from its validated records.
pub(crate) fn required_classes(lent: &Lent, require: Span) -> impl Iterator<Item = &str> {
    lent.records(require)
        .filter_map(|rec| rec.ok()?.text().ok())
}

/// The (class, amount, scale) counts of an OBSERVE, read back from its validated USAGE records.
pub(crate) fn observed_counts(lent: &Lent, counts: Span) -> impl Iterator<Item = (&str, u64, u32)> {
    lent.records(counts).filter_map(|rec| {
        let (head, class) = rec
            .ok()?
            .pod_tail::<busbar_plugin_abi::plane::UsageRec>()
            .ok()?;
        Some((std::str::from_utf8(class).ok()?, head.amount, head.scale))
    })
}

/// The (name, digest) items of a SIGHT, read back from its validated pair records.
pub(crate) fn sighted_items(lent: &Lent, items: Span) -> impl Iterator<Item = (&str, [u8; 32])> {
    lent.records(items).filter_map(|rec| {
        let (name, digest) = rec.ok()?.pair().ok()?;
        Some((name, <[u8; 32]>::try_from(digest).ok()?))
    })
}

/// One intent of an answer. Its bytes live in the answer's [`Lent`] buffer (copied there once, as the sink's borrows end
/// with the answer); a [`Span`] names them. A nested record list (OBS_REQUIRE, OBSERVE counts, SIGHT items, COMMIT
/// ops, PUSH records, a CHANNEL head) keeps the records the adapter validated, read again where they are used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Lookup {
        flags: u32,
        limit: u32,
        key: Span,
    },
    Store {
        flags: u32,
        ttl_s: u64,
        key: Span,
        value: Span,
    },
    Delete {
        flags: u32,
        key: Span,
    },
    /// `ops` = the nested REC_PRED*, REC_PUT*, REC_DEL* the adapter validated.
    Commit {
        check: u32,
        ops: Span,
    },
    Work {
        check: u32,
        op: u32,
        target: Option<Span>,
        reference: Option<Span>,
    },
    /// `recs` = the nested records core's push queue copies and owns.
    Push {
        ttl_s: u64,
        recs: Span,
    },
    Signal {
        flags: u32,
        key: Span,
    },
    /// ENTITLE: does the verified principal hold `grant` (§12.11).
    Entitle {
        check: u32,
        grant: Span,
    },
    /// JUDGE: the destination guard on `dest` (§12.1); `class` <= 4 and `flags` are checked when the answer is read.
    Judge {
        check: u32,
        class: u32,
        flags: u32,
        dest: Span,
    },
    /// MINT: seal a ticket for the verified subject (§12.11); `flags` = MINT_ONCE?.
    Mint {
        check: u32,
        flags: u32,
        ttl_s: u64,
        scope: Option<Span>,
        audience: Option<Span>,
        prefix: Option<Span>,
        record: Option<Span>,
    },
    /// SIGN: sign `payload` with the host's key (§12.11); `flags` = SIGN_JWS_COMPACT or SIGN_JWS_DETACHED.
    Sign {
        check: u32,
        flags: u32,
        payload: Span,
    },
    /// CONNECT: a caller connection to a configured upstream (§12.12); `op` = CONNECT_BEGIN, _STATUS or _REVOKE.
    Connect {
        check: u32,
        op: u32,
        upstream: Span,
        return_to: Option<Span>,
    },
    /// RENDEZVOUS: `flags` = RV_ACCEPT (a client's offer, accepted as client exchange `exchange`) or RV_REMOTE
    /// (the far end's answer for upstream exchange `exchange`); `description` = the session description (§12.13).
    Rendezvous {
        exchange: u32,
        flags: u32,
        description: Span,
    },
    /// OBS_SCOPE: create, reattach or close usage-observation custody (§12.4); `require` = the OBS_REQUIRE classes.
    ObsScope {
        check: u32,
        op: u32,
        scope: Option<[u8; 32]>,
        require: Span,
    },
    /// OBSERVE: one owned usage observation (§12.4); `counts` = (class, amount, scale).
    Observe {
        check: u32,
        state: u32,
        rated_subject: u32,
        revision_order: u64,
        scope: [u8; 32],
        event: Span,
        component: Span,
        revision: Option<Span>,
        counts: Span,
        evidence: Option<Span>,
    },
    /// SIGHT: the plane observed `party` offering `items` (name, SHA-256 digest); no answer (§12.14).
    Sight {
        party: Span,
        catalog: Option<[u8; 32]>,
        items: Span,
    },
    /// TRUST: `op` = TRUST_SERVES (with its optional item) or TRUST_STATE (§12.14).
    Trust {
        check: u32,
        op: u32,
        party: Span,
        item: Option<(Span, Option<[u8; 32]>)>,
    },
    /// TRUST_VERIFY: `signatures` (a JSON array) over `payload`, against the root core holds for `party`.
    TrustVerify {
        check: u32,
        party: Span,
        payload: Span,
        signatures: Span,
    },
    /// CHANNEL: attach `exchange` to a shared upstream channel (§12.19); `head` = the nested HTTP head records.
    Channel {
        exchange: u32,
        carrier: u32,
        flags: u32,
        framing: u32,
        key: Span,
        head: Span,
    },
    /// CH_READY: the greeting session's greeting is done; `tail` is handed to later attachers.
    ChReady {
        exchange: u32,
        tail: Span,
    },
}

/// DETACH: the session outlives its client response until FINISH or `ttl_s` (clamped), registered under `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detach {
    pub ttl_s: u64,
    pub flags: u32,
    pub key: Box<[u8]>,
}

/// A LOOKUP's result, read into the task's one read buffer: its hits in order, and for `LK_CHAIN` the
/// chain's state (`len`, `broken_at`). The hits' keys and values lie end to end in one run of bytes: a hit
/// read from the store is copied once and nothing is allocated per hit. The buffer is made with its task,
/// cleared per LOOKUP, and released with the task.
#[derive(Debug, Default)]
pub struct Looked {
    bytes: Vec<u8>,
    /// Each hit's key length and value length, in order.
    hits: Vec<(usize, usize)>,
    pub chain: Option<(u64, u64)>,
}

impl Looked {
    /// No hits and no chain state; the buffer keeps its room.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.hits.clear();
        self.chain = None;
    }

    /// One more hit: its key, given as parts laid end to end, and its value.
    pub fn push(&mut self, key: &[&[u8]], value: &[u8]) {
        let before = self.bytes.len();
        for part in key {
            self.bytes.extend_from_slice(part);
        }
        let key_len = self.bytes.len() - before;
        self.bytes.extend_from_slice(value);
        self.hits.push((key_len, value.len()));
    }

    /// Where the buffer stands now, for [`Looked::rewind`].
    #[must_use]
    pub fn mark(&self) -> (usize, usize) {
        (self.bytes.len(), self.hits.len())
    }

    /// Drop every hit pushed since `mark`.
    pub fn rewind(&mut self, mark: (usize, usize)) {
        self.bytes.truncate(mark.0);
        self.hits.truncate(mark.1);
    }

    /// The hits, in order: (key, value).
    pub fn hits(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        let mut rest = self.bytes.as_slice();
        self.hits.iter().map(move |&(key_len, value_len)| {
            let (key, after) = rest.split_at(key_len);
            let (value, after) = after.split_at(value_len);
            rest = after;
            (key, value)
        })
    }

    /// How many hits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    /// No hit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

/// One TRUST_STATE item's name length, verdict, approved digest and sighted digest.
type TrustItemState = (usize, u32, Option<[u8; 32]>, Option<[u8; 32]>);

/// A TRUST_STATE's item states, read into the task's one buffer: the names lie end to end in one run of
/// text and nothing is allocated per item. Cleared per TRUST_STATE; released with the task.
#[derive(Debug, Default)]
pub struct TrustItems {
    names: String,
    /// Each item's state, in order.
    items: Vec<TrustItemState>,
}

impl TrustItems {
    /// No items; the buffer keeps its room.
    pub fn clear(&mut self) {
        self.names.clear();
        self.items.clear();
    }

    /// One more item state.
    pub fn push(&mut self, item: &TrustItem<'_>) {
        self.names.push_str(item.name);
        self.items
            .push((item.name.len(), item.verdict, item.approved, item.sighted));
    }

    /// The item states, in order.
    pub fn iter(&self) -> impl Iterator<Item = TrustItem<'_>> {
        let mut rest = self.names.as_str();
        self.items
            .iter()
            .map(move |&(name_len, verdict, approved, sighted)| {
                let (name, after) = rest.split_at(name_len);
                rest = after;
                TrustItem {
                    name,
                    verdict,
                    approved,
                    sighted,
                }
            })
    }

    /// No item.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// What a task's resolver reads into, intent after intent: one LOOKUP's hits, one TRUST_STATE's items and
/// one TRUST_VERIFY's named member. The task owns it ([`Task`]'s `reads`): made empty with the task, each
/// part cleared before the intent that fills it, released with the task.
#[derive(Debug, Default)]
pub struct Reads {
    looked: Looked,
    trust_items: TrustItems,
    named: String,
}

/// One WORK intent, the verified principal's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntent<'a> {
    pub op: u32,
    pub target: Option<&'a str>,
    pub reference: Option<&'a str>,
    /// The request's identity records (ID_*): the principal the row binds to (§12.24).
    pub identity: &'a [u8],
}

/// One WORK_ANS (§8.6): `status` 0 = done, else a generic REFUSED code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOutcome<'a> {
    pub status: u32,
    pub state: u32,
    pub reference: Cow<'a, str>,
    pub target: Cow<'a, str>,
}

impl WorkOutcome<'_> {
    /// Core cannot recover here (no store or no recovery runtime, §12.24).
    #[must_use]
    pub fn unsupported() -> Self {
        Self::refused(R_UNSUPPORTED)
    }

    fn refused(status: u32) -> Self {
        Self {
            status,
            state: 0,
            reference: Cow::Borrowed(""),
            target: Cow::Borrowed(""),
        }
    }
}

/// What resolving an intent needs from core. A call that reaches the store, the push queue or a kernel service is
/// awaited on the session's task (`BoxFut`: the host is a trait object the seat holds, so its future is boxed, one
/// allocation per intent the plane states; a session that states none pays none). The pure reads stay synchronous.
pub trait IntentHost: Send + Sync {
    /// LOOKUP in the scope the resolver chose. `flags` carries `LK_PREFIX` and `LK_CHAIN` (for `LK_CHAIN` the key
    /// is the chain key followed by the 8-byte `after`). The hits, and a chain's state, are read into `looked`,
    /// which the caller hands in cleared; on an error the caller discards whatever was read.
    fn lookup<'a>(
        &'a self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// [`Self::lookup`], bounded by the request's own `deadline` as well: a host whose calls carry a ceiling of
    /// their own ([`Namespace::caller`]) waits until the earlier of the two. Default: [`Self::lookup`] (a host with
    /// no ceiling of its own is bounded by the request's future, which is dropped at the deadline).
    fn lookup_within<'a>(
        &'a self,
        deadline: Instant,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        let _ = deadline;
        self.lookup(scope, flags, limit, key, looked)
    }
    /// STORE. `flags & LK_CHAIN` appends `value` to the host chain `key`.
    fn store<'a>(
        &'a self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &'a [u8],
        value: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn delete<'a>(&'a self, scope: Scope, key: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>>;
    fn commit<'a>(
        &'a self,
        scope: Scope,
        ops: &'a [CommitOp<'a>],
    ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>>;
    /// WORK under the request's verified principal. The default is the fail-closed answer.
    fn work<'a>(&'a self, _intent: &'a WorkIntent<'a>) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(std::future::ready(WorkOutcome::unsupported()))
    }
    fn push<'a>(&'a self, ttl_s: u64, recs: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>>;
    /// SIGNAL: every session of this instance detached under `key` (only `subject`'s when it is Some).
    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>);
    /// A command signal cannot fall back to instance or subject-wide delivery.
    fn signal_command(
        &self,
        _authority: &crate::channels::authority::ChannelAuthority,
        _key: &[u8],
    ) {
    }
    /// ENTITLE: does the verified principal (its ID_* `identity` records) hold `grant`? The default is no.
    fn entitle(&self, _identity: &[u8], _grant: &str) -> bool {
        false
    }
    /// JUDGE: the `DEST_*` verdict for `dest` (the answer the plane renders in its own protocol). The default is
    /// the fail-closed `DEST_INTERNAL`.
    fn judge<'a>(&'a self, _dest: &'a str, _class: u32, _flags: u32) -> BoxFut<'a, u32> {
        Box::pin(std::future::ready(DEST_INTERNAL))
    }
    /// MINT for the verified `m.subject`: the client-facing ticket text and its expiry (epoch seconds), or the
    /// generic REFUSED code. The default is `R_UNSUPPORTED`.
    fn mint<'a>(&'a self, _m: TicketMint<'a>) -> BoxFut<'a, Result<(Box<str>, u64), u32>> {
        Box::pin(std::future::ready(Err(R_UNSUPPORTED)))
    }
    /// SIGN `payload` with the host key as a JWS, or the generic REFUSED code. The default is `R_UNSUPPORTED`.
    fn sign<'a>(
        &'a self,
        _payload: &'a [u8],
        _detached: bool,
    ) -> BoxFut<'a, Result<SignedJws, u32>> {
        Box::pin(std::future::ready(Err(R_UNSUPPORTED)))
    }
    /// SIGHT: record that `party` offered `items` (name, digest), under the listing's `catalog` hash. A sighting
    /// the book cannot record is logged; the plane is not told (SIGHT has no answer). The default records nothing.
    fn sight<'a>(
        &'a self,
        _party: &'a str,
        _catalog: Option<[u8; 32]>,
        _items: &'a [(&'a str, [u8; 32])],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
    }
    /// TRUST_SERVES: `DISTRUST_NONE` or the `DISTRUST_*` that refuses (digest `None` = the last sighting). The
    /// default refuses as unknown.
    fn trust_serves(&self, _party: &str, _item: Option<(&str, Option<[u8; 32]>)>) -> u32 {
        DISTRUST_UNKNOWN
    }
    /// TRUST_STATE: the counterparty verdict and the listing's catalogue digest; the per-item state is read
    /// into `items`, which the caller hands in cleared. The default refuses as unknown.
    fn trust_state(&self, _party: &str, _items: &mut TrustItems) -> (u32, Option<[u8; 32]>) {
        (DISTRUST_UNKNOWN, None)
    }
    /// TRUST_VERIFY: the `SIGNED_*` verdict; for `SIGNED_ALGORITHM` and `SIGNED_CRITICAL` the named member is
    /// written into `named`, which the caller hands in cleared. The default has no root:
    /// `SIGNED_MALFORMED_ROOT`.
    fn trust_verify(
        &self,
        _party: &str,
        _payload: &[u8],
        _signatures: &[u8],
        _named: &mut String,
    ) -> u32 {
        SIGNED_MALFORMED_ROOT
    }
    /// RENDEZVOUS(RV_ACCEPT) on `route`: the local session description and the bridge the session holds under the
    /// exchange. The default is unavailable.
    fn rendezvous_accept<'a>(
        &'a self,
        _route: u32,
        _offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn Held>), RecordsDenied>> {
        Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
    }
    /// OBS_SCOPE as the principal whose identity records are `identity`: (OBS_READY | OBS_CLOSED | OBS_PENDING |
    /// OBS_REFUSED, the scope id for READY and CLOSED). Durable before it returns. The default is `OBS_REFUSED`.
    fn obs_scope<'a>(
        &'a self,
        _identity: &'a [u8],
        _op: u32,
        _scope: Option<[u8; 32]>,
        _require: &'a [&'a str],
    ) -> BoxFut<'a, (u32, Option<[u8; 32]>)> {
        Box::pin(std::future::ready((OBS_REFUSED, None)))
    }
    /// OBSERVE as the principal whose identity records are `identity`: (OBS_ACCEPTED | OBS_PENDING |
    /// OBS_REFUSED, the receipt bytes). Durable before it returns. The default is `OBS_REFUSED`.
    fn observe<'a>(
        &'a self,
        _identity: &'a [u8],
        _o: &'a ObservationIn<'a>,
    ) -> BoxFut<'a, (u32, Vec<u8>)> {
        Box::pin(std::future::ready((OBS_REFUSED, Vec::new())))
    }
    /// CONNECT as the verified `subject`: the `CONN_*` state and, for a BEGIN, the URL to send the caller to.
    /// The default is `CONN_REFUSED`.
    fn connect<'a>(
        &'a self,
        _op: u32,
        _subject: &'a str,
        _upstream: &'a str,
        _return_to: Option<&'a str>,
    ) -> BoxFut<'a, (u32, Option<Box<str>>)> {
        Box::pin(std::future::ready((CONN_REFUSED, None)))
    }
}

/// The request's subject scope: SHA-256 of its ID_SUBJECT text (IF §12.5).
#[must_use]
pub fn subject_scope(subject: &str) -> [u8; 32] {
    Sha256::digest(subject.as_bytes())
}

/// One result piece core delivers: `piece(FROM_CORE, 0, flags, bytes)`.
pub struct Piece<'i> {
    /// The exchange the piece is for (0 for the client side and most FROM_CORE results).
    pub exchange: u32,
    pub flags: u32,
    pub bytes: PieceBytes<'i>,
}

/// A piece's bytes, never copied to be delivered: the records encoded for it (the reply buffer itself, which wipes
/// on drop), an intent's own bytes, or bytes a host answered with, moved in.
pub enum PieceBytes<'i> {
    Records(Reply),
    Lent(&'i [u8]),
    Owned(Box<[u8]>),
}

impl PieceBytes<'_> {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Records(reply) => reply.as_bytes(),
            Self::Lent(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

/// One answer's result pieces, on the stack up to one of each kind (thirteen) and a few spares.
pub type Pieces<'i> = smallvec::SmallVec<[Piece<'i>; 16]>;

/// A piece of records for core's results, encoded into `reply` (created by the first record).
fn records_piece<'i>(flags: u32, reply: Option<Reply>) -> Option<Piece<'i>> {
    reply.map(|reply| Piece {
        exchange: 0,
        flags,
        bytes: PieceBytes::Records(reply),
    })
}

/// Resolves intents against a host for one request: `subject` is the verified principal's scope, if any.
fn signal_admitted(
    host: &dyn IntentHost,
    request: &super::request_admission::AdmittedRequest,
    flags: u32,
    key: &[u8],
    subject: Option<[u8; 32]>,
) {
    if !request.is_live() {
        return;
    }
    if request.registered_command().is_some() {
        if let Ok(authority) = crate::channels::authority::ChannelAuthority::new(request.clone()) {
            host.signal_command(&authority, key);
        }
    } else if flags & LK_CALLER == 0 {
        host.signal(key, None);
    } else if let Some(subject) = subject {
        host.signal(key, Some(subject));
    }
}

/// Resolves intents against the same admitted request throughout the session.
pub struct Resolver<'h> {
    host: &'h dyn IntentHost,
    subject: Option<[u8; 32]>,
    channels: Option<&'h dyn ChannelHost>,
    principal: Option<Principal<'h>>,
    route: u32,
    pending: Option<&'h super::port_admission::Pending>,
    deadline: Option<Instant>,
}

/// The verified principal an intent runs as: its ID_SUBJECT text and the ID_* identity records it was admitted with.
#[derive(Clone, Copy)]
struct Principal<'h> {
    subject: &'h str,
    identity: &'h [u8],
}

impl<'h> Resolver<'h> {
    #[must_use]
    pub fn new(host: &'h dyn IntentHost, subject: Option<[u8; 32]>) -> Self {
        Self {
            host,
            subject,
            channels: None,
            principal: None,
            route: 0,
            pending: None,
            deadline: None,
        }
    }

    /// The request's subject scope (SHA-256 of its ID_SUBJECT), when it has a verified principal.
    #[must_use]
    pub fn subject(&self) -> Option<[u8; 32]> {
        self.subject
    }

    /// The mounted route the request arrived on (RENDEZVOUS picks the route's media listener).
    #[must_use]
    pub fn with_route(mut self, route: u32) -> Self {
        self.route = route;
        self
    }

    pub fn with_admission(mut self, pending: Option<&'h super::port_admission::Pending>) -> Self {
        self.pending = pending;
        self
    }

    /// The request's verified principal: its ID_SUBJECT text and the identity records it was admitted with. It sets
    /// the subject scope as [`subject_scope`] does, and is what ENTITLE, MINT and CONNECT run as; without one they
    /// are refused here and the host is never asked.
    ///
    /// The anonymous principal (`native_chain::ANONYMOUS`) is the one subject every caller of an open chain
    /// shares, so it is no caller reference: it sets no scope and no principal, and every caller-scoped intent is
    /// refused for it as for a request with no verified principal (one anonymous caller never reads another's
    /// records; v1.5.5 refused it the same way).
    #[must_use]
    pub fn with_principal(mut self, subject: &'h str, identity: &'h [u8]) -> Self {
        if subject == crate::auth::native_chain::ANONYMOUS {
            self.subject = None;
            self.principal = None;
            return self;
        }
        self.subject = Some(subject_scope(subject));
        self.principal = Some(Principal { subject, identity });
        self
    }

    /// The request's own deadline: a LOOKUP's wait ends at it when it comes before the host's own ceiling
    /// ([`IntentHost::lookup_within`]). `None`: the host's ceiling alone.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    /// CHANNEL intents attach through `channels`; without it every CHANNEL is a `P_ERROR`.
    #[must_use]
    pub fn with_channels(mut self, channels: &'h dyn ChannelHost) -> Self {
        self.channels = Some(channels);
        self
    }

    /// The scope a flag word selects, or `None` when it asks for the caller's scope and there is no subject: the
    /// intent is then refused by core, the host never asked, and the refusal is logged for the audit trail.
    fn scope(&self, caller_bound: bool) -> Option<Scope> {
        if !caller_bound {
            return Some(Scope::default());
        }
        let scope = self.subject.map(|s| Scope { subject: Some(s) });
        if scope.is_none() {
            tracing::warn!(
                audit = "caller_scope_refused",
                route = self.route,
                "a caller-scoped intent was refused: the request has no caller reference"
            );
        }
        scope
    }

    /// Applies `intents` in answer order and returns the pieces to deliver, in the IF order. `reads` is the
    /// task's read buffer: what a LOOKUP, a TRUST_STATE or a TRUST_VERIFY reads from the host lies there until
    /// it is encoded.
    pub async fn resolve<'i>(
        &self,
        intents: &[Intent],
        lent: &'i Lent,
        held: &mut Channels,
        reads: &mut Reads,
    ) -> Pieces<'i> {
        // STORE, DELETE, COMMIT, PUSH and SIGNAL first, in answer order; LOOKUP and WORK read what they wrote.
        // A failed write's key is the first kind of piece, so it is delivered from here as it fails.
        let mut pieces = Pieces::new();
        let mut committed: Option<Reply> = None;
        let mut channel_pieces: smallvec::SmallVec<[Piece<'i>; 4]> = smallvec::SmallVec::new();
        let mut rendezvous_pieces: smallvec::SmallVec<[Piece<'i>; 4]> = smallvec::SmallVec::new();
        for intent in intents {
            match intent {
                Intent::Store {
                    flags,
                    ttl_s,
                    key,
                    value,
                } => {
                    let (key, value) = (lent.bytes(*key), lent.bytes(*value));
                    let done = match self.scope(flags & LK_CALLER != 0) {
                        Some(scope) => self.host.store(scope, *flags, *ttl_s, key, value).await,
                        None => Err(RecordsDenied::Invalid),
                    };
                    if done.is_err() {
                        pieces.push(store_failed(key));
                    }
                }
                Intent::Delete { flags, key } => {
                    let key = lent.bytes(*key);
                    let done = match self.scope(flags & LK_CALLER != 0) {
                        Some(scope) => self.host.delete(scope, key).await,
                        None => Err(RecordsDenied::Invalid),
                    };
                    if done.is_err() {
                        pieces.push(store_failed(key));
                    }
                }
                Intent::Commit { check, ops } => {
                    let answer = self.commit(*check, lent.bytes(*ops)).await;
                    // A Reply refuses only past its cap; a commit answer is a few words.
                    let put = encode_committed(committed.get_or_insert_with(Reply::new), &[answer]);
                    debug_assert!(put.is_ok(), "COMMITTED answers fit a Reply");
                }
                Intent::Push { ttl_s, recs } => {
                    if let Err(denied) = self.host.push(*ttl_s, lent.bytes(*recs)).await {
                        tracing::warn!(?denied, "a plane push was not queued");
                    }
                }
                Intent::Signal { flags, key } => {
                    let key = lent.bytes(*key);
                    if let Some(pending) = self.pending {
                        if let Some(admitted) = pending.admitted() {
                            signal_admitted(
                                self.host,
                                &admitted.request,
                                *flags,
                                key,
                                self.subject,
                            );
                        }
                    } else if flags & LK_CALLER == 0 {
                        self.host.signal(key, None);
                    } else if let Some(subject) = self.subject {
                        self.host.signal(key, Some(subject));
                    }
                }
                Intent::Channel {
                    exchange,
                    carrier,
                    flags,
                    framing,
                    key,
                    head,
                } => channel_pieces.push(
                    self.channel(
                        held,
                        &ChannelAttach {
                            exchange: *exchange,
                            carrier: *carrier,
                            flags: *flags,
                            framing: *framing,
                            key: lent.text(*key),
                            subject: self.subject,
                            head: lent.bytes(*head),
                        },
                    )
                    .await,
                ),
                Intent::ChReady { exchange, tail } => {
                    if let Some(channel) = held.get_mut(exchange) {
                        if let Err(denied) = channel.ready(lent.bytes(*tail)) {
                            tracing::warn!(?denied, "a channel ready tail was not kept");
                        }
                    }
                }
                Intent::Rendezvous {
                    exchange,
                    flags,
                    description,
                } => rendezvous_pieces.extend(
                    self.rendezvous(held, *exchange, *flags, lent.text(*description))
                        .await,
                ),
                Intent::Sight {
                    party,
                    catalog,
                    items,
                } => {
                    let party = lent.text(*party);
                    let mut seen: smallvec::SmallVec<[(&str, [u8; 32]); 16]> =
                        smallvec::SmallVec::new();
                    seen.extend(sighted_items(lent, *items));
                    if let Err(denied) = self.host.sight(party, *catalog, &seen).await {
                        tracing::warn!(?denied, party, "a plane sighting was not recorded");
                    }
                }
                Intent::Lookup { .. }
                | Intent::ObsScope { .. }
                | Intent::Observe { .. }
                | Intent::Trust { .. }
                | Intent::TrustVerify { .. }
                | Intent::Work { .. }
                | Intent::Entitle { .. }
                | Intent::Judge { .. }
                | Intent::Mint { .. }
                | Intent::Sign { .. }
                | Intent::Connect { .. } => {}
            }
        }
        let kinds = [
            records_piece(
                P_LOOKUP,
                self.lookups(intents, lent, &mut reads.looked).await,
            ),
            records_piece(P_COMMITTED, committed),
            records_piece(P_OBSERVED, self.observeds(intents, lent).await),
            records_piece(P_WORK, self.works(intents, lent).await),
            records_piece(P_ENTITLE, self.entitles(intents, lent)),
            records_piece(P_JUDGED, self.judges(intents, lent).await),
            records_piece(
                P_TRUST,
                self.trusts(intents, lent, &mut reads.trust_items, &mut reads.named),
            ),
            records_piece(P_MINTED, self.mints(intents, lent).await),
            records_piece(P_SIGNED, self.signs(intents, lent).await),
            records_piece(P_CONNECT, self.connects(intents, lent).await),
        ];
        pieces.extend(kinds.into_iter().flatten());
        pieces.extend(channel_pieces);
        pieces.extend(rendezvous_pieces);
        pieces
    }

    /// One CHANNEL: the attachment as P_CHANNEL, or the P_ERROR the exchange ends with.
    async fn channel<'i>(&self, held: &mut Channels, attach: &ChannelAttach<'_>) -> Piece<'i> {
        let attached = match self.channels {
            Some(host) => host.attach(attach).await,
            None => Err(RecordsDenied::Unavailable),
        };
        let mut reply = Reply::new();
        match attached {
            Ok(a) => {
                held.insert(attach.exchange, a.held);
                let put =
                    encode_chan_attach(&mut reply, a.generation, a.slot, a.greet, &a.ready_tail);
                debug_assert!(put.is_ok(), "a CH_ATTACH fits a Reply");
                Piece {
                    exchange: attach.exchange,
                    flags: P_CHANNEL,
                    bytes: PieceBytes::Records(reply),
                }
            }
            Err(denied) => {
                tracing::warn!(
                    ?denied,
                    exchange = attach.exchange,
                    "a plane channel did not attach"
                );
                let put =
                    encode_refusal(&mut reply, 502, F_UNAVAILABLE, "the channel is unavailable");
                debug_assert!(put.is_ok(), "a REFUSAL fits a Reply");
                Piece {
                    exchange: attach.exchange,
                    flags: P_ERROR,
                    bytes: PieceBytes::Records(reply),
                }
            }
        }
    }

    /// One COMMIT: (check, outcome, failed, status).
    async fn commit(&self, check: u32, raw: &[u8]) -> (u32, u32, u32, u32) {
        let refused = |status| (check, 0, 0, status);
        // At most `commit::MAX_OPS`; the common commit is a few ops, held on the stack.
        let mut ops: smallvec::SmallVec<[CommitOp<'_>; 16]> = smallvec::SmallVec::new();
        let mut caller_bound = false;
        let mut mutating = false;
        for rec in Records::new(raw) {
            let Ok(rec) = rec else {
                return refused(R_INVALID);
            };
            let op = match rec.tag {
                tag::REC_PRED if !mutating => {
                    let Ok((head, tail)) = rec.pod_tail::<RecPredRec>() else {
                        return refused(R_INVALID);
                    };
                    let Some((key, value)) = split_key(tail, head.key_len) else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    match head.flags & commit::PRED_MASK {
                        commit::PRED_ABSENT if value.is_empty() => CommitOp::Absent { key, caller },
                        commit::PRED_PRESENT if value.is_empty() => {
                            CommitOp::Present { key, caller }
                        }
                        commit::PRED_EQUALS => CommitOp::Equals { key, value, caller },
                        _ => return refused(R_INVALID),
                    }
                }
                tag::REC_PUT => {
                    mutating = true;
                    let Ok((head, tail)) = rec.pod_tail::<RecPutRec>() else {
                        return refused(R_INVALID);
                    };
                    let Some((key, value)) = split_key(tail, head.key_len) else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    CommitOp::Put {
                        key,
                        value,
                        ttl_s: head.ttl_s,
                        caller,
                    }
                }
                tag::REC_DEL => {
                    mutating = true;
                    let Ok((head, key)) = rec.pod_tail::<RecDelRec>() else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    CommitOp::Del { key, caller }
                }
                _ => return refused(R_INVALID),
            };
            ops.push(op);
        }
        if ops.is_empty() || ops.len() > commit::MAX_OPS as usize {
            return refused(R_INVALID);
        }
        let Some(scope) = self.scope(caller_bound) else {
            return refused(R_DENIED);
        };
        match self.host.commit(scope, &ops).await {
            Ok(CommitOutcome::Applied) => (check, commit::APPLIED, 0, 0),
            Ok(CommitOutcome::Conflict { failed }) => (check, commit::CONFLICT, failed, 0),
            Err(denied) => refused(denied_status(&denied)),
        }
    }

    /// The LOOKUP_HIT* (and CHAIN_STATE) of every LOOKUP of the answer, by index; `None` when it has none. Each
    /// record is encoded as its hit is read (the encoders write one record per element, in order). Each LOOKUP
    /// is read whole into `looked` (the task's read buffer) first: a read that fails part way is a miss, with
    /// none of its hits.
    async fn lookups(&self, intents: &[Intent], lent: &Lent, looked: &mut Looked) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        let mut index = 0u32;
        for intent in intents {
            let Intent::Lookup { flags, limit, key } = intent else {
                continue;
            };
            let reply = reply.get_or_insert_with(Reply::new);
            let at = index;
            index += 1;
            looked.clear();
            if let Some(scope) = self.scope(flags & LK_CALLER != 0) {
                let key = lent.bytes(*key);
                let read = match self.deadline {
                    Some(deadline) => self
                        .host
                        .lookup_within(deadline, scope, *flags, *limit, key, looked),
                    None => self.host.lookup(scope, *flags, *limit, key, looked),
                };
                if let Err(denied) = read.await {
                    tracing::warn!(?denied, "a plane lookup was refused; it reads as a miss");
                    looked.clear();
                }
            }
            for (key, value) in looked.hits().take(*limit as usize) {
                // The reply refuses only past its cap; the host bounds a hit by MAX_VALUE.
                let put = encode_lookup_hits(reply, &[(at, key, value)]);
                debug_assert!(put.is_ok(), "LOOKUP_HITs fit a Reply");
            }
            if let (Some((len, broken_at)), true) = (looked.chain, flags & LK_CHAIN != 0) {
                let put = encode_chain_state(reply, at, len, broken_at);
                debug_assert!(put.is_ok(), "a CHAIN_STATE fits a Reply");
            }
        }
        reply
    }

    /// The ENTITLE_ANS of every ENTITLE of the answer, in intent order; `None` when it has none. Without a
    /// verified principal there is no grant set to ask: not granted, and the host is not asked.
    fn entitles(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Entitle { check, grant } = intent else {
                continue;
            };
            let granted = self
                .principal
                .is_some_and(|p| self.host.entitle(p.identity, lent.text(*grant)));
            let put =
                encode_entitle_answers(reply.get_or_insert_with(Reply::new), &[(*check, granted)]);
            debug_assert!(put.is_ok(), "ENTITLE_ANS records fit a Reply");
        }
        reply
    }

    /// The JUDGE_ANS of every JUDGE of the answer, in intent order; `None` when it has none.
    async fn judges(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Judge {
                check,
                class,
                flags,
                dest,
            } = intent
            else {
                continue;
            };
            let verdict = self.host.judge(lent.text(*dest), *class, *flags).await;
            let put = encode_judged(reply.get_or_insert_with(Reply::new), &[(*check, verdict)]);
            debug_assert!(put.is_ok(), "JUDGE_ANS records fit a Reply");
        }
        reply
    }

    /// One RENDEZVOUS: RV_ACCEPT answers P_RENDEZVOUS (the local description, the bridge now held under
    /// `exchange`) or P_RV_FAILED; RV_REMOTE goes to the bridge held there and answers only a failure.
    async fn rendezvous<'i>(
        &self,
        held: &mut Channels,
        exchange: u32,
        flags: u32,
        description: &str,
    ) -> Option<Piece<'i>> {
        match flags {
            RV_ACCEPT => match self.host.rendezvous_accept(self.route, description).await {
                Ok((local, bridge)) => {
                    held.insert(exchange, bridge);
                    Some(Piece {
                        exchange,
                        flags: P_RENDEZVOUS,
                        bytes: PieceBytes::Owned(local.into_boxed_bytes()),
                    })
                }
                Err(denied) => Some(rv_failed(exchange, &denied, None)),
            },
            RV_REMOTE => match held.get_mut(&exchange) {
                Some(bridge) => match bridge.remote(description).await {
                    Ok(()) => None,
                    Err(denied) => Some(rv_failed(exchange, &denied, bridge.refusal().as_deref())),
                },
                None => Some(rv_failed(exchange, &RecordsDenied::Invalid, None)),
            },
            _ => Some(rv_failed(exchange, &RecordsDenied::Invalid, None)),
        }
    }

    /// The OBS_SCOPE_ANS and OBS_RECEIPT of the answer's OBS_SCOPE and OBSERVE, in intent order; `None` when it
    /// has none. Custody is the verified principal's: without one every answer is OBS_REFUSED and the host is
    /// not asked. The host's calls are durable before they return, so the piece is delivered after the commit.
    async fn observeds(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            match intent {
                Intent::ObsScope {
                    check,
                    op,
                    scope,
                    require,
                } => {
                    let (status, id) = match self.principal {
                        None => (OBS_REFUSED, None),
                        Some(p) => {
                            let mut classes: smallvec::SmallVec<[&str; 16]> =
                                smallvec::SmallVec::new();
                            classes.extend(required_classes(lent, *require));
                            self.host.obs_scope(p.identity, *op, *scope, &classes).await
                        }
                    };
                    let answer = ObservedAnswer::Scope {
                        check: *check,
                        status,
                        scope: id,
                    };
                    let put = encode_observed(reply.get_or_insert_with(Reply::new), &[answer]);
                    debug_assert!(put.is_ok(), "OBS answers fit a Reply");
                }
                Intent::Observe {
                    check,
                    state,
                    rated_subject,
                    revision_order,
                    scope,
                    event,
                    component,
                    revision,
                    counts,
                    evidence,
                } => {
                    let (status, receipt) = match self.principal {
                        None => (OBS_REFUSED, Vec::new()),
                        Some(p) => {
                            let mut counted: smallvec::SmallVec<[(&str, u64, u32); 16]> =
                                smallvec::SmallVec::new();
                            counted.extend(observed_counts(lent, *counts));
                            let observation = ObservationIn {
                                scope: *scope,
                                event: lent.bytes(*event),
                                component: lent.bytes(*component),
                                revision: revision.map(|r| (lent.bytes(r), *revision_order)),
                                state: *state,
                                counts: &counted,
                                rated_subject: *rated_subject,
                                evidence: evidence.map_or(&[][..], |e| lent.bytes(e)),
                            };
                            self.host.observe(p.identity, &observation).await
                        }
                    };
                    let answer = ObservedAnswer::Receipt {
                        check: *check,
                        status,
                        receipt: &receipt,
                    };
                    let put = encode_observed(reply.get_or_insert_with(Reply::new), &[answer]);
                    debug_assert!(put.is_ok(), "OBS answers fit a Reply");
                }
                _ => {}
            }
        }
        reply
    }

    /// The TRUST_ANS of every TRUST and TRUST_VERIFY of the answer, in intent order; `None` when it has none.
    /// A STATE's item states are read into `items` and a VERIFY's named member into `named` (the task's read
    /// buffers), both empty for every other intent.
    fn trusts(
        &self,
        intents: &[Intent],
        lent: &Lent,
        items: &mut TrustItems,
        named: &mut String,
    ) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            items.clear();
            named.clear();
            // (verdict, the listing's catalog hash)
            let (check, verdict, catalog) = match intent {
                Intent::Trust {
                    check, op, party, ..
                } if *op == TRUST_STATE => {
                    let (verdict, catalog) = self.host.trust_state(lent.text(*party), items);
                    (*check, verdict, catalog)
                }
                Intent::Trust {
                    check,
                    op,
                    party,
                    item,
                } if *op == TRUST_SERVES => {
                    let item = item.map(|(name, digest)| (lent.text(name), digest));
                    let verdict = self.host.trust_serves(lent.text(*party), item);
                    (*check, verdict, None)
                }
                Intent::Trust { check, .. } => {
                    // The adapter admits only SERVES and STATE; anything else does not serve.
                    (*check, DISTRUST_UNKNOWN, None)
                }
                Intent::TrustVerify {
                    check,
                    party,
                    payload,
                    signatures,
                } => {
                    let verdict = self.host.trust_verify(
                        lent.text(*party),
                        lent.bytes(*payload),
                        lent.bytes(*signatures),
                        named,
                    );
                    (*check, verdict, None)
                }
                _ => continue,
            };
            let mut views: smallvec::SmallVec<[TrustItem<'_>; 16]> = smallvec::SmallVec::new();
            views.extend(items.iter());
            let answer = TrustAnswer {
                check,
                verdict,
                catalog,
                items: &views,
                named: named.as_str(),
            };
            let put = encode_trust_answers(reply.get_or_insert_with(Reply::new), &[answer]);
            debug_assert!(put.is_ok(), "TRUST_ANS records fit a Reply");
        }
        reply
    }

    /// The MINTED of every MINT of the answer, in intent order; `None` when it has none. A ticket binds the
    /// verified subject: without one the answer is `R_DENIED` and the host is not asked.
    async fn mints(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Mint {
                check,
                flags,
                ttl_s,
                scope,
                audience,
                prefix,
                record,
            } = intent
            else {
                continue;
            };
            let minted = match self.principal {
                None => Err(R_DENIED),
                Some(p) => {
                    self.host
                        .mint(TicketMint {
                            subject: p.subject,
                            scope: scope.map_or("", |s| lent.text(s)),
                            // Stated by the plane, else the door every ticket route redeems at.
                            audience: audience
                                .map_or(crate::auth::native_ticket::TICKET_DOOR, |s| lent.text(s)),
                            ttl_s: *ttl_s,
                            once: flags & MINT_ONCE != 0,
                            prefix: prefix.map_or("", |s| lent.text(s)),
                            record: record.map_or(&[][..], |r| lent.bytes(r)),
                        })
                        .await
                }
            };
            let reply = reply.get_or_insert_with(Reply::new);
            let put = match &minted {
                Ok((ticket, expires_at_s)) => {
                    encode_minted(reply, &[(*check, 0, *expires_at_s, &**ticket)])
                }
                Err(status) => encode_minted(reply, &[(*check, *status, 0, "")]),
            };
            debug_assert!(put.is_ok(), "MINTED records fit a Reply");
        }
        reply
    }

    /// The SIGNED of every SIGN of the answer, in intent order; `None` when it has none.
    async fn signs(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Sign {
                check,
                flags,
                payload,
            } = intent
            else {
                continue;
            };
            let detached = *flags == SIGN_JWS_DETACHED;
            let jws = self.host.sign(lent.bytes(*payload), detached).await;
            let answer = match &jws {
                Ok(SignedJws::Compact(jws)) if !detached => {
                    SignedAnswer::Compact { check: *check, jws }
                }
                Ok(SignedJws::Detached {
                    protected,
                    signature,
                }) if detached => SignedAnswer::Detached {
                    check: *check,
                    protected,
                    signature,
                },
                // A signer that answers the other form than the one asked is a core bug, never a signature.
                Ok(_) => SignedAnswer::Refused {
                    check: *check,
                    status: R_DENIED,
                },
                Err(status) => SignedAnswer::Refused {
                    check: *check,
                    status: *status,
                },
            };
            let put = encode_signed(reply.get_or_insert_with(Reply::new), &[answer]);
            debug_assert!(put.is_ok(), "SIGNED records fit a Reply");
        }
        reply
    }

    /// The CONNECT_ANS of every CONNECT of the answer, in intent order; `None` when it has none. A connection
    /// is the verified subject's: without one the state is `CONN_REFUSED` and the host is not asked.
    async fn connects(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Connect {
                check,
                op,
                upstream,
                return_to,
            } = intent
            else {
                continue;
            };
            let (state, url) = match self.principal {
                None => (CONN_REFUSED, None),
                Some(p) => {
                    self.host
                        .connect(
                            *op,
                            p.subject,
                            lent.text(*upstream),
                            return_to.map(|r| lent.text(r)),
                        )
                        .await
                }
            };
            // Only a BEGIN carries a URL.
            let url = url.filter(|_| *op == CONNECT_BEGIN);
            let put = encode_connect_answers(
                reply.get_or_insert_with(Reply::new),
                &[(*check, state, url.as_deref())],
            );
            debug_assert!(put.is_ok(), "CONNECT_ANS records fit a Reply");
        }
        reply
    }

    /// The WORK_ANS of every WORK of the answer, in intent order; `None` when it has none.
    async fn works(&self, intents: &[Intent], lent: &Lent) -> Option<Reply> {
        let mut reply: Option<Reply> = None;
        for intent in intents {
            let Intent::Work {
                check,
                op,
                target,
                reference,
            } = intent
            else {
                continue;
            };
            let asked = WorkIntent {
                op: *op,
                target: target.map(|t| lent.text(t)),
                reference: reference.map(|r| lent.text(r)),
                identity: self.principal.map_or(&[], |p| p.identity),
            };
            let outcome = if self.subject.is_none() {
                // §12.24: no verified principal, no row to bind.
                WorkOutcome::refused(R_DENIED)
            } else {
                self.host.work(&asked).await
            };
            let answer = WorkAnswer {
                check: *check,
                status: outcome.status,
                state: outcome.state,
                reference: &outcome.reference,
                target: &outcome.target,
            };
            let put = encode_work_answers(reply.get_or_insert_with(Reply::new), &[answer]);
            debug_assert!(put.is_ok(), "WORK_ANS records fit a Reply");
        }
        reply
    }
}

fn split_key(tail: &[u8], key_len: u32) -> Option<(&[u8], &[u8])> {
    let at = usize::try_from(key_len).ok()?;
    if at > MAX_KEY {
        return None;
    }
    tail.split_at_checked(at)
}

/// A STORE or DELETE the host refused: its key, as the plane sent it (P_STORE_FAILED).
fn store_failed(key: &[u8]) -> Piece<'_> {
    Piece {
        exchange: 0,
        flags: P_STORE_FAILED,
        bytes: PieceBytes::Lent(key),
    }
}

/// P_RV_FAILED's bytes: one REFUSAL in core's own fixed text for the cause (§12.15), or `mirrored`'s text when the
/// media bridge says why the far end's answer was refused.
fn rv_failed<'i>(exchange: u32, denied: &RecordsDenied, text: Option<&str>) -> Piece<'i> {
    let (status, code, fixed) = match denied {
        RecordsDenied::Invalid | RecordsDenied::TooLarge => {
            (400, R_INVALID, "the media session description was refused")
        }
        RecordsDenied::Quota => (429, R_RATE_LIMITED, "the media session limit is reached"),
        RecordsDenied::Unavailable => (502, F_UNAVAILABLE, "the media session is unavailable"),
    };
    let mut reply = Reply::new();
    let put = encode_refusal(&mut reply, status, code, text.unwrap_or(fixed));
    debug_assert!(put.is_ok(), "a REFUSAL fits a Reply");
    Piece {
        exchange,
        flags: P_RV_FAILED,
        bytes: PieceBytes::Records(reply),
    }
}

/// The REFUSED code a denied record write answers with (a COMMITTED `status`).
fn denied_status(denied: &RecordsDenied) -> u32 {
    match denied {
        RecordsDenied::Quota => R_RATE_LIMITED,
        RecordsDenied::TooLarge | RecordsDenied::Invalid => R_INVALID,
        RecordsDenied::Unavailable => R_UNSUPPORTED,
    }
}

impl<K: Calls + ?Sized> Task<'_, K> {
    /// Resolve only prerequisites whose results are needed to bind the enforcement stage.
    pub async fn resolve_before_hooks(
        &mut self,
        first: Answer,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
    ) -> Result<Vec<Answer>, SessionError> {
        self.resolve_stage(first, resolver, effects, true).await
    }

    /// Resolves the intents of `first` and of every answer their results provoke. Answers come back in delivery
    /// order, `first` first, each with its intents taken (resolved), so the caller applies their client items,
    /// forward and facts as it would any answer.
    pub async fn resolve(
        &mut self,
        first: Answer,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
    ) -> Result<Vec<Answer>, SessionError> {
        self.resolve_stage(first, resolver, effects, false).await
    }

    async fn resolve_stage(
        &mut self,
        first: Answer,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
        screening: bool,
    ) -> Result<Vec<Answer>, SessionError> {
        let mut out = Vec::new();
        // The task's queue, lent to this stage; an error ends the session, so only a stage that finishes hands it back.
        let mut queue = std::mem::take(&mut self.queue);
        queue.clear();
        queue.push_back(first);
        let mut rounds = 0u32;
        let mut held_effects = false;
        while let Some(mut answer) = queue.pop_front() {
            if !screening
                && self.is_command()
                && !answer.command_channel
                && answer
                    .intents
                    .iter()
                    .any(|intent| matches!(intent, Intent::Channel { .. }))
            {
                return Err(SessionError::Violation(Violation::BadRecords));
            }
            let intents = std::mem::take(&mut answer.intents);
            let lent = std::mem::take(&mut answer.lent);
            if screening && !intents.is_empty() {
                let reads = intents.iter().any(prerequisite);
                let writes = intents.iter().any(|intent| !prerequisite(intent));
                if (reads && (writes || held_effects))
                    || (writes && answer.forward.is_none() && answer.client.is_empty())
                {
                    return Err(SessionError::HookPrerequisite);
                }
                if writes {
                    held_effects = true;
                    answer.intents = intents;
                    answer.lent = lent;
                    out.push(answer);
                    continue;
                }
            }
            out.push(answer);
            if intents.is_empty() {
                continue;
            }
            rounds += 1;
            if rounds > MAX_ROUNDS {
                return Err(SessionError::Violation(Violation::IntentStorm));
            }
            let pieces = resolver
                .resolve(&intents, &lent, &mut self.held, &mut self.reads)
                .await;
            for piece in pieces {
                let next = self.piece(
                    FROM_CORE,
                    piece.exchange,
                    piece.flags,
                    piece.bytes.as_bytes(),
                    effects,
                )?;
                queue.push_back(next);
            }
        }
        self.queue = queue;
        Ok(out)
    }
}

/// Whether a record write is bound to the verified caller by its own flags: a STORE or DELETE in the
/// caller's scope (`LK_CALLER`, never the instance-wide host chain `LK_CHAIN`), a COMMIT whose every
/// record is the caller's (`REC_CALLER`). A DATA unit drives no other write: its records are the
/// caller's by the kernel's rule, not by the plane's choice. `None` for an intent that is no record
/// write.
pub(crate) fn caller_scoped_write(intent: &Intent, lent: &Lent) -> Option<bool> {
    match intent {
        Intent::Store { flags, .. } | Intent::Delete { flags, .. } => {
            Some(flags & LK_CALLER != 0 && flags & LK_CHAIN == 0)
        }
        Intent::Commit { ops, .. } => {
            let mut any = false;
            for rec in Records::new(lent.bytes(*ops)) {
                let Ok(rec) = rec else { return Some(false) };
                let flags = match rec.tag {
                    tag::REC_PRED => rec.pod_tail::<RecPredRec>().map(|(head, _)| head.flags),
                    tag::REC_PUT => rec.pod_tail::<RecPutRec>().map(|(head, _)| head.flags),
                    tag::REC_DEL => rec.pod_tail::<RecDelRec>().map(|(head, _)| head.flags),
                    _ => return Some(false),
                };
                match flags {
                    Ok(flags) if flags & commit::REC_CALLER != 0 => any = true,
                    _ => return Some(false),
                }
            }
            Some(any)
        }
        _ => None,
    }
}

/// These operations can discover a deferred route without opening a wire or changing state.
fn prerequisite(intent: &Intent) -> bool {
    matches!(
        intent,
        Intent::Lookup { .. }
            | Intent::Entitle { .. }
            | Intent::Judge { .. }
            | Intent::Work { op: WORK_FIND, .. }
    )
}

/// Who a plane instance is to the store: its record namespace (IF §12.5).
#[derive(Clone)]
pub struct Namespace {
    /// The verified stamp name.
    pub plugin: Arc<str>,
    /// The configured instance name.
    pub name: Arc<str>,
    /// Runtime instance id (the signal registry's key).
    pub instance: u64,
    pub slot: u32,
}

impl Namespace {
    #[must_use]
    pub fn caller(&self) -> Caller<'_> {
        Caller {
            plugin: &self.plugin,
            kind: KindCode::Plane,
            name: &self.name,
            instance: self.instance,
            slot: self.slot,
            chain: 1,
            // The node's monotonic clock service, read once for this call.
            deadline: busbar_contract::mono_instant::instant_at(crate::store::monotonic_ns())
                + Duration::from_secs(30),
            stack: CallStack::default(),
            out_of_process: false,
            limits: InstanceLimits::default(),
        }
    }

    /// [`Self::caller`] for one request: its ceiling cut to the request's `deadline` when that comes first. The
    /// clock is read once, by [`Self::caller`].
    #[must_use]
    pub fn caller_until(&self, deadline: Instant) -> Caller<'_> {
        let mut caller = self.caller();
        caller.deadline = caller.deadline.min(deadline);
        caller
    }
}

/// The production [`IntentHost`]: records through [`PluginRecords`], pushes through the [`StorePushQueue`], signals
/// through the [`SessionSignals`] registry, WORK through the decider (default [`NoWork`]). Its calls are awaited on
/// the session's own task; it holds no runtime handle.
pub struct KernelIntents<R: PluginRecords> {
    records: Arc<R>,
    push: Arc<StorePushQueue>,
    signals: Arc<dyn SessionSignals>,
    work: Arc<dyn WorkDecider>,
    services: Services,
    who: Namespace,
}

/// Decides WORK intents (§12.24).
pub trait WorkDecider: Send + Sync + 'static {
    fn decide<'a>(
        &'a self,
        who: &'a Namespace,
        intent: &'a WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>>;
}

/// Durable paid work (IF §12.24): the store-backed rows over `host_work/` and the recovery runtime over
/// `host_recovery.rs`. Every call is durable before it returns. `principal` = the request's identity records
/// (ID_*); rows are scoped to `plane`'s configured instance name. Errors are generic REFUSED codes
/// (`R_UNSUPPORTED`: core cannot recover here; `R_DENIED`: another principal's row; `R_NOT_FOUND`;
/// `R_RATE_LIMITED`: the instance's live-work cap).
pub trait DurableWork: Send + Sync + 'static {
    /// WORK_OPEN (the target already matched to a ROUTE_RECOVERY route). Ok = the reference text.
    fn open<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        target: &'a str,
    ) -> BoxFut<'a, Result<Box<str>, u32>>;
    /// WORK_FIND: (WORK_LIVE | WORK_SETTLED, the row's target).
    fn find<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(u32, Box<str>), u32>>;
    /// WORK_SETTLE (idempotent).
    fn settle<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(), u32>>;
    /// The scheduler side (§12.24 step 3): live rows of this instance not held by a running recovery session. Each
    /// `RecoveryWork` releases its hold when it drops.
    fn recoverable<'a>(
        &'a self,
        plane: &'a Caller<'_>,
    ) -> BoxFut<'a, Result<Vec<crate::host_services::RecoveryWork>, &'static str>>;
}

/// The production [`WorkDecider`] (§12.24): the checks core owns, then [`DurableWork`]. OPEN needs a target on one
/// of the instance's ROUTE_RECOVERY routes (`recovers`), else `R_INVALID`; FIND and SETTLE need a reference. The
/// verified-principal rule is the resolver's: a WORK with no principal never reaches here.
pub struct DurableDecider {
    work: Arc<dyn DurableWork>,
    recovers: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl DurableDecider {
    /// `recovers` says whether a path-and-query target matches one of the instance's ROUTE_RECOVERY patterns.
    #[must_use]
    pub fn new(
        work: Arc<dyn DurableWork>,
        recovers: Box<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        Self { work, recovers }
    }
}

impl WorkDecider for DurableDecider {
    fn decide<'a>(
        &'a self,
        who: &'a Namespace,
        intent: &'a WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(self.decided(who, intent))
    }
}

impl DurableDecider {
    async fn decided<'a>(
        &'a self,
        who: &'a Namespace,
        intent: &'a WorkIntent<'a>,
    ) -> WorkOutcome<'a> {
        let plane = who.caller();
        match intent.op {
            WORK_OPEN => {
                let Some(target) = intent.target.filter(|t| (self.recovers)(t)) else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self.work.open(&plane, intent.identity, target).await {
                    Ok(reference) => WorkOutcome {
                        status: 0,
                        state: WORK_LIVE,
                        reference: Cow::Owned(reference.into()),
                        target: Cow::Borrowed(""),
                    },
                    Err(code) => WorkOutcome::refused(code),
                }
            }
            WORK_FIND => {
                let Some(reference) = intent.reference else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self.work.find(&plane, intent.identity, reference).await {
                    Ok((state, target)) => WorkOutcome {
                        status: 0,
                        state,
                        reference: Cow::Borrowed(reference),
                        target: Cow::Owned(target.into()),
                    },
                    Err(code) => WorkOutcome::refused(code),
                }
            }
            WORK_SETTLE => {
                let Some(reference) = intent.reference else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self.work.settle(&plane, intent.identity, reference).await {
                    Ok(()) => WorkOutcome {
                        status: 0,
                        state: WORK_SETTLED,
                        reference: Cow::Borrowed(""),
                        target: Cow::Borrowed(""),
                    },
                    Err(code) => WorkOutcome::refused(code),
                }
            }
            _ => WorkOutcome::refused(R_INVALID),
        }
    }
}

/// No recovery runtime: every WORK is `R_UNSUPPORTED`.
pub struct NoWork;

impl WorkDecider for NoWork {
    fn decide<'a>(
        &'a self,
        _: &'a Namespace,
        _: &'a WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(std::future::ready(WorkOutcome::unsupported()))
    }
}

impl<R: PluginRecords> KernelIntents<R> {
    #[must_use]
    pub fn new(
        records: Arc<R>,
        push: Arc<StorePushQueue>,
        signals: Arc<dyn SessionSignals>,
        who: Namespace,
    ) -> Self {
        Self {
            records,
            push,
            signals,
            work: Arc::new(NoWork),
            services: Services::default(),
            who,
        }
    }

    /// WORK is decided by `work` instead of refused.
    #[must_use]
    pub fn with_work(mut self, work: Arc<dyn WorkDecider>) -> Self {
        self.work = work;
        self
    }

    /// The kernel services the grant intents run on (ENTITLE, JUDGE, ...); one not installed answers fail-closed.
    #[must_use]
    pub fn with_services(mut self, services: Services) -> Self {
        self.services = services;
        self
    }
}

impl<R: PluginRecords> KernelIntents<R> {
    /// One LOOKUP, asked of the records as `who` (whose deadline bounds the store's wait).
    fn read<'a>(
        &'a self,
        who: Caller<'a>,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            if flags & LK_CHAIN != 0 {
                let split = key.len().checked_sub(8).ok_or(RecordsDenied::Invalid)?;
                let (chain, after) = key.split_at(split);
                let after =
                    u64::from_le_bytes(after.try_into().map_err(|_| RecordsDenied::Invalid)?);
                // A chain hit's key is the chain key then the entry's sequence number, big-endian.
                let read = self
                    .records
                    .chain(&who, scope, chain, after, limit, &mut |seq, entry| {
                        looked.push(&[chain, &seq.to_be_bytes()], entry);
                    })
                    .await?;
                looked.chain = Some((read.len, read.broken_at));
            } else if flags & LK_PREFIX != 0 {
                self.records
                    .list(&who, scope, key, limit, &mut |k, v| {
                        looked.push(&[k], v);
                    })
                    .await?;
            } else {
                // One hit, and only when the store says found: the value the store handed last.
                let mark = looked.mark();
                let found = self
                    .records
                    .get(&who, scope, key, &mut |v| {
                        looked.rewind(mark);
                        looked.push(&[key], v);
                    })
                    .await?;
                if !found {
                    looked.rewind(mark);
                }
            }
            Ok(())
        })
    }
}

impl<R: PluginRecords> IntentHost for KernelIntents<R> {
    fn lookup<'a>(
        &'a self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        self.read(self.who.caller(), scope, flags, limit, key, looked)
    }

    fn lookup_within<'a>(
        &'a self,
        deadline: Instant,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        self.read(
            self.who.caller_until(deadline),
            scope,
            flags,
            limit,
            key,
            looked,
        )
    }

    fn store<'a>(
        &'a self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &'a [u8],
        value: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            if key.len() > MAX_KEY || value.len() > MAX_VALUE {
                return Err(RecordsDenied::TooLarge);
            }
            let who = self.who.caller();
            if flags & LK_CHAIN != 0 {
                if ttl_s != 0 {
                    return Err(RecordsDenied::Invalid);
                }
                return self
                    .records
                    .append(&who, scope, key, value)
                    .await
                    .map(|_| ());
            }
            self.records.put(&who, scope, key, value, ttl_s).await
        })
    }

    fn delete<'a>(&'a self, scope: Scope, key: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let who = self.who.caller();
            self.records.del(&who, scope, key).await
        })
    }

    fn commit<'a>(
        &'a self,
        scope: Scope,
        ops: &'a [CommitOp<'a>],
    ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
        Box::pin(async move {
            let who = self.who.caller();
            self.records.commit(&who, scope, ops).await
        })
    }

    fn work<'a>(&'a self, intent: &'a WorkIntent<'a>) -> BoxFut<'a, WorkOutcome<'a>> {
        self.work.decide(&self.who, intent)
    }

    fn push<'a>(&'a self, ttl_s: u64, recs: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let who = self.who.caller();
            self.push.enqueue(&who, ttl_s, recs).await
        })
    }

    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>) {
        self.signals
            .signal(self.who.instance, key, subject, P_SIGNAL, key);
    }

    fn signal_command(&self, authority: &crate::channels::authority::ChannelAuthority, key: &[u8]) {
        self.signals
            .signal_command(self.who.instance, authority, key, P_SIGNAL, key);
    }

    fn entitle(&self, identity: &[u8], grant: &str) -> bool {
        self.services
            .entitlements
            .as_ref()
            .is_some_and(|e| e.check(&self.who.caller(), identity, grant))
    }

    fn judge<'a>(&'a self, dest: &'a str, class: u32, flags: u32) -> BoxFut<'a, u32> {
        Box::pin(async move {
            let who = self.who.caller();
            let judge = self
                .services
                .judge
                .clone()
                .unwrap_or_else(PlaneJudge::unavailable);
            judge.judge(dest, class, flags, who.deadline).await
        })
    }

    fn mint<'a>(&'a self, m: TicketMint<'a>) -> BoxFut<'a, Result<(Box<str>, u64), u32>> {
        Box::pin(async move {
            let tickets = self.services.tickets.as_ref().ok_or(R_UNSUPPORTED)?;
            let who = self.who.caller();
            tickets
                .mint(&who, m)
                .await
                .map_err(|denied| denied_status(&denied))
        })
    }

    fn sign<'a>(&'a self, payload: &'a [u8], detached: bool) -> BoxFut<'a, Result<SignedJws, u32>> {
        Box::pin(async move {
            let signer = self.services.signer.as_ref().ok_or(R_UNSUPPORTED)?;
            let who = self.who.caller();
            signer
                .sign_jws(&who, payload, detached)
                .await
                .map_err(|denied| denied_status(&denied))
        })
    }

    fn sight<'a>(
        &'a self,
        party: &'a str,
        catalog: Option<[u8; 32]>,
        items: &'a [(&'a str, [u8; 32])],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(async move {
            let book = self
                .services
                .trust
                .as_ref()
                .ok_or(RecordsDenied::Unavailable)?;
            let who = self.who.caller();
            book.sight(&who, party, catalog, items).await
        })
    }

    fn trust_serves(&self, party: &str, item: Option<(&str, Option<[u8; 32]>)>) -> u32 {
        match &self.services.trust {
            Some(book) => book.serves(&self.who.caller(), party, item),
            None => DISTRUST_UNKNOWN,
        }
    }

    fn trust_state(&self, party: &str, items: &mut TrustItems) -> (u32, Option<[u8; 32]>) {
        let Some(book) = &self.services.trust else {
            return (DISTRUST_UNKNOWN, None);
        };
        book.state(&self.who.caller(), party, &mut |item| items.push(&item))
    }

    fn trust_verify(
        &self,
        party: &str,
        payload: &[u8],
        signatures: &[u8],
        named: &mut String,
    ) -> u32 {
        let Some(book) = &self.services.trust else {
            return SIGNED_MALFORMED_ROOT;
        };
        book.verify(&self.who.caller(), party, payload, signatures, named)
    }

    fn rendezvous_accept<'a>(
        &'a self,
        route: u32,
        offer: &'a str,
    ) -> BoxFut<'a, Result<(Box<str>, Box<dyn Held>), RecordsDenied>> {
        Box::pin(async move {
            let media = self
                .services
                .media
                .as_ref()
                .ok_or(RecordsDenied::Unavailable)?;
            let (local, bridge) = media.accept(route, offer).await?;
            Ok((local, Box::new(MediaHeld::new(bridge)) as Box<dyn Held>))
        })
    }

    fn obs_scope<'a>(
        &'a self,
        identity: &'a [u8],
        op: u32,
        scope: Option<[u8; 32]>,
        require: &'a [&'a str],
    ) -> BoxFut<'a, (u32, Option<[u8; 32]>)> {
        Box::pin(async move {
            let Some(custody) = self.services.observations.as_ref() else {
                return (OBS_REFUSED, None);
            };
            let who = self.who.caller();
            custody.scope(&who, identity, op, scope, require).await
        })
    }

    fn observe<'a>(
        &'a self,
        identity: &'a [u8],
        o: &'a ObservationIn<'a>,
    ) -> BoxFut<'a, (u32, Vec<u8>)> {
        Box::pin(async move {
            let Some(custody) = self.services.observations.as_ref() else {
                return (OBS_REFUSED, Vec::new());
            };
            let who = self.who.caller();
            let (status, receipt) = custody.observe(&who, identity, o).await;
            (status, receipt.into_vec())
        })
    }

    fn connect<'a>(
        &'a self,
        op: u32,
        subject: &'a str,
        upstream: &'a str,
        return_to: Option<&'a str>,
    ) -> BoxFut<'a, (u32, Option<Box<str>>)> {
        Box::pin(async move {
            let Some(connections) = self.services.connections.as_ref() else {
                return (CONN_REFUSED, None);
            };
            let who = self.who.caller();
            match op {
                // The caller is sent to the URL to consent: pending until the callback stores the grant.
                CONNECT_BEGIN => {
                    match connections.begin(&who, subject, upstream, return_to).await {
                        Ok(url) => (CONN_PENDING, Some(url)),
                        Err(_) => (CONN_REFUSED, None),
                    }
                }
                CONNECT_STATUS => (connections.status(&who, subject, upstream).await, None),
                CONNECT_REVOKE => match connections.revoke(&who, subject, upstream).await {
                    Ok(()) => (CONN_NONE, None),
                    Err(_) => (CONN_REFUSED, None),
                },
                _ => (CONN_REFUSED, None),
            }
        })
    }
}

#[cfg(test)]
#[path = "tests/port_intents_tests.rs"]
mod tests;
