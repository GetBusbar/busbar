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

use std::collections::VecDeque;
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
use tokio::runtime::Handle;

use super::plane_judge::PlaneJudge;
use super::port_channels::{ChannelAttach, ChannelHost, Channels, Held};
use super::port_services::{MediaHeld, ObservationIn, Services, TrustItemOwned};
use super::port_session::{Answer, Calls, Effects, SessionError, Task, Violation};
use crate::channels::SessionSignals;
use crate::hashing::Sha256;
use crate::plane_grants::{SignedJws, TicketMint};
use crate::plugin_records::{
    CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, MAX_KEY, MAX_VALUE,
};
use crate::push::PushQueue;

/// How many rounds of intents one answer may chain (an answer's pieces answering with more intents) before the
/// session is cut. A plane's real chains are two or three deep (LOOKUP, then COMMIT, then WORK).
const MAX_ROUNDS: u32 = 64;

/// One intent of an answer, owned (the sink's borrows end with the answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Lookup {
        flags: u32,
        limit: u32,
        key: Vec<u8>,
    },
    Store {
        flags: u32,
        ttl_s: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        flags: u32,
        key: Vec<u8>,
    },
    /// `ops` = the nested REC_PRED*, REC_PUT*, REC_DEL* the adapter validated.
    Commit {
        check: u32,
        ops: Vec<u8>,
    },
    Work {
        check: u32,
        op: u32,
        target: Option<String>,
        reference: Option<String>,
    },
    /// `recs` = the nested records core's push queue copies and owns.
    Push {
        ttl_s: u64,
        recs: Vec<u8>,
    },
    Signal {
        flags: u32,
        key: Vec<u8>,
    },
    /// ENTITLE: does the verified principal hold `grant` (§12.11).
    Entitle {
        check: u32,
        grant: String,
    },
    /// JUDGE: the destination guard on `dest` (§12.1); `class` <= 4 and `flags` are checked when the answer is read.
    Judge {
        check: u32,
        class: u32,
        flags: u32,
        dest: String,
    },
    /// MINT: seal a ticket for the verified subject (§12.11); `flags` = MINT_ONCE?.
    Mint {
        check: u32,
        flags: u32,
        ttl_s: u64,
        scope: Option<String>,
        audience: Option<String>,
        prefix: Option<String>,
        record: Option<Vec<u8>>,
    },
    /// SIGN: sign `payload` with the host's key (§12.11); `flags` = SIGN_JWS_COMPACT or SIGN_JWS_DETACHED.
    Sign {
        check: u32,
        flags: u32,
        payload: Vec<u8>,
    },
    /// CONNECT: a caller connection to a configured upstream (§12.12); `op` = CONNECT_BEGIN, _STATUS or _REVOKE.
    Connect {
        check: u32,
        op: u32,
        upstream: String,
        return_to: Option<String>,
    },
    /// RENDEZVOUS: `flags` = RV_ACCEPT (a client's offer, accepted as client exchange `exchange`) or RV_REMOTE
    /// (the far end's answer for upstream exchange `exchange`); `description` = the session description (§12.13).
    Rendezvous {
        exchange: u32,
        flags: u32,
        description: String,
    },
    /// OBS_SCOPE: create, reattach or close usage-observation custody (§12.4); `require` = the OBS_REQUIRE classes.
    ObsScope {
        check: u32,
        op: u32,
        scope: Option<[u8; 32]>,
        require: Vec<String>,
    },
    /// OBSERVE: one owned usage observation (§12.4); `counts` = (class, amount, scale).
    Observe {
        check: u32,
        state: u32,
        rated_subject: u32,
        revision_order: u64,
        scope: [u8; 32],
        event: Vec<u8>,
        component: Vec<u8>,
        revision: Option<Vec<u8>>,
        counts: Vec<(String, u64, u32)>,
        evidence: Option<Vec<u8>>,
    },
    /// SIGHT: the plane observed `party` offering `items` (name, SHA-256 digest); no answer (§12.14).
    Sight {
        party: String,
        catalog: Option<[u8; 32]>,
        items: Vec<(String, [u8; 32])>,
    },
    /// TRUST: `op` = TRUST_SERVES (with its optional item) or TRUST_STATE (§12.14).
    Trust {
        check: u32,
        op: u32,
        party: String,
        item: Option<(String, Option<[u8; 32]>)>,
    },
    /// TRUST_VERIFY: `signatures` (a JSON array) over `payload`, against the root core holds for `party`.
    TrustVerify {
        check: u32,
        party: String,
        payload: Vec<u8>,
        signatures: Vec<u8>,
    },
    /// CHANNEL: attach `exchange` to a shared upstream channel (§12.19); `head` = the nested HTTP head records.
    Channel {
        exchange: u32,
        carrier: u32,
        flags: u32,
        framing: u32,
        key: String,
        head: Vec<u8>,
    },
    /// CH_READY: the greeting session's greeting is done; `tail` is handed to later attachers.
    ChReady {
        exchange: u32,
        tail: Vec<u8>,
    },
}

/// DETACH: the session outlives its client response until FINISH or `ttl_s` (clamped), registered under `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detach {
    pub ttl_s: u64,
    pub flags: u32,
    pub key: Box<[u8]>,
}

/// One hit of a LOOKUP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A LOOKUP's result: its hits in order, and for `LK_CHAIN` the chain's state (`len`, `broken_at`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Looked {
    pub hits: Vec<Hit>,
    pub chain: Option<(u64, u64)>,
}

/// One WORK intent, the verified principal's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntent {
    pub op: u32,
    pub target: Option<String>,
    pub reference: Option<String>,
    /// The request's identity records (ID_*): the principal the row binds to (§12.24).
    pub identity: Vec<u8>,
}

/// One WORK_ANS (§8.6): `status` 0 = done, else a generic REFUSED code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOutcome {
    pub status: u32,
    pub state: u32,
    pub reference: String,
    pub target: String,
}

impl WorkOutcome {
    /// Core cannot recover here (no store or no recovery runtime, §12.24).
    #[must_use]
    pub fn unsupported() -> Self {
        Self::refused(R_UNSUPPORTED)
    }

    fn refused(status: u32) -> Self {
        Self {
            status,
            state: 0,
            reference: String::new(),
            target: String::new(),
        }
    }
}

/// What resolving an intent needs from core. The calls are synchronous: a driver runs a task inside
/// `spawn_blocking`, and a production host blocks on the runtime for the store.
pub trait IntentHost: Send + Sync {
    /// LOOKUP in the scope the resolver chose. `flags` carries `LK_PREFIX` and `LK_CHAIN` (for `LK_CHAIN` the key
    /// is the chain key followed by the 8-byte `after`).
    fn lookup(
        &self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &[u8],
    ) -> Result<Looked, RecordsDenied>;
    /// STORE. `flags & LK_CHAIN` appends `value` to the host chain `key`.
    fn store(
        &self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), RecordsDenied>;
    fn delete(&self, scope: Scope, key: &[u8]) -> Result<(), RecordsDenied>;
    fn commit(&self, scope: Scope, ops: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied>;
    /// WORK under the request's verified principal. The default is the fail-closed answer.
    fn work(&self, _intent: &WorkIntent) -> WorkOutcome {
        WorkOutcome::unsupported()
    }
    fn push(&self, ttl_s: u64, recs: &[u8]) -> Result<(), RecordsDenied>;
    /// SIGNAL: every session of this instance detached under `key` (only `subject`'s when it is Some).
    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>);
    /// ENTITLE: does the verified principal (its ID_* `identity` records) hold `grant`? The default is no.
    fn entitle(&self, _identity: &[u8], _grant: &str) -> bool {
        false
    }
    /// JUDGE: the `DEST_*` verdict for `dest` (the answer the plane renders in its own protocol). The default is
    /// the fail-closed `DEST_INTERNAL`.
    fn judge(&self, _dest: &str, _class: u32, _flags: u32) -> u32 {
        DEST_INTERNAL
    }
    /// MINT for the verified `m.subject`: the client-facing ticket text and its expiry (epoch seconds), or the
    /// generic REFUSED code. The default is `R_UNSUPPORTED`.
    fn mint(&self, _m: TicketMint<'_>) -> Result<(Box<str>, u64), u32> {
        Err(R_UNSUPPORTED)
    }
    /// SIGN `payload` with the host key as a JWS, or the generic REFUSED code. The default is `R_UNSUPPORTED`.
    fn sign(&self, _payload: &[u8], _detached: bool) -> Result<SignedJws, u32> {
        Err(R_UNSUPPORTED)
    }
    /// SIGHT: record that `party` offered `items` (name, digest), under the listing's `catalog` hash. A sighting
    /// the book cannot record is logged; the plane is not told (SIGHT has no answer). The default records nothing.
    fn sight(
        &self,
        _party: &str,
        _catalog: Option<[u8; 32]>,
        _items: &[(&str, [u8; 32])],
    ) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    /// TRUST_SERVES: `DISTRUST_NONE` or the `DISTRUST_*` that refuses (digest `None` = the last sighting). The
    /// default refuses as unknown.
    fn trust_serves(&self, _party: &str, _item: Option<(&str, Option<[u8; 32]>)>) -> u32 {
        DISTRUST_UNKNOWN
    }
    /// TRUST_STATE: the counterparty verdict and the per-item state. The default refuses as unknown.
    fn trust_state(&self, _party: &str) -> (u32, Option<[u8; 32]>, Vec<TrustItemOwned>) {
        (DISTRUST_UNKNOWN, None, Vec::new())
    }
    /// TRUST_VERIFY: the `SIGNED_*` verdict and, for `SIGNED_ALGORITHM` and `SIGNED_CRITICAL`, the named member.
    /// The default has no root: `SIGNED_MALFORMED_ROOT`.
    fn trust_verify(&self, _party: &str, _payload: &[u8], _signatures: &[u8]) -> (u32, String) {
        (SIGNED_MALFORMED_ROOT, String::new())
    }
    /// RENDEZVOUS(RV_ACCEPT) on `route`: the local session description and the bridge the session holds under the
    /// exchange. The default is unavailable.
    fn rendezvous_accept(
        &self,
        _route: u32,
        _offer: &str,
    ) -> Result<(Box<str>, Box<dyn Held>), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    /// OBS_SCOPE as the principal whose identity records are `identity`: (OBS_READY | OBS_CLOSED | OBS_PENDING |
    /// OBS_REFUSED, the scope id for READY and CLOSED). Durable before it returns. The default is `OBS_REFUSED`.
    fn obs_scope(
        &self,
        _identity: &[u8],
        _op: u32,
        _scope: Option<[u8; 32]>,
        _require: &[&str],
    ) -> (u32, Option<[u8; 32]>) {
        (OBS_REFUSED, None)
    }
    /// OBSERVE as the principal whose identity records are `identity`: (OBS_ACCEPTED | OBS_PENDING |
    /// OBS_REFUSED, the receipt bytes). Durable before it returns. The default is `OBS_REFUSED`.
    fn observe(&self, _identity: &[u8], _o: &ObservationIn<'_>) -> (u32, Vec<u8>) {
        (OBS_REFUSED, Vec::new())
    }
    /// CONNECT as the verified `subject`: the `CONN_*` state and, for a BEGIN, the URL to send the caller to.
    /// The default is `CONN_REFUSED`.
    fn connect(
        &self,
        _op: u32,
        _subject: &str,
        _upstream: &str,
        _return_to: Option<&str>,
    ) -> (u32, Option<Box<str>>) {
        (CONN_REFUSED, None)
    }
}

/// The request's subject scope: SHA-256 of its ID_SUBJECT text (IF §12.5).
#[must_use]
pub fn subject_scope(subject: &str) -> [u8; 32] {
    Sha256::digest(subject.as_bytes())
}

/// One result piece core delivers: `piece(FROM_CORE, 0, flags, bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The exchange the piece is for (0 for the client side and most FROM_CORE results).
    pub exchange: u32,
    pub flags: u32,
    pub bytes: Vec<u8>,
}

/// Resolves intents against a host for one request: `subject` is the verified principal's scope, if any.
pub struct Resolver<'h> {
    host: &'h dyn IntentHost,
    subject: Option<[u8; 32]>,
    channels: Option<&'h dyn ChannelHost>,
    principal: Option<Principal<'h>>,
    route: u32,
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

    /// The request's verified principal: its ID_SUBJECT text and the identity records it was admitted with. It sets
    /// the subject scope as [`subject_scope`] does, and is what ENTITLE, MINT and CONNECT run as; without one they
    /// are refused here and the host is never asked.
    #[must_use]
    pub fn with_principal(mut self, subject: &'h str, identity: &'h [u8]) -> Self {
        self.subject = Some(subject_scope(subject));
        self.principal = Some(Principal { subject, identity });
        self
    }

    /// CHANNEL intents attach through `channels`; without it every CHANNEL is a `P_ERROR`.
    #[must_use]
    pub fn with_channels(mut self, channels: &'h dyn ChannelHost) -> Self {
        self.channels = Some(channels);
        self
    }

    /// The scope a flag word selects, or `None` when it asks for the caller's scope and there is no subject.
    fn scope(&self, caller_bound: bool) -> Option<Scope> {
        if caller_bound {
            self.subject.map(|s| Scope { subject: Some(s) })
        } else {
            Some(Scope::default())
        }
    }

    /// Applies `intents` in answer order and returns the pieces to deliver, in the IF order.
    #[must_use]
    pub fn resolve(&self, intents: &[Intent], held: &mut Channels) -> Vec<Piece> {
        // STORE, DELETE, COMMIT, PUSH and SIGNAL first, in answer order; LOOKUP and WORK read what they wrote.
        let mut failed: Vec<&[u8]> = Vec::new();
        let mut committed: Vec<(u32, u32, u32, u32)> = Vec::new();
        let mut channel_pieces: Vec<Piece> = Vec::new();
        let mut rendezvous_pieces: Vec<Piece> = Vec::new();
        for intent in intents {
            match intent {
                Intent::Store {
                    flags,
                    ttl_s,
                    key,
                    value,
                } => {
                    let done = self
                        .scope(flags & LK_CALLER != 0)
                        .ok_or(RecordsDenied::Invalid)
                        .and_then(|scope| self.host.store(scope, *flags, *ttl_s, key, value));
                    if done.is_err() {
                        failed.push(key);
                    }
                }
                Intent::Delete { flags, key } => {
                    let done = self
                        .scope(flags & LK_CALLER != 0)
                        .ok_or(RecordsDenied::Invalid)
                        .and_then(|scope| self.host.delete(scope, key));
                    if done.is_err() {
                        failed.push(key);
                    }
                }
                Intent::Commit { check, ops } => committed.push(self.commit(*check, ops)),
                Intent::Push { ttl_s, recs } => {
                    if let Err(denied) = self.host.push(*ttl_s, recs) {
                        tracing::warn!(?denied, "a plane push was not queued");
                    }
                }
                Intent::Signal { flags, key } => {
                    if flags & LK_CALLER == 0 {
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
                } => channel_pieces.push(self.channel(
                    held,
                    &ChannelAttach {
                        exchange: *exchange,
                        carrier: *carrier,
                        flags: *flags,
                        framing: *framing,
                        key,
                        subject: self.subject,
                        head,
                    },
                )),
                Intent::ChReady { exchange, tail } => {
                    if let Some(channel) = held.get_mut(exchange) {
                        channel.ready(tail);
                    }
                }
                Intent::Rendezvous {
                    exchange,
                    flags,
                    description,
                } => {
                    rendezvous_pieces.extend(self.rendezvous(held, *exchange, *flags, description))
                }
                Intent::Sight {
                    party,
                    catalog,
                    items,
                } => {
                    let seen: Vec<(&str, [u8; 32])> =
                        items.iter().map(|(name, d)| (name.as_str(), *d)).collect();
                    if let Err(denied) = self.host.sight(party, *catalog, &seen) {
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
        let mut pieces = Vec::new();
        for key in failed {
            pieces.push(Piece {
                exchange: 0,
                flags: P_STORE_FAILED,
                bytes: key.to_vec(),
            });
        }
        if let Some(bytes) = self.lookups(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_LOOKUP,
                bytes,
            });
        }
        if !committed.is_empty() {
            let mut reply = Reply::new();
            // A Reply refuses only past its cap; a commit answer is a few words.
            let put = encode_committed(&mut reply, &committed);
            debug_assert!(put.is_ok(), "COMMITTED answers fit a Reply");
            pieces.push(Piece {
                exchange: 0,
                flags: P_COMMITTED,
                bytes: reply.as_bytes().to_vec(),
            });
        }
        if let Some(bytes) = self.observeds(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_OBSERVED,
                bytes,
            });
        }
        if let Some(bytes) = self.works(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_WORK,
                bytes,
            });
        }
        if let Some(bytes) = self.entitles(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_ENTITLE,
                bytes,
            });
        }
        if let Some(bytes) = self.judges(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_JUDGED,
                bytes,
            });
        }
        if let Some(bytes) = self.trusts(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_TRUST,
                bytes,
            });
        }
        if let Some(bytes) = self.mints(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_MINTED,
                bytes,
            });
        }
        if let Some(bytes) = self.signs(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_SIGNED,
                bytes,
            });
        }
        if let Some(bytes) = self.connects(intents) {
            pieces.push(Piece {
                exchange: 0,
                flags: P_CONNECT,
                bytes,
            });
        }
        pieces.extend(channel_pieces);
        pieces.extend(rendezvous_pieces);
        pieces
    }

    /// One CHANNEL: the attachment as P_CHANNEL, or the P_ERROR the exchange ends with.
    fn channel(&self, held: &mut Channels, attach: &ChannelAttach<'_>) -> Piece {
        let attached = self
            .channels
            .ok_or(RecordsDenied::Unavailable)
            .and_then(|host| host.attach(attach));
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
                    bytes: reply.as_bytes().to_vec(),
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
                    bytes: reply.as_bytes().to_vec(),
                }
            }
        }
    }

    /// One COMMIT: (check, outcome, failed, status).
    fn commit(&self, check: u32, raw: &[u8]) -> (u32, u32, u32, u32) {
        let refused = |status| (check, 0, 0, status);
        let mut ops = Vec::new();
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
        match self.host.commit(scope, &ops) {
            Ok(CommitOutcome::Applied) => (check, commit::APPLIED, 0, 0),
            Ok(CommitOutcome::Conflict { failed }) => (check, commit::CONFLICT, failed, 0),
            Err(denied) => refused(denied_status(&denied)),
        }
    }

    /// The LOOKUP_HIT* (and CHAIN_STATE) of every LOOKUP of the answer, by index; `None` when it has none.
    fn lookups(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut reply = Reply::new();
        let mut any = false;
        let mut index = 0u32;
        for intent in intents {
            let Intent::Lookup { flags, limit, key } = intent else {
                continue;
            };
            any = true;
            let at = index;
            index += 1;
            let looked = match self.scope(flags & LK_CALLER != 0) {
                Some(scope) => match self.host.lookup(scope, *flags, *limit, key) {
                    Ok(looked) => looked,
                    Err(denied) => {
                        tracing::warn!(?denied, "a plane lookup was refused; it reads as a miss");
                        Looked::default()
                    }
                },
                None => Looked::default(),
            };
            let hits: Vec<(u32, &[u8], &[u8])> = looked
                .hits
                .iter()
                .take(*limit as usize)
                .map(|h| (at, &h.key[..], &h.value[..]))
                .collect();
            // The reply refuses only past its cap; the host bounds a hit by MAX_VALUE.
            let put = encode_lookup_hits(&mut reply, &hits);
            debug_assert!(put.is_ok(), "LOOKUP_HITs fit a Reply");
            if let (Some((len, broken_at)), true) = (looked.chain, flags & LK_CHAIN != 0) {
                let put = encode_chain_state(&mut reply, at, len, broken_at);
                debug_assert!(put.is_ok(), "a CHAIN_STATE fits a Reply");
            }
        }
        any.then(|| reply.as_bytes().to_vec())
    }

    /// The ENTITLE_ANS of every ENTITLE of the answer, in intent order; `None` when it has none. Without a
    /// verified principal there is no grant set to ask: not granted, and the host is not asked.
    fn entitles(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut answers: Vec<(u32, bool)> = Vec::new();
        for intent in intents {
            let Intent::Entitle { check, grant } = intent else {
                continue;
            };
            let granted = self
                .principal
                .is_some_and(|p| self.host.entitle(p.identity, grant));
            answers.push((*check, granted));
        }
        if answers.is_empty() {
            return None;
        }
        let mut reply = Reply::new();
        let put = encode_entitle_answers(&mut reply, &answers);
        debug_assert!(put.is_ok(), "ENTITLE_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The JUDGE_ANS of every JUDGE of the answer, in intent order; `None` when it has none.
    fn judges(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut answers: Vec<(u32, u32)> = Vec::new();
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
            answers.push((*check, self.host.judge(dest, *class, *flags)));
        }
        if answers.is_empty() {
            return None;
        }
        let mut reply = Reply::new();
        let put = encode_judged(&mut reply, &answers);
        debug_assert!(put.is_ok(), "JUDGE_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// One RENDEZVOUS: RV_ACCEPT answers P_RENDEZVOUS (the local description, the bridge now held under
    /// `exchange`) or P_RV_FAILED; RV_REMOTE goes to the bridge held there and answers only a failure.
    fn rendezvous(
        &self,
        held: &mut Channels,
        exchange: u32,
        flags: u32,
        description: &str,
    ) -> Option<Piece> {
        match flags {
            RV_ACCEPT => match self.host.rendezvous_accept(self.route, description) {
                Ok((local, bridge)) => {
                    held.insert(exchange, bridge);
                    Some(Piece {
                        exchange,
                        flags: P_RENDEZVOUS,
                        bytes: local.as_bytes().to_vec(),
                    })
                }
                Err(denied) => Some(rv_failed(exchange, &denied, None)),
            },
            RV_REMOTE => match held.get_mut(&exchange) {
                Some(bridge) => match bridge.remote(description) {
                    Ok(()) => None,
                    Err(denied) => Some(rv_failed(exchange, &denied, bridge.refusal())),
                },
                None => Some(rv_failed(exchange, &RecordsDenied::Invalid, None)),
            },
            _ => Some(rv_failed(exchange, &RecordsDenied::Invalid, None)),
        }
    }

    /// The OBS_SCOPE_ANS and OBS_RECEIPT of the answer's OBS_SCOPE and OBSERVE, in intent order; `None` when it
    /// has none. Custody is the verified principal's: without one every answer is OBS_REFUSED and the host is
    /// not asked. The host's calls are durable before they return, so the piece is delivered after the commit.
    fn observeds(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        enum Seen {
            Scope(u32, u32, Option<[u8; 32]>),
            Receipt(u32, u32, Vec<u8>),
        }
        let mut seen: Vec<Seen> = Vec::new();
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
                            let classes: Vec<&str> = require.iter().map(String::as_str).collect();
                            self.host.obs_scope(p.identity, *op, *scope, &classes)
                        }
                    };
                    seen.push(Seen::Scope(*check, status, id));
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
                            let counted: Vec<(&str, u64, u32)> = counts
                                .iter()
                                .map(|(class, amount, scale)| (class.as_str(), *amount, *scale))
                                .collect();
                            self.host.observe(
                                p.identity,
                                &ObservationIn {
                                    scope: *scope,
                                    event,
                                    component,
                                    revision: revision.as_deref().map(|r| (r, *revision_order)),
                                    state: *state,
                                    counts: &counted,
                                    rated_subject: *rated_subject,
                                    evidence: evidence.as_deref().unwrap_or(&[]),
                                },
                            )
                        }
                    };
                    seen.push(Seen::Receipt(*check, status, receipt));
                }
                _ => {}
            }
        }
        if seen.is_empty() {
            return None;
        }
        let answers: Vec<ObservedAnswer<'_>> = seen
            .iter()
            .map(|s| match s {
                Seen::Scope(check, status, scope) => ObservedAnswer::Scope {
                    check: *check,
                    status: *status,
                    scope: *scope,
                },
                Seen::Receipt(check, status, receipt) => ObservedAnswer::Receipt {
                    check: *check,
                    status: *status,
                    receipt,
                },
            })
            .collect();
        let mut reply = Reply::new();
        let put = encode_observed(&mut reply, &answers);
        debug_assert!(put.is_ok(), "OBS answers fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The TRUST_ANS of every TRUST and TRUST_VERIFY of the answer, in intent order; `None` when it has none.
    fn trusts(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        // (check, verdict, item states of a STATE, the named member of a VERIFY)
        let mut rows: Vec<(u32, u32, Vec<TrustItemOwned>, String, Option<[u8; 32]>)> = Vec::new();
        for intent in intents {
            match intent {
                Intent::Trust {
                    check, op, party, ..
                } if *op == TRUST_STATE => {
                    let (verdict, catalog, items) = self.host.trust_state(party);
                    rows.push((*check, verdict, items, String::new(), catalog));
                }
                Intent::Trust {
                    check,
                    op,
                    party,
                    item,
                } if *op == TRUST_SERVES => {
                    let item = item.as_ref().map(|(name, digest)| (name.as_str(), *digest));
                    let verdict = self.host.trust_serves(party, item);
                    rows.push((*check, verdict, Vec::new(), String::new(), None));
                }
                Intent::Trust { check, .. } => {
                    // The adapter admits only SERVES and STATE; anything else does not serve.
                    rows.push((*check, DISTRUST_UNKNOWN, Vec::new(), String::new(), None));
                }
                Intent::TrustVerify {
                    check,
                    party,
                    payload,
                    signatures,
                } => {
                    let (verdict, named) = self.host.trust_verify(party, payload, signatures);
                    rows.push((*check, verdict, Vec::new(), named, None));
                }
                _ => {}
            }
        }
        if rows.is_empty() {
            return None;
        }
        let views: Vec<Vec<TrustItem<'_>>> = rows
            .iter()
            .map(|(_, _, items, _, _)| {
                items
                    .iter()
                    .map(|i| TrustItem {
                        name: &i.name,
                        verdict: i.verdict,
                        approved: i.approved,
                        sighted: i.sighted,
                    })
                    .collect()
            })
            .collect();
        let answers: Vec<TrustAnswer<'_>> = rows
            .iter()
            .zip(&views)
            .map(|((check, verdict, _, named, catalog), items)| TrustAnswer {
                check: *check,
                verdict: *verdict,
                catalog: *catalog,
                items,
                named,
            })
            .collect();
        let mut reply = Reply::new();
        let put = encode_trust_answers(&mut reply, &answers);
        debug_assert!(put.is_ok(), "TRUST_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The MINTED of every MINT of the answer, in intent order; `None` when it has none. A ticket binds the
    /// verified subject: without one the answer is `R_DENIED` and the host is not asked.
    fn mints(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut answers: Vec<(u32, u32, u64, Box<str>)> = Vec::new();
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
                Some(p) => self.host.mint(TicketMint {
                    subject: p.subject,
                    scope: scope.as_deref().unwrap_or(""),
                    audience: audience.as_deref().unwrap_or("ticket"),
                    ttl_s: *ttl_s,
                    once: flags & MINT_ONCE != 0,
                    prefix: prefix.as_deref().unwrap_or(""),
                    record: record.as_deref().unwrap_or(&[]),
                }),
            };
            answers.push(match minted {
                Ok((ticket, expires_at_s)) => (*check, 0, expires_at_s, ticket),
                Err(status) => (*check, status, 0, Box::from("")),
            });
        }
        if answers.is_empty() {
            return None;
        }
        let refs: Vec<(u32, u32, u64, &str)> = answers
            .iter()
            .map(|(check, status, exp, ticket)| (*check, *status, *exp, &**ticket))
            .collect();
        let mut reply = Reply::new();
        let put = encode_minted(&mut reply, &refs);
        debug_assert!(put.is_ok(), "MINTED records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The SIGNED of every SIGN of the answer, in intent order; `None` when it has none.
    fn signs(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut signed: Vec<(u32, Result<SignedJws, u32>, bool)> = Vec::new();
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
            signed.push((*check, self.host.sign(payload, detached), detached));
        }
        if signed.is_empty() {
            return None;
        }
        let answers: Vec<SignedAnswer<'_>> = signed
            .iter()
            .map(|(check, jws, detached)| match jws {
                Ok(SignedJws::Compact(jws)) if !detached => {
                    SignedAnswer::Compact { check: *check, jws }
                }
                Ok(SignedJws::Detached {
                    protected,
                    signature,
                }) if *detached => SignedAnswer::Detached {
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
            })
            .collect();
        let mut reply = Reply::new();
        let put = encode_signed(&mut reply, &answers);
        debug_assert!(put.is_ok(), "SIGNED records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The CONNECT_ANS of every CONNECT of the answer, in intent order; `None` when it has none. A connection
    /// is the verified subject's: without one the state is `CONN_REFUSED` and the host is not asked.
    fn connects(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut answers: Vec<(u32, u32, Option<Box<str>>)> = Vec::new();
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
                Some(p) => self
                    .host
                    .connect(*op, p.subject, upstream, return_to.as_deref()),
            };
            // Only a BEGIN carries a URL.
            let url = url.filter(|_| *op == CONNECT_BEGIN);
            answers.push((*check, state, url));
        }
        if answers.is_empty() {
            return None;
        }
        let refs: Vec<(u32, u32, Option<&str>)> = answers
            .iter()
            .map(|(check, state, url)| (*check, *state, url.as_deref()))
            .collect();
        let mut reply = Reply::new();
        let put = encode_connect_answers(&mut reply, &refs);
        debug_assert!(put.is_ok(), "CONNECT_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }

    /// The WORK_ANS of every WORK of the answer, in intent order; `None` when it has none.
    fn works(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut outcomes: Vec<(u32, WorkOutcome)> = Vec::new();
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
            let outcome = if self.subject.is_none() {
                // §12.24: no verified principal, no row to bind.
                WorkOutcome::refused(R_DENIED)
            } else {
                self.host.work(&WorkIntent {
                    op: *op,
                    target: target.clone(),
                    reference: reference.clone(),
                    identity: self
                        .principal
                        .map_or_else(Vec::new, |p| p.identity.to_vec()),
                })
            };
            outcomes.push((*check, outcome));
        }
        if outcomes.is_empty() {
            return None;
        }
        let answers: Vec<WorkAnswer<'_>> = outcomes
            .iter()
            .map(|(check, o)| WorkAnswer {
                check: *check,
                status: o.status,
                state: o.state,
                reference: &o.reference,
                target: &o.target,
            })
            .collect();
        let mut reply = Reply::new();
        let put = encode_work_answers(&mut reply, &answers);
        debug_assert!(put.is_ok(), "WORK_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }
}

fn split_key(tail: &[u8], key_len: u32) -> Option<(&[u8], &[u8])> {
    let at = usize::try_from(key_len).ok()?;
    if at > MAX_KEY {
        return None;
    }
    tail.split_at_checked(at)
}

/// P_RV_FAILED's bytes: one REFUSAL in core's own fixed text for the cause (§12.15), or `mirrored`'s text when the
/// media bridge says why the far end's answer was refused.
fn rv_failed(exchange: u32, denied: &RecordsDenied, text: Option<String>) -> Piece {
    let (status, code, fixed) = match denied {
        RecordsDenied::Invalid | RecordsDenied::TooLarge => {
            (400, R_INVALID, "the media session description was refused")
        }
        RecordsDenied::Quota => (429, R_RATE_LIMITED, "the media session limit is reached"),
        RecordsDenied::Unavailable => (502, F_UNAVAILABLE, "the media session is unavailable"),
    };
    let mut reply = Reply::new();
    let put = encode_refusal(&mut reply, status, code, text.as_deref().unwrap_or(fixed));
    debug_assert!(put.is_ok(), "a REFUSAL fits a Reply");
    Piece {
        exchange,
        flags: P_RV_FAILED,
        bytes: reply.as_bytes().to_vec(),
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
    /// Resolves the intents of `first` and of every answer their results provoke. Answers come back in delivery
    /// order, `first` first, each with its intents taken (resolved), so the caller applies their client items,
    /// forward and facts as it would any answer.
    pub fn resolve(
        &mut self,
        first: Answer,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
    ) -> Result<Vec<Answer>, SessionError> {
        let mut out = Vec::new();
        let mut queue = VecDeque::from([first]);
        let mut rounds = 0u32;
        while let Some(mut answer) = queue.pop_front() {
            let intents = std::mem::take(&mut answer.intents);
            out.push(answer);
            if intents.is_empty() {
                continue;
            }
            rounds += 1;
            if rounds > MAX_ROUNDS {
                return Err(SessionError::Violation(Violation::IntentStorm));
            }
            for piece in resolver.resolve(&intents, &mut self.held) {
                let next = self.piece(
                    FROM_CORE,
                    piece.exchange,
                    piece.flags,
                    &piece.bytes,
                    effects,
                )?;
                queue.push_back(next);
            }
        }
        Ok(out)
    }
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
            deadline: Instant::now() + Duration::from_secs(30),
            stack: CallStack::default(),
            out_of_process: false,
            limits: InstanceLimits::default(),
        }
    }
}

/// The production [`IntentHost`]: records through [`PluginRecords`], pushes through the [`PushQueue`], signals
/// through the [`SessionSignals`] registry, WORK through the decider (default [`NoWork`]). Its calls block on `rt`,
/// so they run from `spawn_blocking`, never on a runtime worker.
pub struct KernelIntents<R: PluginRecords> {
    records: Arc<R>,
    push: Arc<dyn PushQueue>,
    signals: Arc<dyn SessionSignals>,
    work: Arc<dyn WorkDecider>,
    services: Services,
    who: Namespace,
    rt: Handle,
}

/// Decides WORK intents (§12.24).
pub trait WorkDecider: Send + Sync + 'static {
    fn decide(&self, who: &Namespace, intent: &WorkIntent) -> WorkOutcome;
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
    rt: Handle,
}

impl DurableDecider {
    /// `recovers` says whether a path-and-query target matches one of the instance's ROUTE_RECOVERY patterns.
    #[must_use]
    pub fn new(
        work: Arc<dyn DurableWork>,
        recovers: Box<dyn Fn(&str) -> bool + Send + Sync>,
        rt: Handle,
    ) -> Self {
        Self { work, recovers, rt }
    }
}

impl WorkDecider for DurableDecider {
    fn decide(&self, who: &Namespace, intent: &WorkIntent) -> WorkOutcome {
        let plane = who.caller();
        match intent.op {
            WORK_OPEN => {
                let Some(target) = intent.target.as_deref().filter(|t| (self.recovers)(t)) else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self
                    .rt
                    .block_on(self.work.open(&plane, &intent.identity, target))
                {
                    Ok(reference) => WorkOutcome {
                        status: 0,
                        state: WORK_LIVE,
                        reference: reference.into(),
                        target: String::new(),
                    },
                    Err(code) => WorkOutcome::refused(code),
                }
            }
            WORK_FIND => {
                let Some(reference) = intent.reference.as_deref() else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self
                    .rt
                    .block_on(self.work.find(&plane, &intent.identity, reference))
                {
                    Ok((state, target)) => WorkOutcome {
                        status: 0,
                        state,
                        reference: reference.to_owned(),
                        target: target.into(),
                    },
                    Err(code) => WorkOutcome::refused(code),
                }
            }
            WORK_SETTLE => {
                let Some(reference) = intent.reference.as_deref() else {
                    return WorkOutcome::refused(R_INVALID);
                };
                match self
                    .rt
                    .block_on(self.work.settle(&plane, &intent.identity, reference))
                {
                    Ok(()) => WorkOutcome {
                        status: 0,
                        state: WORK_SETTLED,
                        reference: String::new(),
                        target: String::new(),
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
    fn decide(&self, _: &Namespace, _: &WorkIntent) -> WorkOutcome {
        WorkOutcome::unsupported()
    }
}

impl<R: PluginRecords> KernelIntents<R> {
    #[must_use]
    pub fn new(
        records: Arc<R>,
        push: Arc<dyn PushQueue>,
        signals: Arc<dyn SessionSignals>,
        who: Namespace,
        rt: Handle,
    ) -> Self {
        Self {
            records,
            push,
            signals,
            work: Arc::new(NoWork),
            services: Services::default(),
            who,
            rt,
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

impl<R: PluginRecords> IntentHost for KernelIntents<R> {
    fn lookup(
        &self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &[u8],
    ) -> Result<Looked, RecordsDenied> {
        let who = self.who.caller();
        let mut looked = Looked::default();
        if flags & LK_CHAIN != 0 {
            let split = key.len().checked_sub(8).ok_or(RecordsDenied::Invalid)?;
            let (chain, after) = key.split_at(split);
            let after = u64::from_le_bytes(after.try_into().map_err(|_| RecordsDenied::Invalid)?);
            let mut hits = Vec::new();
            let read = self.rt.block_on(self.records.chain(
                &who,
                scope,
                chain,
                after,
                limit,
                &mut |seq, entry| {
                    let mut hit = chain.to_vec();
                    hit.extend_from_slice(&seq.to_be_bytes());
                    hits.push(Hit {
                        key: hit,
                        value: entry.to_vec(),
                    });
                },
            ))?;
            looked.hits = hits;
            looked.chain = Some((read.len, read.broken_at));
        } else if flags & LK_PREFIX != 0 {
            let mut hits = Vec::new();
            self.rt
                .block_on(self.records.list(&who, scope, key, limit, &mut |k, v| {
                    hits.push(Hit {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    });
                }))?;
            looked.hits = hits;
        } else {
            let mut value = None;
            let found = self
                .rt
                .block_on(self.records.get(&who, scope, key, &mut |v| {
                    value = Some(v.to_vec());
                }))?;
            if let (true, Some(value)) = (found, value) {
                looked.hits.push(Hit {
                    key: key.to_vec(),
                    value,
                });
            }
        }
        Ok(looked)
    }

    fn store(
        &self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), RecordsDenied> {
        if key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return Err(RecordsDenied::TooLarge);
        }
        let who = self.who.caller();
        if flags & LK_CHAIN != 0 {
            if ttl_s != 0 {
                return Err(RecordsDenied::Invalid);
            }
            return self
                .rt
                .block_on(self.records.append(&who, scope, key, value))
                .map(|_| ());
        }
        self.rt
            .block_on(self.records.put(&who, scope, key, value, ttl_s))
    }

    fn delete(&self, scope: Scope, key: &[u8]) -> Result<(), RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.records.del(&who, scope, key))
    }

    fn commit(&self, scope: Scope, ops: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.records.commit(&who, scope, ops))
    }

    fn work(&self, intent: &WorkIntent) -> WorkOutcome {
        self.work.decide(&self.who, intent)
    }

    fn push(&self, ttl_s: u64, recs: &[u8]) -> Result<(), RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.push.enqueue(&who, ttl_s, recs))
    }

    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>) {
        self.signals
            .signal(self.who.instance, key, subject, P_SIGNAL, key);
    }

    fn entitle(&self, identity: &[u8], grant: &str) -> bool {
        self.services
            .entitlements
            .as_ref()
            .is_some_and(|e| e.check(&self.who.caller(), identity, grant))
    }

    fn judge(&self, dest: &str, class: u32, flags: u32) -> u32 {
        let who = self.who.caller();
        let judge = self
            .services
            .judge
            .clone()
            .unwrap_or_else(PlaneJudge::unavailable);
        self.rt
            .block_on(judge.judge(dest, class, flags, who.deadline))
    }

    fn mint(&self, m: TicketMint<'_>) -> Result<(Box<str>, u64), u32> {
        let tickets = self.services.tickets.as_ref().ok_or(R_UNSUPPORTED)?;
        let who = self.who.caller();
        self.rt
            .block_on(tickets.mint(&who, m))
            .map_err(|denied| denied_status(&denied))
    }

    fn sign(&self, payload: &[u8], detached: bool) -> Result<SignedJws, u32> {
        let signer = self.services.signer.as_ref().ok_or(R_UNSUPPORTED)?;
        let who = self.who.caller();
        self.rt
            .block_on(signer.sign_jws(&who, payload, detached))
            .map_err(|denied| denied_status(&denied))
    }

    fn sight(
        &self,
        party: &str,
        catalog: Option<[u8; 32]>,
        items: &[(&str, [u8; 32])],
    ) -> Result<(), RecordsDenied> {
        let book = self
            .services
            .trust
            .as_ref()
            .ok_or(RecordsDenied::Unavailable)?;
        let who = self.who.caller();
        self.rt.block_on(book.sight(&who, party, catalog, items))
    }

    fn trust_serves(&self, party: &str, item: Option<(&str, Option<[u8; 32]>)>) -> u32 {
        match &self.services.trust {
            Some(book) => book.serves(&self.who.caller(), party, item),
            None => DISTRUST_UNKNOWN,
        }
    }

    fn trust_state(&self, party: &str) -> (u32, Option<[u8; 32]>, Vec<TrustItemOwned>) {
        let Some(book) = &self.services.trust else {
            return (DISTRUST_UNKNOWN, None, Vec::new());
        };
        let mut items = Vec::new();
        let (verdict, catalog) = book.state(&self.who.caller(), party, &mut |item| {
            items.push(TrustItemOwned {
                name: item.name.to_owned(),
                verdict: item.verdict,
                approved: item.approved,
                sighted: item.sighted,
            });
        });
        (verdict, catalog, items)
    }

    fn trust_verify(&self, party: &str, payload: &[u8], signatures: &[u8]) -> (u32, String) {
        let Some(book) = &self.services.trust else {
            return (SIGNED_MALFORMED_ROOT, String::new());
        };
        let mut named = String::new();
        let verdict = book.verify(&self.who.caller(), party, payload, signatures, &mut named);
        (verdict, named)
    }

    fn rendezvous_accept(
        &self,
        route: u32,
        offer: &str,
    ) -> Result<(Box<str>, Box<dyn Held>), RecordsDenied> {
        let media = self
            .services
            .media
            .as_ref()
            .ok_or(RecordsDenied::Unavailable)?;
        let (local, bridge) = self.rt.block_on(media.accept(route, offer))?;
        Ok((local, Box::new(MediaHeld::new(bridge, self.rt.clone()))))
    }

    fn obs_scope(
        &self,
        identity: &[u8],
        op: u32,
        scope: Option<[u8; 32]>,
        require: &[&str],
    ) -> (u32, Option<[u8; 32]>) {
        let Some(custody) = self.services.observations.as_ref() else {
            return (OBS_REFUSED, None);
        };
        let who = self.who.caller();
        self.rt
            .block_on(custody.scope(&who, identity, op, scope, require))
    }

    fn observe(&self, identity: &[u8], o: &ObservationIn<'_>) -> (u32, Vec<u8>) {
        let Some(custody) = self.services.observations.as_ref() else {
            return (OBS_REFUSED, Vec::new());
        };
        let who = self.who.caller();
        let (status, receipt) = self.rt.block_on(custody.observe(&who, identity, o));
        (status, receipt.into_vec())
    }

    fn connect(
        &self,
        op: u32,
        subject: &str,
        upstream: &str,
        return_to: Option<&str>,
    ) -> (u32, Option<Box<str>>) {
        let Some(connections) = self.services.connections.as_ref() else {
            return (CONN_REFUSED, None);
        };
        let who = self.who.caller();
        match op {
            // The caller is sent to the URL to consent: pending until the callback stores the grant.
            CONNECT_BEGIN => match self
                .rt
                .block_on(connections.begin(&who, subject, upstream, return_to))
            {
                Ok(url) => (CONN_PENDING, Some(url)),
                Err(_) => (CONN_REFUSED, None),
            },
            CONNECT_STATUS => (
                self.rt
                    .block_on(connections.status(&who, subject, upstream)),
                None,
            ),
            CONNECT_REVOKE => match self
                .rt
                .block_on(connections.revoke(&who, subject, upstream))
            {
                Ok(()) => (CONN_NONE, None),
                Err(_) => (CONN_REFUSED, None),
            },
            _ => (CONN_REFUSED, None),
        }
    }
}

#[cfg(test)]
#[path = "tests/port_intents_tests.rs"]
mod tests;
