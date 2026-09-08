// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM A DUPLEX TRANSPORT HANDS A SESSION ACROSS, frame by frame.
//!
//! ## Why the one-shot seam is not enough
//!
//! [`crate::driver::UnitDriver`] is the whole of the request/answer shape: one arrival goes over, one
//! [`crate::driver::Answer`] comes back, and the transport is done. Every wire in this tree that
//! answers one request with one document is served by it, and none of them needs anything more.
//!
//! A duplex wire is a different shape and the difference is not a detail. ONE upgrade carries MANY
//! frames, in BOTH directions, and what a frame means depends on the frames before it: the far side
//! is talking, not asking. A transport that served that through the one-shot seam would have to hand
//! the state across on every frame — which means holding it, which means being the thing that knows
//! what a session accumulates, which is exactly the knowledge the transport axis is not allowed.
//!
//! So the session is handed over once, at the open, and what comes back is a HANDLE. The state lives
//! behind the handle, on the driver's side, where the arena and the ledger already are. The transport
//! holds an integer.
//!
//! ## The three moments, and why they are three
//!
//! [`SessionDriver::open`] runs once, on the upgrade, and is the only moment a refusal can be
//! answered on the wire the upgrade arrived on — after it, the protocol has changed and there is no
//! status field left to put one in. [`SessionDriver::drive`] runs per inbound frame and answers with
//! the frames that go back out. [`SessionDriver::close`] runs once, whichever end cut, and is what
//! releases whatever `open` allocated.
//!
//! `close` is called on EVERY ending — an orderly close, a peer that vanished, a sink that stopped
//! accepting, a driver that ended it itself. A transport that skipped it on the ugly endings would
//! leak exactly the sessions that failed, which is the population you can least afford to leak.
//!
//! ## What is deliberately NOT here
//!
//! No frame kind, no close code, no ping, no continuation, no size limit. Those are one wire's
//! spelling of a session and this seam is not about one wire. What travels is bytes, a media type
//! the DECLARATION named, an ordering, and the closed vocabularies this crate already owns —
//! [`crate::driver::Outcome`] for what happened to a frame's unit and [`crate::wire::CloseReason`]
//! for why a session ended. A transport spells those onto its own numbering; nothing here knows the
//! numbers.

use crate::driver::Outcome;
use crate::surface::{Bar, WireSurface};
use crate::wire::CloseReason;

/// What the transport knows at the moment a session opens, before any frame has arrived.
///
/// The same facts an [`crate::driver::Arrival`] carries, minus the body — an upgrade has none — and
/// plus the BINDING, which a session needs and a one-shot arrival does not. A duplex mount addresses
/// a binding rather than an operation: the frames name the operations, and they have not arrived yet.
#[derive(Clone, Copy, Debug)]
pub struct SessionOpen<'a> {
    /// The facts this transport published for the upgrade, in the order it publishes them.
    ///
    /// Ordered for the reason [`crate::driver::Arrival::facts`] is ordered: the reserved keys come
    /// first and a declared capture that collides with one is never reached.
    pub facts: &'a [(&'a str, &'a str)],
    /// The registry key of the layer the session ended on.
    pub transport: &'static str,
    /// The composed transport stack, bottom layer first.
    pub chain: &'a [&'static str],
    /// The declared binding this session was opened on, by the declarer's own name for it.
    pub binding: &'static str,
    /// The credential bar the declaration puts on that binding.
    pub bar: Bar,
}

impl SessionOpen<'_> {
    /// The value of one published fact. First match wins.
    #[must_use]
    pub fn fact(&self, key: &str) -> Option<&str> {
        self.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// The driver's own name for one open session.
///
/// Opaque on purpose, and minted by the DRIVER rather than the transport. Everything a session
/// accumulates — the arena, the decoded state, the principal, the ledger rows — is on the driver's
/// side, and a transport that held a key into that would be holding a reference to machinery it is
/// not allowed to name. What it holds instead is a number it got back and hands in again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionHandle(pub u64);

/// One inbound frame, on the way across the seam.
#[derive(Clone, Copy, Debug)]
pub struct SessionFrame<'a> {
    /// The frame's payload, exactly as it arrived.
    pub payload: &'a [u8],
    /// Which inbound frame of this session it is, counting from zero.
    ///
    /// The driver's evidence that the transport delivered the session IN ORDER, and the only thing
    /// that makes an out-of-order delivery detectable rather than silently reinterpreted: a duplex
    /// plane's state machine reads frame *n* against what frame *n-1* left behind.
    pub seq: u64,
}

/// What the driver answered one inbound frame with.
///
/// The BYTES ARE THE PLANE'S, always. What the transport decides from the rest is the framing, the
/// order and whether the session continues.
///
/// No `Default`, deliberately. There is no default [`Outcome`]: a reply that did not say what
/// happened would post `Completed` to the ledger for a frame nobody ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReply {
    /// The frames to write back, IN THIS ORDER, and empty where this frame calls for no answer.
    ///
    /// A run rather than one, because a duplex plane routinely answers one arrival with several —
    /// and because the alternative, a driver that could only answer one and pushed the rest out of
    /// band, would put the ordering in the hands of whatever raced to the sink first.
    pub frames: Vec<Vec<u8>>,
    /// The media type the declaration names for these frames.
    ///
    /// Empty where no operation was resolved, which is the honest answer rather than a guess. A
    /// transport whose wire distinguishes frame kinds reads it to choose one.
    pub media: String,
    /// What happened to this frame's unit, in the closed vocabulary every wire can say.
    ///
    /// Carried on every reply even for a wire with no status field, because the fee decision and the
    /// journal read it. A frame that was refused does NOT end the session by itself: the plane wrote
    /// its refusal into the frames above, and a duplex peer is expected to carry on.
    pub outcome: Outcome,
    /// Where set, the session ends after these frames are written, for this reason.
    ///
    /// The driver's half of the cut, and the only way this side ends a session. A transport does not
    /// decide that a session is over on the strength of an outcome: eight words that mean "this frame
    /// went badly" say nothing about whether the next one will.
    pub close: Option<CloseReason>,
}

impl SessionReply {
    /// A reply that writes nothing and lets the session run on.
    #[must_use]
    pub fn quiet(outcome: Outcome) -> Self {
        Self {
            frames: Vec::new(),
            media: String::new(),
            outcome,
            close: None,
        }
    }

    /// A reply that writes nothing and ends the session.
    #[must_use]
    pub fn ending(outcome: Outcome, reason: CloseReason) -> Self {
        Self {
            close: Some(reason),
            ..Self::quiet(outcome)
        }
    }

    /// A reply that writes one run of frames under one declared media type.
    #[must_use]
    pub fn frames(frames: Vec<Vec<u8>>, media: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            frames,
            media: media.into(),
            outcome,
            close: None,
        }
    }
}

/// WHICH END CUT a session.
///
/// Two values because there are two ends and a session ends at exactly one of them first. Which one
/// is not bookkeeping: a session the far side dropped is a session this node was still willing to
/// serve, and a session this node ended is one it decided against. A journal that recorded them the
/// same way could not tell a flaky client from a node shedding load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Cut {
    /// The far side went first: it closed, or its stream ended, or its socket died.
    Client,
    /// This side went first: the driver ended it, or the transport could not go on.
    Upstream,
}

/// HOW A SESSION ENDED, as the transport reports it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct SessionEnd {
    /// Which end cut.
    pub cut: Cut,
    /// Why, in the closed vocabulary.
    pub reason: CloseReason,
}

/// WHAT RUNS A DUPLEX SESSION. Implemented by the composition root, handed to a transport at listen.
///
/// The duplex sibling of [`crate::driver::UnitDriver`], and the division is the same one: the arena,
/// the context, the plane call, the loop, the per-session state and the ledger are all on this side,
/// and the transport holds bytes and a handle. `Send + Sync` because one driver serves every session
/// a listener accepts, concurrently.
pub trait SessionDriver: Send + Sync {
    /// Open one session against a declared surface.
    ///
    /// The one moment a refusal can still be answered on the wire the upgrade arrived on, which is
    /// why this one returns a `Result` where [`SessionDriver::drive`] does not: after the upgrade the
    /// protocol has changed and there is no status field left. A refusal here is one of the eight
    /// words, and the transport spells it onto whatever its own pre-upgrade leg has.
    ///
    /// # Errors
    ///
    /// The driver will not open a session for this arrival.
    fn open(&self, open: SessionOpen<'_>, surface: &WireSurface) -> Result<SessionHandle, Outcome>;

    /// Run one inbound frame of an open session, and answer with the frames that go back.
    ///
    /// Infallible for the reason the one-shot seam is infallible: every way a frame can fail is one
    /// of the eight words, and a second failure channel would be one no wire has a field for.
    fn drive(&self, session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply;

    /// Release one session, whichever end cut it.
    ///
    /// Called EXACTLY ONCE per handle [`SessionDriver::open`] returned, on every ending including the
    /// ugly ones. A transport that skipped it on a peer that vanished would leak precisely the
    /// sessions that failed.
    fn close(&self, session: SessionHandle, end: SessionEnd);
}

/// A session driver that opens nothing, for a mount composed before its driver exists.
///
/// The duplex twin of [`crate::driver::Detached`], and there for the same reason: a mount is handed a
/// driver at listen, and a deployment that has mounted a surface it cannot yet run has to answer
/// SOMETHING. Refusing the upgrade with the word that means "this node cannot serve it" is the only
/// answer that is true, and it is refused BEFORE the protocol changes, so the caller gets it on a
/// wire that still has somewhere to put it.
#[derive(Clone, Copy, Debug, Default)]
pub struct DetachedSession;

impl SessionDriver for DetachedSession {
    fn open(
        &self,
        _open: SessionOpen<'_>,
        _surface: &WireSurface,
    ) -> Result<SessionHandle, Outcome> {
        Err(Outcome::Unavailable)
    }

    fn drive(&self, _session: SessionHandle, _frame: SessionFrame<'_>) -> SessionReply {
        SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed)
    }

    fn close(&self, _session: SessionHandle, _end: SessionEnd) {}
}
