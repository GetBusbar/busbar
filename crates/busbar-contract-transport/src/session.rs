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

use core::fmt;

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

/// THE COMPOSITION'S CEILING ON ONE SESSION.
///
/// One field, and the "one" is the deliberate half. The other bounds a duplex session runs under
/// live where the thing they bound lives: a message ceiling is the CARRIER's, because the carrier
/// is what buffers a partial message before anyone above has been handed anything, and a keepalive
/// answer is the carrier's too, because it is a frame of one wire's own protocol that no plane may
/// ever see. A seam that carried either would be a seam that had to know what a wire's frames are,
/// which is precisely the knowledge this module is arranged not to have.
///
/// What is left is the one bound that is genuinely about the SESSION rather than about a frame: how
/// long the whole thing may run. It is spelled here rather than in a wire's own crate because the
/// answer is the COMPOSITION's — the same number for every wire this node serves — and a wire that
/// owned it would be a wire an acceptor had to name in order to state a deadline.
///
/// `Default` is the unbounded session, which is the honest posture for a session between two things
/// one deployment composed itself: the deadline exists to bound a session opened by a stranger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionBudgets {
    /// How long the whole session may run, measured from the pump's first read.
    ///
    /// `None` is unbounded, and it is a real choice rather than a missing value: a deadline on an
    /// exchange with no stranger on either end would cut a healthy long-lived session for no reason
    /// anybody could act on.
    pub deadline: Option<std::time::Duration>,
}

/// HOW DEEP THE UPSTREAM LEG OF ONE SESSION MAY QUEUE, spelled beside the budget it belongs with.
///
/// Beside [`SessionBudgets`] rather than in a wire, for the same reason the deadline is: it is the
/// COMPOSITION's number — the same for every wire this node relays over — and a copy per wire is a
/// set of ceilings that drift apart with nothing to notice. Small on purpose. The queue exists only
/// so that a synchronous driver can hand a frame off without awaiting a socket; anything deeper
/// would be this node buffering a peer's backlog on a session it is merely relaying, and a leg that
/// has fallen this far behind is one the session is better off ending than hiding.
pub const EGRESS_DEPTH: usize = 32;

/// WHERE AN UPSTREAM TAKES THIS DEPLOYMENT'S CREDENTIAL, as the dialect that speaks to it declares.
///
/// A duplex upstream authenticates ONCE, at the upgrade, and every vendor spells that one
/// presentation differently: one reads a request header, one reads a query parameter of the dial
/// URL. Neither is a choice the composition root, the wire or the plane may make — it is the
/// dialect's own statement about the protocol it speaks, so it is DECLARED on the dialect's row and
/// read here rather than branched on a vendor's name at the dial.
///
/// The `Query` arm is why [`redact_url_credentials`] exists and why it is in this crate: this is the
/// declaration that says a secret may travel in a URL, so the redactor that keeps it out of a log
/// belongs beside it rather than in whichever caller remembered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialAt {
    /// A request header of the upgrade, by name.
    Header(&'static str),
    /// A query parameter of the dial URL, by name.
    Query(&'static str),
}

/// THE CREDENTIAL ONE LEG PRESENTS when it dials, with the place its dialect declared for it.
///
/// Borrowed, never owned: the secret is the deployment's, resolved once by the one catalog that
/// resolves it, and a copy per dial would be a second lifetime for a value whose whole handling rule
/// is that it has one. Not `Serialize` and not `Clone`: the only thing that may be done with this is
/// present it.
pub struct LegCredential<'a> {
    /// Where the dialect said it goes.
    pub at: CredentialAt,
    /// The resolved secret itself.
    pub secret: &'a str,
}

/// WRITTEN, NEVER DERIVED. A derived `Debug` puts the resolved secret in whatever line formatted the
/// value — which is every `{:?}` an author reaches for while debugging a dial that will not open.
/// This says where the credential goes and how long it is, which is what a reader of that line is
/// actually asking, and says the value nowhere.
impl fmt::Debug for LegCredential<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegCredential")
            .field("at", &self.at)
            .field("secret", &format_args!("<{} bytes>", self.secret.len()))
            .finish()
    }
}

/// SCRUB a credential carried in a dial target's QUERY STRING out of a message before it is logged.
///
/// THE ONE REDACTOR, and it is here because [`CredentialAt::Query`] is here: this crate is the one
/// that declares a secret may ride a URL, so it is the one that owes the scrub. A dialect whose
/// native scheme puts the key in the query means every URL-shaped refusal — a dialer quoting the
/// target back verbatim, a handshake error, an audit record naming where a leg went — would
/// otherwise write the deployment's resolved provider credential where it is exactly as readable as
/// the config file it came from.
///
/// Everything from `key=` to the next delimiter is replaced. Deliberately blunt: this runs on paths
/// about to be logged or recorded, and a message that over-redacts costs an operator nothing while
/// one that under-redacts costs them the credential.
#[must_use]
pub fn redact_url_credentials(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(at) = rest.find("key=") {
        // Only a query/fragment parameter — `key=` inside an ordinary word is not a credential.
        let is_param = at == 0
            || matches!(
                rest.as_bytes()[at - 1],
                b'?' | b'&' | b';' | b'#' | b' ' | b'"'
            );
        let (head, tail) = rest.split_at(at + "key=".len());
        out.push_str(head);
        if is_param {
            let end = tail.find(['&', '#', '"', ' ', '\'']).unwrap_or(tail.len());
            if end > 0 {
                out.push_str("<redacted>");
            }
            rest = &tail[end..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// THE UPSTREAM HALF OF ONE SESSION, as a SYNCHRONOUS driver may reach it.
///
/// [`SessionDriver::drive`] is sync, and it is sync on purpose: the arena, the plane call and the
/// ledger all run under it, and a seam that could await would be a seam a session's state could be
/// held across. So the driver cannot own a socket — it can only own something it can hand a frame
/// to and get an answer from without suspending, which is what this is.
///
/// ## Why it REFUSES rather than blocks
///
/// The lease is bounded, and an offer that does not fit is [`crate::wire::TransportError::Backpressure`]
/// rather than a wait. It is the same posture the duplex mount's own header states for the inbound
/// direction: no queue, and the absence is the backpressure answer rather than a missing feature. A
/// lease that blocked would suspend the pump — the one thread of the session — behind an upstream
/// that stopped reading, and a lease that grew would let that upstream decide how much of this
/// node's memory one session costs. Refusing hands the decision back to the driver, which has the
/// only vocabulary that can say what happened: one of the eight words, on the session that owns the
/// leg.
///
/// ## What is NOT here
///
/// No dial, no address, no close code, no media, no reconnect. Where the leg goes and what it is
/// made of are the WIRE's, decided once when the lease was minted; a driver holding one could not
/// tell you which wire is under it. And no read: the inbound direction of the leg is a
/// [`SessionOpen`]-shaped thing the composition pumps, not something a lease hands back.
pub trait EgressLease: Send {
    /// Offer one frame to the upstream leg, without waiting for it to reach the wire.
    ///
    /// # Errors
    ///
    /// The leg would not take it: [`crate::wire::TransportError::Backpressure`] if the lease is at
    /// depth, and [`crate::wire::TransportError::Closed`] if the leg is over. Both are the session's
    /// to answer — there is no third party to retry against.
    fn offer(&mut self, frame: &[u8]) -> Result<(), crate::wire::TransportError>;

    /// Say that nothing further will be offered, so the leg may finish what it holds and close.
    ///
    /// Infallible and idempotent: the leg is over either way, and a finish that could fail would let
    /// an upstream that stopped reading decide how this node records the ending.
    fn finish(&mut self);
}

/// A WIRE THAT UPGRADES AND PUMPS: the seam an ACCEPTOR reaches a duplex wire through.
///
/// [`SessionDriver`] is the seam a session's FRAMES cross, and it faces the other way. This one is
/// what a composition root holds: it has a listener, a declared surface and a driver, and it needs
/// to ask SOME wire for one session at a time without being written against a particular one.
///
/// ## Why it is TWO calls
///
/// Because a node that can be asked to stop has two situations and they are not the same situation.
/// WAITING for an upgrade it owes nobody anything: nothing has been accepted, no caller has been
/// told yes, and dropping the wait is free and correct. MID-SESSION a caller HAS been told yes and
/// is being served, and dropping that is a session cut by this node for a reason the caller cannot
/// see. An acceptor holding a single accept-upgrade-open-and-pump future cannot tell those apart —
/// one future spans both — so a stop either cancels a live session or waits on a connection that
/// may never come.
///
/// [`DuplexWire::serve_upgrade`] returns exactly where the first situation ends and the second
/// begins, and it says so by handing back a VALUE. That is the whole of the drain, stated in
/// ownership: "is anything open?" is not a flag an acceptor sets, clears and remembers to read, it
/// is a value the acceptor either holds or does not, and the only thing that can be done with one
/// is move it into [`DuplexWire::pump_session`].
///
/// ## What is NOT here
///
/// No frame, no close code, no ping, no handshake, no address and no bind. A wire's own protocol is
/// its own, and an acceptor written against this face could not tell you which wire it just served.
/// Neither is a refusal: whether a session may be opened at all is the DRIVER's answer, given while
/// the upgrade still has somewhere to carry one, and whether a target is a session mount is the
/// DECLARATION's, read by the wire.
pub trait DuplexWire: Send + Sync {
    /// ONE SESSION THAT IS OPEN AND HAS NOT BEEN PUMPED — the wire's own value for it.
    ///
    /// Associated rather than a shared struct, because what an open session IS differs by wire: an
    /// upgraded carrier here, a stream identifier there, a peer connection somewhere else. What the
    /// face fixes is not its contents but its OWNERSHIP — an acceptor holding one has told a caller
    /// yes — so an implementation that made it `Clone` would be handing out a promise twice.
    type OpenSession: Send + 'static;

    /// THE WAITING HALF: take one upgrade off the listener and OPEN the session it names — and stop
    /// there, with the session open and not one frame pumped.
    ///
    /// The future may be DROPPED, and that is the point: everything it holds before a session opens
    /// is this node's own, and dropping it tells no caller anything, which is what makes it the arm
    /// of an acceptor's stop-or-accept race. An implementation that answered a caller and then
    /// returned would have moved the promise before the value that carries it.
    ///
    /// # Errors
    ///
    /// No session opened — the listener could not yield one, the upgrade failed, or the driver
    /// refused it before the protocol changed. Either way nothing is open, so nothing is draining
    /// and the acceptor may go round again; a listener that will never yield another reports
    /// [`crate::wire::TransportError::Closed`], which is how the two are told apart.
    fn serve_upgrade<'w>(
        &'w self,
        listener: &'w crate::wire::Listener,
        driver: &'w dyn SessionDriver,
        surface: &'w WireSurface,
    ) -> impl core::future::Future<Output = Result<Self::OpenSession, crate::wire::TransportError>>
           + Send
           + 'w;

    /// THE MID-SESSION HALF: run one already-open session to its end.
    ///
    /// Takes the session BY VALUE, which is the ownership statement the drain rests on. It answers
    /// rather than erring, because past the open every ending is an ending — the peer went, the
    /// deadline ran out, the driver ended it, the carrier failed — and which end cut it is in the
    /// [`SessionEnd`]. [`SessionDriver::close`] has been called exactly once by the time it
    /// returns, on every one of those endings including the ugly ones.
    ///
    /// The budget arrives HERE rather than with the upgrade, so an acceptor that held an open
    /// session across a configuration change is not holding a stale ceiling.
    fn pump_session<'w>(
        &'w self,
        open: Self::OpenSession,
        driver: &'w dyn SessionDriver,
        budgets: SessionBudgets,
    ) -> impl core::future::Future<Output = SessionEnd> + Send + 'w;
}
