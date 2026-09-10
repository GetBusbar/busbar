// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNTING A DECLARED SURFACE ON A DUPLEX SESSION: any plane's, and none of them by name.
//!
//! ## What this module is for
//!
//! The request/answer mounts one layer down read a declaration and serve one arrival with one
//! answer. That is the whole shape of the wires they carry and it is not the shape of this one. Here
//! ONE upgrade opens a session, many frames travel on it in both directions, and what a frame means
//! depends on the frames before it.
//!
//! Every duplex protocol this tree has ever served was therefore written as a protocol's own server:
//! the upgrade handling, the read pump, the write pump, the ordering, the backpressure posture and
//! the close codes all lived beside the codec that knew what the frames meant, and none of those six
//! is about a protocol. They are about how a SESSION is carried, and a plane can declare the part
//! that is its own — the binding, the mount, the credential bar, the media types — in
//! `busbar_contract_transport::surface`, which this module reads.
//!
//! So: hand this a declared surface and a session driver, and it mounts the surface. Which surface it
//! is, it does not know and may not ask. There is no protocol name in this file and none in this
//! crate; `tests/no_plane_names.rs` asserts that over the crate's own source and its own manifest.
//!
//! ## The two calls, and why they are two rather than one
//!
//! [`address`] and [`open_session`] run BEFORE the upgrade; [`pump`] runs after it. The split is not
//! stylistic. A refusal has to be answered on a wire that has somewhere to put one, and the moment
//! this transport's own protocol takes over, the status line is gone — there is no field left to
//! refuse in, only a close code that arrives after the caller has already been told yes. So a mount
//! that is not addressed, and a driver that will not open a session, are both answered on the leg
//! underneath, which still has a status. `busbar_transport_http::mount::status_of` is the mapping,
//! and it is the one the layer below already uses.
//!
//! ## What backpressure means here, and what it deliberately does not
//!
//! [`pump`] reads one frame, drives it, writes everything the driver answered, and only then reads
//! again. There is no queue between the two directions, and that is the design rather than a
//! simplification: a queue would let a peer that has stopped READING keep this node writing into
//! memory on its behalf, which is a peer choosing how much of this node's heap it occupies. The
//! sequential pump makes the inbound rate no faster than the outbound wire, with no accounting and
//! nothing to tune.
//!
//! A sink that reports [`TransportError::Backpressure`] anyway — a bounded writer that is genuinely
//! full — ends the session. It does not buffer and it does not drop frames: dropping one frame of a
//! duplex session hands the far side a state machine that silently disagrees with this one, which is
//! worse than an honest close.
//!
//! ## The one budget the pump itself owns
//!
//! [`SessionBudgets`] carries a WHOLE-SESSION deadline and nothing else, and the "nothing else" is
//! the deliberate half. The other two bounds a duplex session runs under live where the thing they
//! bound lives: the message ceiling is the carrier's, because the carrier is what buffers a partial
//! message before anyone above it has been handed anything, and a pump-side check would only refuse
//! bytes already in this node's heap; and the keepalive answer is the carrier's for the same reason,
//! because a ping is a frame of the wire's own protocol that no plane may ever see. A pump that owned
//! either would be a pump that had to know what the wire's frames are, which is the knowledge this
//! module is arranged not to have.
//!
//! What is left is the one bound that is genuinely about the SESSION rather than about a frame: how
//! long the whole thing may run. It is measured from the pump's first read and it ends the session
//! with [`CloseReason::Timeout`] as this side's cut — a deadline this node was waiting on is this
//! node's own decision, not a caller's failure to meet one.
//!
//! ## What this transport therefore does NOT know
//!
//! Which plane answered. What a frame meant. What the session accumulated. What any of it cost. It
//! knows that an upgrade named a declared binding, that frames arrived in an order, which bytes the
//! driver answered with, and — from the closed close vocabulary — which number its own wire spells.

use busbar_contract_transport::driver::Outcome;
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::session::{
    Cut, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen,
};
use busbar_contract_transport::surface::{Bar, BindingDecl, Capture, WireSurface};
use busbar_contract_transport::wire::{CloseReason, TransportError};
use busbar_transport_http::mount::Unaddressed;

// ── what arrived ────────────────────────────────────────────────────────────────────────────────

/// One upgrade request, as the layer below read it and before any plane is chosen.
///
/// Two fields, where the request/answer mount's own arrival has five, and the difference is the
/// honest one. A session is addressed by WHERE it was opened and by WHO opened it; the method is
/// fixed by the upgrade's own definition and carries no choice, and after the upgrade there is no
/// method at all. Publishing one would be this transport declaring a fact it does not have.
#[derive(Clone, Copy, Debug)]
pub struct Upgrade<'u> {
    /// The request target the upgrade named, query and fragment included, exactly as it arrived.
    pub target: &'u str,
    /// The peer's source address as the bottom layer saw it.
    pub peer: &'u str,
    /// The credential the caller presented on the upgrade, exactly as it arrived.
    ///
    /// THE ONLY REQUEST THIS SESSION EVER HAS. A one-shot arrival presents its credential on every
    /// request and can be challenged on any of them; a session presents one on the upgrade and never
    /// again, because after it the protocol has changed and there is no request left to carry one. So
    /// a mount that dropped this would leave a declared [`Bar::Credential`] binding with nothing to
    /// resolve for the whole life of the session, and the only posture left to the driver would be
    /// the anonymous one.
    ///
    /// Whole and unstripped, for the reason the one-shot mount publishes it whole: the scheme word is
    /// the authentication chain's to read, and a transport that stripped the wrong prefix would turn
    /// one caller's secret into a different string.
    ///
    /// `None` is an upgrade that presented none, which is a posture a declaration can legitimately
    /// admit and is NOT the same as an empty one — a driver handed an empty credential is being told
    /// one was presented and is blank.
    pub credential: Option<&'u str>,
}

/// The RESERVED fact keys a mounted session publishes.
///
/// Exactly the three this transport declares in its own `TRANSPORT_FACTS`, and the test beside this
/// module holds the two lists to each other. A reserved key published but never declared is a value
/// a plane reads that no boot check knows about, which is the failure the reserved-key registry
/// exists to make impossible.
///
/// The reserved keys and not the whole published list, for the reason the request/answer mount's
/// own `MOUNT_FACTS` is the reserved keys: a session opened at a mount PATTERN also publishes what
/// the pattern captured, under the names the DECLARER gave them, and those are the declarer's
/// vocabulary rather than the kernel's. A transport that had to enumerate them here would be
/// enumerating the routes of every plane it will ever carry.
pub const SESSION_FACTS: &[&str] = &[tfacts::PATH, tfacts::PEER, tfacts::CREDENTIAL];

/// Which declared binding an upgrade was addressed to, and what this transport stands on.
///
/// Built once, before the upgrade, and then carried for the life of the session. It holds no state:
/// everything the session accumulates is behind the [`SessionHandle`], on the driver's side.
#[derive(Clone, Debug)]
pub struct Mount<'m> {
    /// The declared binding the upgrade named.
    pub binding: &'m BindingDecl,
    /// The credential bar that binding declares.
    pub bar: Bar,
    /// The registry key of this transport.
    pub key: &'static str,
    /// The composed transport stack, bottom layer first.
    pub chain: &'m [&'static str],
    /// What the binding's matched mount PATTERN captured, in declaration order.
    ///
    /// Empty for an all-literal mount, which is every mount declared before patterns existed. Where
    /// it is not empty it is the ONLY thing this session is ever told about where it was opened
    /// beyond the raw path: a session declares no target template — after the upgrade this wire has
    /// no target at all — so the pattern that admitted the upgrade is the one place the identifier
    /// in the published URL was written down.
    pub captures: Vec<Capture<'m>>,
}

/// Address one upgrade against a declared surface.
///
/// THREE questions, and each of the last two is one a mount that stopped at the previous one would
/// get wrong. A target has to be one of a binding's declared mounts; that binding has to be carried
/// by THIS transport, because a surface routinely declares several bindings over several wires at
/// overlapping paths and a session opened at another wire's path would be a session nobody declared,
/// served under that binding's bar; and the binding has to declare a
/// [`busbar_contract_transport::surface::Dispatch::Duplex`] row — it has to be a place the DECLARER
/// said a session may be opened.
///
/// The third question is the one this file could not ask before the contract had a duplex kind. A
/// mount that asked only the first two upgrades any binding of this transport, an ordinary
/// posted-envelope endpoint included — a deployment is entitled to declare one over a wire that can
/// also carry sessions — and the caller is handed a session on a surface whose own declaration says
/// it answers one document with one answer. Nothing in the declaration was ever consulted about
/// whether that was allowed, because there was nothing in it that could say.
///
/// All three are the single walk in
/// [`busbar_contract_transport::surface::duplex_binding_at`], so no second duplex wire can grow a
/// second reading of them, and the bar comes back off the same walk — read from the duplex rows,
/// which are the only rows that say anything about an upgrade.
///
/// # Errors
///
/// No duplex binding of this transport declares a mount at that target.
pub fn address<'s>(
    surface: &'s WireSurface,
    key: &'static str,
    chain: &'s [&'static str],
    upgrade: &Upgrade<'s>,
) -> Result<Mount<'s>, Unaddressed> {
    let (binding, bar, captures) =
        busbar_contract_transport::surface::duplex_binding_at(surface, key, upgrade.target)
            .ok_or(Unaddressed)?;
    Ok(Mount {
        binding,
        bar,
        key,
        chain,
        captures,
    })
}

/// Build the fact list one session publishes, reserved keys first and the mount's captures after.
///
/// The ORDER is load-bearing for the reason it is load-bearing on the request/answer mount: every
/// location resolved further in is resolved against these, and a session whose `path` fact was not
/// the path it was opened at would be a session answered about somewhere else. A declaration is
/// free to name a capture `path`, or `credential`, and a session authenticated against a segment of
/// its own URL instead of against what the caller presented would be a door opened by whoever wrote
/// the mount. Reserved first, first match wins, and a capture that collides is simply never reached.
///
/// The captures come LAST and are the declarer's own names, which is exactly what
/// `busbar_transport_http::mount::published_facts` does with a template's captures. They are the
/// only account a session gets of where it was opened beyond the raw path.
#[must_use]
pub fn published_facts<'a>(
    upgrade: &'a Upgrade<'a>,
    captures: &'a [Capture<'a>],
) -> Vec<(&'a str, &'a str)> {
    let mut facts = Vec::with_capacity(SESSION_FACTS.len() + captures.len());
    facts.push((tfacts::PATH, upgrade.target));
    facts.push((tfacts::PEER, upgrade.peer));
    // Pushed only where the upgrade actually carried one, because an ABSENT fact and an EMPTY one
    // are different statements and the difference is a security one here: a driver reading an empty
    // credential is being told one was presented and is blank, and a caller that presented none did
    // not present a blank one. An anonymous caller has to stay representable.
    if let Some(credential) = upgrade.credential {
        facts.push((tfacts::CREDENTIAL, credential));
    }
    for c in captures {
        facts.push((c.name, c.value));
    }
    facts
}

// ── opening, on the far side of the seam ────────────────────────────────────────────────────────

/// Hand one addressed upgrade to the driver, and take back the session's handle.
///
/// Called BEFORE the protocol changes, which is what makes the refusal answerable: an `Err` here is
/// one of the eight words, and the caller spells it as a status on the leg underneath and never
/// upgrades at all. Once [`pump`] is running there is no such answer left.
///
/// # Errors
///
/// The driver will not open a session for this upgrade.
pub fn open_session<'a>(
    driver: &dyn SessionDriver,
    surface: &WireSurface,
    mount: &'a Mount<'a>,
    upgrade: &'a Upgrade<'a>,
) -> Result<SessionHandle, Outcome> {
    let facts = published_facts(upgrade, &mount.captures);
    driver.open(
        SessionOpen {
            facts: &facts,
            transport: mount.key,
            chain: mount.chain,
            binding: mount.binding.name,
            bar: mount.bar,
        },
        surface,
    )
}

// ── the frames, in both directions ──────────────────────────────────────────────────────────────

/// Where the inbound frames of one open session come from.
///
/// A trait rather than the concrete socket, because [`pump`] is the part of this that has rules in
/// it — ordering, backpressure, whose cut it was — and rules that can only be exercised through a
/// real socket are rules that get tested for the happy path and reasoned about for the rest.
///
/// `None` is an ORDERLY end: the peer closed, or its stream finished. An `Err` is the other kind,
/// and the two are answered differently — one gets a courtesy close frame back and the other does
/// not, because there is nothing left to write to.
pub trait FrameSource {
    /// The next inbound frame, the orderly end of the stream, or the failure that ended it.
    fn next_frame(
        &mut self,
    ) -> impl std::future::Future<Output = Option<Result<Vec<u8>, TransportError>>> + Send;
}

/// Where the outbound frames of one open session go.
///
/// `write_frame` carries the media type the DECLARATION named beside the bytes, because a wire whose
/// frames come in kinds has to choose one and the declaration is the only thing entitled to say
/// which. A wire with one kind ignores it.
pub trait FrameSink {
    /// Write one frame, or report why it could not be written.
    fn write_frame(
        &mut self,
        frame: &[u8],
        media: &str,
    ) -> impl std::future::Future<Output = Result<(), TransportError>> + Send;

    /// Write the close, best effort. Nothing follows it and nothing reads its result: the session is
    /// over either way, and a close that could fail the ending would let a peer that stopped reading
    /// decide how this node records what happened.
    fn write_close(&mut self, code: u16) -> impl std::future::Future<Output = ()> + Send;
}

/// This wire's own close code for one reason.
///
/// Eight words in, one number out. The mapping is the same for every plane because it is a statement
/// about what happened to the SESSION rather than about what the session was carrying, and a plane
/// that wants a finer word than these writes it into a frame before the close — which the plane
/// wrote and this module does not read.
#[must_use]
pub fn close_code(reason: CloseReason) -> u16 {
    match reason {
        // An orderly close is orderly from either end. A peer that closed first gets the same 1000
        // it sent: the exchange finished, and nothing about it was anybody's fault.
        CloseReason::Normal | CloseReason::PeerClosed => 1000,
        // 1001 is literally "going away", which is what draining is.
        CloseReason::Drain => 1001,
        // 1011 is the node saying the fault was its own. A deadline this node was waiting on, codec
        // state a panic poisoned, and a carrier that failed under us are all that: none of the three
        // is something the caller did, and a code from the 1008 family would tell a well-behaved
        // client to go and change its behaviour.
        CloseReason::Timeout | CloseReason::Poisoned | CloseReason::TransportFailed => 1011,
        // 1008 is the policy family, and a withdrawn authority is exactly a policy answer.
        CloseReason::Revoked => 1008,
        // 1013 is "try again later", which is what a money reason means: nothing is wrong with the
        // caller or the request, and the same session opened later may well run.
        CloseReason::CapacityExhausted => 1013,
    }
}

/// The close reason one carrier failure spells.
///
/// Deliberately narrow. Only two of the transport failures say anything about the SESSION that a
/// close vocabulary has a word for; the rest are this node's carrier giving out, which is
/// [`CloseReason::TransportFailed`] whatever the shape of the giving out.
#[must_use]
pub fn reason_for(error: TransportError) -> CloseReason {
    match error {
        TransportError::Timeout => CloseReason::Timeout,
        TransportError::Closed => CloseReason::PeerClosed,
        _ => CloseReason::TransportFailed,
    }
}

/// The bounds one mounted session runs under, spelled ONCE and not here.
///
/// It used to be declared in this module, and that was a wire owning a number that is not a wire's:
/// how long a session may run is the COMPOSITION's answer, the same for every wire a node serves,
/// and a copy per wire is a set of ceilings that drift apart with nothing to notice. It lives beside
/// the face this transport implements now, and is re-exported here because this module's header is
/// where what it does and does not bound is written down.
pub use busbar_contract_transport::session::SessionBudgets;

/// DIAL THE UPSTREAM LEG OF ONE SESSION, and hand back the three pieces of it that are owned in
/// three different places.
///
/// ## Why three values and not a handle
///
/// A relayed session has three parts and each has a different owner, so a call that returned one
/// object would be a call that decided all three:
///
/// * the INBOUND half is read in a loop, by whatever is pumping the leg — a [`FrameSource`], the
///   same face this module's own pump reads a client through;
/// * the OFFERING half is reached from [`busbar_contract_transport::session::SessionDriver::drive`],
///   which is synchronous, so it is an
///   [`busbar_contract_transport::session::EgressLease`] and not a socket;
/// * the DRAIN is a future, and it is RETURNED rather than spawned. A transport that spawned it
///   would be choosing the composition's runtime and deciding when the task is cancelled; the root
///   spawns it beside the session that owns it and drops it with that session.
///
/// ## What this adds over `Transport::dial`, and what it deliberately does not
///
/// Nothing about WHERE the leg goes. The destination is already sealed and already narrowed by the
/// trust unit's resolve-then-pin guard, and the `wss://`-over-cleartext refusal is the dial's own,
/// made before a socket is opened — this call reaches it through the same
/// [`busbar_contract::Transport::dial`] every other caller does, so there is no second dialling path
/// to keep honest. What it adds is only the OWNERSHIP move: the socket leaves the connection
/// registry whole, which is what makes the session its single owner.
///
/// `media` is the declaration's, for the reason this module's [`FrameSink`] takes one: this wire has
/// two frame kinds and the declaration is the only thing entitled to choose which carries a plane's
/// bytes. `depth` is the composition's, spelled beside the session budget it belongs with.
///
/// # Errors
///
/// The dial itself was refused or failed, or the socket could not be taken whole out of the
/// connection it arrived as. Both are [`busbar_contract_transport::wire::TransportError`] and
/// neither leaves a leg half-open: on either, nothing has been handed back to own.
#[cfg(feature = "serve-sessions")]
pub async fn dial_session(
    transport: &crate::WsTransport,
    dest: &busbar_contract::dest::VerifiedDestination,
    keys: &busbar_contract::TransportKeyHandle,
    media: &str,
    depth: usize,
) -> Result<
    (
        impl FrameSource + Send,
        Box<dyn busbar_contract_transport::session::EgressLease>,
        impl std::future::Future<Output = ()> + Send,
    ),
    TransportError,
> {
    use busbar_contract::Transport as _;

    let conn = transport.dial(dest, keys).await?;
    // Whole, and out of the registry in the same breath. A socket left reachable by `Conn` while a
    // session held its two halves would be two unsynchronised writers on one WebSocket, which is a
    // protocol error rather than a race that resolves itself.
    let sock = transport
        .take_sock(&conn)
        .ok_or(TransportError::HandoffMismatch)?;
    let (source, sink) = crate::session_io::split(sock);
    let (lease, drain) = crate::session_io::lease(depth, sink, media);
    Ok((source, Box::new(lease), drain))
}

/// RUN ONE OPEN SESSION to its end, and report which end cut it.
///
/// One frame at a time, in order, with no queue in either direction — see this module's own header
/// for why the absence of the queue is the backpressure posture rather than a missing feature.
///
/// [`SessionDriver::close`] is called exactly once, on every ending: the peer's orderly close, a
/// carrier that failed under the read, a sink that would not take a frame, the whole-session deadline
/// running out, and the driver's own decision to end it. A pump that skipped it on the ugly endings
/// would leak precisely the sessions that failed.
pub async fn pump<Src, Snk>(
    driver: &dyn SessionDriver,
    session: SessionHandle,
    mut source: Src,
    mut sink: Snk,
    budgets: SessionBudgets,
) -> SessionEnd
where
    Src: FrameSource,
    Snk: FrameSink,
{
    let end = run(driver, session, &mut source, &mut sink, budgets).await;
    driver.close(session, end);
    end
}

/// The deadline, wrapped around the whole exchange rather than around one read.
///
/// Around the WHOLE of it, because the budget is a statement about the session and a peer can spend
/// it in either direction: one that sends a frame a second forever and one that sends nothing at all
/// have both been on this node for the same length of time. A timeout on the read alone would bound
/// only the second, and would let the first run for as long as it kept talking.
///
/// The expiry drops the exchange and then writes the close on the sink the exchange was using, which
/// is why the future is bound to a local first: a future left as a match scrutinee lives to the end
/// of the match, and the borrow it holds on the sink with it.
async fn run<Src, Snk>(
    driver: &dyn SessionDriver,
    session: SessionHandle,
    source: &mut Src,
    sink: &mut Snk,
    budgets: SessionBudgets,
) -> SessionEnd
where
    Src: FrameSource,
    Snk: FrameSink,
{
    let Some(deadline) = budgets.deadline else {
        return frames(driver, session, source, sink).await;
    };
    let bounded = tokio::time::timeout(deadline, frames(driver, session, source, sink)).await;
    match bounded {
        Ok(end) => end,
        Err(_) => {
            // This side's cut, and this side's fault in the only sense a close code can say: the
            // deadline was this node's, the caller never agreed to it, and nothing the caller did
            // was wrong. The courtesy close still goes out — the peer is there, by definition, or
            // the read would have ended instead.
            sink.write_close(close_code(CloseReason::Timeout)).await;
            SessionEnd {
                cut: Cut::Upstream,
                reason: CloseReason::Timeout,
            }
        }
    }
}

/// The loop itself, split out so that [`pump`] has exactly one exit and the `close` call cannot be
/// forgotten on one of the four ways out.
async fn frames<Src, Snk>(
    driver: &dyn SessionDriver,
    session: SessionHandle,
    source: &mut Src,
    sink: &mut Snk,
) -> SessionEnd
where
    Src: FrameSource,
    Snk: FrameSink,
{
    let mut seq: u64 = 0;
    loop {
        let payload = match source.next_frame().await {
            // The peer went first, orderly. It is owed the courtesy close its own protocol defines,
            // and the write is best effort: a peer that has already gone will not read it.
            None => {
                sink.write_close(close_code(CloseReason::PeerClosed)).await;
                return SessionEnd {
                    cut: Cut::Client,
                    reason: CloseReason::PeerClosed,
                };
            }
            // The peer's end failed rather than ended. Still the client's cut — this node was
            // willing to carry on — and no close frame, because there is nothing there to read one.
            Some(Err(error)) => {
                return SessionEnd {
                    cut: Cut::Client,
                    reason: reason_for(error),
                }
            }
            Some(Ok(payload)) => payload,
        };
        let reply = driver.drive(
            session,
            SessionFrame {
                payload: &payload,
                seq,
            },
        );
        seq += 1;
        for frame in &reply.frames {
            if let Err(error) = sink.write_frame(frame, &reply.media).await {
                // This side could not go on, so this side is the one that cut — even though the
                // proximate cause is usually a peer that stopped reading. The distinction the cut
                // records is which END stopped serving, and this one did.
                return SessionEnd {
                    cut: Cut::Upstream,
                    reason: reason_for(error),
                };
            }
        }
        if let Some(reason) = reply.close {
            sink.write_close(close_code(reason)).await;
            return SessionEnd {
                cut: Cut::Upstream,
                reason,
            };
        }
    }
}

#[cfg(test)]
#[path = "tests/mount.rs"]
mod tests;
