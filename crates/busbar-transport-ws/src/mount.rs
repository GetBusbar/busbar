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
use busbar_contract_transport::surface::{Bar, BindingDecl, WireSurface};
use busbar_contract_transport::wire::{CloseReason, TransportError};
use busbar_transport_http::mount::{document_bar, Unaddressed};

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
}

/// The reserved fact keys a mounted session publishes.
///
/// Exactly the two this transport declares in its own `TRANSPORT_FACTS`, and the test beside this
/// module holds the two lists to each other. A reserved key published but never declared is a value
/// a plane reads that no boot check knows about, which is the failure the reserved-key registry
/// exists to make impossible.
pub const SESSION_FACTS: &[&str] = &[tfacts::PATH, tfacts::PEER];

/// Which declared binding an upgrade was addressed to, and what this transport stands on.
///
/// Built once, before the upgrade, and then carried for the life of the session. It holds no state:
/// everything the session accumulates is behind the [`SessionHandle`], on the driver's side.
#[derive(Clone, Copy, Debug)]
pub struct Mount<'m> {
    /// The declared binding the upgrade named.
    pub binding: &'m BindingDecl,
    /// The credential bar that binding declares.
    pub bar: Bar,
    /// The registry key of this transport.
    pub key: &'static str,
    /// The composed transport stack, bottom layer first.
    pub chain: &'m [&'static str],
}

/// Address one upgrade against a declared surface.
///
/// Two questions, and the second one is the one a mount that only asked the first would get wrong. A
/// target has to be one of a binding's declared mounts — and that binding has to be carried by THIS
/// transport. A surface routinely declares several bindings over several wires at overlapping paths,
/// and a session opened at a path some other wire's binding declared would be a session nobody
/// declared, served with that binding's credential bar.
///
/// # Errors
///
/// No binding of this transport declares a mount at that target.
pub fn address<'s>(
    surface: &'s WireSurface,
    key: &'static str,
    chain: &'s [&'static str],
    upgrade: &Upgrade<'_>,
) -> Result<Mount<'s>, Unaddressed> {
    let path = upgrade
        .target
        .split(['?', '#'])
        .next()
        .unwrap_or(upgrade.target);
    let binding = surface
        .bindings
        .iter()
        .find(|b| b.transport == key && b.mounts.contains(&path))
        .ok_or(Unaddressed)?;
    Ok(Mount {
        binding,
        bar: document_bar(surface, binding.name),
        key,
        chain,
    })
}

/// Build the fact list one session publishes, reserved keys first.
///
/// The ORDER is load-bearing for the reason it is load-bearing on the request/answer mount: every
/// location resolved further in is resolved against these, and a session whose `path` fact was not
/// the path it was opened at would be a session answered about somewhere else.
#[must_use]
pub fn published_facts<'a>(upgrade: &'a Upgrade<'a>) -> Vec<(&'a str, &'a str)> {
    vec![(tfacts::PATH, upgrade.target), (tfacts::PEER, upgrade.peer)]
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
pub fn open_session(
    driver: &dyn SessionDriver,
    surface: &WireSurface,
    mount: &Mount<'_>,
    upgrade: &Upgrade<'_>,
) -> Result<SessionHandle, Outcome> {
    let facts = published_facts(upgrade);
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

/// RUN ONE OPEN SESSION to its end, and report which end cut it.
///
/// One frame at a time, in order, with no queue in either direction — see this module's own header
/// for why the absence of the queue is the backpressure posture rather than a missing feature.
///
/// [`SessionDriver::close`] is called exactly once, on every ending: the peer's orderly close, a
/// carrier that failed under the read, a sink that would not take a frame, and the driver's own
/// decision to end it. A pump that skipped it on the ugly endings would leak precisely the sessions
/// that failed.
pub async fn pump<Src, Snk>(
    driver: &dyn SessionDriver,
    session: SessionHandle,
    mut source: Src,
    mut sink: Snk,
) -> SessionEnd
where
    Src: FrameSource,
    Snk: FrameSink,
{
    let end = run(driver, session, &mut source, &mut sink).await;
    driver.close(session, end);
    end
}

/// The loop itself, split out so that [`pump`] has exactly one exit and the `close` call cannot be
/// forgotten on one of the four ways out.
async fn run<Src, Snk>(
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
