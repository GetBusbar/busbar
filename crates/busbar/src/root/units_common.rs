// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The step bodies that are the SAME on every plane, written once.
//!
//! A composition root mounts several planes on ONE loop, and some of what each mounting needs is
//! not about the plane at all: reading a frame through whatever ingress decoder the plane brought,
//! taking a per-unit lock, naming the step a refusal was raised at, reporting what the encode step
//! wrote. Those bodies are identical word for word across the planes that are mounted, and a body
//! that is identical in two files is two bodies with one of them free to drift. So they live here,
//! once, and each plane's file hands over to them.
//!
//! Nothing in this file names a plane. That is the test of whether a body belongs here: if it has
//! to ask which protocol it is serving, it belongs in that protocol's own mounting and not in this
//! one. What is here asks only about the KERNEL's vocabulary and the CONTRACT's — the loop's ten
//! step names, the closed reason vocabulary, the frame, the arena — and is therefore as true of a
//! plane that lands next year as of the ones mounted today.

use busbar_caps::ReasonCode;
use busbar_contract::ids::OpClassId;
use busbar_contract::plane::Plane;

/// A lock a plane's mounting holds, taken the way the root takes its locks.
///
/// A poisoned lock is read through rather than refused. The panic that poisoned it happened
/// somewhere else, and what is behind it is written once per field and then read — so a reader
/// after a panic sees a prefix of the truth rather than a corrupted one. The alternative is a node
/// whose audit chain stops sealing, and whose exit path stops settling, because one unrelated unit
/// panicked once: a poisoned node-global lock would take every later request with it, which is a
/// far larger failure than the one that poisoned it.
pub fn read_through_poison<T>(lock: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|p| p.into_inner())
}

/// What a plane made of one inbound frame.
///
/// Three answers rather than two, because "not a unit" is not one thing. A notice nothing
/// recognises is dropped and a partial frame is waited on, and neither is a refusal: a protocol
/// that forbids answering a message carrying no identifier would have a refusal sent to a caller
/// who is owed silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read<'u> {
    /// A draft the loop runs. Boxed because the fact map is a fixed array sized for the declared
    /// key ceiling, and an enum whose other arms are empty should not be that wide everywhere.
    Unit(Box<Decoded<'u>>),
    /// A notice this node does not recognise. Counted, never answered.
    Dropped,
    /// Not a whole frame yet.
    NeedMore,
}

/// What a plane's read of one request body yielded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded<'u> {
    /// The operation class the plane's own method table named.
    pub op: OpClassId,
    /// Whether the unit holds its direction open rather than being answered once.
    pub streaming: bool,
    /// The facts the plane read off the bytes.
    pub facts: busbar_contract::bounded::Facts<'u>,
}

/// Read one inbound frame through THE PLANE'S OWN ingress decoder.
///
/// The root does not parse any of these protocols and must not: the envelope shape, the method
/// table and the pointer table are all the plane's, and a second reading here would be a second
/// grammar. What the root owns is the mapping from the plane's decode failure onto the loop's
/// closed reason vocabulary, which is the thing the journal and the refusal both name — and that
/// mapping is about the LOOP rather than about the protocol, which is why one copy serves every
/// plane that is mounted.
///
/// # Errors
/// Returns the reason a refusal at the decode step carries when the plane could not read the bytes.
pub fn read_ingress<'u, P: Plane>(
    plane: &P,
    frames: &mut busbar_contract::wire::FrameCursor<'u>,
    ctx: &busbar_contract::unit::Ctx<'u>,
) -> Result<Read<'u>, ReasonCode> {
    let ingress = plane
        .decode_ingress(frames, None, ctx)
        .map_err(|failure| match failure {
            // The arena running out is a budget, not a misread body, and the two carry different
            // reasons because a caller who is over a bound and a caller who sent nonsense are owed
            // different answers.
            busbar_contract::wire::Decode::Oversize => ReasonCode::ArenaBudget,
            _ => ReasonCode::DecodeFailed,
        })?;
    Ok(match ingress {
        busbar_contract::plane::Ingress::OneShot(draft) => Read::Unit(Box::new(Decoded {
            op: draft.op,
            streaming: false,
            facts: draft.facts,
        })),
        busbar_contract::plane::Ingress::Open(draft) => Read::Unit(Box::new(Decoded {
            op: draft.op,
            streaming: true,
            facts: draft.facts,
        })),
        busbar_contract::plane::Ingress::Discard { .. } => Read::Dropped,
        busbar_contract::plane::Ingress::NeedMore => Read::NeedMore,
        // Neither of the planes mounted here opens a handshake unit or closes a session of its own
        // on the ingress path — every claim they make carries its credential on the first frame. A
        // decoder that started answering either would be a plane whose shape changed, and carrying
        // such a frame on as a unit would give it a class nobody decoded.
        _ => return Err(ReasonCode::DecodeFailed),
    })
}

/// **The bytes the caller is owed, from the ending the loop sealed.**
///
/// The loop decides how a unit ended and the PLANE renders it — that is the split, and this is the
/// hinge. What the root owns is the join between the kernel's own closed vocabulary and the
/// contract's spelling of it, so that a refusal a caller reads is the refusal the loop raised
/// rather than an envelope a mounting wrote out by hand. The reason side of the join already exists
/// as one `From` in the capability crate, walked by that crate's own tests; the step side is
/// [`refusal_step`], written totally, so a step added to the loop does not compile until a caller
/// can be told which one it was.
///
/// `None` is a unit that SETTLED. A settled unit's bytes are its answer, which the plane writes
/// from the unit's own arena, and rendering a refusal for one would be inventing an error nothing
/// raised.
#[must_use]
pub fn refusal_of(
    ended: &busbar_kernel::teller::Ended,
) -> Option<busbar_contract::unit::Refusal<'static>> {
    let (step, reason) = match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => match end.outcome() {
            busbar_caps::Outcome::Refused(step, reason) => (step, reason),
            // Every other ending either delivered an answer or lost the unit before one could be
            // written, and neither is a refusal a caller is owed an envelope for.
            _ => return None,
        },
        // The node's own sweep took the hold first, so this unit will not produce an answer at all.
        busbar_kernel::teller::Ended::AlreadySettled => return None,
    };
    Some(busbar_contract::unit::Refusal {
        step: refusal_step(step),
        reason: reason.into(),
        retry_after_secs: None,
        stream: None,
        correlates: None,
    })
}

/// The contract's spelling of the step a refusal was raised at.
///
/// Two crates name the same ten steps and neither depends on the other, so the mapping is written
/// once, here, where both are in scope. Totality is what makes it safe: an eleventh step would not
/// compile.
#[must_use]
pub fn refusal_step(step: busbar_caps::StepName) -> busbar_contract::unit::Step {
    use busbar_caps::StepName;
    match step {
        StepName::Arrival => busbar_contract::unit::Step::Arrival,
        StepName::Decode => busbar_contract::unit::Step::Decode,
        StepName::Authenticate => busbar_contract::unit::Step::Authenticate,
        StepName::Verify => busbar_contract::unit::Step::Verify,
        StepName::Approve => busbar_contract::unit::Step::Approve,
        StepName::Admit => busbar_contract::unit::Step::Admit,
        StepName::Route => busbar_contract::unit::Step::Route,
        StepName::Meter => busbar_contract::unit::Step::Meter,
        StepName::Audit => busbar_contract::unit::Step::Audit,
        StepName::Encode => busbar_contract::unit::Step::Encode,
    }
}

/// What the encode step REPORTS, for a mounting whose bytes were written where the borrow lives.
///
/// The planes' encoders take the unit's arena, and the step's signature carries neither an arena
/// nor the plane's draft — so the bytes go out where the borrow is (see [`refusal_of`], which is
/// how the root hands the loop's ending back to the plane to render) and this step reports what
/// left. A root that allocated a second buffer here would be writing the wire format twice.
#[must_use]
pub fn encoded_frame(bytes: u64) -> busbar_contract::wire::Frame {
    busbar_contract::wire::Frame {
        direction: busbar_contract::wire::Direction::Outbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: busbar_contract::bounded::SlabBytes::new(std::sync::Arc::from(&[][..])),
        meta: busbar_contract::wire::FrameMeta {
            bytes,
            transport_units: None,
            status: None,
            status_code: None,
            retry_after_secs: None,
        },
    }
}
