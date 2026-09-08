// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM A TRANSPORT HANDS AN ARRIVAL ACROSS, and the closed vocabulary it gets back.
//!
//! ## Why this exists, and what it is refusing
//!
//! A transport that serves a plane's declared surface has to get what arrived to something that
//! will run it. The obvious way to write that is for the transport to run it — build the context,
//! call the loop, read the ending — and it is the wrong way, because the tree's rule runs the other
//! direction: **core drives plugins, and a plugin never names core.** A transport that called the
//! loop would name the kernel, the capability types and the ending vocabulary, and the axis that is
//! meant to know only bytes would be holding the machinery that knows what a unit costs.
//!
//! So the transport hands the arrival OVER. [`UnitDriver`] is what it hands it to, the composition
//! root is what implements it, and the root gives one to a transport at listen — the same shape and
//! the same moment as the transport key handle, which is the other thing a transport is given rather
//! than allowed to obtain.
//!
//! ## What is deliberately on the driver's side of it
//!
//! The per-unit arena, the context, the plane call, the loop, the ending and the ledger. All of it.
//! A transport does not allocate a plane's scratch space, does not build a context, does not know
//! which plane answered and does not learn how a unit settled. What comes back is [`Answer`]: the
//! bytes the plane wrote, the media type the declaration named, whether the answer is one document
//! or a run of them, and one word from a CLOSED list for what happened.
//!
//! ## Why the outcome is a closed list and not the kernel's own
//!
//! Because a transport does something with it: it picks the status its own wire spells. That is a
//! real decision and it needs a real input, so the input cannot be "nothing" — but it must not be
//! the loop's ending either, which carries the step, the reason code and the posting, none of which
//! a wire has a field for. [`Outcome`] is the intersection: eight words, each of which every wire
//! this tree carries has a way to say. A protocol that wants finer than eight puts it in the body,
//! which is the plane's to write.

use core::fmt;

/// What one arrival is, on the way across the seam.
///
/// Plain data, all of it borrowed for the length of one call. Nothing here is derived and nothing is
/// a protocol fact: the facts the transport published, the bytes, the composed stack, and what
/// addressing the arrival against the declaration produced.
#[derive(Clone, Copy, Debug)]
pub struct Arrival<'a> {
    /// The facts this transport published for this arrival, in the order it publishes them.
    ///
    /// A list of pairs rather than a map, and ORDERED, because the order is the transport's
    /// statement about precedence: the kernel's reserved keys come first, so a declaration that
    /// happened to name a capture `path` cannot hand a plane something other than the path. A map
    /// would lose that and hand the ambiguity to whoever iterated it.
    pub facts: &'a [(&'a str, &'a str)],
    /// The request body.
    pub body: &'a [u8],
    /// The registry key of the layer this connection ended on.
    pub transport: &'static str,
    /// The composed transport stack, bottom layer first.
    pub chain: &'a [&'static str],
    /// The operation the declaration says this address names, where the ADDRESS names one.
    ///
    /// `None` where the operation is named inside the document instead. That is not missing
    /// information: it is the transport saying it addressed a mount rather than a route, and that
    /// naming the operation is the plane's job, off bytes the transport does not read.
    pub operation: Option<&'a crate::surface::Operation>,
    /// The credential bar the declaration puts on this address.
    pub bar: crate::surface::Bar,
}

impl Arrival<'_> {
    /// The value of one published fact.
    ///
    /// First match wins, which is what makes the ordering above load-bearing rather than cosmetic.
    #[must_use]
    pub fn fact(&self, key: &str) -> Option<&str> {
        self.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// What happened to one unit, in the eight words every wire has a way to say.
///
/// Deliberately not the loop's own ending. That carries the step it stopped at, the reason code and
/// the posting, and no wire has a field for any of the three — a transport handed one would either
/// throw most of it away or leak a kernel word onto a wire. This is the intersection: enough for a
/// transport to choose the status its protocol spells, and nothing a transport has no business
/// knowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Outcome {
    /// The unit ran to the end and the answer is in the body.
    Completed,
    /// The caller was not identified.
    Unauthenticated,
    /// The caller was identified and may not do this.
    Forbidden,
    /// What the caller named does not exist.
    NotFound,
    /// The caller is over a rate or a budget.
    Throttled,
    /// A deadline expired.
    TimedOut,
    /// The unit was ended early.
    Cancelled,
    /// Nothing here can serve this, for a reason that is the node's and not the caller's.
    Unavailable,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// What the driver answered one arrival with.
///
/// The BYTES ARE THE PLANE'S, always — a response it encoded or a refusal it encoded — and never the
/// driver's own prose and never the transport's. What the transport decides from the rest is the
/// frame around them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The plane's own bytes.
    pub body: Vec<u8>,
    /// The media type the declaration names for this operation's answer.
    ///
    /// Empty where the driver could not resolve an operation at all, which is the honest answer:
    /// no declaration named a media type, so the transport puts none on rather than guessing one.
    pub media: String,
    /// Whether the declaration says the answer is a run of documents rather than one.
    pub answering: crate::surface::Answering,
    /// What happened, in the closed vocabulary above.
    pub outcome: Outcome,
}

impl Answer {
    /// An answer carrying no body, for an outcome that produced none.
    ///
    /// Used where a driver refused before any plane could write anything. It is a constructor rather
    /// than a caller building the struct so that "there is nothing to send" is one shape everywhere
    /// instead of several.
    #[must_use]
    pub fn empty(outcome: Outcome) -> Self {
        Self {
            body: Vec::new(),
            media: String::new(),
            answering: crate::surface::Answering::Unary,
            outcome,
        }
    }
}

/// WHAT RUNS A UNIT. Implemented by the composition root, handed to a transport at listen.
///
/// One method, because a transport has one question. Everything the answer takes — the arena, the
/// context, the plane, the loop, the ledger — is on this side of the seam, which is the whole point:
/// the transport axis knows bytes, and the thing that knows what a unit costs is not reachable from
/// it.
///
/// `Send + Sync` because one driver serves every connection a listener accepts, concurrently. It is
/// held by reference for the life of the listener and never cloned per request.
pub trait UnitDriver: Send + Sync {
    /// Run one arrival against a declared surface, and answer with what the plane wrote.
    ///
    /// The surface travels WITH the arrival rather than being held by the driver, because one driver
    /// may serve several: a node mounts more than one protocol on one listener, and a driver that
    /// held one surface would need one driver per protocol and a way for the transport to pick
    /// between them — which is the transport knowing which protocol it is carrying, one indirection
    /// further out.
    ///
    /// Infallible on purpose. Every way a unit can fail to produce an answer is one of the eight
    /// [`Outcome`] words, and a `Result` here would give a transport a second failure channel with
    /// no wire behind it — it would have to invent a status for "the driver itself errored", which
    /// is a thing no protocol defines.
    fn drive(&self, arrival: Arrival<'_>, surface: &crate::surface::WireSurface) -> Answer;
}

/// A driver that refuses everything, for a listener composed before its driver exists.
///
/// Not a convenience and not a stub to be tidied away later: a transport is handed a driver at
/// listen, and a deployment that has mounted a surface it cannot yet run has to answer SOMETHING.
/// Refusing honestly — with the outcome that means "this node cannot serve it", not one that blames
/// the caller — is the only answer that is true. A listener wired to this one serves no bytes of any
/// plane, and the boot log can say so because the type has a name.
#[derive(Clone, Copy, Debug, Default)]
pub struct Detached;

impl UnitDriver for Detached {
    fn drive(&self, _arrival: Arrival<'_>, _surface: &crate::surface::WireSurface) -> Answer {
        Answer::empty(Outcome::Unavailable)
    }
}
