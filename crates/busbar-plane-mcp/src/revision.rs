// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REVISIONS OF THE ONE MCP DIALECT, and how two peers agree on one.
//!
//! MCP is one dialect with dated revisions. This plane speaks four of them, and a revision is not a
//! plugin: it is a set of rules inside the dialect about how a conversation is opened and carried.
//!
//! | revision     | opened by                       | sessions | version header | carried as |
//! |--------------|---------------------------------|----------|----------------|------------|
//! | `2026-07-28` | nothing: every request is whole | none     | required       | one endpoint, POST only |
//! | `2025-11-25` | `initialize`                    | yes      | required       | one endpoint, POST + GET stream + DELETE |
//! | `2025-06-18` | `initialize`                    | yes      | required       | one endpoint, POST + GET stream + DELETE |
//! | `2024-11-05` | `initialize`                    | yes      | none           | an event stream that names a message address |
//!
//! `2025-03-26` is not implemented: it is the only revision that allows batched bodies, and a
//! client that asks for it is offered `2025-06-18` in the `initialize` answer, which the spec's
//! negotiation rule permits (the client disconnects if it cannot speak what it is offered).
//!
//! OWNER RULING 2026-09-29: 1.6.0 interoperates with all four, in both directions. The revision
//! negotiation below is the spec's own: the client names the revision it wants in `initialize`; a
//! server that implements it answers with it, and otherwise answers with the latest revision it does
//! implement. A client with a stateless probe that is refused falls back to `initialize`, and a
//! client whose `initialize` POST is refused with a 4xx falls back to the event-stream revision.

/// One revision of the MCP dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revision {
    /// The event-stream revision: a GET opens a stream whose first event names the address
    /// messages are POSTed to, and every answer arrives on that stream.
    R2024_11_05,
    /// The first session revision with the `MCP-Protocol-Version` request header.
    R2025_06_18,
    /// The latest session revision.
    R2025_11_25,
    /// The stateless revision: no handshake, no session, every request self-describing.
    R2026_07_28,
}

/// The revisions answered with a session, latest first. The order is the negotiation order.
pub const SESSION_REVISIONS: &[Revision] = &[
    Revision::R2025_11_25,
    Revision::R2025_06_18,
    Revision::R2024_11_05,
];

/// Every implemented revision, latest first.
pub const ALL: &[Revision] = &[
    Revision::R2026_07_28,
    Revision::R2025_11_25,
    Revision::R2025_06_18,
    Revision::R2024_11_05,
];

/// The revision a session request is read as when it carries no version header and no session
/// names one: the spec's stated default for a server that cannot otherwise tell.
pub const HEADERLESS_DEFAULT: &str = "2025-03-26";

impl Revision {
    /// The revision's wire string.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::R2024_11_05 => "2024-11-05",
            Self::R2025_06_18 => "2025-06-18",
            Self::R2025_11_25 => "2025-11-25",
            Self::R2026_07_28 => crate::codec::PROTOCOL_VERSION,
        }
    }

    /// Reads a wire string. `None` for a revision this plane does not implement.
    #[must_use]
    pub fn parse(wire: &str) -> Option<Self> {
        ALL.iter().copied().find(|r| r.wire() == wire)
    }

    /// Whether a conversation in this revision is opened by `initialize` and lives in a session.
    #[must_use]
    pub const fn has_sessions(self) -> bool {
        !matches!(self, Self::R2026_07_28)
    }

    /// Whether every request after `initialize` must carry the `MCP-Protocol-Version` header.
    #[must_use]
    pub const fn requires_version_header(self) -> bool {
        matches!(
            self,
            Self::R2025_06_18 | Self::R2025_11_25 | Self::R2026_07_28
        )
    }

    /// Whether this revision is carried as an event stream naming a message address, rather than
    /// on the single endpoint.
    #[must_use]
    pub const fn is_event_stream_revision(self) -> bool {
        matches!(self, Self::R2024_11_05)
    }

    /// Whether a disconnected server stream may be resumed with `Last-Event-ID`.
    #[must_use]
    pub const fn resumable(self) -> bool {
        matches!(self, Self::R2025_06_18 | Self::R2025_11_25)
    }
}

/// THE SERVER HALF OF `initialize` NEGOTIATION. The client's requested revision is echoed when it is
/// a session revision this plane implements; anything else, including an unknown string and the
/// stateless revision (which has no `initialize`), is answered with the latest session revision.
#[must_use]
pub fn negotiate(requested: Option<&str>) -> Revision {
    requested
        .and_then(Revision::parse)
        .filter(|r| r.has_sessions())
        .unwrap_or(SESSION_REVISIONS[0])
}

/// How a session request's `MCP-Protocol-Version` header reads against the session's revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderCheck {
    /// The header agrees with the session, or is absent where the session's revision allows that.
    Agrees,
    /// The header is absent on a revision that requires it.
    Missing,
    /// The header names a revision other than the session's (400 per the spec).
    Disagrees,
}

/// Judges a session request's version header. A session knows its revision, so an absent header is
/// only a defect on a revision that requires it.
#[must_use]
pub fn check_header(session: Revision, header: Option<&str>) -> HeaderCheck {
    match header {
        Some(h) if h == session.wire() => HeaderCheck::Agrees,
        Some(_) => HeaderCheck::Disagrees,
        None if session.requires_version_header() => HeaderCheck::Missing,
        None => HeaderCheck::Agrees,
    }
}

/// THE CLIENT LADDER: the order in which busbar, as a client, tries to open a conversation with an
/// upstream whose revision it does not yet know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientStep {
    /// A stateless `2026-07-28` request.
    Stateless,
    /// A POSTed `initialize` naming the latest session revision.
    Initialize,
    /// A GET for the `2024-11-05` event stream and its message address.
    EventStream,
}

/// What one rung of the ladder observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// The upstream answered in the rung's revision.
    Answered,
    /// A status in 400..500, or a JSON-RPC refusal that says the revision or method is not
    /// implemented (`-32601`, `-32600`, `-32602`, the unsupported-version code). The spec's
    /// fallback is not keyed to one code, and neither is this.
    Refused4xx,
    /// No answer at all: the upstream could not be reached, or answered 5xx. Not a revision
    /// signal, so the ladder does not move.
    Unreachable,
}

/// The next rung after `step` observed `outcome`. `None` means stop: either the rung answered, or
/// there is nothing left to try, or the failure says nothing about the revision.
#[must_use]
pub fn next_step(step: ClientStep, outcome: StepOutcome) -> Option<ClientStep> {
    match (step, outcome) {
        (_, StepOutcome::Answered | StepOutcome::Unreachable) => None,
        (ClientStep::Stateless, StepOutcome::Refused4xx) => Some(ClientStep::Initialize),
        (ClientStep::Initialize, StepOutcome::Refused4xx) => Some(ClientStep::EventStream),
        (ClientStep::EventStream, StepOutcome::Refused4xx) => None,
    }
}

/// THE CLIENT HALF OF `initialize` NEGOTIATION: the revision the server answered with, if this plane
/// can speak it on a session. A server answering a revision this plane does not implement is a
/// server the client must disconnect from, per the spec.
#[must_use]
pub fn accept_offered(offered: &str) -> Option<Revision> {
    Revision::parse(offered).filter(|r| r.has_sessions())
}

#[cfg(test)]
#[path = "tests/revision_tests.rs"]
mod tests;
