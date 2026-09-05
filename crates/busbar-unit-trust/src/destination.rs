// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a destination can be, which kinds each origin may reach, and the rule each kind is sealed
//! behind.
//!
//! The permitted-kinds table is the interesting part: it is the reason a provider pushing a frame
//! cannot address an administrative verb, and the reason a delivery fan-out cannot bill itself
//! against a session's accrual. Stating it as a table rather than as scattered checks means a new
//! origin has exactly one place to be considered.

/// Where a unit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginKind {
    /// A client's own request.
    Client,
    /// A frame an upstream pushed on an open session.
    Provider,
    /// The transport-level facts of a connection, before any plane is known. An arrival is a
    /// refusal subject and never reaches a destination.
    Arrival,
    /// The node bringing itself up.
    Bootstrap,
    /// A handshake unit, opened to carry a challenge.
    Handshake,
    /// The heartbeat and sweep.
    Tick,
    /// A plane calling another plane.
    Nested,
    /// One recipient of a fan-out.
    Delivery,
}

/// What a destination IS.
///
/// The payload of each arm is deliberately thin: this unit judges destinations, and the wire detail
/// each kind needs belongs to the crate that dials it.
// contract: the fuller shape of each arm lands with the contract crate's `DestinationFacts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationKind {
    /// A pool member dialled fresh.
    Upstream,
    /// The upstream this session already paired with.
    SessionUpstream,
    /// Back to a client on this session.
    Client,
    /// One of the kernel's own verbs.
    KernelVerb,
    /// Another plane, called as a child.
    NestedPlane,
    /// The priced passage of session time.
    SessionAccrual,
    /// A record the calling plane declared a schema for.
    PlaneRecord,
    /// Another node.
    Peer,
    /// An upgrade of the current transport.
    Upgrade,
}

/// One candidate destination as the plane proposed it, before the trust unit judged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationFacts {
    /// What it is.
    pub kind: DestinationKind,
    /// The lane it sits on — the priced axis.
    pub lane: busbar_caps::LaneId,
    /// The lane's position in the lane table, when it has one.
    pub lane_index: Option<usize>,
}

/// Whether an origin may reach a kind at all.
///
/// - A client may reach everything except peers, which are reached only through the session lookup,
///   and session accrual, which only the heartbeat raises.
/// - A provider push may only answer on the session it arrived on, call a child plane, or write a
///   record. It can never address a verb.
/// - An arrival reaches nothing; a bootstrap reaches only its own verb.
/// - A handshake reaches only an upgrade or a delivery to the client it is challenging.
/// - The heartbeat reaches nothing but a session accrual.
/// - A nested call may go one level further down but never sideways into a verb.
/// - A delivery may deliver, hop to a peer, or dial an upstream — a scatter to many upstreams is
///   many delivery children, each with its own reservation, which is why the per-unit leg bound
///   never limits a fan-out.
pub fn kind_permitted(origin: OriginKind, kind: &DestinationKind) -> bool {
    use DestinationKind::*;
    match origin {
        OriginKind::Client => !matches!(kind, Peer | SessionAccrual),
        OriginKind::Provider => {
            matches!(kind, Client | SessionUpstream | NestedPlane | PlaneRecord)
        }
        OriginKind::Arrival => false,
        OriginKind::Bootstrap => matches!(kind, KernelVerb),
        OriginKind::Handshake => matches!(kind, Upgrade | Client),
        OriginKind::Tick => matches!(kind, SessionAccrual),
        OriginKind::Nested => matches!(
            kind,
            Upstream | SessionUpstream | NestedPlane | PlaneRecord | Client
        ),
        OriginKind::Delivery => matches!(kind, Client | Peer | Upstream),
    }
}

/// Everything the per-kind rules need to consult, as one borrowed view.
///
/// A trait rather than a struct of data because the answers live in tables this unit must not own:
/// the allow-list, the transport-key registry, the session's pairing, the nesting depth, the
/// declared schemas, the lease table and the upgrade set.
pub trait KindFacts {
    /// Whether this destination is on the deployment's allow-list.
    fn allow_listed(&self, dest: &DestinationFacts) -> bool;
    /// Whether the transport key for this destination resolves.
    fn transport_key_resolves(&self, dest: &DestinationFacts) -> bool;
    /// Whether the lane is permitted for the draft's operation class. The located name may be a
    /// pool, in which case it expands to its member lanes.
    fn lane_permitted_for_op_class(&self, lane: &str) -> bool;
    /// Whether the session's paired upstream exists and the stream is in range.
    fn session_upstream_ok(&self) -> bool;
    /// Whether the session's principal is this unit's.
    fn session_principal_matches(&self) -> bool;
    /// Whether a client selector resolves within the session, and the recipient's policy admits
    /// delivery from the sender.
    fn client_selector_ok(&self) -> bool;
    /// Whether an awaited reply's deadline is within the turn's maximum duration.
    fn await_deadline_ok(&self) -> bool;
    /// Whether the principal holds the verb's administrative scope. Always asked — the open posture
    /// answers yes for the anonymous principal rather than skipping the question.
    fn verb_scope_held(&self) -> bool;
    /// Whether the child plane is registered and the nesting depth is still under its maximum, and
    /// the operation class is permitted for this principal.
    fn nested_plane_ok(&self) -> bool;
    /// Whether the schema is declared by the calling plane, the operation is within its declared
    /// operations, and the size is within the cap.
    fn plane_record_ok(&self) -> bool;
    /// Whether the node holds a live lease at the current epoch. Never taken from a claim.
    fn peer_lease_live(&self) -> bool;
    /// Whether the upgrade target is one the current top transport declares, with at most one
    /// upgrade in flight on this connection.
    fn upgrade_ok(&self) -> bool;
}

/// Judge one destination against its kind's rule.
///
/// The rules read as they are written in the design, one arm per kind. Two of them are worth
/// pointing at: the administrative verb's scope check ALWAYS runs, and a read-only verb is pinned at
/// zero price and is never refused for a budget or a breaker — an operator locked out of the
/// read-only surface because a budget ran dry cannot diagnose why the budget ran dry.
pub fn kind_rule_passes(dest: &DestinationFacts, facts: &dyn KindFacts) -> bool {
    match dest.kind {
        DestinationKind::Upstream => {
            facts.allow_listed(dest)
                && facts.transport_key_resolves(dest)
                && facts.lane_permitted_for_op_class(dest.lane.as_str())
        }
        DestinationKind::SessionUpstream => {
            facts.session_upstream_ok() && facts.session_principal_matches()
        }
        DestinationKind::Client => facts.client_selector_ok() && facts.await_deadline_ok(),
        DestinationKind::KernelVerb => facts.verb_scope_held(),
        DestinationKind::NestedPlane => facts.nested_plane_ok(),
        DestinationKind::PlaneRecord => facts.plane_record_ok(),
        DestinationKind::Peer => facts.peer_lease_live(),
        DestinationKind::Upgrade => facts.upgrade_ok(),
        // A session accrual is the passage of time on a lane already paired at session open; there
        // is nothing further to verify about it.
        DestinationKind::SessionAccrual => true,
    }
}
