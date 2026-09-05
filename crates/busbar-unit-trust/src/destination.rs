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

/// What a destination IS, as the contract crate declares it.
///
/// A plane writes these facts, so they are the plane's own words and this unit reads what it was
/// handed. The arms carried no payload here until now, flagged as thin on purpose against the
/// contract's fuller shape; that shape has landed, so the thin copy is gone and the wire detail
/// each kind needs travels with the kind that needs it.
pub use busbar_contract::DestinationFacts;

/// One candidate destination as the plane proposed it, before the trust unit judged it.
///
/// The facts are the plane's; the lane index is this unit's own, because it is a position in the
/// lane table the walk orders and nothing outside this unit has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What the plane said it is.
    pub facts: DestinationFacts,
    /// The lane's position in the lane table, when it has one.
    pub lane_index: Option<usize>,
}

impl Candidate {
    /// The lane this candidate is priced on, where its kind has one.
    #[must_use]
    pub fn lane(&self) -> Option<busbar_caps::LaneId> {
        self.facts.lane()
    }
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
pub fn kind_permitted(origin: OriginKind, kind: &DestinationFacts) -> bool {
    use DestinationFacts as D;
    match origin {
        OriginKind::Client => !matches!(kind, D::Peer { .. } | D::SessionAccrual { .. }),
        OriginKind::Provider => {
            matches!(
                kind,
                D::Client { .. }
                    | D::SessionUpstream { .. }
                    | D::NestedPlane { .. }
                    | D::PlaneRecord { .. }
            )
        }
        OriginKind::Arrival => false,
        OriginKind::Bootstrap => matches!(kind, D::KernelVerb { .. }),
        OriginKind::Handshake => matches!(kind, D::Upgrade { .. } | D::Client { .. }),
        OriginKind::Tick => matches!(kind, D::SessionAccrual { .. }),
        OriginKind::Nested => matches!(
            kind,
            D::Upstream { .. }
                | D::SessionUpstream { .. }
                | D::NestedPlane { .. }
                | D::PlaneRecord { .. }
                | D::Client { .. }
        ),
        OriginKind::Delivery => {
            matches!(kind, D::Client { .. } | D::Peer { .. } | D::Upstream { .. })
        }
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
    match dest {
        DestinationFacts::Upstream { lane, .. } => {
            facts.allow_listed(dest)
                && facts.transport_key_resolves(dest)
                && facts.lane_permitted_for_op_class(lane.as_str())
        }
        DestinationFacts::SessionUpstream { .. } => {
            facts.session_upstream_ok() && facts.session_principal_matches()
        }
        DestinationFacts::Client { .. } => facts.client_selector_ok() && facts.await_deadline_ok(),
        DestinationFacts::KernelVerb { .. } => facts.verb_scope_held(),
        DestinationFacts::NestedPlane { .. } => facts.nested_plane_ok(),
        DestinationFacts::PlaneRecord { .. } => facts.plane_record_ok(),
        DestinationFacts::Peer { .. } => facts.peer_lease_live(),
        DestinationFacts::Upgrade { .. } => facts.upgrade_ok(),
        // A session accrual is the passage of time on a lane already paired at session open; there
        // is nothing further to verify about it.
        DestinationFacts::SessionAccrual { .. } => true,
    }
}
