// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE POOL VIEW AND THE KIND FACTS, WRITTEN ONCE FOR EVERY PLANE THAT REGISTERS PEERS.
//!
//! ## Why this file exists, said as the finding that produced it
//!
//! The MCP plane's two trust-unit views — [`busbar_unit_trust::guard::PoolView`] over its registered
//! servers, and [`busbar_unit_trust::destination::KindFacts`] over its destinations — were the only
//! implementations of either trait in the composition root. The A2A plane needs both, and its
//! registration is `busbar_plane_a2a::Agent`:
//!
//! ```text
//! pub struct Server { id: &'static str, lane: LaneId, host: &'static str, transport: &'static str }
//! pub struct Agent  { id: &'static str, lane: LaneId, host: &'static str, transport: &'static str }
//! ```
//!
//! **They are the same shape, so there is one generic and not two views.** That is the whole content
//! of this module and it is stated out loud because the alternative was on the table: a second file
//! of a2a-shaped code, field for field identical, with two copies of "is this pool allowed", two
//! copies of the breaker's lane-index mapping and two copies of the allow-list conjunct. Two copies
//! of a guard is how a deployment ends up guarded on one plane and not on the other, and the copy
//! that drifts is always the one nobody re-derived.
//!
//! ## What is generic and what is DATA
//!
//! Everything a registration answers is generic: the id, the priced lane, the host and the transport
//! are read through [`Registered`], which each plane's own type implements in one line apiece.
//!
//! What differs between two planes is not code, it is FACTS, and facts are carried as data on
//! [`KindRules`]: which transports this plane's hops may be made over, whether it reaches a kernel
//! verb, whether it names a peer, whether it upgrades in band, and whether the record leg it is
//! about is one the plane declared. A plane-shaped `match` here would be this file learning the
//! plane axis's identity, which is the one thing a composition root's shared half must not do.
//!
//! ## What is NOT here
//!
//! No money, no scope, no auth. A `PoolView` answers where a caller's key may reach and a `KindFacts`
//! answers whether a destination's own kind rule passes; both are the trust unit's questions and
//! neither is decided here — this file only supplies the readings the unit asks for.

use busbar_contract::dest::DestinationFacts;
use busbar_contract::ids::{LaneId, RecordSchemaId};
use busbar_unit_trust::destination::KindFacts;
use busbar_unit_trust::guard::PoolView;
use busbar_unit_trust::lane::BreakerQuery;
use busbar_unit_trust::net::{Denylist, GuardPolicy, Resolver};

/// ONE PEER A PLANE REGISTERED, as the trust unit's views read it.
///
/// Four readings and nothing else, because four is what the two traits below actually consult. A
/// fifth would be a field one plane has and the other does not, which is the point at which this
/// stops being one view and becomes two wearing one name.
pub trait Registered: Copy {
    /// The name the operator gave this peer, and the resource the scope unit judges.
    fn id(&self) -> &'static str;
    /// The priced lane this peer is reached on.
    fn lane(&self) -> LaneId;
    /// The host to dial, or the empty string for a peer this node launches itself.
    fn host(&self) -> &'static str;
    /// Which transport the hop is made over.
    fn transport(&self) -> &'static str;
}

impl Registered for busbar_plane_mcp::Server {
    fn id(&self) -> &'static str {
        self.id
    }
    fn lane(&self) -> LaneId {
        self.lane
    }
    fn host(&self) -> &'static str {
        self.host
    }
    fn transport(&self) -> &'static str {
        self.transport
    }
}

impl Registered for busbar_plane_a2a::Agent {
    fn id(&self) -> &'static str {
        self.id
    }
    fn lane(&self) -> LaneId {
        self.lane
    }
    fn host(&self) -> &'static str {
        self.host
    }
    fn transport(&self) -> &'static str {
        self.transport
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE POOL VIEW
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// What the guards read about one plane's pools.
///
/// A pool here is one registered peer, keyed the way the breaker keys it. The explicit empty scope
/// list is the case worth naming: a key scoped to nothing denies every pool, which is a different
/// answer from a key that names no restriction at all, and it is the rig's own verify cell.
///
/// GENERIC over the registration, and identical for every plane — see the module header. The
/// `prefix` is the only thing a plane brings: the breaker and the pool table share one keyspace, so
/// each plane's destinations occupy a labelled region of it and a pool name arrives here with that
/// label still attached.
pub struct Pools<R: Registered + 'static> {
    registrations: &'static [R],
    prefix: &'static str,
    scopes: Option<Vec<String>>,
    has_key: bool,
    priced: bool,
}

impl<R: Registered + 'static> Pools<R> {
    /// The view for one caller over one deployment's registrations.
    ///
    /// Named `over` rather than `new` so each plane's own file can carry the one-line inherent
    /// constructor its callers already spell `new` — the shape stays generic and the call sites stay
    /// the ones the plane's tests already pin.
    #[must_use]
    pub fn over(
        registrations: &'static [R],
        prefix: &'static str,
        scopes: Option<Vec<String>>,
        has_key: bool,
        priced: bool,
    ) -> Self {
        Pools {
            registrations,
            prefix,
            scopes,
            has_key,
            priced,
        }
    }

    /// The peer one pool key refers to, where it refers to one.
    fn peer_of(&self, pool: &str) -> Option<&'static R> {
        let name = pool.strip_prefix(self.prefix).unwrap_or(pool);
        self.registrations.iter().find(|s| s.id() == name)
    }
}

impl<R: Registered + 'static> PoolView for Pools<R> {
    fn key_scopes(&self) -> Option<&[String]> {
        self.scopes.as_deref()
    }

    fn pool_allowed(&self, pool: &str) -> bool {
        match self.scopes.as_deref() {
            // No restriction named: every registration is reachable.
            None => true,
            // An explicit list — including an explicitly empty one — is the whole of what is allowed.
            Some(scopes) => {
                let name = pool.strip_prefix(self.prefix).unwrap_or(pool);
                scopes.iter().any(|s| s == pool || s == name)
            }
        }
    }

    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        // A registration falls over to nothing. The protocol's own answer to an unreachable peer is
        // an error naming that peer, and quietly serving a caller from a different one would be
        // answering a question nobody asked.
        None
    }

    fn is_configured(&self, name: &str) -> bool {
        self.peer_of(name).is_some()
    }

    fn pricing_enabled(&self) -> bool {
        self.priced
    }

    fn is_unpriced(&self, name: &str) -> bool {
        self.priced && self.peer_of(name).is_none()
    }

    fn has_key(&self) -> bool {
        self.has_key
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE KIND FACTS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The three halves of the network guard, as this root binds them.
///
/// They travel together because they are one decision: which resolver answers, how far the policy
/// lets a hop reach, and what the operator added to or carved out of the metadata denylist. Passing
/// them singly is how a caller ends up guarding with one deployment's policy and another
/// deployment's denylist.
#[derive(Clone, Copy)]
pub struct NetSeam<'r> {
    /// The one resolution the guard makes goes through here.
    pub resolver: &'r dyn Resolver,
    /// How far this plane's hops may reach.
    pub policy: GuardPolicy,
    /// The deployment's additions to and carve-outs from the metadata denylist.
    pub denylist: &'r Denylist,
}

/// THE PER-PLANE ANSWERS, AS DATA.
///
/// Six readings a plane makes about its own declarations, carried as values rather than as a
/// plane-shaped `match` in [`Kinds`] below. That is deliberate and it is the line this module holds:
/// the shared half must not learn which plane it is serving, because the moment it can it will grow
/// a seventh arm for one plane and a reader will have to work out which plane each arm is for.
#[derive(Clone, Copy)]
pub struct KindRules {
    /// The transports a hop of this plane may be made over. A destination naming anything else has
    /// no key to resolve, which is the trust unit's own refusal.
    pub transports: &'static [&'static str],
    /// Whether this plane reaches an administrative verb at all.
    pub verb_scope_held: bool,
    /// Whether a nested destination this plane names is one the registry can resolve.
    pub nested_plane_ok: bool,
    /// Whether this plane names a peer whose lease could be live.
    pub peer_lease_live: bool,
    /// Whether this plane upgrades a connection in band.
    pub upgrade_ok: bool,
    /// Whether the record leg this unit is about is one the plane declared, ASKED OF THE PLANE and
    /// decided at construction. A function pointer rather than a bool so the answer is still the
    /// plane's own table read at the plane's own schema, and so a schema that gains or loses an
    /// operation changes what is refused without a line here being edited.
    pub record_ok: fn(RecordSchemaId, &'static str) -> bool,
}

/// What the per-kind destination rules consult, for one unit of one plane.
///
/// Generic over the registration for the same reason [`Pools`] is: every reading below is a reading
/// of the registered set, and the registered set is the same shape on both planes that have one.
pub struct Kinds<'r, R: Registered + 'static> {
    registrations: &'static [R],
    schema: RecordSchemaId,
    op: &'static str,
    rules: KindRules,
    net: NetSeam<'r>,
}

impl<'r, R: Registered + 'static> Kinds<'r, R> {
    /// The facts for one unit, whose plan reaches one schema under one operation.
    ///
    /// `over` rather than `new`, for the reason [`Pools::over`] gives.
    #[must_use]
    pub fn over(
        registrations: &'static [R],
        schema: RecordSchemaId,
        op: &'static str,
        rules: KindRules,
        net: NetSeam<'r>,
    ) -> Self {
        Kinds {
            registrations,
            schema,
            op,
            rules,
            net,
        }
    }

    /// Where one lane sits in the registered table, which is the position the breaker keys its cells
    /// by.
    fn lane_index(&self, lane: &LaneId) -> Option<usize> {
        self.registrations.iter().position(|s| s.lane() == *lane)
    }

    /// The registered peer one destination names, where it names one.
    fn peer_for(&self, dest: &DestinationFacts) -> Option<&'static R> {
        let lane = dest.lane()?;
        self.registrations.iter().find(|s| s.lane() == lane)
    }
}

impl<R: Registered + 'static> KindFacts for Kinds<'_, R> {
    fn net_guard_passes(&self, dest: &DestinationFacts) -> bool {
        match busbar_unit_trust::net::check_destination_facts(
            dest,
            &[],
            self.net.resolver,
            self.net.policy,
            self.net.denylist,
        ) {
            // Only an upstream is dialled at an address; every other kind of a plane's destinations
            // reaches where it is going without one, so "not an upstream" is this caller's pass
            // rather than its refusal. A spawned stdio server has an address that is a program, and
            // the guard answers `Ok(None)` for it for the same reason.
            Ok(_) | Err(busbar_unit_trust::NetworkRefusal::NotAnUpstream) => true,
            Err(_) => false,
        }
    }

    fn allow_listed(&self, dest: &DestinationFacts) -> bool {
        match dest {
            // A hop is permitted when it reaches a peer this deployment registered. A plane with
            // nothing registered answers with an empty host and an empty lane precisely so this
            // returns false rather than the plane inventing somewhere to go.
            DestinationFacts::Upstream { address, .. } => {
                address.authority().is_some_and(|a| !a.is_empty()) && self.peer_for(dest).is_some()
            }
            DestinationFacts::SessionUpstream { .. } => self.peer_for(dest).is_some(),
            // Everything else stays on this node.
            _ => true,
        }
    }

    fn transport_key_resolves(&self, dest: &DestinationFacts) -> bool {
        match dest {
            DestinationFacts::Upstream { transport, .. } => {
                self.rules.transports.contains(transport)
            }
            _ => true,
        }
    }

    fn lane_permitted_for_op_class(&self, lane: &str) -> bool {
        self.registrations.iter().any(|l| l.lane().as_str() == lane)
    }

    fn session_upstream_ok(&self) -> bool {
        // A held stream of either protocol lives inside one connection and is paired at the moment
        // it opens; there is no way to reach a session's upstream that did not come from that
        // pairing.
        true
    }

    fn session_principal_matches(&self) -> bool {
        true
    }

    fn client_selector_ok(&self) -> bool {
        // The only selector either plane names is the opener, which resolves for as long as the unit
        // that opened the stream is the unit being delivered to.
        true
    }

    fn await_deadline_ok(&self) -> bool {
        // These planes' client legs deliver; none of them awaits a reply, so there is no deadline to
        // be out of range.
        true
    }

    fn verb_scope_held(&self) -> bool {
        self.rules.verb_scope_held
    }

    fn nested_plane_ok(&self) -> bool {
        self.rules.nested_plane_ok
    }

    fn plane_record_ok(&self) -> bool {
        (self.rules.record_ok)(self.schema, self.op)
    }

    fn peer_lease_live(&self) -> bool {
        self.rules.peer_lease_live
    }

    fn upgrade_ok(&self) -> bool {
        self.rules.upgrade_ok
    }

    fn unit_price_within_max(&self, _dest: &DestinationFacts) -> bool {
        // A card that states no maximum unit price has said nothing for a price to be over. Reading
        // that silence as a ceiling of zero would exclude every registered peer on every deployment
        // whose card predates the field.
        true
    }

    fn breaker_admits(&self, dest: &DestinationFacts, at: &BreakerQuery<'_>) -> bool {
        // The mapping is this root's — a lane name is a position in the registered table and nothing
        // outside here knows the order. The QUESTION is the query's, so the answer here is the same
        // answer the pre-walk's filter gives about the same lane at the same moment.
        match dest.lane().and_then(|lane| self.lane_index(&lane)) {
            Some(index) => at.admits_lane(index),
            // A destination priced on no registered lane has no position for the breaker to hold an
            // opinion about; the allow-list conjunct beside this one has already refused it.
            None => true,
        }
    }
}
