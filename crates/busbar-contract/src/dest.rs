//! Destinations, the route plan, and what an outbound request looks like.
//!
//! The destinations section of the design draws a hard line here. A plane returns *facts* about
//! where a unit wants to go; the trust unit turns those facts into a verified destination under
//! its own rule per kind, and only a verified destination can be dialled. A plane never holds a
//! connection and never names a lane outside the set its claim's configuration declares.

use crate::bounded::{ArenaBytes, BoundedVec, MAX_LEGS};
use crate::ids::{LaneId, OpClassId, RecordSchemaId, SchemeKey, StreamId, UpstreamIdx};
use crate::plugin::KernelSeal;
use crate::wire::TransportEnvelope;
use core::fmt;

/// Where a dial lands, as the transport family that dials it spells it.
///
/// The transport contract's, named here: a plane builds one when it says where a unit wants to go,
/// so it must be reachable from the contract, but what the arms MEAN is a transport author's
/// reading and lives with the rest of what only a transport reads.
pub use busbar_contract_transport::dest::UpstreamAddress;

/// How a client leg delivers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ClientMode {
    /// Send it and move on.
    Deliver,
    /// Send it and wait for a correlated answer.
    AwaitReply {
        /// The correlation the answer must carry.
        ///
        /// A destination is sealed and held past the frame it was built in, so its correlation
        /// cannot borrow the per-unit arena the way a draft's does: what a leg waits on is fixed
        /// when the leg is planned, and it outlives the bytes that planned it.
        correlation: crate::ids::CorrelationRef<'static>,
        /// How long to wait, in seconds, bounded by the configured turn ceiling.
        deadline_secs: u32,
    },
}

/// Where a plane says a unit wants to go.
///
/// These are facts, not a decision. Which kinds are reachable at all is decided by the unit's
/// origin, and the design fixes that table: a tick unit reaches nothing but its own session
/// accrual, a bootstrap unit reaches nothing but the bootstrap verb, an arrival subject reaches
/// nothing at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum DestinationFacts {
    /// A fresh connection to a configured upstream.
    Upstream {
        /// Which transport to dial with.
        transport: &'static str,
        /// Where it lands, spelled the way the transport's own family dials.
        address: UpstreamAddress,
        /// Which priced lane.
        lane: LaneId,
    },
    /// An upstream this session already holds.
    SessionUpstream {
        /// Which of the session's upstreams.
        upstream: UpstreamIdx,
        /// Which stream on it.
        stream: Option<StreamId>,
        /// The lane copied from the paired upstream when it was opened.
        lane: LaneId,
    },
    /// Back to a client on a session.
    Client {
        /// Which session member.
        selector: &'static str,
        /// Deliver, or deliver and wait.
        mode: ClientMode,
    },
    /// One of the kernel's own verbs.
    KernelVerb {
        /// Which verb.
        verb: &'static str,
    },
    /// Another plane, one level down.
    NestedPlane {
        /// Which plane.
        plane: &'static str,
        /// Which of its operation classes.
        op: OpClassId,
    },
    /// Priced session time, raised by the node's clock.
    SessionAccrual {
        /// Which lane the time is priced on.
        lane: LaneId,
    },
    /// A kernel-held durable record belonging to the calling plane.
    PlaneRecord {
        /// Which declared schema.
        schema: RecordSchemaId,
        /// Which of the schema's declared operations.
        op: &'static str,
    },
    /// Another node of the fleet.
    Peer {
        /// Which node.
        node: &'static str,
        /// Which of its sessions.
        selector: &'static str,
    },
    /// An in-band upgrade of the current connection.
    Upgrade {
        /// Which transport to upgrade to.
        to: &'static str,
    },
}

impl DestinationFacts {
    /// The lane this destination is priced on, where it has one.
    #[must_use]
    pub const fn lane(&self) -> Option<LaneId> {
        match self {
            Self::Upstream { lane, .. }
            | Self::SessionUpstream { lane, .. }
            | Self::SessionAccrual { lane } => Some(*lane),
            _ => None,
        }
    }

    /// Whether this kind is one the flat request fee is charged against.
    ///
    /// The settlement table is explicit that the fee follows the *kind*, not the price: a client
    /// unit whose route selected an upstream posts the fee even with no rate card configured,
    /// and every other kind posts nothing unless the card's kernel-verb section prices it.
    #[must_use]
    pub const fn is_upstream_kind(&self) -> bool {
        matches!(self, Self::Upstream { .. } | Self::SessionUpstream { .. })
    }
}

/// A destination the trust unit has checked and sealed.
///
/// This is the only thing that can be dialled. It is built by the trust unit against the rule for
/// its kind — allow-list, transport key, lane permitted for the draft's operation class, unit price
/// under the configured maximum, breaker consulted — and the constructor here takes a kernel seal
/// because a plane that could seal its own destination would have skipped every one of those.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDestination {
    facts: DestinationFacts,
    lane: Option<LaneId>,
    transport: &'static str,
    budget_remaining: Option<i64>,
}

impl VerifiedDestination {
    /// Seal a destination. Trust-unit-only; the seal is what says so.
    #[must_use]
    pub fn seal(
        _seal: &dyn KernelSeal,
        facts: DestinationFacts,
        transport: &'static str,
        budget_remaining: Option<i64>,
    ) -> Self {
        Self {
            lane: facts.lane(),
            facts,
            transport,
            budget_remaining,
        }
    }

    /// What the plane said about it.
    #[must_use]
    pub fn facts(&self) -> DestinationFacts {
        self.facts
    }

    /// The priced lane the trust unit sealed, re-derived against the allow-list.
    #[must_use]
    pub fn lane(&self) -> Option<LaneId> {
        self.lane
    }

    /// Which transport dials it.
    #[must_use]
    pub fn transport(&self) -> &'static str {
        self.transport
    }

    /// The same sealed destination, re-addressed for the layer underneath this one.
    ///
    /// A composed transport does not open its own socket: it dials through the layer below it, and
    /// that layer reads a socket address where this one reads a URL or a method. Re-addressing is
    /// not re-sealing — every judgement the trust unit made travels unchanged, and only the
    /// spelling of where the bytes go changes to what the lower layer can parse. There is no way to
    /// reach this without already holding a sealed destination, so walking down a stack can never
    /// widen where a unit may go.
    ///
    /// `None` for a destination that is not an upstream: nothing else has a layer beneath it.
    #[must_use]
    pub fn beneath(&self, transport: &'static str, address: UpstreamAddress) -> Option<Self> {
        let DestinationFacts::Upstream { lane, .. } = self.facts else {
            return None;
        };
        Some(Self {
            facts: DestinationFacts::Upstream {
                transport,
                address,
                lane,
            },
            lane: self.lane,
            transport,
            budget_remaining: self.budget_remaining,
        })
    }

    /// The destination's remaining lifetime request budget, where it declares one.
    ///
    /// The transport section exposes this to hooks under its own fact key so pick order can take
    /// it into account; an exhausted destination is excluded from the walk rather than ordered
    /// last.
    #[must_use]
    pub fn budget_remaining(&self) -> Option<i64> {
        self.budget_remaining
    }
}

/// One leg of a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    /// Where the leg goes.
    pub destination: DestinationFacts,
}

/// What a plane's routing step returns.
///
/// The leg count is bounded because a unit is one authorization: a plane that wants to reach a
/// hundred recipients does not get a hundred legs, it gets delivery children, each with its own
/// hold drawn from the same chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoutePlan {
    /// The legs, in the order the plane wants them run.
    pub legs: BoundedVec<Leg, MAX_LEGS>,
}

/// One member of a configured pool, as everything that keys on a member names it.
///
/// The egress unit owns the connection pool per `(transport, destination)` and the breaker unit
/// owns trip, cooldown and fast-fail per `(pool, destination)` — the same object, keyed the same
/// way, so it has one spelling and one width. It is a node-local identity sealed at registration,
/// not a wire value: nothing outside the node ever sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct DestinationId(u64);

impl DestinationId {
    /// Name a pool member.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The identity, as the pool's member list orders it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DestinationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "destination {}", self.0)
    }
}

/// A candidate's position in the verified set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct CandidateIdx(pub u16);

/// An order over the verified set.
///
/// A ranking hook returns one of these and the failover walk takes it as-is. Candidate sets are
/// unbounded because configured pools are unbounded, so this is one of the few places the contract
/// does not impose a ceiling — imposing one would refuse a configuration the previous release
/// accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Permutation {
    /// The candidates, in the order they should be walked.
    pub order: Vec<CandidateIdx>,
}

/// A narrowing of the verified set.
///
/// Restrictions from several hooks at one seat intersect. What happens when the intersection is
/// empty is the hook's own declaration, and the default is to reject.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CandidateSet {
    /// Which candidates survive.
    pub members: Vec<CandidateIdx>,
    /// What to do when nothing survives.
    pub on_empty: OnEmpty,
}

/// What a gate does when its restriction leaves nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub enum OnEmpty {
    /// Refuse the unit. The default, and the previous release's default.
    #[default]
    Reject,
    /// Skip this gate's restriction and leave the candidate set unchanged.
    Weighted,
    /// Order only, as the terminal of an on-error chain; an empty restriction still refuses.
    First,
}

/// The closed code a gate hook vetoes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum VetoCode {
    /// The principal may not perform this operation.
    NotPermitted,
    /// The content is not admissible.
    ContentRefused,
    /// An external policy said no.
    PolicyRefused,
    /// The rate this principal is asking at is not admissible.
    RateRefused,
}

/// The wire request a plane encoded for one verified destination.
///
/// The envelope is the transport's shape, the body is arena bytes, and the scheme names which
/// egress-auth plugin decorates it. The plane names the scheme; it never holds the credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressBody<'u> {
    /// The transport-level envelope.
    pub envelope: TransportEnvelope<'u>,
    /// The body bytes.
    pub body: ArenaBytes<'u>,
    /// Which egress-auth scheme decorates it.
    pub auth: SchemeKey,
}

/// A placeholder the egress-auth unit substitutes a secret into.
///
/// The plugin that asks for a slot never sees what goes in it. Substitution happens in the
/// egress-auth unit, after the envelope has been checked against the verified destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SecretSlot {
    /// The envelope field or body span the secret goes into.
    pub target: &'static str,
    /// How many bytes the substituted value will occupy.
    pub len: u16,
}

/// A one-time minted secret's placeholder.
///
/// Minted by the verbs unit under an admin token. It must appear exactly once at its declared
/// target location, and if it does not, the encode step fails and the mint is reversed. It never
/// appears in content facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretOnce {
    nonce: u128,
    target: &'static str,
}

impl SecretOnce {
    /// Mint a placeholder. Verbs-unit-only; the seal is what says so.
    #[must_use]
    pub fn mint(_seal: &dyn KernelSeal, nonce: u128, target: &'static str) -> Self {
        Self { nonce, target }
    }

    /// The nonce that must appear exactly once.
    #[must_use]
    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    /// Where it must appear.
    #[must_use]
    pub fn target(&self) -> &'static str {
        self.target
    }
}

/// What an egress-auth scheme adds to an outbound request.
///
/// Either a decoration applied in one pass, or a declaration that this upstream needs a
/// multi-round exchange, in which case the upstream's challenge comes back through the scheme's
/// continue call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthDecoration<'u> {
    /// Fields, a body signature and slots, applied in one pass.
    Decorate {
        /// Envelope fields to set, from the closed allow-list; never a lane-locator field.
        envelope_fields: BoundedVec<crate::wire::EnvelopeField<'u>, { crate::bounded::MAX_KEYS }>,
        /// A signature over the body, where the scheme signs one.
        body_signature: Option<ArenaBytes<'u>>,
        /// Placeholders the egress-auth unit substitutes secrets into.
        slots: BoundedVec<SecretSlot, { crate::bounded::MAX_KEYS }>,
    },
    /// This upstream needs a multi-round exchange first.
    Handshake {
        /// The most frames the exchange may take.
        max_frames: u16,
        /// The most bytes the exchange may take.
        max_bytes: u32,
    },
}

/// An opaque handle to transport key material.
///
/// Resolved by the transport-key unit through the secret plugin at listen, dial and upgrade, and
/// journaled as an access entry each time. The handle carries no bytes a caller can read: only the
/// three units the design names can expose a secret, and a transport is not one of them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportKeyHandle {
    slot: u64,
    fingerprint: &'static str,
}

impl TransportKeyHandle {
    /// Hand out a handle for resolved key material. Transport-key-unit-only.
    ///
    /// The token is what says so: the capability crate lends a `TransportKeyToken` to the
    /// transport-key unit and to nothing else, so this is the one place a handle comes from. There
    /// is no second spelling of this type — the transports, the egress unit and the unit that
    /// resolves the key all name this one.
    #[must_use]
    pub fn issue(_token: &dyn KernelSeal, slot: u64, fingerprint: &'static str) -> Self {
        Self { slot, fingerprint }
    }

    /// The node-local slot the material lives in.
    #[must_use]
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// The material's fingerprint, for the journal's access entry.
    #[must_use]
    pub fn fingerprint(&self) -> &'static str {
        self.fingerprint
    }
}

impl fmt::Debug for TransportKeyHandle {
    /// Says what the handle is and what it is not. A handle is a registry entry, never bytes, and
    /// a log line that printed material would be the one leak the whole indirection exists to stop.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransportKeyHandle(slot {}, {} <no material>)",
            self.slot, self.fingerprint
        )
    }
}
