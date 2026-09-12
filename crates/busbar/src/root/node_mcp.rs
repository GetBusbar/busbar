// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MCP NODE** — the composition's own serving path for the MCP plane, and the first one this
//! plane has ever had.
//!
//! ## What this file is, in one sentence
//!
//! [`root::units_mcp`] is the BINDING — ten arms that hand each of the loop's steps to the unit that
//! answers it — and it has never been reached, because nothing assembled the long-lived half a unit
//! borrows or drove the loop over it. This file is that half, and the drive.
//!
//! [`root::units_mcp`]: crate::root::units_mcp
//!
//! ## The precedent it is built on, and the one place it departs from it
//!
//! `root::units_llm`'s `LlmNode` is the shape: one kernel, one in-flight table, one gauge, one
//! canary, a monotonic clock that ORDERS what the wall clock only DATES, the tokens minted outside
//! the loop because the postings they seal land after the exit, and one `answer` that walks a
//! request through the ten steps and returns what the terminal posted. Every one of those is here
//! and is here for the reason that file gives.
//!
//! Where it departs: the LLM node reaches its plane's engine through the `Route` seam and never
//! names the contract's wire vocabulary at all — `units_llm.rs` says `arena` zero times. This plane's
//! steps read an owned [`McpDraft`], and the draft's route plan comes off `McpPlane::route`, which
//! takes a kernel-sealed `Unit` and a `Ctx`. So this file mints both, over the three views in
//! [`seam`] — and the arena among them ALLOCATES NOTHING AND SAYS SO, because `McpPlane::route`
//! reads a unit's operation class and touches neither the body nor the facts nor the ctx. That is a
//! measurement, not an assumption; the cell `the_route_plan_is_read_without_an_allocation` is what
//! keeps it true.
//!
//! ## What is deliberately NOT here
//!
//! **No bytes.** This node chooses the PATH a class is answered on and never the answer: the
//! document is produced by the byte source the class already had, handed in as a closure at the
//! composition point, and invoked only where the loop settled. A node that wrote a byte of this
//! protocol would be a second grammar, and the plan's later lines are what move those bytes
//! plane-side.
//!
//! **No pricing.** The classes this node serves today are money-free — a listing reaches two record
//! legs and no upstream — so the estimate carries a zero maximum for both declared classes and a
//! zero fee, and NOBODY prices anything. That is the uniform-billing posture stated as a value
//! rather than as a comment: the plane never prices, and a class that reaches an upstream is the
//! class that will need a card, at which point the card is read where every other plane's is.
//!
//! **No second grammar.** The operation class comes off the plane's own method table
//! (`busbar_plane_mcp::ops::row_for`) over a method name the neutral ingress reader already
//! extracted, which is exactly what the legacy dispatch reads. This file parses nothing.

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_caps::{ArrivalRecord, PrincipalId};
use busbar_contract::dest::{DestinationFacts, Leg};
use busbar_contract::ids::OpClassId;
use busbar_contract::plane::{Plane, PlaneMeta};
use busbar_kernel::inflight::InFlight;
use busbar_kernel::slice::ConcurrencyGauge;
use busbar_kernel::teller::{AccrualMeter, Kernel, UnitCtx};
use busbar_plane_mcp::{claims, ops, McpPlane};
use busbar_unit_admission::{ChainWalk, GroupTable};
use busbar_unit_scope::{Grants, Scope};

use crate::root::bindings::{resolve_bindings, Node};
use crate::root::units_mcp::{
    Catalogue, ClassPrices, Clocks, McpBindings, McpDraft, McpUnits, NetSeam, Pools, Views,
};

/// The three views a `Ctx` stands on, as this node binds them — and each is a statement about what
/// the path it serves does NOT do.
///
/// They are grouped because they are one decision: what this node is entitled to ask the contract's
/// wire vocabulary for while reading a route plan. Splitting them into three `static`s scattered
/// through the file would hide that the answer is "nothing" three times over.
pub mod seam {
    use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Span};
    use busbar_contract::unit::{ConfigView, TransportView};

    /// **THE ARENA THAT ALLOCATES NOTHING, AND SAYS SO.**
    ///
    /// Not a stub and not a double. `McpPlane::route` — the one call this node makes across the
    /// contract's wire seam — reads a unit's operation class and nothing else: it never touches the
    /// body, never reads a fact, and its `_ctx` parameter is unused. So the honest arena for this
    /// path is the one that reports zero bytes remaining and refuses every request, in the same
    /// shape as `RefusingStore` (`root/kernel.rs`): a capability that is not used, stated as a value
    /// a test can read rather than as a comment nobody checks.
    ///
    /// This is deliberately NOT the shape a real arena takes. Every `Arena` in the tree today is a
    /// cell's double that allocates by `Box::leak`, and a leak on a request path is a leak per
    /// frame. When a class's ANSWER is framed through `Plane::encode_response` — the plan's
    /// answer-framing line — that line needs a real bounded allocator, and it is a KIND-NEUTRAL one
    /// resolved at boot beside the door and the book, not a bump allocator invented in one plane's
    /// node. Reaching this type from that path would be a compile-time success and a runtime
    /// refusal, which is why the refusal is total.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct NoAllocation;

    impl Arena for NoAllocation {
        fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
            Err(ArenaBudget {
                wanted: src.len(),
                remaining: 0,
            })
        }

        fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
            Err(ArenaBudget {
                wanted: src.len(),
                remaining: 0,
            })
        }

        fn alloc_spans<'a>(
            &'a self,
            src: &[(&'a str, Span)],
        ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
            Err(ArenaBudget {
                wanted: src.len(),
                remaining: 0,
            })
        }

        fn remaining(&self) -> usize {
            0
        }
    }

    /// The composed stack one unit of this plane arrived over, as the composition reports it.
    ///
    /// A VALUE rather than a call, and the chain is the one the claim named: this plane's claims key
    /// on the TOP of the stack (see `units_mcp::arrival`, which refuses a record whose chain does not
    /// end at the claim's transport), so a node that reported a chain ending anywhere else would be
    /// handing the arrival step a record from one surface under another surface's claim.
    #[derive(Debug, Clone, Copy)]
    pub struct Stack {
        /// The top of the chain — the layer the claim that matched names.
        pub top: &'static str,
        /// The whole composed chain, bottom layer first.
        pub chain: &'static [&'static str],
    }

    impl TransportView for Stack {
        fn key(&self) -> &'static str {
            self.top
        }

        fn chain(&self) -> &[&'static str] {
            self.chain
        }

        /// No transport fact is read on this path. The facts a plane reads off a stack are the
        /// ingress's (the peer identity, the negotiated protocol), and the route plan reads none of
        /// them — so answering `None` is the report, not a gap.
        fn fact(&self, _key: &str) -> Option<&str> {
            None
        }
    }

    /// **NO PLUGIN CONFIGURATION ON THIS PATH.**
    ///
    /// `ConfigView` is a PLUGIN's own settings block, and a plane is not a plugin: what the operator
    /// configured about this plane reached the node through the mount, at boot, and nothing on the
    /// request path may re-read it. Three production implementors of this face exist in the tree and
    /// every one of them is a transport's; none of them is a plane's, and that is correct.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct NoSettings;

    impl ConfigView for NoSettings {
        fn get_str(&self, _key: &str) -> Option<&str> {
            None
        }

        fn get_int(&self, _key: &str) -> Option<i64> {
            None
        }

        fn get_bool(&self, _key: &str) -> Option<bool> {
            None
        }
    }
}

/// **THE RESOLVER THIS NODE IS NEVER ASKED THROUGH**, on the classes it serves today.
///
/// `check_destination_facts` answers `NotAnUpstream` before it reaches a resolver for every
/// destination that is not an upstream, and every leg of every money-free class of this plane is a
/// kernel-held record. So the resolution this seam offers is one that cannot happen, and it is
/// written as a refusal rather than as a fixed address: a fixed address would make a hop that
/// reached here LOOK guarded.
///
/// The class that dials — `tools/call` — is the last one this node takes, and it takes a real
/// resolver with it. One exists in the tree (`busbar_a2a`'s Tokio one) and it is another plane's, so
/// the resolver that class binds is a kind-neutral one resolved at boot beside the breaker, not this.
struct NeverDialled;

impl busbar_unit_trust::net::Resolver for NeverDialled {
    fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Err(format!(
            "the mcp node's money-free classes reach no upstream, so {host} was never to be resolved"
        ))
    }
}

/// The deployment's metadata denylist, as this node's guard seam reads it.
///
/// Empty, and empty is the narrowest thing it can be: an empty denylist BLOCKS the built-in metadata
/// hosts and carves nothing out, which is the shipped posture. It is a `LazyLock` rather than a field
/// because a denylist is a property of the deployment and not of a node, and the node that served
/// the first request must read the same one as the node that serves the last.
static DENYLIST: std::sync::LazyLock<busbar_unit_trust::Denylist> =
    std::sync::LazyLock::new(busbar_unit_trust::Denylist::default);

static NEVER_DIALLED: NeverDialled = NeverDialled;

/// **THE NODE.** One per process, built at boot, borrowed by every unit.
///
/// The long-lived half and nothing else: the kernel whose seal mints every step's token, the table a
/// unit's hold lives in, the gauge the door's leases go back to, the counts the canary balances, the
/// monotonic clock that orders this node's records against each other, and the one
/// [`Node`](crate::root::bindings::Node) every plane's leg bindings are resolved out of.
///
/// The plane is a field because a plane is DATA the operator configured and this node was handed it
/// at the mount; the group table is a field for the same reason. Neither is re-read per request.
pub struct McpNode {
    kernel: Kernel,
    inflight: InFlight,
    gauge: ConcurrencyGauge,
    canary: busbar_caps::Canary,
    /// THE NODE'S MONOTONIC CLOCK. A counter that only ever goes up, whatever the wall clock does,
    /// so two units of one second are still orderable. It lives on the node rather than in a unit
    /// because ordering is a statement about a SET of units.
    mono: AtomicU64,
    next_key: AtomicU64,
    /// The plane, with the registrations the operator configured, as the mount handed it over.
    plane: McpPlane,
    /// **THE ONE RESOLVER'S NODE**, with this plane mounted on it. Every unit below is bound over
    /// what `resolve_bindings` answers — one door, one book, one breaker, one chain — which is what
    /// makes this plane's figures the node's figures rather than a second set that agreed once.
    bindings: Node,
    /// The configured limit tree, resolved at boot into the shape the door walks.
    groups: GroupTable,
}

impl std::fmt::Debug for McpNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpNode")
            .field("mounted", &self.bindings.mounted())
            .finish_non_exhaustive()
    }
}

/// What the composition already knew about one arriving request, as the node is handed it.
///
/// Every field is a fact somebody else established before this unit existed — the transport named
/// the claim, the ingress reader extracted the method, the session bound the principal — and a
/// constructor taking them singly is one a caller can fill in wrongly one at a time.
pub struct Arriving<'a> {
    /// The method name, as the neutral ingress reader read it off the envelope. The node looks its
    /// CLASS up in the plane's own table and never compares this string to one of its own.
    pub method: &'a str,
    /// The whole request document's length, which is what this plane prices its input on.
    pub request_bytes: u64,
    /// The caller's resolved key, or `None` on an ungoverned deployment.
    pub key: Option<&'a busbar_api::VirtualKey>,
    /// The claim that matched, which is how this plane names a transport.
    pub claim_transport: &'static str,
    /// The composed stack the request arrived over, bottom layer first.
    pub chain: &'static [&'static str],
    /// The credential the carrier presented, where one arrived on THIS frame.
    pub credential: Option<&'a str>,
    /// Whether the principal is a bound session's rather than these bytes'.
    pub from_session: bool,
}

/// Why the node did not serve a class it was asked for.
///
/// The refusal the LOOP raised, in the contract's spelling, or the one thing the loop cannot answer
/// for: a method the plane's own table does not name as a client-sent class. The second is not a
/// refusal at a step — no unit opened — and the caller renders it as the not-implemented answer it
/// always did.
#[derive(Debug)]
pub enum NotServed {
    /// The plane's method table does not carry this method as a class a caller may send.
    NoSuchClass,
    /// The loop stopped the unit at a step, and this is the step and the reason.
    Refused(busbar_contract::unit::Refusal<'static>),
    /// The loop ran and ended without an answer and without a refusal — the node's own sweep took
    /// the hold first, or the in-flight table declined the unit for a reason that is not capacity.
    Unavailable,
}

impl McpNode {
    /// Compose the node this plane is served by.
    ///
    /// Takes the mount's two products and the node the bindings were resolved on, because both are
    /// boot's: a node that built its own would be a second door and a second book, and both halves
    /// of that look healthy because an empty ledger reconciles.
    #[must_use]
    pub fn over(plane: McpPlane, bindings: Node, groups: GroupTable) -> Self {
        McpNode {
            kernel: crate::root::kernel::new_kernel(),
            // The transport in front of this node already carries the operator-configured inbound
            // concurrency, which is where admission-to-the-node is decided. A second cap here would
            // be a second answer to one question and the one that refused first would decide,
            // silently. So the table is opened at a ceiling no deployment reaches — it is still a
            // real table, because a hold still has to live somewhere and the sweep still walks it.
            inflight: InFlight::new(usize::MAX, 0),
            gauge: ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            mono: AtomicU64::new(0),
            next_key: AtomicU64::new(1),
            plane,
            bindings,
            groups,
        }
    }

    /// Which planes this node mounted, in key order — the instrument that says the mount happened.
    #[must_use]
    pub fn mounted(&self) -> Vec<&'static str> {
        self.bindings.mounted()
    }

    /// The plane this node serves, as the mount handed it over.
    #[must_use]
    pub fn plane(&self) -> &McpPlane {
        &self.plane
    }

    /// WHEN A UNIT ARRIVED, taken once: this node's two clocks, read together.
    ///
    /// The one place on the request path either clock is read. The window a unit is judged in, the
    /// stamp the in-flight table enters it under and the pair its record is dated and ordered by are
    /// all spelled out of this one value, because a second read is a second arrival.
    fn arrived(&self) -> Clocks {
        Clocks {
            wall: busbar_substrate_values::store::now_ms() / 1_000,
            mono: self.mono.fetch_add(1, Ordering::AcqRel),
        }
    }

    /// The operation class the plane's own table names this method, where it names one a caller may
    /// send.
    ///
    /// `busbar_plane_mcp::ops::row_for` is the same read the legacy dispatch makes, and the
    /// `Sender::Client` narrowing is the same one: a class an upstream sends back mid-call is not a
    /// class this node answers, and answering one would be answering a message nobody sent.
    fn class_of(method: &str) -> Option<OpClassId> {
        let row = ops::row_for(method)?;
        (row.sender == ops::Sender::Client).then_some(row.op)
    }

    /// **THE ROUTE PLAN, off the plane's own routing method.**
    ///
    /// The plan is the plane's and is not second-guessed: a `RoutePlan` for a class is what
    /// `McpPlane::route` returns, and the alternative — a table of legs per class kept in the root —
    /// is a second declaration that drifts from the first.
    ///
    /// Reaching it needs a kernel-sealed `Unit` and a `Ctx`, and both are minted here over
    /// [`seam::NoAllocation`]: `route` reads `u.op()` and nothing else, so the body is empty, the
    /// facts are empty, and the arena is never asked for a byte. The cell beside this asserts all
    /// three.
    fn plan_for(
        &self,
        op: OpClassId,
        chain: &'static [&'static str],
        top: &'static str,
    ) -> Vec<Leg> {
        let arena = seam::NoAllocation;
        let settings = seam::NoSettings;
        let stack = seam::Stack { top, chain };
        let labels = busbar_contract::bounded::Labels::new();
        let ctx = busbar_contract::unit::Ctx::new(
            busbar_contract::unit::Clock {
                // The plan depends on the class and on nothing else, least of all on the time: a
                // route that read a clock would be a plan that could differ between two identical
                // requests. Zero is the reading that says so.
                unix_secs: 0,
                monotonic_nanos: 0,
            },
            &settings,
            None,
            &stack,
            &labels,
            &arena,
        );
        let unit = busbar_contract::unit::Unit::new(
            // A TOKEN, which is what the contract's seal is: the implementors of `KernelSeal` are
            // the capability tokens, and this node mints its own off its own kernel. The seal says
            // "the kernel built this unit", and on this path the kernel is this node's.
            &self.kernel.durability_token(),
            busbar_contract::ids::UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed)),
            busbar_contract::unit::Origin::Client,
            None,
            None,
            busbar_contract::wire::Direction::Inbound,
            None,
            op,
            busbar_contract::bounded::Ir::new(&[], &[]),
            busbar_contract::bounded::Facts::new(),
            None,
        );
        self.plane
            .route(&unit, &ctx)
            .legs
            .as_slice()
            .iter()
            .map(|l| Leg {
                destination: l.destination,
            })
            .collect()
    }

    /// The registration this unit is judged and keyed against.
    ///
    /// The first registered server, and `""` where nothing is registered. A listing is not ABOUT one
    /// server — it is about everything this caller can reach — but the door, the breaker and the
    /// pool view are all keyed by a registration, so the key is the deployment's own first one
    /// rather than a name invented here. A deployment with nothing registered keys against the empty
    /// string, which the pool view reads as unconfigured, which is the refusal it should be.
    fn pool(&self) -> String {
        self.plane
            .servers()
            .first()
            .map_or_else(String::new, |s| crate::root::units_mcp::pool_key(s.id))
    }

    /// **SERVE ONE CLASS THROUGH THE LOOP.**
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a class that used to be
    /// answered by a `match` arm. What comes back on the served arm is what `answer` produced — this
    /// function chooses the PATH and never the bytes.
    ///
    /// `answer` is invoked on exactly one arm: the unit settled, and the loop raised no refusal.
    /// Invoking it before the loop would be answering a caller the door has not admitted; invoking
    /// it on a refusal would be answering twice.
    ///
    /// # Errors
    ///
    /// The plane's table does not carry the method as a client class, or the loop refused the unit
    /// at a step, or the unit ended without either.
    pub fn serve_class<T>(
        &self,
        arriving: &Arriving<'_>,
        answer: impl FnOnce() -> T,
    ) -> Result<T, NotServed> {
        let Some(op) = Self::class_of(arriving.method) else {
            return Err(NotServed::NoSuchClass);
        };
        let Some(bound) = resolve_bindings(<McpPlane as PlaneMeta>::KEY, &self.bindings) else {
            // A plane this node did not mount. An absence and not an empty binding: a leg driven
            // over a default door admits and charges against something the operator never
            // configured, and it would look like it worked.
            return Err(NotServed::Unavailable);
        };

        let at = self.arrived();
        let legs = self.plan_for(op, arriving.chain, arriving.claim_transport);
        // The endpoint the trust step seals, which is not the same as the plan: `verify` names where
        // the unit ends up and `route` names every leg it passes through. The plan's first leg is
        // this plane's endpoint for every class that reaches a record, and a class with no plan at
        // all reaches no destination — which the routing step refuses rather than the root guessing.
        let destination = legs.first().map_or(
            DestinationFacts::PlaneRecord {
                schema: busbar_plane_mcp::records::SCHEMA_CATALOGUE,
                op: busbar_plane_mcp::records::OP_SCAN,
            },
            |l| l.destination,
        );
        // One key per leg, in the plan's order. Every money-free class of this plane reaches whole
        // schemas rather than named rows, and the schema's own key vocabulary spells "the whole of
        // it" as the empty string.
        let record_keys: Vec<String> = legs.iter().map(|_| String::new()).collect();

        let principal = PrincipalId::new(arriving.key.map_or_else(
            || busbar_api::AuthPrincipal(None).actor_id(),
            |k| k.id.as_str(),
        ));
        let record = ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: arriving.chain.to_vec(),
        };
        let draft = McpDraft {
            op: Ok(op),
            streaming: false,
            credential: arriving.credential.map(ToString::to_string),
            claim_transport: arriving.claim_transport,
            // A claim that declares a scheme is one whose credential arrives on the frame. The
            // session-bound transports declare one and present it once, at the session's open, which
            // is why the authenticate arm reads `from_session` and not this.
            under_scheme: claims::CLAIMS
                .iter()
                .any(|c| c.transport == arriving.claim_transport && c.scheme.is_some()),
            from_session: arriving.from_session,
            // THE PRINCIPAL THE DOOR RESOLVED. Every class this node serves arrives behind one — the
            // document route's middleware or the pipe's session bind — so the authenticate step
            // reads that outcome rather than running the chain a second time. An ungoverned
            // deployment resolved the anonymous actor, which is an outcome too, and it is the same
            // spelling every other reader of `gov.key` uses for the absence.
            admitted: Some(principal.clone()),
            arrival: record,
            destination,
            legs,
            record_keys,
            // A listing writes no record. The body a record leg would write is the caller's, and a
            // class that reads has none.
            record_body: Vec::new(),
            request_bytes: arriving.request_bytes,
            // THE ANSWER'S SIZE IS NOT KNOWN HERE, and this node does not pretend it is. The draft
            // is read by every step and is built before any of them run, so the figure the metering
            // step locates is the one the draft carries — zero, on a class whose bytes this node
            // does not produce. The class that produces its own bytes through the plane's face is
            // the class that can fill this in, and that is the plan's answer-framing line.
            response_bytes: 0,
            finish: busbar_contract::unit::FinishClass::Complete,
        };

        let chain = self
            .groups
            .chain_for(
                principal.as_str(),
                arriving.key.and_then(|k| k.group.as_deref()),
            )
            .ok();
        let scopes = arriving.key.and_then(|k| {
            k.allowed_scopes
                .as_ref()
                .map(|s| s.iter().map(|r| r.value.clone()).collect::<Vec<String>>())
        });
        let pool = self.pool();
        let net = NetSeam {
            resolver: &NEVER_DIALLED,
            // The shipped posture: a hop must be https and must not reach a private address unless
            // the registration says so. Read off the unit's default rather than stated here, because
            // what a deployment permits a hop to reach is the deployment's statement and not this
            // node's.
            policy: busbar_unit_trust::net::GuardPolicy::default(),
            denylist: &DENYLIST,
        };
        let facts = Catalogue::new(
            self.plane,
            busbar_plane_mcp::records::SCHEMA_CATALOGUE,
            busbar_plane_mcp::records::OP_SCAN,
            net,
        );
        let pools = Pools::new(
            self.plane,
            scopes,
            arriving.key.is_some(),
            // NOTHING IS PRICED ON THIS PATH, and that is the whole of the money statement for the
            // classes this node serves today: a listing reaches two record legs and no upstream, so
            // there is no per-unit price and no flat fee, and the pool view says so rather than
            // reading a card the plane may not see.
            false,
        );
        let bindings = McpBindings {
            plane: self.plane,
            auth: bound.auth,
            auth_bindings: bound.auth_bindings,
            trust: &TRUST,
            views: Views {
                pools: &pools,
                facts: &facts,
                breaker: bound.breaker,
            },
            door: bound.door,
            pricer: bound.pricer,
            chain: chain.as_ref(),
            // Zero for both declared classes and zero for the fee. See `Pools::new` above: the plane
            // never prices, and a money-free class has nothing for a card to say.
            prices: ClassPrices::default(),
            fee_nanos: 0,
            records: bound.records,
            meter_policy: bound.meter_policy,
            scope_policy: bound.scope_policy,
            // THE DEPLOYMENT'S OWN POSTURE, carried to the approve step rather than inferred at it.
            // Read once, at boot, off the operator's `auth.role_bindings`; see `bindings::Posture`.
            posture: bound.posture,
            durability: bound.durability,
            pool: &pool,
            at,
            origin: bound.origin,
            // No grant is redeemed by a class that reads, so nothing lapses. The classes that spend
            // one carry the arriving grant's own lapse.
            expires_at: at.wall,
        };

        // THE CALLER'S AUTHORITY over the resources the plane names. A resolved key is a caller the
        // chain admitted, and what a key NARROWS is which registrations it may target — which is
        // `allowed_scopes`, read by the pool view above, not a read/write lattice. So the authority
        // handed to the approve step is the full one and the narrowing happens where the key states
        // it, which is the same reading the other switched-over planes take.
        let grants = Grants::of(Scope::Full);
        let unit = McpUnits::new(bindings, draft, grants);

        let hold = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &crate::root::kernel::AdmissionDoor,
            principal.clone(),
        );
        let key = busbar_caps::UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            admin_listener: false,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival: hold,
            // The SAME reading the unit is billed and recorded under. A second read here is a second
            // arrival: the table would stamp the unit in one window and the books would bill it in
            // another, and nothing downstream could say which the request arrived in.
            now: at.wall * 1_000,
        });
        let Ok(slot) = entered else {
            // The table is uncapped on this node, so this is the table declining for a reason that
            // is not capacity. It is still an answer rather than a panic.
            return Err(NotServed::Unavailable);
        };
        let meter = AccrualMeter::new();
        let ended = busbar_kernel::teller::run_unit(
            &self.kernel,
            &unit,
            &UnitCtx {
                key,
                origin: busbar_caps::OriginKind::Client,
                session: None,
                generation: busbar_kernel::registry::Generation::FIRST,
                admin_listener: false,
                kernel_verb_only: false,
            },
            busbar_kernel::teller::Run {
                cell: slot.cell(),
                parent: None,
                leases: slot.leases(),
                gauge: &self.gauge,
                canary: &self.canary,
                meter: &meter,
            },
        );
        // THE EXIT ARM. The loop took the hold out of the cell and handed back a POSTING, which has
        // moved no balance and left no record until something settles it.
        let refusal = crate::root::units_mcp::refusal_of(&ended);
        let settled = self.settle(&unit, &principal, ended);
        match refusal {
            // A refusal the loop raised, rendered by the caller in this protocol's own vocabulary.
            Some(refusal) => Err(NotServed::Refused(refusal)),
            // `None` is a unit that SETTLED — its bytes are its answer. The byte source runs HERE
            // and nowhere else on this path.
            None if settled => Ok(answer()),
            None => Err(NotServed::Unavailable),
        }
    }

    /// Put what the loop posted onto the node's one book, and say whether the unit settled at all.
    ///
    /// Two ways this answers `false`, and each is a statement rather than a swallow: the node's sweep
    /// took the hold first, so this unit will produce no answer; or the loop ended in a shape that
    /// carries no posting. A journal that refuses the record is NOT a settlement rolled back — the
    /// books have moved and the value was delivered, and what is lost is the proof, which the exit
    /// arm's own error says.
    fn settle(
        &self,
        unit: &McpUnits<'_>,
        principal: &PrincipalId,
        ended: busbar_kernel::teller::Ended,
    ) -> bool {
        let busbar_kernel::teller::Ended::Settled { end, .. } = ended else {
            return false;
        };
        let Ok(posted) = end.into_posted() else {
            // The loop already recorded the durability loss on the end it sealed, and there is no
            // posting to move. The unit still SETTLED — its answer is owed.
            return true;
        };
        let _settled = unit.settle(principal, posted, &self.kernel.durability_token());
        true
    }
}

/// The trust unit, as this node borrows it.
///
/// A unit struct and a `static` rather than a field, and both facts are the same fact: what a
/// verification depends on is the three views handed beside the request, never a table this unit
/// keeps. A second one would be a second opinion about which destinations a node may reach.
static TRUST: busbar_unit_trust::Trust = busbar_unit_trust::Trust;

#[cfg(test)]
#[path = "tests/node_mcp.rs"]
mod tests;

// ─────────────────────────────────────────────────────────────────────────────
// The serving seam
// ─────────────────────────────────────────────────────────────────────────────

/// **THE PLANE'S DISPATCH REACHES THIS NODE THROUGH HERE**, and through nothing else.
///
/// One method and one direction: the plane hands over what arrived and the document the class
/// already had, and the node answers with that document on the arm where the loop settled. The node
/// never sees the bytes it returns, and the plane never sees the steps they passed. That is the whole
/// of the contract, and it is what makes each class's move provable — the document is the SAME
/// function that produced the class's answer when it still had a `match` arm, so a byte that changed
/// is a byte the move changed.
///
/// A LIFT, and deliberately nothing more. Every judgement is [`McpNode::serve_class`]'s; what this
/// impl owns is the translation between the two crates' spellings of one arriving request, and the
/// translation of the loop's ending into the plane's own refusal vocabulary. A conversion that
/// decided anything would be a second serving path wearing an adapter's clothes.
/// **THE COMPOSED STACK THE DOCUMENT SURFACE STANDS ON**, bottom layer first.
///
/// It ends at the claim's own transport, and that is not decoration: `units_mcp::arrival` refuses an
/// arrival record whose chain does not END at the claim that matched, and it reads the top rather
/// than membership precisely because the streamed surface stands on the document one — a chain read
/// by membership would let a stream be matched as a request.
///
/// It is HERE and not in the plane's serving crate because a stack is a fact about a DEPLOYMENT:
/// what is under a surface and what is over it is what the composition wired, and the retiring crate
/// that used to hold this constant was holding an answer it is not the one asked.
#[cfg(feature = "plane-mcp")]
const DOCUMENT_CHAIN: &[&str] = &["tcp", "tls", claims::TRANSPORT_HTTP];

/// **THE COMPOSED STACK A PIPE STANDS ON**, which is one layer.
///
/// There is no TCP under a pipe and no TLS over it, so a chain that reported either would be a
/// transport describing a connection it does not have.
#[cfg(feature = "plane-mcp")]
const PIPE_CHAIN: &[&str] = &[claims::TRANSPORT_STDIO];

#[cfg(feature = "plane-mcp")]
impl busbar_mcp::mcp::method::ServingNode for McpNode {
    fn serve(
        &self,
        request: &busbar_mcp::mcp::method::ClassRequest<'_>,
        answer: &dyn Fn() -> axum::response::Response,
    ) -> Result<axum::response::Response, busbar_mcp::mcp::method::Denied> {
        // THE SURFACE PAIRED WITH THE CLAIM AND THE STACK UNDER IT, in the one kind that may make
        // the pairing. The plane's serving crate says which of its two doors the frame came through;
        // which claim that door is matched by, and what is composed beneath it, is what this
        // deployment wired and is read here.
        let (claim_transport, chain) = match request.surface {
            busbar_mcp::mcp::method::Surface::Document => (claims::TRANSPORT_HTTP, DOCUMENT_CHAIN),
            busbar_mcp::mcp::method::Surface::Pipe => (claims::TRANSPORT_STDIO, PIPE_CHAIN),
        };
        let arriving = Arriving {
            method: request.method,
            request_bytes: request.request_bytes,
            key: request.key,
            claim_transport,
            chain,
            // No credential is read off the frame on any surface of this plane: the identity chain
            // ran before any plane code did, and `McpDraft::admitted` is what carries its outcome.
            // Carrying a credential here too would be handing the authenticate step a second input
            // for a decision it no longer makes.
            credential: None,
            from_session: request.from_session,
        };
        self.serve_class(&arriving, answer)
            .map_err(|not_served| match not_served {
                NotServed::Refused(refusal) => busbar_mcp::mcp::method::Denied::Refused(refusal),
                // A method the plane's own table does not name as a client class cannot reach here —
                // the seam looked the class up in that table before it called this node. It is mapped
                // rather than unwrapped because a path that cannot be taken still has to say something
                // if it is, and "no answer" is the honest thing to say about a unit that never opened.
                NotServed::NoSuchClass | NotServed::Unavailable => {
                    busbar_mcp::mcp::method::Denied::Unavailable
                }
            })
    }
}
