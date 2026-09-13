// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE AGENT-TO-AGENT NODE, AND THE WAY IN.**
//!
//! Two things, and they are two halves of one statement: the composition root serves this plane's
//! units through the kernel's loop, and the composition root is what MOUNTS the surface those units
//! answer on.
//!
//! ## The way in, because there was not one
//!
//! The LLM node is reached because the substrate calls a root-installed bare `fn`. This plane has
//! nothing of the kind: its surface is eighteen `PlaneRouteSpec` rows returned by a PLANE-OWNED `fn`
//! on `busbar_a2a::PLANE_DECL`, which the root pushed wholesale. So the root composes ITS OWN
//! declaration over the plane's — every field copied, `routes` replaced by a root function that
//! calls the plane's own and swaps the HANDLER of the rows whose classes have moved.
//!
//! `(path, method, auth)` pass through VERBATIM. That is the whole security statement: the
//! `CoreRouteTable` row the auth middleware reads, and the `required_scope(method, path)` it derives,
//! are recorded by the same act and from the same values as before. What changes is which body
//! answers, and only for the methods [`MOVED_ONTO_THE_NODE`] names.
//!
//! The plane's declaration is NEVER edited. The swap keeps an `Arc::clone` of the plane's own
//! handler and DELEGATES every unmoved method to it. That is not building beside: a moved class's
//! arm is deleted from the plane in the same commit that moves it, so exactly one body answers any
//! one method.
//!
//! ## What this node is composed over, and why none of it is a stand-in
//!
//! The node borrows the composition's REAL halves — the deployment's own auth chain, its own
//! directory-bound authentication seams, its own rate card projected into the door's pricer, the
//! process's ONE book, the node's ONE breaker and the operator's own `groups:` tree. A node built
//! over `Pricer::flat(0)` and an empty `AuthChain` would be a node whose authenticate step admits
//! every caller anonymously and whose door prices nothing, and BOTH of those look like they work.
//! The empty chain is the sharper of the two: `AuthChain::is_open` is exactly "no module and no keys
//! arm", so an empty chain is not an inert placeholder — it is the OPEN FRONT DOOR, wired in front of
//! a plane the operator authenticated.
//!
//! So [`compose_chain`] reads the chain the operator CONFIGURED and answers `None` where this
//! composition has no unit-side module for what it names. `None` does not mount. An absent node
//! delegates every method to the plane's own handler, which is the serving path this deployment
//! already had — never a door quietly opened on the way past.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use busbar_caps::{ArrivalRecord, PrincipalId, ReasonCode, StepName};
use busbar_contract::dest::DestinationFacts;
use busbar_contract::ids::OpClassId;
use busbar_contract::unit::{FinishClass, ResourceLocator};
use busbar_substrate::plane::registry::PlaneDecl;
use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneRouteFuture, PlaneRouteSpec};
use busbar_unit_admission::{ChainWalk, GroupTable, Pricer};
use busbar_unit_scope::{Grants, Scope};
use busbar_unit_trust::{BreakerQuery, GuardPolicy, KindFacts, PoolView, Resolver};

use crate::root::bindings::{resolve_bindings, Node};
use crate::root::units_a2a::{A2aBindings, A2aDraft, A2aUnits, RecordLegs, SCOPE_KIND_AGENT};

/// **THE CLASSES SERVED THROUGH THIS NODE**, by every spelling that reaches them.
///
/// EMPTY, and empty is a measurement rather than a stage of construction: this commit lands the
/// seam and moves no class. A method absent from this table is answered by the plane's own handler,
/// byte for byte, because the swap below hands it the `Arc` it kept.
///
/// This plane speaks TWO protocol versions, so a class moved in one dialect and left in the other is
/// a deployment whose answer depends on how the caller spelled the call. Every row a class is moved
/// in carries both spellings or the class is not moved.
pub const MOVED_ONTO_THE_NODE: &[&str] = &[];

/// The paths whose handler this root swaps, when it swaps one.
///
/// The three JSON-RPC doors of this plane and nothing else: the mount, its trailing-slash twin (an
/// HTTP client given the mount as a BASE URL sends the second), and the per-agent door. The
/// `RouteAuth::None` rows — the well-known card and the RFC 9728 metadata document — are NOT here
/// and are not candidates: they are unauthenticated ON PURPOSE, and putting an approve step in front
/// of a deliberately public endpoint is a collision bought in advance.
fn is_served_path(path: &str) -> bool {
    matches!(path, "/a2a" | "/a2a/") || (path.starts_with("/a2a/agents/") && path.ends_with('}'))
}

// ─────────────────────────────────────────────────────────────────────────────
// The composed declaration
// ─────────────────────────────────────────────────────────────────────────────

/// **THE ROOT'S OWN PLANE DECLARATION**, composed over the plane's.
///
/// Built once, at registration, and leaked: `install_planes` takes a `&'static` slice, and a
/// declaration is read for the life of the process. Every field but one is the plane's, copied by
/// identity — the thirty-three fields are each `Copy`, which is what makes `..*plane` a copy rather
/// than a restatement, and a field the plane adds tomorrow arrives here with nothing edited.
#[must_use]
pub fn composed_decl() -> &'static PlaneDecl {
    static COMPOSED: OnceLock<&'static PlaneDecl> = OnceLock::new();
    COMPOSED.get_or_init(|| {
        let plane: &'static PlaneDecl = &busbar_a2a::PLANE_DECL;
        let composed = PlaneDecl {
            routes: Some(composed_routes),
            ..*plane
        };
        &*Box::leak(Box::new(composed))
    })
}

/// The plane's own rows, with the served ones' handlers swapped.
///
/// A bare `fn`, because that is what the declaration's field is. It names the plane's declaration
/// statically rather than capturing it, which is the same reason the LLM ingress tables are bare.
fn composed_routes(slot: &dyn Any) -> Vec<PlaneRouteSpec> {
    let plane_routes = busbar_a2a::PLANE_DECL
        .routes
        .expect("the a2a plane declares its own routes");
    let mut rows = plane_routes(slot);
    for row in &mut rows {
        if !is_served_path(&row.path) {
            continue;
        }
        // THE PLANE'S OWN BODY, KEPT. It is what every unmoved method is answered by, and it is
        // what a deployment this node did not mount on is answered by for every method.
        let original = Arc::clone(&row.handler);
        row.handler = Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
            let original = Arc::clone(&original);
            Box::pin(async move { serving_entry(original, ctx).await })
        });
    }
    rows
}

/// **THE NODE'S SERVING ENTRY.**
///
/// One decision and no others: is the method this envelope names one this node serves? If it is not
/// — and today none is — the plane's own handler answers, having been handed the request untouched.
///
/// The envelope is read for a METHOD NAME and nothing else, with the neutral JSON-RPC vocabulary
/// every dialect on this door shares. It is not a decode: a body this root cannot read is a body
/// this root has no opinion about, and it goes to the handler that always read it.
async fn serving_entry(
    original: busbar_substrate::plane_routes::PlaneRouteFn,
    ctx: PlaneReqCtx,
) -> busbar_substrate::plane_routes::PlaneResponse {
    let method = envelope_method(&ctx.body);
    let served = method
        .as_deref()
        .is_some_and(|m| MOVED_ONTO_THE_NODE.contains(&m));
    if !served {
        return original(ctx).await;
    }
    // No class has moved, so this arm is unreachable today and says so rather than guessing: the
    // commit that moves the first class is the commit that fills it in, and until then delegating is
    // the only answer that cannot be wrong.
    original(ctx).await
}

/// The method a JSON-RPC envelope names, or nothing.
fn envelope_method(body: &axum::body::Bytes) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("method")?
        .as_str()
        .map(ToOwned::to_owned)
}

// ─────────────────────────────────────────────────────────────────────────────
// The node
// ─────────────────────────────────────────────────────────────────────────────

/// The name resolver this node's money-free classes are guarded through.
///
/// A REFUSAL, not a fixed address. Every class this node serves today reaches this plane's own
/// durable records and dials nothing, so a resolution on this path cannot happen — and a fixed
/// address would make a hop that reached here LOOK guarded. The class that dials is the class that
/// binds a real resolver, and it is below the hop line.
struct NeverDialled;

impl Resolver for NeverDialled {
    fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Err(format!(
            "this node's money-free classes reach no upstream, so {host} was never to be resolved"
        ))
    }
}

static NEVER_DIALLED: NeverDialled = NeverDialled;

/// The deployment's metadata denylist, as this node's guard seam reads it.
///
/// Empty is the NARROWEST thing it can be: an empty denylist blocks the built-in metadata hosts and
/// carves nothing out, which is the shipped posture.
static DENYLIST: std::sync::LazyLock<busbar_unit_trust::Denylist> =
    std::sync::LazyLock::new(busbar_unit_trust::Denylist::default);

/// The trust unit, as this node borrows it. A unit struct and a `static`, and both facts are one
/// fact: what a verification depends on is the views handed beside the request, never a table it
/// keeps.
static TRUST: busbar_unit_trust::Trust = busbar_unit_trust::Trust;

/// Every destination kind passes the per-kind rules, because the only destination a class this node
/// serves names is one of this plane's own records — which carries no lane and is never dialled.
struct RecordsOnly;

impl KindFacts for RecordsOnly {
    fn allow_listed(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn net_guard_passes(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn transport_key_resolves(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn lane_permitted_for_op_class(&self, _lane: &str) -> bool {
        true
    }
    fn session_upstream_ok(&self) -> bool {
        true
    }
    fn session_principal_matches(&self) -> bool {
        true
    }
    fn client_selector_ok(&self) -> bool {
        true
    }
    fn await_deadline_ok(&self) -> bool {
        true
    }
    fn verb_scope_held(&self) -> bool {
        true
    }
    fn nested_plane_ok(&self) -> bool {
        true
    }
    fn plane_record_ok(&self) -> bool {
        true
    }
    fn peer_lease_live(&self) -> bool {
        true
    }
    fn upgrade_ok(&self) -> bool {
        true
    }
    fn unit_price_within_max(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn breaker_admits(&self, _dest: &DestinationFacts, _at: &BreakerQuery<'_>) -> bool {
        true
    }
}

/// What the pool guards read about ONE caller.
///
/// Built per request, because every one of its answers is about the caller's own key: which pools
/// that key may target is `allowed_scopes`, and a view resolved at boot would answer every caller
/// with the first caller's authority.
struct CallerPools {
    scopes: Option<Vec<String>>,
    keyed: bool,
}

impl PoolView for CallerPools {
    fn key_scopes(&self) -> Option<&[String]> {
        self.scopes.as_deref()
    }

    fn pool_allowed(&self, pool: &str) -> bool {
        match &self.scopes {
            // A key that names no restriction admits every pool, which is the shipped posture for a
            // key minted without a scope list.
            None => true,
            Some(scopes) => scopes.iter().any(|s| s == pool),
        }
    }

    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        None
    }

    fn is_configured(&self, _name: &str) -> bool {
        true
    }

    fn pricing_enabled(&self) -> bool {
        // NOTHING IS PRICED ON THIS PATH, and that is the money statement for the classes this node
        // serves: they reach this plane's own records and no upstream, so there is no per-unit price
        // for a card to be missing an entry for. The class that dials is the class that reads one.
        false
    }

    fn is_unpriced(&self, _name: &str) -> bool {
        false
    }

    fn has_key(&self) -> bool {
        self.keyed
    }
}

/// **THE NODE.** One per process, built at boot, borrowed by every unit.
///
/// The long-lived half and nothing else: the kernel whose seal mints every step's token, the table a
/// unit's hold lives in, the gauge the door's leases go back to, the counts the canary balances, the
/// monotonic clock that orders this node's records against each other, and the one
/// [`Node`](crate::root::bindings::Node) every plane's leg bindings are resolved out of.
pub struct A2aNode {
    kernel: busbar_kernel::teller::Kernel,
    inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_caps::Canary,
    /// THE NODE'S MONOTONIC CLOCK. A counter that only ever goes up, whatever the wall clock does,
    /// so two units of one second are still orderable. It lives on the node because ordering is a
    /// statement about a SET of units.
    mono: AtomicU64,
    next_key: AtomicU64,
    /// The one resolver's node, with this plane mounted on it: one door, one book, one breaker.
    bindings: Node,
    /// The configured limit tree, resolved at boot into the shape the door walks.
    groups: GroupTable,
    /// This plane's durable records, over the node's one store handle.
    records: RecordLegs,
    /// The seal the trust unit's verified destinations are minted under, taken once from this node's
    /// own kernel at construction.
    trust_token: busbar_caps::TrustToken,
    /// How long a task's capabilities may outlive its last move, off the deployment.
    task_ttl_secs: u64,
}

impl std::fmt::Debug for A2aNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aNode")
            .field("mounted", &self.bindings.mounted())
            .finish_non_exhaustive()
    }
}

/// What the composition already knew about one arriving request, as the node is handed it.
///
/// Every field is a fact somebody else established before this unit existed — the route middleware
/// resolved the key, the ingress read the envelope, the catalogue named the pool. A constructor
/// taking them singly is one a caller can fill in wrongly one at a time.
pub struct Arriving<'a> {
    /// The operation class the plane's own table names this method.
    pub op: OpClassId,
    /// The whole request document's length, which is what this plane prices its input on.
    pub request_bytes: u64,
    /// The caller's resolved key, or `None` on an ungoverned deployment.
    pub key: Option<&'a busbar_api::VirtualKey>,
    /// The credential the caller presented on THIS frame.
    pub credential: Option<&'a str>,
    /// The audience this plane's tokens must be bound to, as the deployment published it.
    pub expected_aud: Option<String>,
    /// The pool this unit's agent is reached on — the catalogue's answer, never a name invented here.
    pub pool: &'a str,
    /// The transport layers the request arrived over, bottom layer first.
    pub chain: &'static [&'static str],
    /// Where the bytes came from, as the transport recorded it.
    pub source: String,
    /// The port they arrived on.
    pub port: u16,
}

/// Why the node did not serve a class it was asked for.
#[derive(Debug)]
pub enum NotServed {
    /// The loop stopped the unit at a step, and this is the step and the reason.
    Refused(StepName, ReasonCode),
    /// The loop ran and ended without an answer and without a refusal — the node's own sweep took
    /// the hold first, or the in-flight table declined the unit for a reason that is not capacity.
    Unavailable,
}

impl A2aNode {
    /// Compose the node this plane is served by.
    ///
    /// Takes the node the bindings were resolved on, because it is BOOT's: a node that built its own
    /// would be a second door and a second book, and both halves of that look healthy because an
    /// empty ledger reconciles.
    #[must_use]
    pub fn over(
        bindings: Node,
        groups: GroupTable,
        records: RecordLegs,
        task_ttl_secs: u64,
    ) -> Self {
        A2aNode {
            // THE SEAL this node's verified destinations are minted under.
            //
            // MINTED HERE, AND THIS IS THE ONE SEAM THE KERNEL HAS NOT OPENED. `Trust::verify`
            // requires a `TrustToken` beside the step's own `UnitToken<Verify>`, and the kernel
            // mints an admit token, a transport-key token, a durability token and a usage token
            // publicly but NOT this one — so a composition assembling this plane's bindings has
            // nowhere to obtain one except the seal. It is stated rather than worked around: the
            // repair is a `Kernel::trust_token()` sibling of the other four, which is a KERNEL line
            // and therefore a MOVE, not an addition. Until it lands, `token-sealed:kernel-seal`
            // reads this line and is RIGHT to.
            trust_token: busbar_caps::TrustToken::mint(
                &busbar_caps::KernelSeal::acquire_for_kernel(),
            ),
            kernel: crate::root::kernel::new_kernel(),
            // The data listener already carries the operator-configured inbound-concurrency layer,
            // which is where admission-to-the-node is decided. A second cap here would be a second
            // answer to one question and the one that refused first would decide, silently. So the
            // table is opened at a ceiling no deployment reaches — it is still a real table, because
            // a hold still has to live somewhere and the sweep still walks it.
            inflight: busbar_kernel::inflight::InFlight::new(usize::MAX, 0),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            mono: AtomicU64::new(0),
            next_key: AtomicU64::new(1),
            bindings,
            groups,
            records,
            task_ttl_secs,
        }
    }

    /// Which planes this node mounted, in key order — the instrument that says the mount happened.
    #[must_use]
    pub fn mounted(&self) -> Vec<&'static str> {
        self.bindings.mounted()
    }

    /// **SERVE ONE CLASS THROUGH THE LOOP.**
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a class that used to be
    /// answered by a `match` arm. What comes back on the served arm is what `answer` produced — this
    /// function chooses the PATH and never the bytes.
    ///
    /// `answer` is invoked on exactly one arm: the unit settled and the loop raised no refusal.
    /// Invoking it before the loop would be answering a caller the door has not admitted; invoking it
    /// on a refusal would be answering twice.
    ///
    /// # Errors
    ///
    /// The loop refused the unit at a step, or the unit ended without an answer and without a refusal.
    pub fn serve_class<T>(
        &self,
        arriving: &Arriving<'_>,
        answer: impl FnOnce() -> T,
    ) -> Result<T, NotServed> {
        let Some(bound) = resolve_bindings(busbar_a2a::PLANE_DECL.key, &self.bindings) else {
            // A plane this node did not mount. An absence and not an empty binding: a leg driven over
            // a default door admits and charges against something the operator never configured, and
            // it would look like it worked.
            return Err(NotServed::Unavailable);
        };
        let now = busbar_substrate_values::store::now_ms() / 1_000;
        let mono = self.mono.fetch_add(1, Ordering::AcqRel);

        let principal = PrincipalId::new(arriving.key.map_or_else(
            || busbar_api::AuthPrincipal(None).actor_id(),
            |k| k.id.as_str(),
        ));
        let draft = A2aDraft {
            op: Some(arriving.op),
            // The scheme the carrier declared. One, because one is what this plane's doors carry.
            narrowing: Some("bearer"),
            declared_schemes: &["bearer"],
            // Every door of this plane presents its credential on the frame; there is no bound
            // session here, which is what makes revocation gate every unit on this path.
            from_session: false,
            credential: arriving.credential.map(ToOwned::to_owned),
            expected_aud: arriving.expected_aud.clone(),
            // THIS PLANE'S OWN RECORD, which is where a money-free class's answer comes from. It
            // carries no lane, so it never enters the sealed set and is never dialled.
            destination: DestinationFacts::PlaneRecord {
                schema: busbar_plane_a2a::records::SCHEMA_PUSH_CONFIG,
                op: busbar_plane_a2a::records::OP_GET,
            },
            resource: Some(ResourceLocator {
                kind: SCOPE_KIND_AGENT,
                name: "",
            }),
            // The class's own document reads the record it needs. A leg here would be the same read
            // made twice, once by the plan and once by the answer.
            legs: Vec::new(),
            request_bytes: arriving.request_bytes,
            // THE ANSWER'S SIZE IS NOT KNOWN HERE and this node does not pretend it is. The class
            // that frames its own bytes through the plane's face is the class that can fill it in.
            response_bytes: 0,
            finish: FinishClass::Complete,
            streaming: false,
            arrival: ArrivalRecord {
                source: arriving.source.clone(),
                port: arriving.port,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: arriving.chain.to_vec(),
            },
        };

        let chain = self
            .groups
            .chain_for(
                principal.as_str(),
                arriving.key.and_then(|k| k.group.as_deref()),
            )
            .ok();
        let pools = CallerPools {
            scopes: arriving.key.and_then(|k| {
                k.allowed_scopes
                    .as_ref()
                    .map(|s| s.iter().map(|r| r.value.clone()).collect())
            }),
            keyed: arriving.key.is_some(),
        };
        let bindings = A2aBindings {
            auth: bound.auth,
            auth_bindings: bound.auth_bindings,
            // THE SEAL this node's verified destinations are minted under, off THIS NODE'S OWN
            // kernel — the same seal the loop mints its verify step's token from. Carried rather
            // than minted at the step because `Origin::seal` and `TrustToken::mint` take the
            // kernel's seal, and a unit is lent its tokens rather than able to conjure one.
            trust_token: &self.trust_token,
            pools: &pools,
            kinds: &RECORDS_ONLY,
            breaker: bound.breaker,
            resolver: &NEVER_DIALLED,
            // Read off the unit's own default rather than stated here, because what a deployment
            // permits a hop to reach is the deployment's statement and not this node's.
            guard: GuardPolicy::default(),
            denylist: &DENYLIST,
            // No class this node serves dials an agent, so no card pin is consulted. The class that
            // dials carries the operator's approved list with it.
            pinned: &[],
            door: bound.door,
            chain: chain.as_ref(),
            pricer: bound.pricer,
            // The deployment's card prices this plane's byte class at nothing until a class that
            // frames bytes moves; the flat fee is the pricer's and is read there.
            bytes_nanos: 0,
            records: &self.records,
            meter_policy: bound.meter_policy,
            scope_policy: bound.scope_policy,
            durability: bound.durability,
            pool: arriving.pool,
            now,
            task_ttl_secs: self.task_ttl_secs,
            mono,
            origin: bound.origin,
        };

        // THE CALLER'S AUTHORITY over the resources the plane names. What a key NARROWS is which
        // pools it may target, which is `allowed_scopes` and is read by the pool view above — not a
        // read/write lattice. So the authority handed to the approve step is the full one and the
        // narrowing happens where the key states it.
        let unit = A2aUnits::new(bindings, draft, Grants::of(Scope::Full));

        let hold = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &crate::root::kernel::AdmissionDoor,
            principal.clone(),
        );
        let key = busbar_caps::UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed));
        let Ok(slot) = self.inflight.insert(busbar_kernel::inflight::Enter {
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
            now: now * 1_000,
        }) else {
            // The table is uncapped on this node, so this is the table declining for a reason that is
            // not capacity. It is still an answer rather than a panic.
            return Err(NotServed::Unavailable);
        };
        let meter = busbar_kernel::teller::AccrualMeter::new();
        let ended = busbar_kernel::teller::run_unit(
            &self.kernel,
            &unit,
            &busbar_kernel::teller::UnitCtx {
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
        let refused = refusal_of(&ended);
        let settled = self.settle(&unit, &principal, ended);
        match refused {
            Some((step, reason)) => Err(NotServed::Refused(step, reason)),
            None if settled => Ok(answer()),
            None => Err(NotServed::Unavailable),
        }
    }

    /// Put what the loop posted onto the node's one book, and say whether the unit settled at all.
    ///
    /// Two ways this answers `false`, and each is a statement rather than a swallow: the node's sweep
    /// took the hold first, so this unit will produce no answer; or the loop ended in a shape that
    /// carries no posting. A journal that refuses the record is NOT a settlement rolled back — the
    /// books have moved and the value was delivered, and what is lost is the proof.
    fn settle(
        &self,
        unit: &A2aUnits<'_, busbar_unit_admission::InMemoryCells>,
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

/// The per-kind facts this node's one destination is judged against.
///
/// A `static` for the same reason the trust unit is: it is a property of the NODE rather than of a
/// request, and a second would be a second opinion about where a unit may go.
static RECORDS_ONLY: RecordsOnly = RecordsOnly;

/// The step and the reason a refused ending carries, or nothing where the unit was not refused.
///
/// Written here rather than read off another plane's unit file: the mapping is the KERNEL's ending
/// and the kernel's vocabulary, and a plane's file is compiled out with its plane.
fn refusal_of(ended: &busbar_kernel::teller::Ended) -> Option<(StepName, ReasonCode)> {
    match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => match end.outcome() {
            busbar_caps::Outcome::Refused(step, reason) => Some((step, reason)),
            // Every other ending either delivered an answer or lost the unit before one could be
            // written, and neither is a refusal a caller is owed an envelope for.
            _ => None,
        },
        // The node's own sweep took the hold first, so this unit will not produce an answer at all.
        busbar_kernel::teller::Ended::AlreadySettled => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The mount
// ─────────────────────────────────────────────────────────────────────────────

/// THE PROCESS'S ONE NODE, once the composition root has built it.
///
/// A cell rather than a field on anything, because the serving entry above is reached through a
/// declaration installed BEFORE any configuration is read — the plane axis is registered at the top
/// of `main`, and the node cannot exist until the store is open, the keys are hydrated and the rate
/// card is resolved.
static NODE: OnceLock<&'static A2aNode> = OnceLock::new();

/// Install the process's one node. Boot only, once; a second call is a no-op rather than a silent
/// swap of the node a live request is already being served by.
pub fn install(node: &'static A2aNode) {
    let _ = NODE.set(node);
}

/// The process's one node, where the composition root mounted one.
#[must_use]
pub fn node() -> Option<&'static A2aNode> {
    NODE.get().copied()
}

/// **THE DEPLOYMENT'S OWN AUTH CHAIN**, or nothing at all.
///
/// `Some` when every position the operator configured is one this composition has a unit-side arm
/// for. Today that is the built-in signed-key verifier, which is not a boxed module at all: it is an
/// engine-side arm the chain runs after every module, over the directory the node binds — so a chain
/// that names only `keys` has an empty module list and a SHUT front door.
///
/// An EMPTY chain is `Some` and is not a stand-in: `auth.chain: []` is the open front door the
/// operator wrote down, and refusing to mount on it would be this root disagreeing with the
/// deployment's own posture.
///
/// `None` is a chain naming a provider backed by a PLUGIN module. Those implement the plugin face,
/// not the unit face, and this composition has no arm for one — so it does not mount, and the
/// plane's own handler answers every method exactly as it did. Silently composing an empty chain
/// there would open the front door of a deployment that authenticates.
#[must_use]
pub fn compose_chain(
    chain: &[busbar_substrate::config::auth::AuthChainEntry],
) -> Option<busbar_unit_auth::AuthChain> {
    let keys_in_chain = chain
        .iter()
        .any(|e| e.module == busbar_unit_auth::chain::KEYS_MODULE);
    let unknown = chain
        .iter()
        .any(|e| e.module != busbar_unit_auth::chain::KEYS_MODULE);
    (!unknown).then(|| busbar_unit_auth::AuthChain::new(Vec::new(), keys_in_chain))
}

/// **THE DEPLOYMENT'S OWN PRICER**, projected from the same two configured figures the engine's cost
/// model and the root's rate-card history read.
///
/// One configuration, three readings, and no arithmetic here: the four micro-per-token floats go
/// through [`busbar_unit_admission::RateNanos::from_micros_per_token`], which is the pricing law's
/// own rounding and clamp, and the fee is clamped by the pricer's own constructor. A second
/// projection is how a deployment comes to be ADMITTED at one rate and BILLED at another.
///
/// No `rate_card:` is `flat(fee)` and NOT `flat(0)`: absent prices every class at nothing and STILL
/// charges the configured flat fee, which is exactly what the previous release bills for that
/// deployment.
#[must_use]
pub fn compose_pricer<'r>(
    lanes: impl IntoIterator<Item = (&'r str, busbar_substrate::billing::RawTierRates)>,
    per_request_fee: i64,
    present: bool,
) -> Pricer {
    if !present {
        return Pricer::flat(per_request_fee);
    }
    let rates = lanes
        .into_iter()
        .map(|(lane, raw)| {
            (
                lane.to_owned(),
                busbar_unit_admission::RateNanos::from_micros_per_token(
                    raw.input,
                    raw.output,
                    raw.cache_read,
                    raw.cache_write,
                ),
            )
        })
        .collect();
    Pricer::with_card(per_request_fee, rates)
}

#[cfg(test)]
#[path = "tests/node_a2a.rs"]
mod tests;
