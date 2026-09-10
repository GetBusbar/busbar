// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the leg and the mount beside it carry the
// same line: this is composition of the SERVING path and it names items that exist only under this
// feature. Declared in `root/mod.rs` under `root-a2a`, so a plane-gated module is not named from
// code under a different feature.
#![cfg(feature = "root-a2a-serve")]

//! THE A2A PLANE'S COMPOSITION AT BOOT: every binding resolved, from configuration this deployment
//! already has, or the node does not bind a listener.
//!
//! ## The finding this file is the answer to
//!
//! `A2aLeg::assemble` had no production caller. Ten of its sources had no boot resolution at all —
//! the guard, the pin list, the breaker, the door, the group table, the two money halves, the store,
//! the key scopes and the authentication chain — and the audience had none either, which meant that
//! reading a bearer at this plane's door would have accepted every token this node's own signing key
//! ever minted, for any surface. So the leg existed, the mount existed, and nothing composed either.
//! This file is that composition.
//!
//! ## NO INVENTED CONFIGURATION, and the table says where each one comes from
//!
//! Not one key here is new. [`BOOT_SOURCES`] is one row per thing this file resolves, and each row
//! names the configuration it is read from or the composition-root value it is taken from. A source
//! that could not be named REFUSES BOOT with the operator-facing sentence, rather than defaulting:
//! an empty chain admits anonymously, an empty group table says yes to every cap, an empty denylist
//! guards nothing, and every one of those boots clean and serves traffic.
//!
//! ## Two halves, because configuration and the routers do not exist at the same moment
//!
//! [`read`] runs while the resolved configuration is still in scope, and answers with values that
//! name no configuration type. [`mount`] runs after the routers are built, when the book and the
//! governance state exist, and answers with the wrapped router. Splitting them is what keeps the
//! composition root's own file down to one line at each seam rather than a screen of resolution.
//!
//! ## What this file does NOT do
//!
//! It decides nothing about a request, holds no protocol knowledge beyond asking the plane its own
//! declarations, and shapes no wire. What it does is read configuration and hand values to the
//! things that own them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use busbar_core::{config, config_validate, governance::GovState};
use busbar_plane_a2a::{A2aPlane, Agent};
use busbar_unit_admission::{Door, InMemoryCells};
use busbar_unit_auth::Auth;
use busbar_unit_trust::net::{Denylist, GuardPolicy};

use crate::root::data_plane::{data_chain, ChainPosition, PlaneChain};
use crate::root::durability::Durability;
use crate::root::units_a2a_leg::{A2aLeg, A2aLegSources};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHERE EVERY BOOT-RESOLVED VALUE COMES FROM
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// ONE ROW PER THING THIS FILE RESOLVES, and the configuration or root value it comes from.
///
/// The r31g hand-back listed ten binding sources plus the audience as having no boot resolution.
/// This is that list, answered, as DATA rather than as prose — the cell beside this file asserts
/// every row names a real place, so "everything is sourced" cannot rot into a comment that was true
/// once.
///
/// The second column is a LOCATION. Where a deployment writes the value down, the row names the
/// configuration key verbatim; where the composition root already holds it for its other planes, the
/// row names the root's own resolution.
pub const BOOT_SOURCES: &[(&str, &str)] = &[
    (
        "agents",
        "config `agents:` — the plane's own registration set, each agent's id, its declared \
         `url:`'s host, and the lane it is reached on",
    ),
    (
        "guard",
        "config `agents.<name>.allow_private:` — folded to the NARROWEST across the configured \
         set, because one leg-wide policy may not be looser than any agent's own",
    ),
    (
        "pinned",
        "config `agents.<name>.pin.fingerprint:` — the agents whose declared pin carries an \
         approved fingerprint, exactly as `pin.rs`'s artifact reads it",
    ),
    (
        "denylist",
        "config `security.blocked_metadata_hosts:` ∪ `security.allow_metadata_hosts:` ∪ \
         `security.allow_all_metadata:`, over the built-in list `--print-metadata-blocklist` prints",
    ),
    (
        "breaker",
        "root: the node's breaker cells, read at the trust unit's own token-free width — the \
         destination's lifetime budget; the cooldown ladder is enforced at the dispatch below",
    ),
    (
        "door",
        "root: an admission door over in-memory ledger cells, the same shape the node's own \
         `ProductionUnits` opens",
    ),
    (
        "groups",
        "config `groups:` through `policy::group_table`, with each group's lease name interned \
         once at boot",
    ),
    (
        "meter_policy",
        "config `pools:` and `rate_card:` through `policy::build` — the lane expansions and the \
         comparable lane prices in name order, never the unit's own defaults",
    ),
    (
        "scope_policy",
        "root: `units_a2a::scope_policy`, the twelve entries `main()` already seals",
    ),
    (
        "rates",
        "root: `kernel::ROOT_CARD`, this deployment's resolved rates — the assembly refuses \
         before the boot's own resolution has happened, and the walk re-reads them",
    ),
    (
        "store",
        "root: the node's ONE governance store (`GovState::store`), the same handle the \
         governance path itself uses",
    ),
    (
        "auth",
        "config `auth.chain:` through `data_plane::data_chain` — the same builder every data \
         plane's door is resolved by, refusing any position it cannot honour",
    ),
    (
        "auth_bindings",
        "root: `AuthBindings` over this node's governance directory — the cache, the signed-key \
         verifier and the revocation view",
    ),
    (
        "expected_aud",
        "config `public_url:` joined to this plane's OWN declared mount by \
         `data_plane::PlaneChain::audience` — the RFC 8707 canonical URI, derived once",
    ),
    (
        "key_scopes",
        "not a boot value: a restriction is a property of the CALLER's key, and `None` here is \
         'no restriction named', which is a posture rather than a missing source",
    ),
];

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT ONE AGENT'S CONFIGURATION SAYS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// One configured agent, reduced to the four things this composition reads about it.
///
/// A value of this file's own rather than the plugin's configuration type, so every helper below can
/// be exercised against real inputs without a whole resolved deployment being built to reach them.
/// The projection from the configuration type is one function, [`declared_agents`], and it is the
/// only place that names the plugin's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredAgent {
    /// The name the operator gave this agent, which is the resource the scope unit judges.
    pub name: String,
    /// The host of the `url:` this agent is reached at.
    pub host: String,
    /// Whether this agent's own configuration lets a hop reach a private address.
    pub allow_private: bool,
    /// Whether this agent's declared pin carries an approved fingerprint.
    pub approved: bool,
}

/// THIS DEPLOYMENT'S AGENTS, off the type-erased `agents:` section.
///
/// The one place the plugin's configuration shape is named. Everything after this reads
/// [`DeclaredAgent`]s, which is what lets the folding rules below be proved against inputs a cell
/// can write down.
///
/// A section that is not this plane's answers with nothing — the honest reading of a deployment that
/// has no `agents:` block at all, which is the same deployment the legacy plugin mounts no route for.
///
/// AND THE PLANE CRATE IS A SEPARATE SWITCH FROM THE LEG, which is why the downcast is behind its
/// own cfg. `root-a2a-serve` says the root's leg is on the request path; `plane-a2a` says this
/// binary carries the A2A plane crate at all. The strong-form deletion test builds a binary with
/// the second removed and the first, being in `default`, still on — and an unconditional
/// `busbar_a2a::` here made that build fail to compile, which is the plane failing to be deletable
/// rather than the plane being absent. With the crate gone there is no configuration shape to
/// downcast TO, and a deployment whose `agents:` section this binary cannot read fronts no agents:
/// the same empty answer a deployment with no `agents:` block gets, which is the honest one.
#[cfg(not(feature = "plane-a2a"))]
fn declared_agents(_section: &dyn std::any::Any) -> Vec<DeclaredAgent> {
    Vec::new()
}

/// The same question, asked of a binary that CARRIES the plane crate. See the twin above.
#[cfg(feature = "plane-a2a")]
fn declared_agents(section: &dyn std::any::Any) -> Vec<DeclaredAgent> {
    let Some(agents) = section.downcast_ref::<busbar_a2a::a2a::config::AgentsCfg>() else {
        return Vec::new();
    };
    agents
        .agents
        .iter()
        .map(|(name, def)| DeclaredAgent {
            name: name.clone(),
            host: host_of(&def.url),
            allow_private: def.allow_private,
            // The pin's own reading: a root is DECLARED by every agent, and what makes it an
            // approval is a fingerprint under it. `pin.rs`'s artifact answers `None` for a
            // declared root with nothing approved, and this is that same question asked of the
            // same field rather than of the mechanism word beside it.
            approved: def.pin.fingerprint.is_some(),
        })
        .collect()
}

/// The host of one declared address, with the scheme, the credentials, the port and the path off it.
///
/// The guard and the pool view work in HOSTS: a scheme is how to speak to an address and a port is
/// where, and neither is part of who. Written as a cut rather than a parse because this file carries
/// no URL grammar and inventing one would be a second opinion about what a deployment configured.
fn host_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host_port
        .rsplit_once(':')
        .map_or(host_port, |(host, _)| host)
        .to_string()
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE FOLDING RULES
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **HOW FAR A HOP OF THIS PLANE MAY REACH**, folded to the narrowest the configured set allows.
///
/// `allow_private:` is written PER AGENT, and the leg carries ONE policy — the trust unit's guard is
/// bound once for the whole leg, because the plane's own destination facts do not yet name which
/// agent a unit reaches. Two directions were available and only one of them is safe: a leg-wide
/// policy that allowed private if ANY agent did would let a request bound for an agent the operator
/// deliberately kept on the public internet reach a private address, silently. So the fold is the
/// other way — the leg allows it only where EVERY configured agent was told it could — and a
/// deployment with no agents at all allows nothing, because "all of none" is vacuously true and is
/// exactly the reading that would open the guard on an empty deployment.
///
/// The three fields beside it are the trust unit's own declared bounds. They are not
/// `agents.<name>` values: a redirect budget, a body cap and a timeout are properties of a FETCH,
/// and the legacy plugin's own copies of them govern its card fetch rather than a unit's hop.
fn narrowest_guard(agents: &[DeclaredAgent]) -> GuardPolicy {
    GuardPolicy {
        allow_private: !agents.is_empty() && agents.iter().all(|a| a.allow_private),
        ..GuardPolicy::default()
    }
}

/// **THE AGENTS WHOSE CARD CARRIES AN APPROVED FINGERPRINT**, in configuration order.
fn approved_pins(agents: &[DeclaredAgent]) -> Vec<String> {
    agents
        .iter()
        .filter(|a| a.approved)
        .map(|a| a.name.clone())
        .collect()
}

/// **THE POSITIONS THIS DEPLOYMENT'S FRONT DOOR IS BUILT FROM**, off the resolved `auth.chain:`.
///
/// A deployment with no `auth:` block at all named no position, which is the open front door it
/// asked for. The refusal for a position this composition cannot honour is [`data_chain`]'s, and it
/// is deliberately not softened here: a door with one fewer lock than its operator wrote is worse
/// than a node that will not start.
fn chain_positions(chain: &[config::AuthChainEntry]) -> Vec<(String, String)> {
    chain
        .iter()
        .map(|entry| (entry.name.clone(), entry.module.clone()))
        .collect()
}

/// **WHAT THE USAGE UNIT METERS AGAINST**, off the configured pools and rate card.
///
/// The two fields that matter are the ones a default gets wrong. An empty lane expansion turns the
/// unit's set-membership test into an equality test, which disputes every pooled posting; an empty
/// price table makes the three-legged cross-check pick arbitrarily when its legs disagree. Both come
/// from configuration here, and the two tolerances are left to the unit's own figures, which ARE the
/// design's numbers — a deployment that sets neither is asking for them.
fn meter_config(
    expansions: &BTreeMap<String, Vec<String>>,
    prices: &BTreeMap<String, f64>,
) -> crate::root::policy::MeterPolicyConfig {
    crate::root::policy::MeterPolicyConfig {
        pools: expansions
            .iter()
            .map(|(pool, lanes)| crate::root::policy::PoolExpansion {
                pool: pool.clone(),
                lanes: lanes.clone(),
            })
            .collect(),
        prices: prices
            .iter()
            .map(|(lane, micro)| crate::root::policy::LanePrice {
                lane: lane.clone(),
                // THE COMPARABLE PRICE, and it is the card's own input rate lifted by the cost
                // unit's own conversion. Read for ONE thing - choosing the cheaper entry when the
                // cross-check's three legs disagree - so what it needs is an ORDERING over lanes,
                // and the input rate is the one figure every configured lane carries. The
                // arithmetic is the cost unit's; there is none here.
                price: u128::from(busbar_unit_cost::nano_rate(*micro)),
            })
            .collect(),
        ..crate::root::policy::MeterPolicyConfig::default()
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BREAKER, AT THE WIDTH THE TRUST UNIT ASKS AT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE NODE'S OWN BREAKER CELLS, presented at the width the trust unit reads them.
///
/// ## Two ports over one set of cells
///
/// The breaker unit answers the EGRESS port, whose readiness peek is sealed behind a `Route` token
/// because a peek that could drive a cell out of its open state is a dispatch. The trust unit's
/// `BreakerView` is deliberately token-free: it is asked at Verify, before any token for Route
/// exists. So the two cannot be the same method, and this is the join — over the SAME adapter, the
/// SAME cells, and no second set. Two breaker units would be two sets of cells, and a trip recorded
/// through one would be invisible to the other.
///
/// ## What each half reads, said exactly
///
/// `ready` answers from the destination's LIFETIME BUDGET, which is the one breaker fact that needs
/// no token. It is NARROWER than the egress peek: a destination the breaker has benched under
/// cooldown still reads ready here. That is stated rather than hidden, and it is not a hole — the
/// cooldown is enforced where the dispatch happens, which on this plane is the surface the mounted
/// router already puts in front of every hop. What this view ADDS is the budget refusal at Verify;
/// what it does not add is a second cooldown opinion.
///
/// `try_admit` takes NO PROBE. The trait's own words are that this is where a half-open probe is
/// actually taken, and taking one here would spend a half-open budget the dispatch below is about
/// to spend again — two dispatches' worth of probe for one request, and a lane that reads recovered
/// because the loop probed it rather than because anything succeeded.
///
/// ## The lane index IS the destination
///
/// The trust unit indexes a pool's candidates by position, and the breaker names a destination by
/// `DestinationId`, which its own documentation calls "the identity, as the pool's member list
/// orders it". They are the same number. The member list this plane's pool view walks is
/// `A2aPlane::agents()`, in declaration order, which is the order the registrations were interned
/// in — so one agent has ONE identity here rather than one for the meter and another for the
/// breaker.
struct AgentLanes {
    adapter: crate::root::adapters::BreakerAdapter,
    /// How many candidates this pool has, so a lane index outside it is refused rather than
    /// answered about a destination this deployment does not have.
    lanes: usize,
}

impl std::fmt::Debug for AgentLanes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgentLanes")
    }
}

impl busbar_unit_trust::lane::BreakerView for AgentLanes {
    fn ready(&self, _pool: &str, lane: usize, _now: u64) -> bool {
        use busbar_unit_egress::ports::Breaker as _;
        let Ok(index) = u64::try_from(lane) else {
            return false;
        };
        lane < self.lanes
            && self
                .adapter
                .admissible(busbar_unit_breaker::DestinationId::new(index))
    }

    fn try_admit(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
    ) -> Result<(), busbar_unit_trust::Unavailable> {
        if self.ready(pool, lane, now) {
            Ok(())
        } else {
            // The one refusal this view can state truthfully. A destination out of lifetime budget
            // is not going to become available by waiting, which is the whole difference between it
            // and a cooldown — and naming a cooldown here would be reporting a window this view
            // never read.
            Err(busbar_unit_trust::Unavailable::BudgetExhausted)
        }
    }
}

//   THE AGENT SET, INTERNED ONCE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE REGISTRATIONS THIS PROCESS SERVES, interned once and never again.
///
/// The trust unit's pool view and its per-kind facts read `&'static [Agent]`, because a registration
/// set is a fact about the deployment and not about a request — a set that could be rebuilt per
/// request is a set a request could change. A `OnceLock` rather than a leak: the allocation is one,
/// it is countable, and there is no arm that makes a second.
static REGISTRATIONS: OnceLock<Vec<Agent>> = OnceLock::new();

/// This deployment's agent set, in the plane's own registration shape.
///
/// The four fields are the ones every plane's registration carries. `lane` is the AGENT'S OWN NAME:
/// a unit of this plane is metered on the agent it reaches, and the pool view keys the same set
/// under this plane's region of the breaker keyspace — so naming the lane anything else would give
/// one agent two identities, one for the meter and one for the breaker.
///
/// Interned through the composition root's own vocabulary, which leaks each distinct string exactly
/// once and refuses after boot. Called once; a second call answers with the first call's set rather
/// than interning a second, which is what makes "once" a property of the type instead of a hope.
fn registrations(agents: &[DeclaredAgent]) -> &'static [Agent] {
    REGISTRATIONS.get_or_init(|| {
        let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
        let built = agents
            .iter()
            .map(|agent| Agent {
                id: vocabulary.key(&agent.name),
                lane: busbar_contract::ids::LaneId::new(vocabulary.key(&agent.name)),
                host: vocabulary.key(&agent.host),
                // The document carrier, which is what every `url:` an operator declares names. The
                // framed binding this protocol also declares is an INGRESS claim — a client speaks
                // it to this node — and reading it as an egress transport here would say this node
                // dials an agent over a carrier no deployment configured.
                transport: busbar_plane_a2a::claims::TRANSPORT_HTTP,
            })
            .collect();
        vocabulary.seal();
        built
    })
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT CONFIGURATION SAID
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// EVERY VALUE THIS DEPLOYMENT'S CONFIGURATION DECIDED, resolved while it is still in scope.
///
/// It names no configuration type, deliberately: the composition root's own file hands this across
/// the gap between "the configuration exists" and "the routers exist", and a value carrying a
/// configuration type would make that gap a lifetime problem.
pub struct A2aConfigured {
    plane: A2aPlane,
    guard: GuardPolicy,
    pinned: Vec<String>,
    denylist: Denylist,
    groups: busbar_unit_admission::GroupTable,
    meter_policy: crate::root::policy::MeterPolicyHandle,
    lanes: usize,
    auth: Auth,
    expected_aud: String,
    chain: Arc<PlaneChain>,
}

impl std::fmt::Debug for A2aConfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("A2aConfigured")
    }
}

/// **READ WHAT THIS DEPLOYMENT SAID ABOUT THIS PLANE**, or refuse boot saying what it could not.
///
/// `Ok(None)` is a deployment with NO RECEIVING SIDE — one that declared no `public_url:`, which is
/// exactly the deployment the legacy plugin mounts no A2A route on at all. Not a refusal: fronting
/// no inbound surface is a configuration, and the honest answer to it is to mount nothing.
///
/// # Errors
///
/// A value this leg needs has no source on this deployment, or `auth.chain:` names a position this
/// composition cannot honour, or this plane's own declared surface does not check. Each refusal is
/// the operator-facing sentence of the thing that refused, never a summary written here.
pub fn read(cfg: &config::RootCfg) -> Result<Option<A2aConfigured>, String> {
    let chain =
        Arc::new(PlaneChain::over(&busbar_plane_a2a::surface::SURFACE).map_err(|e| e.to_string())?);
    // NO DECLARED IDENTITY IS NO RECEIVING SIDE, and it is the plane's own rule rather than this
    // file's: without a `public_url:` there is no canonical URI to bind an audience to, so the
    // plugin serves no route and this composition mounts nothing. Reading a bearer with no audience
    // to check it against would admit every token this node ever minted for any surface.
    let Some(expected_aud) = cfg
        .public_url
        .as_deref()
        .and_then(|declared| chain.audience(declared))
    else {
        return Ok(None);
    };

    let agents = declared_agents(cfg.agent_defs.as_any());
    let positions: Vec<(String, String)> =
        chain_positions(cfg.auth.as_ref().map_or(&[], |auth| &auth.chain));
    let auth = data_chain(
        &positions
            .iter()
            .map(|(provider, module)| ChainPosition { provider, module })
            .collect::<Vec<_>>(),
    )
    .map_err(|e| e.to_string())?;

    let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
    let keys = crate::root::vocabulary::ConfigKeys {
        groups: cfg.groups.keys().cloned().collect(),
        ..crate::root::vocabulary::ConfigKeys::default()
    };
    let lease_ids = vocabulary.group_ids(&keys);
    vocabulary.seal();

    Ok(Some(A2aConfigured {
        plane: A2aPlane::new(registrations(&agents)),
        guard: narrowest_guard(&agents),
        pinned: approved_pins(&agents),
        // The operator's metadata answer, whole: what they added, what they carved out, and the
        // nuclear override — over the built-in list, which the denylist itself carries.
        denylist: Denylist::new(
            &cfg.blocked_metadata_hosts,
            &cfg.allow_metadata_hosts,
            cfg.allow_all_metadata,
        ),
        groups: crate::root::policy::group_table(&cfg.groups, &lease_ids),
        // The lane expansions and the comparable prices, projected out of configuration HERE and
        // into ordered maps: the pool section is hashed, and a policy whose expansions arrived in
        // iteration order is the same value reached two ways - which is true, and is exactly the
        // kind of true that stops being true the day something compares two boots.
        meter_policy: crate::root::policy::build(&meter_config(
            &cfg.pools
                .iter()
                .map(|(pool, def)| {
                    (
                        pool.clone(),
                        def.members.iter().map(|m| m.name().to_string()).collect(),
                    )
                })
                .collect(),
            &cfg.rate_card
                .iter()
                .flatten()
                .map(|(lane, entry)| (lane.clone(), entry.input_utok))
                .collect(),
        )),
        auth: Auth::new(auth),
        lanes: agents.len(),
        expected_aud,
        chain,
    }))
}

/// The built-in metadata denylist, for a caller reporting what this node guards.
///
/// Named here so the composition and `--print-metadata-blocklist` read the SAME list; the count is
/// what the boot line already reports and the entries are what the guard already refuses.
#[must_use]
pub fn builtin_denylist_size() -> usize {
    config_validate::metadata_denylist_entries().len()
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **WRAP THE DATA ROUTER SO EVERY UNIT OF THIS PLANE ON IT TRAVELS THROUGH THE KERNEL.**
///
/// `None` for `configured` is the deployment with no receiving side: the router is handed back
/// exactly as it arrived, which is the byte-for-byte answer that deployment already has.
///
/// # Errors
///
/// A binding this leg needs has no source. The refusal is `A2aLeg::assemble`'s own, naming the field
/// and quoting the source table's row for it, so an operator reads what to configure.
pub fn mount(
    inner: axum::Router,
    configured: Option<A2aConfigured>,
    kernel: busbar_kernel::teller::Kernel,
    governance: Option<Arc<GovState>>,
    durability: Arc<Mutex<Durability>>,
    request_body_max_bytes: usize,
) -> Result<axum::Router, String> {
    let Some(configured) = configured else {
        return Ok(inner);
    };
    let leg = A2aLeg::assemble(A2aLegSources {
        plane: configured.plane,
        kernel: &kernel,
        auth: Some(configured.auth),
        // THE NODE'S OWN KEY AUTHORITIES where it has a governance directory, and the unbound
        // posture where it has none — which is the posture a deployment with no governance state
        // already serves under, reached the same way rather than restated.
        auth_bindings: Some(governance.clone().map_or_else(
            crate::root::auth_bindings::AuthBindings::without_directory,
            |gov| {
                crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    crate::root::auth_bindings::GovernanceDirectory::new(gov),
                ))
            },
        )),
        // THE NODE'S BREAKER CELLS, at the width the trust unit reads them. See `AgentLanes`: the
        // egress port's peek is token-sealed and this one is asked at Verify, so the join is a
        // second READING of one set of cells and never a second set.
        breaker: Some(Arc::new(AgentLanes {
            adapter: crate::root::adapters::BreakerAdapter::with_diagnostics(
                crate::root::adapters::root_diagnostics(),
                crate::root::adapters::BreakerPolicy::new(),
            ),
            lanes: configured.lanes,
        })),
        guard: Some(configured.guard),
        denylist: Some(configured.denylist),
        pinned: Some(configured.pinned),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(configured.groups),
        // Read at the instant the leg is assembled: the entry in force NOW is the proof that a
        // resolution has happened, and the walk re-reads the history at its own arrival instant.
        rates: crate::root::kernel::ROOT_CARD.pin_rates(
            u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
        ),
        // The node's ONE store, the same handle the governance path itself uses. A deployment with
        // no governance state has no store, and the assembly refuses rather than opening a second
        // one: a leg writing to a store nothing reads and reading one nothing writes would look
        // healthy from both ends, because an empty table reconciles.
        store: governance.map(|gov| gov.store()),
        meter_policy: Some(configured.meter_policy),
        scope_policy: Some(crate::root::units_a2a::scope_policy(
            crate::root::policy::ScopePolicy::new(),
        )),
        durability: Some(durability),
        // NO RESTRICTION NAMED. A key's scopes are a property of the CALLER's credential and are
        // read when one is presented; `None` here is "this deployment names no restriction", which
        // is a different answer from an empty list and is the one that is true at boot.
        key_scopes: None,
        expected_aud: Some(configured.expected_aud),
        priced: false,
        has_key: false,
    })
    .map_err(|refusal| refusal.to_string())?;

    Ok(crate::root::units_a2a_mount::mount(
        inner,
        Arc::new(leg),
        kernel,
        // THE NODE'S PARTS, taken from the chain this composition already built over them rather
        // than made here. A second set would be a second node, which is the whole reason the chain
        // holds one rather than each mount holding its own.
        Arc::clone(configured.chain.parts()),
        request_body_max_bytes,
    ))
}

#[cfg(test)]
#[path = "tests/units_a2a_boot.rs"]
mod tests;
