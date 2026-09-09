// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, for the reason the leg and the mount beside it carry the
// same line: this is composition of the SERVING path and it names items that exist only under this
// feature. Declared in `root/mod.rs` under `root-mcp`, so a plane-gated module is not named from
// code under a different feature.
#![cfg(feature = "root-mcp-serve")]

//! THE MCP PLANE'S COMPOSITION AT BOOT: every binding resolved, from configuration this deployment
//! already has, or the node does not bind a listener.
//!
//! ## The finding this file is the answer to
//!
//! [`crate::root::units_mcp_leg::McpLeg::assemble`] had no production caller, and neither did
//! [`crate::root::units_mcp_mount::mount`]. The leg's own source table named eighteen bindings and
//! the composition root resolved none of them: the plane the mount registers is
//! `McpPlane::EMPTY`, so a node that served this surface would have served it over a registration
//! set with nothing in it — every dialled unit refused at a destination the trust unit does not
//! have, and the refusal blamed on the request. So the leg existed, the mount existed, and nothing
//! composed either. This file is that composition.
//!
//! ## NO INVENTED CONFIGURATION, and the table says where each one comes from
//!
//! Not one key here is new. [`BOOT_SOURCES`] is one row per thing this file resolves, and each row
//! names the configuration it is read from or the composition-root value it is taken from. A source
//! that could not be named REFUSES BOOT with the operator-facing sentence of the thing that refused,
//! rather than defaulting — because a leg assembled with an empty auth chain admits anonymously, a
//! leg assembled with an empty group table says yes to every cap, and both of those boot clean.
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

use busbar_core::config;
use busbar_plane_mcp::{McpPlane, Server};
use busbar_unit_admission::{Door, InMemoryCells, Pricer};
use busbar_unit_auth::Auth;
use busbar_unit_trust::net::{Denylist, GuardPolicy};

use crate::root::data_plane::{data_chain, ChainPosition, PlaneChain};
use crate::root::durability::Durability;
use crate::root::units_mcp_leg::{McpLeg, McpLegSources};

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHERE EVERY BOOT-RESOLVED VALUE COMES FROM
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// ONE ROW PER THING THIS FILE RESOLVES, and the configuration or root value it comes from.
///
/// The leg's own [`crate::root::units_mcp_leg::SOURCES`] is one row per BINDING and says where each
/// binding would come from. This is the other end of the same sentence: one row per thing the
/// composition root actually goes and gets, as DATA rather than as prose, so the cell beside this
/// file can assert every row names a real place and "everything is sourced" cannot rot into a
/// comment that was true once.
///
/// The second column is a LOCATION. Where a deployment writes the value down, the row names the
/// configuration key verbatim; where the composition root already holds it for its other planes, the
/// row names the root's own resolution.
pub const BOOT_SOURCES: &[(&str, &str)] = &[
    (
        "servers",
        "config `tools:` — the plane's own registration set, each server's name, the host of its \
         declared `url:`, and whether it is reached by spawning rather than by dialling",
    ),
    (
        "guard",
        "config `tools.<name>.allow_private:` — folded to the NARROWEST across the configured set, \
         because one leg-wide policy may not be looser than any registration's own",
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
        "pricer",
        "root: `kernel::ROOT_CARD`'s own pricer half — the price an ARRIVING unit is admitted \
         against, built by the same apply that built the card a settled one is priced against. Not \
         derived here and not read off a config field: the deployment's fee lives behind the cost \
         unit's own, and the construction gate names the two crates that may read it",
    ),
    (
        "meter_policy",
        "config `pools:` and `rate_card:` through `policy::build` — the lane expansions and the \
         comparable lane prices in name order, never the unit's own defaults",
    ),
    (
        "scope_policy",
        "root: `McpLeg::scope_policy`, one entry per operation class the plane declares",
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
        "durability",
        "root: the node's ONE book, opened before either listener binds",
    ),
    (
        "chain",
        "root: `data_plane::PlaneChain` over this plane's OWN declared surface, which is what the \
         mount is composed on and what checks the declaration before a listener is bound",
    ),
    (
        "key_scopes",
        "not a boot value: a restriction is a property of the CALLER's key, and `None` here is \
         'no restriction named', which is a posture rather than a missing source",
    ),
    (
        "audience",
        "NOT SOURCED HERE, and that is a statement rather than a gap: `units_mcp::authenticate` \
         derives it from the plane's own canonical key on every credentialed claim, and a second \
         answer to which tokens open this surface is the worst thing to hold two of",
    ),
];

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   WHAT ONE REGISTRATION'S CONFIGURATION SAYS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// One configured server, reduced to the four things this composition reads about it.
///
/// A value of this file's own rather than the plugin's configuration type, so every helper below can
/// be exercised against real inputs without a whole resolved deployment being built to reach them.
/// The projection from the configuration type is one function, [`declared_servers`], and it is the
/// only place that names the plugin's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredServer {
    /// The name the operator gave this server, which is the resource the scope unit judges.
    pub name: String,
    /// The host of the `url:` this server is dialled at, or empty for one this node launches.
    pub host: String,
    /// Whether this server's own configuration lets a hop reach a private address.
    pub allow_private: bool,
    /// Whether this registration is reached by SPAWNING a child rather than by dialling an address.
    pub spawns_child: bool,
}

/// THIS DEPLOYMENT'S SERVERS, off the type-erased `tools:` section.
///
/// The one place the plugin's configuration shape is named. Everything after this reads
/// [`DeclaredServer`]s, which is what lets the folding rules below be proved against inputs a cell
/// can write down.
///
/// A section that is not this plane's answers with nothing — the honest reading of a deployment that
/// has no `tools:` block at all, which is the same deployment the legacy plugin registers no server
/// for.
fn declared_servers(section: &dyn std::any::Any) -> Vec<DeclaredServer> {
    let Some(tools) = section.downcast_ref::<busbar_mcp::mcp::config::ToolsCfg>() else {
        return Vec::new();
    };
    tools
        .servers
        .iter()
        .map(|(name, def)| DeclaredServer {
            name: name.clone(),
            // A SPAWNED registration has no address, and the grammar refuses it a `url:` at all —
            // so there is nothing to cut a host out of and the empty string is what the plane's own
            // registration shape documents for exactly this case. Reading the field regardless
            // would key a network fact by a host no deployment configured.
            host: if def.spawns_child() {
                String::new()
            } else {
                host_of(def.url())
            },
            allow_private: def.allow_private(),
            spawns_child: def.spawns_child(),
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
/// `allow_private:` is written PER REGISTRATION, and the leg carries ONE policy — the trust unit's
/// guard is bound once for the whole leg, because the plane's own destination facts do not yet name
/// which server a unit reaches. Two directions were available and only one of them is safe: a
/// leg-wide policy that allowed private if ANY server did would let a request bound for a server the
/// operator deliberately kept on the public internet reach a private address, silently. So the fold
/// is the other way — the leg allows it only where EVERY configured server was told it could — and a
/// deployment with no servers at all allows nothing, because "all of none" is vacuously true and is
/// exactly the reading that would open the guard on an empty deployment.
///
/// A SPAWNED registration is not counted, and that is the one difference from the sibling plane's
/// fold. `allow_private:` is a statement about an ADDRESS, and a registration this node launches has
/// none — the grammar refuses it a `url:` outright. Folding a key that could not widen anything into
/// the narrowest of a set would let a deployment of nothing but child processes close the guard for
/// the dialled servers beside them, or open it, on a value that governs no hop of theirs at all.
///
/// The three fields beside it are the trust unit's own declared bounds. They are not
/// `tools.<name>` values: a redirect budget, a body cap and a timeout are properties of a FETCH, and
/// this plane's own copies of them govern its upstream call rather than a unit's hop.
fn narrowest_guard(servers: &[DeclaredServer]) -> GuardPolicy {
    let mut addressed = servers.iter().filter(|s| !s.spawns_child).peekable();
    GuardPolicy {
        allow_private: addressed.peek().is_some() && addressed.all(|s| s.allow_private),
        ..GuardPolicy::default()
    }
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
                // unit's own conversion. Read for ONE thing — choosing the cheaper entry when the
                // cross-check's three legs disagree — so what it needs is an ORDERING over lanes,
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
/// actually taken, and taking one here would spend a half-open budget the dispatch below is about to
/// spend again — two dispatches' worth of probe for one request, and a lane that reads recovered
/// because the loop probed it rather than because anything succeeded.
///
/// ## The lane index IS the destination
///
/// The trust unit indexes a pool's candidates by position, and the breaker names a destination by
/// `DestinationId`, which its own documentation calls "the identity, as the pool's member list
/// orders it". They are the same number. The member list this plane's pool view walks is
/// `McpPlane::servers()`, in declaration order, which is the order the registrations were interned
/// in — so one server has ONE identity here rather than one for the meter and another for the
/// breaker.
struct ServerLanes {
    adapter: crate::root::adapters::BreakerAdapter,
    /// How many candidates this pool has, so a lane index outside it is refused rather than answered
    /// about a destination this deployment does not have.
    lanes: usize,
}

impl std::fmt::Debug for ServerLanes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerLanes")
    }
}

impl busbar_unit_trust::lane::BreakerView for ServerLanes {
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

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE REGISTRATION SET, INTERNED ONCE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// THE REGISTRATIONS THIS PROCESS SERVES, interned once and never again.
///
/// The trust unit's pool view and its per-kind facts read `&'static [Server]`, because a registration
/// set is a fact about the deployment and not about a request — a set that could be rebuilt per
/// request is a set a request could change. A `OnceLock` rather than a leak: the allocation is one,
/// it is countable, and there is no arm that makes a second.
static REGISTRATIONS: OnceLock<Vec<Server>> = OnceLock::new();

/// **THE CARRIER ONE REGISTRATION IS REACHED OVER**, and it is one of this plane's own three.
///
/// The plane declares three transports and this maps the config grammar's ONE question — is this
/// registration reached by spawning a child — onto the two of them that name an egress hop. The
/// third is a framed INGRESS claim: a client speaks it TO this node, and reading it as an egress
/// carrier here would say this node reaches a server over something no deployment configured.
///
/// A named constant of the plane's rather than a literal, so a registration's carrier and the claim
/// the arrival step matches it against are one string and not two that agreed once — the arrival
/// step refuses a unit whose transport no claim declares, and a registration on one is a server
/// nothing could ever answer from.
fn carrier(spawns_child: bool) -> &'static str {
    if spawns_child {
        busbar_plane_mcp::claims::TRANSPORT_STDIO
    } else {
        busbar_plane_mcp::claims::TRANSPORT_HTTP
    }
}

/// This deployment's server set, in the plane's own registration shape.
///
/// The four fields are the ones every plane's registration carries. `lane` is the SERVER'S OWN NAME:
/// a unit of this plane is metered on the server it reaches, and the pool view keys the same set
/// under this plane's region of the breaker keyspace — so naming the lane anything else would give
/// one server two identities, one for the meter and one for the breaker.
///
/// Interned through the composition root's own vocabulary, which leaks each distinct string exactly
/// once and refuses after boot. Called once; a second call answers with the first call's set rather
/// than interning a second, which is what makes "once" a property of the type instead of a hope.
fn registrations(servers: &[DeclaredServer]) -> &'static [Server] {
    REGISTRATIONS.get_or_init(|| {
        let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
        let built = servers
            .iter()
            .map(|server| Server {
                id: vocabulary.key(&server.name),
                lane: busbar_contract::ids::LaneId::new(vocabulary.key(&server.name)),
                host: vocabulary.key(&server.host),
                transport: carrier(server.spawns_child),
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
pub struct McpConfigured {
    plane: McpPlane,
    guard: GuardPolicy,
    denylist: Denylist,
    groups: busbar_unit_admission::GroupTable,
    meter_policy: crate::root::policy::MeterPolicyHandle,
    lanes: usize,
    auth: Auth,
    chain: Arc<PlaneChain>,
}

impl std::fmt::Debug for McpConfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("McpConfigured")
    }
}

/// **READ WHAT THIS DEPLOYMENT SAID ABOUT THIS PLANE**, or refuse boot saying what it could not.
///
/// `Ok(None)` is a deployment with NO MCP SURFACE — one that wrote no `mcp:` block, which is exactly
/// the deployment the legacy plugin adds nothing to the route table for. Not a refusal: a gateway
/// that is not an MCP server should not answer as one, and the honest answer to that configuration
/// is to mount nothing.
///
/// The block's mere PRESENCE is the whole of the question asked here. What is IN it — the canonical
/// URI, the authorization servers, the accepted browser origins — was validated and lowered at
/// resolve, by the plane's own seam, into the resource the mounted surface already publishes. A
/// second reading of it here would be a second answer to which tokens open this surface.
///
/// # Errors
///
/// A value this leg needs has no source on this deployment, or `auth.chain:` names a position this
/// composition cannot honour, or this plane's own declared surface does not check. Each refusal is
/// the operator-facing sentence of the thing that refused, never a summary written here.
pub fn read(cfg: &config::RootCfg) -> Result<Option<McpConfigured>, String> {
    let chain =
        Arc::new(PlaneChain::over(&busbar_plane_mcp::surface::SURFACE).map_err(|e| e.to_string())?);
    // NO ENDPOINT BLOCK IS NO SURFACE, and it is the plane's own rule rather than this file's: the
    // `mcp:` block's presence is what mounts this plane, and a deployment without one carries no MCP
    // ingress and no metadata document at all. The block is reached by the SECTION its owning plane
    // declares, which is the neutral, section-keyed read the root already uses in place of a
    // per-plane configuration field.
    if cfg
        .endpoint_resource(busbar_mcp::PLANE_DECL.config_section)
        .is_none()
    {
        return Ok(None);
    }

    let servers = declared_servers(cfg.tool_defs.as_any());
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

    Ok(Some(McpConfigured {
        plane: McpPlane::new(registrations(&servers)),
        guard: narrowest_guard(&servers),
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
        // iteration order is the same value reached two ways — which is true, and is exactly the
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
        lanes: servers.len(),
        chain,
    }))
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MOUNT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **WRAP THE DATA ROUTER SO EVERY UNIT OF THIS PLANE ON IT TRAVELS THROUGH THE KERNEL.**
///
/// `None` for `configured` is the deployment with no MCP surface: the router is handed back exactly
/// as it arrived, which is the byte-for-byte answer that deployment already has.
///
/// # Errors
///
/// A binding this leg needs has no source. The refusal is `McpLeg::assemble`'s own, naming the field
/// and quoting the source table's row for it, so an operator reads what to configure.
pub fn mount(
    inner: axum::Router,
    configured: Option<McpConfigured>,
    kernel: busbar_kernel::teller::Kernel,
    governance: Option<Arc<busbar_core::governance::GovState>>,
    durability: Arc<Mutex<Durability>>,
    request_body_max_bytes: usize,
) -> Result<axum::Router, String> {
    let Some(configured) = configured else {
        return Ok(inner);
    };
    let leg = McpLeg::assemble(McpLegSources {
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
        // THE NODE'S BREAKER CELLS, at the width the trust unit reads them. See `ServerLanes`: the
        // egress port's peek is token-sealed and this one is asked at Verify, so the join is a
        // second READING of one set of cells and never a second set.
        breaker: Some(Arc::new(ServerLanes {
            adapter: crate::root::adapters::BreakerAdapter::with_diagnostics(
                crate::root::adapters::root_diagnostics(),
                crate::root::adapters::BreakerPolicy::new(),
            ),
            lanes: configured.lanes,
        })),
        guard: Some(configured.guard),
        denylist: Some(configured.denylist),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(configured.groups),
        pricer: pricer(),
        // The node's ONE store, the same handle the governance path itself uses. A deployment with
        // no governance state has no store, and the assembly refuses rather than opening a second
        // one: a leg writing to a store nothing reads and reading one nothing writes would look
        // healthy from both ends, because an empty table reconciles.
        store: governance.map(|gov| gov.store()),
        meter_policy: Some(configured.meter_policy),
        scope_policy: Some(McpLeg::scope_policy(crate::root::policy::ScopePolicy::new())),
        durability: Some(durability),
        // NO RESTRICTION NAMED. A key's scopes are a property of the CALLER's credential and are
        // read when one is presented; `None` here is "this deployment names no restriction", which
        // is a different answer from an empty list and is the one that is true at boot.
        key_scopes: None,
        priced: false,
        has_key: false,
    })
    .map_err(|refusal| refusal.to_string())?;

    Ok(crate::root::units_mcp_mount::mount(
        inner,
        Arc::new(leg),
        kernel,
        configured.chain,
        request_body_max_bytes,
    ))
}

/// **WHAT THE DOOR PRICES AN ARRIVING UNIT AGAINST**, off the process's own card holder.
///
/// The one money value this leg is handed rather than reads live, and the reason is the rule rather
/// than a convenience: the deployment's per-request fee lives behind the cost unit's own field, and
/// the construction gate names the two crates that may read it — so the root hands a PRICER down,
/// built by the apply that built the card, instead of a figure it read for itself.
///
/// It is taken from the SAME `pin_rates` load the leg's own walk re-reads for the classes it meters,
/// so the price a unit was admitted against and the card it settles against are one apply's. `None`
/// before the boot's first resolution has happened, which is a state the assembly refuses by name
/// rather than one this file supplies a default for — a zero fee invented here is a deployment
/// served at a price nobody wrote down.
fn pricer() -> Option<Pricer> {
    crate::root::kernel::ROOT_CARD
        .pin_rates()
        .map(|rates| rates.pricer().clone())
}

#[cfg(test)]
#[path = "tests/units_mcp_boot.rs"]
mod tests;
