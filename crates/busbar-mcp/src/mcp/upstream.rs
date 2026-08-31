// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM LEG — the join between the SERVER direction (busbar's front door) and the CLIENT
//! direction (busbar calling out to a registered MCP server).
//!
//! Everything here is glue, and the glue is the point. Both halves already existed and each was
//! proven on its own; what did not exist was the path by which an authenticated inbound `tools/call`
//! becomes an outbound one, and the two integrity properties that only mean anything once it does:
//!
//! - the SERVER direction's inbound audience validation is the confused-deputy defence, and it
//!   defends nothing without an inbound surface that does something;
//! - the CLIENT direction's outbound down-scoping has no meaning without upstreams.
//!
//! ## The inbound principal is carried, never re-derived
//!
//! [`authorise`] takes the caller's resolved `VirtualKey` — the SAME value the catalogue filter and
//! the budget charge were computed from — and hands it to the client direction's
//! `egress::plan_credential`. Nothing here re-derives a principal, re-parses a token, or synthesises
//! a "service" identity for the outbound hop. The outbound credential is selected under the inbound
//! caller's own grant or it is not selected at all, and that sentence is the whole of the defence.
//!
//! ## The gate runs BEFORE any network I/O, and that ordering is load-bearing
//!
//! [`authorise`] is synchronous and reaches nothing. It is called before the input-required loop is
//! entered, so a caller whose grant does not cover this call cannot cause busbar to make a
//! token-exchange round trip against busbar's OWN authorization server. An unauthorised request that
//! still costs an authenticated round trip on the operator's IdP is an unauthenticated party
//! spending the operator's rate limit, and it is asserted on the token endpoint's OWN hit counter
//! rather than inferred from the refusal.
//!
//! ## Governance disabled is not a special case here either
//!
//! With governance off there is no key, so there is no grant, and `crate::mcp::method::Ctx::grant`
//! already answers "all scopes" for exactly the reason `pool_allowed` does on the LLM plane: a
//! deployment with no governance has no principal to carry a grant, and refusing everything would
//! make it unable to serve. This module takes the same posture, by synthesising the WILDCARD
//! principal rather than by skipping the gate — which matters, because a wildcard principal is
//! down-scoped to the single tool it called. Skipping the gate would have asked for everything.
//!
//! ## Re-planned on EVERY round, deliberately
//!
//! The credential is planned and minted inside the per-round call rather than once before the loop.
//! Under on-demand negotiation every defence is a per-request check, and one logical dispatch is
//! several requests: a grant narrowed part-way through must bite on the very next round. Caching the
//! minted token across rounds would be a session by another name.

use super::catalogue::{ServerEntry, ToolEntry};
use super::client::egress::{
    plan_credential, CredentialPlan, EgressDenied, ExchangeCfg, ExchangeRequest, UpstreamCredential,
};
use super::client::identity::{ServerId, ToolKey};
use super::client::jsonrpc::{self, RpcOutcome};
use super::client::pool::McpConnectionPool;
use super::client::ssrf::SsrfPolicy;
use super::client::wire::{TransportError, WireLeg};
use super::inputreq::{Ask, Round};
use busbar_api::{Redacted, VirtualKey};
use std::sync::Arc;
use std::time::Duration;

/// The wall-clock budget for ONE outbound leg — the tool call, and separately the token exchange —
/// FOR A REGISTRATION THAT NAMES NONE.
///
/// A number rather than an inherited default, because an upstream MCP server is not trusted to
/// answer and a dispatch that hangs holds a concurrency slot the caller already paid for. Thirty
/// seconds is the same order the proxy path allows a provider, so a tool call and a model call fail
/// on the same timescale rather than on two an operator has to learn separately.
///
/// It was the ONLY value, hard-coded, until `tools.<server>.timeout:` — and one constant for every
/// upstream is either too generous for a loopback diagnostic or too mean for an LLM-backed tool.
/// The DEFAULT is unchanged, so no registration that exists today behaves differently.
pub(crate) const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the outbound leg needs, resolved and AUTHORISED, ready to be spent.
///
/// Constructed only by [`authorise`], which is what makes "the gate ran" a property of having the
/// value rather than a call somebody remembers to make.
#[derive(Debug)]
pub(crate) struct Authorised {
    /// THE REGISTRATION this leg reaches. Present on BOTH shapes of ask, because both reach one.
    ///
    /// It rides here rather than being read off [`Authorised::key`] so that a SERVER-SCOPED verb —
    /// which names no tool and therefore has no key — still has a registration to name. Deriving it
    /// from the key was what made an `mcp_tool` grant a prerequisite for issuing a `prompts/list`:
    /// `super::client::egress::ServerVerb` correctly requires one grant, and the only constructor
    /// of the value the send site needs demanded two.
    pub(crate) server: ServerId,
    /// The routing key — the bound identity, never a description — for an ask that NAMES A TOOL.
    ///
    /// `None` on a server-scoped verb. An `Option` rather than a synthetic key, because every
    /// available synthetic value is one this plane has already refused elsewhere: a literal
    /// `fs_prompts/list` invents a grant no operator can write, and reusing an unrelated tool's key
    /// authorises one thing against a grant for another. The absence is the honest representation
    /// and `super::client::issue` never needs it.
    pub(crate) key: Option<ToolKey>,
    /// The upstream endpoint, as the operator registered it. Empty for a transport that reaches no
    /// address; the wire that needs it is the wire that has one.
    pub(crate) url: String,
    /// THE CHANNEL this dispatch rides, resolved once here and turned into a vtable by
    /// [`busbar_substrate::transport::Transport::upstream_wire`] at the send site. Nothing between the two asks it
    /// which one it is — that is the axis rule, and it is what keeps a second transport from
    /// becoming a second dispatch path.
    pub(crate) transport: busbar_substrate::transport::Transport,
    /// The spawn recipe for a child-process upstream, carried verbatim from the snapshot. `None` on
    /// every registration that is reached over a network.
    pub(crate) stdio: Option<super::client::stdio::StdioCommand>,
    /// The addressing posture for the dispatch-time SSRF check.
    pub(crate) policy: SsrfPolicy,
    /// THE PER-SERVER GRANTS for the three authority asks a peer can make. Carried onto the leg so
    /// the INBOUND half — a child's own `sampling/createMessage`, arriving on its stdout while
    /// busbar waits for an answer — is judged against the operator's grants rather than against a
    /// default nobody chose. See `super::client::peer`.
    pub(crate) grants: super::config::ServerRequestGrants,
    /// The operator-declared filesystem roots this server may be told about when it asks
    /// `roots/list` — the satisfier behind `grants.roots`, lifted from the same snapshot the
    /// grants are. Empty on a server-scoped verb, which never enters the ask loop.
    pub(crate) roots: Vec<super::config::RootCfg>,
    /// The operator-declared sampling policy — the satisfier behind `grants.sampling`, lifted from
    /// the same snapshot for the same reason. `None` on a server-scoped verb.
    pub(crate) sampling: Option<super::config::SamplingCfg>,
    /// The credential MODE this server is configured with.
    pub(crate) credential: UpstreamCredential,
    /// The INBOUND principal, carried through so the credential planner re-derives the same
    /// down-scope the gate was computed from. An `Arc` because `PoolRoute::build` authorises the
    /// SAME caller against every pool member, and `VirtualKey` is a large record (several `String`s,
    /// a scope `Vec`, two maps) — sharing the one the request already holds by refcount rather than
    /// deep-cloning it per member is what keeps a wide `tool_pools` route cheap.
    pub(crate) caller: Arc<VirtualKey>,
    /// THE DEADLINE for each leg of this dispatch, lifted from the snapshot the call was admitted
    /// against. Resolved to a concrete `Duration` here — never `Option` past this point — so no
    /// send site can forget to apply the default.
    pub(crate) timeout: Duration,
}

/// Why the upstream leg could not even be set up. Distinct from an upstream FAILURE, because an
/// operator's remedy is completely different: one is a grant, the other is a network.
#[derive(Debug)]
pub(crate) enum SetupRefusal {
    /// The registered ids do not form a valid routing key. A registration that cannot be named
    /// cannot be dispatched to, and guessing at a repair here would be routing on a rendering.
    Malformed(String),
    /// The inbound principal's grant does not cover this call.
    Egress(EgressDenied),
    /// The operator's credential configuration cannot be honoured (an unresolvable secret, a
    /// `passthrough` server with no caller credential to forward). Fail CLOSED: busbar never
    /// substitutes its own ambient credential for one it was told the caller would supply.
    Credential(String),
    /// A URL or host carried INSIDE the per-request tool arguments failed the same addressing check
    /// the destination does. The routing rule makes the DESTINATION immune to attacker-chosen text;
    /// it does not make the PAYLOAD immune, and this is the arm that says so.
    Argument(String),
    /// THE ORDERED VALIDATOR REFUSED. Carried whole rather than flattened to a string, because its
    /// arms are four different operator remedies and its `reason()` is already an audit word — see
    /// `busbar_substrate::trust::validate`, whose header is explicit that collapsing them is the cheap
    /// unification and the wrong one.
    ///
    /// Reached only by [`authorise_verb`]. A `tools/call` meets the same validator one layer up, in
    /// the catalogue's `resolve`, and renders its refusal in that path's own vocabulary.
    #[cfg_attr(any(not(test), not(feature = "test-support")), allow(dead_code))]
    Trust(busbar_substrate::trust::validate::Refusal),
}

impl std::fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetupRefusal::Malformed(m) => write!(f, "{m}"),
            SetupRefusal::Egress(e) => write!(f, "{e}"),
            SetupRefusal::Credential(m) => write!(f, "{m}"),
            SetupRefusal::Argument(m) => write!(f, "{m}"),
            SetupRefusal::Trust(r) => write!(f, "{r}"),
        }
    }
}

impl SetupRefusal {
    /// The stable audit reason word, named once so a new arm cannot land without one.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            SetupRefusal::Malformed(_) => "malformed_identity",
            // Core's word — see `busbar_substrate::audit::vocab::REASON_EGRESS_DENIED` for why an
            // egress refusal is deliberately distinguishable from a grant refusal.
            SetupRefusal::Egress(_) => busbar_substrate::audit::vocab::REASON_EGRESS_DENIED,
            SetupRefusal::Credential(_) => "credential_unavailable",
            SetupRefusal::Argument(_) => "tool_argument_refused",
            // The validator's OWN word, not a fifth one invented here. It is already an
            // `audit::vocab` token, and re-spelling it would be the two-streams-one-decision defect
            // the audit unification closed.
            SetupRefusal::Trust(r) => r.reason(),
        }
    }
}

/// THE GATE. Synchronous, reaches no network, and runs before the loop is entered.
///
/// `caller` is `None` only when governance is disabled — see the module header for why that becomes
/// the WILDCARD principal rather than a skipped check.
pub(crate) fn authorise(
    server: &ServerEntry,
    selected: &ToolEntry,
    arguments: &serde_json::Value,
    caller: Option<&Arc<VirtualKey>>,
) -> Result<Authorised, SetupRefusal> {
    let server_id =
        ServerId::new(&selected.server).map_err(|e| SetupRefusal::Malformed(e.to_string()))?;
    let key = ToolKey::new(server_id.clone(), &selected.tool)
        .map_err(|e| SetupRefusal::Malformed(e.to_string()))?;
    // A refcount bump of the caller the request already holds — never a deep clone — so authorising
    // one caller against every member of a pool costs one `Arc` per member, not one `VirtualKey`.
    let caller = match caller {
        Some(k) => Arc::clone(k),
        None => Arc::new(ungoverned_principal()),
    };
    let credential = credential_mode(server).map_err(SetupRefusal::Credential)?;
    // THE TRANSITIVE-DEPUTY CALL. `plan_credential` runs `authorise_tool_egress` first and returns nothing to a caller
    // that fails it, so the plan below is not reachable without the grant. It is called here — where
    // there is no network — precisely so the refusal costs no round trip.
    plan_credential(&server_id, &credential, &caller, None, &key).map_err(SetupRefusal::Egress)?;
    let policy = SsrfPolicy {
        allow_private: server.upstream.allow_private,
    };
    // THE ARGUMENT GUARD, and it runs AFTER the grant deliberately: a caller with no grant learns
    // that it is ungranted and nothing about the tool's schema. The schema is the operator's
    // APPROVED one from the catalogue snapshot, not one the upstream offered at refresh time, so
    // the document the walk reads is the document the operator signed off.
    //
    // A tool that declared no schema is walked against `{"type": "object"}` rather than skipped: the
    // walk is VALUE-driven with the schema riding alongside, so an absent schema narrows what the
    // walk can call "declared" and narrows nothing else. Skipping it would make "declare no schema"
    // the way past this check.
    let schema = selected
        .input_schema
        .clone()
        .unwrap_or_else(|| serde_json::json!({ "type": "object" }));
    super::client::argguard::guard(&schema, arguments, policy)
        .map_err(|e| SetupRefusal::Argument(e.to_string()))?;
    Ok(Authorised {
        server: server_id,
        key: Some(key),
        url: server.url.clone(),
        transport: server.transport,
        stdio: server.stdio.clone(),
        policy,
        grants: server.grants,
        roots: server.roots.clone(),
        sampling: server.sampling.clone(),
        credential,
        caller,
        timeout: server.upstream.timeout.unwrap_or(DEFAULT_UPSTREAM_TIMEOUT),
    })
}

/// THE GATE FOR A SERVER-SCOPED VERB — an ask that names the REGISTRATION and no tool.
///
/// ## Why this is not [`authorise`] with a tool left out
///
/// `authorise` resolves a `ToolKey` and then runs `plan_credential`, whose subject requires BOTH
/// `mcp_server` and `mcp_tool`. Every verb in `super::client::verb::UpstreamVerb` except
/// `tools/call` names no tool, so routing one through that constructor made an `mcp_tool` grant a
/// prerequisite for `prompts/list` — while `super::client::egress::ServerVerb`, the subject the
/// send site actually gates on, correctly requires one grant. A deployment fronting an upstream for
/// its prompts and no tools at all could not reach it.
///
/// ## It is the ORDERED VALIDATOR, not a fourth sequence
///
/// A `tools/call` meets `busbar_substrate::trust::validate::validate_request` one layer up, inside the
/// catalogue's `resolve`, which owns the tool half of the question. A server-scoped verb never
/// touches the catalogue's tool index, so it asks the validator DIRECTLY — identity, then the
/// `mcp_server` grant, then whether the registration is serving at all, then whether the snapshot
/// it was admitted under is still live. Writing those four steps out here instead would have been
/// the fourth call site that module's own header says drifts.
///
/// `capability: None` is a statement rather than an omission: an ask addressed to the registration
/// has no per-capability fingerprint to compare, and inventing one would be inventing an approval.
/// The REGISTRATION-level half still runs, so a quarantined or suspended upstream serves no
/// `prompts/list` either — which is the assertion that stops "no capability to check" quietly
/// becoming "nothing to check".
///
/// The verb's own params are NOT judged here. They are judged in `super::client::issue::issue`,
/// once, for every verb however the leg was authorised — a guard on the constructor is a guard a
/// second constructor can skip.
#[cfg_attr(any(not(test), not(feature = "test-support")), allow(dead_code))]
pub(crate) fn authorise_verb(
    server: &ServerEntry,
    sighting: &busbar_substrate::trust::Sighting<super::client::catalogue::TransportPin>,
    caller: Option<&Arc<VirtualKey>>,
    generation: busbar_substrate::trust::validate::Generations,
    now: u64,
) -> Result<Authorised, SetupRefusal> {
    let server_id =
        ServerId::new(&server.id).map_err(|e| SetupRefusal::Malformed(e.to_string()))?;
    // Shared by refcount, not deep-cloned — see `authorise`.
    let caller = match caller {
        Some(k) => Arc::clone(k),
        None => Arc::new(ungoverned_principal()),
    };
    busbar_substrate::trust::validate::validate_request(&busbar_substrate::trust::validate::Ask {
        principal: Some(caller.as_ref()),
        now,
        grants: &[busbar_substrate::trust::validate::Grant::Scope {
            kind: "mcp_server",
            name: &server.id,
        }],
        approval: &server.approval,
        sighting,
        capability: None,
        generation,
    })
    .map_err(SetupRefusal::Trust)?;
    let credential = credential_mode(server).map_err(SetupRefusal::Credential)?;
    Ok(Authorised {
        server: server_id,
        // NAMES NO TOOL, and says so. See the field.
        key: None,
        url: server.url.clone(),
        transport: server.transport,
        stdio: server.stdio.clone(),
        policy: SsrfPolicy {
            allow_private: server.upstream.allow_private,
        },
        grants: server.grants,
        // A server-scoped verb never enters the ask loop, so there is nothing here for a
        // satisfier to read; the empty list and the absent policy are the honest values rather
        // than lookups skipped.
        roots: Vec::new(),
        sampling: None,
        credential,
        caller,
        timeout: server.upstream.timeout.unwrap_or(DEFAULT_UPSTREAM_TIMEOUT),
    })
}

/// The WILDCARD principal an ungoverned deployment dispatches as.
///
/// `allowed_scopes: None` is the store's wildcard, and it is the honest representation of "there is
/// no key here to carry a grant". It is NOT a way past the gate: a wildcard principal is
/// down-scoped, on the outbound side, to the single tool it actually called.
fn ungoverned_principal() -> VirtualKey {
    VirtualKey {
        id: "ungoverned".to_string(),
        name: "ungoverned".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: None,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
        ..Default::default()
    }
}

/// Turn the operator's registration into the client direction's credential mode.
///
/// The subject token is resolved HERE, at dispatch, rather than at snapshot build: a secret that
/// resolves at build time is a secret whose rotation needs a restart, and a snapshot holding
/// resolved plaintext is a snapshot that cannot be compared or logged safely.
pub(super) fn credential_mode(server: &ServerEntry) -> Result<UpstreamCredential, String> {
    if matches!(
        server.upstream.credentials,
        Some(busbar_api::UpstreamCreds::Passthrough)
    ) {
        // Honest and fail-closed: this revision's ingress defines no carrier for a credential the
        // caller holds FOR THE UPSTREAM (the inbound `Authorization` is the caller's BUSBAR key, and
        // forwarding that is the one thing rule 1 forbids). So `passthrough` selects the passthrough
        // mode and the planner refuses it for want of a caller credential, which is the correct
        // answer until a carrier exists — never busbar's own credential in its place.
        return Ok(UpstreamCredential::Passthrough);
    }
    let Some(tx) = &server.upstream.token_exchange else {
        // No exchange configured: a public or network-authenticated upstream. Sending nothing is the
        // honest answer, and it is not a fallback to an ambient credential — there is none.
        return Ok(UpstreamCredential::None);
    };
    let resource = server.upstream.aud.clone().ok_or_else(|| {
        "an RFC 8693 exchange needs `aud:` as its RFC 8707 resource indicator; without one the \
         issued token is spendable at any backend the authorization server serves"
            .to_string()
    })?;
    let subject_token = busbar_api::resolve_builtin_string(&tx.subject_token)
        .map_err(|e| format!("busbar's own subject token for this upstream cannot resolve: {e}"))?;
    Ok(UpstreamCredential::Exchange(ExchangeCfg {
        token_url: tx.token_url.clone(),
        subject_token: Redacted::new(subject_token),
        subject_token_type: tx.subject_token_type.clone(),
        resource,
    }))
}

/// ONE BREAKER CELL'S COORDINATES: the plane-qualified pool key and the member's lane. Degenerate
/// (un-pooled) targets are `("tool:<server>", 0)`; a pooled member is `("tool:<pool>", position)`.
/// A value rather than a re-derivation inside [`call`] so the selection (`failover::walk`) and the
/// recording below are FORCED onto the same cell — the two deriving the key independently is how a
/// trip lands somewhere the admission never looks.
#[derive(Clone, Debug)]
pub(crate) struct BreakerCell {
    pub(crate) key: String,
    pub(crate) lane: usize,
}

impl BreakerCell {
    /// The degenerate single-member cell for an un-pooled server — lane 0, exactly the shape the
    /// breaker unit landed.
    pub(crate) fn degenerate(server: &str) -> Self {
        BreakerCell {
            key: busbar_substrate::store::tool_key(server),
            lane: 0,
        }
    }
}

/// A failed upstream leg, still carrying the ONE structural fact the reroute decision needs: had
/// anything left busbar when it failed? The `String` alone (which is all the caller used to get)
/// cannot answer that, and re-parsing prose to decide whether a second dispatch duplicates work
/// would be routing on a rendering.
#[derive(Debug)]
pub(crate) struct LegFailure {
    pub(crate) message: String,
    /// [`busbar_substrate::failover::Stage::BeforeFirstByte`] iff the wire itself says nothing was
    /// transmitted (a connect-class failure, or busbar's own pre-wire refusal). Everything
    /// ambiguous is `AfterDispatch`.
    pub(crate) stage: busbar_substrate::failover::Stage,
}

impl LegFailure {
    fn dispatched(message: String) -> Self {
        LegFailure {
            message,
            stage: busbar_substrate::failover::Stage::AfterDispatch,
        }
    }
}

/// ONE ROUND of the upstream leg: plan, mint, send, parse.
///
/// The plan is re-derived here rather than carried from [`authorise`] because the caller's grant is
/// re-read per round — see the module header. `authorise` proves the gate ran before any I/O; this
/// proves it runs again on the round that actually spends.
///
/// `satisfaction` is the answer to the PREVIOUS round's `InputRequiredResult`, built by the granted
/// satisfier and threaded back through [`super::inputreq::drive`]'s loop — `None` on the first
/// round and after any round the upstream answered normally. It rides onto the retry as MRTR's own
/// `inputResponses`/`requestState` continuation.
pub(crate) async fn call(
    pool: &McpConnectionPool,
    auth: &Authorised,
    arguments: &serde_json::Value,
    request_id: u64,
    satisfaction: Option<serde_json::Value>,
    outcome: &mut LegOutcome,
) -> Result<Round, LegFailure> {
    // STAGE-1 CLASSIFICATION stays HERE, where the raw transport/status structure still exists; the
    // SETTLE moves to the caller's host scope (CLUSTER-1). `outcome` is the classified breaker fact
    // this leg hands back — `Nothing` until a wire/status point overwrites it, so every pre-socket
    // refusal below (a missing key, a credential plan / exchange failure) leaves it `Nothing`: no
    // byte left busbar, so nothing is recorded against the target's cell.
    *outcome = LegOutcome::Nothing;
    // A `tools/call` NAMES A TOOL, so this leg must carry one. The refusal is a `String` and not a
    // panic because `Authorised` is constructible for a server-scoped verb too, and the type cannot
    // yet say which shape a given value is — what it can say is that this path does not proceed
    // without a routing key, rather than inventing one.
    let key = auth.key.as_ref().ok_or_else(|| {
        // Busbar-side: no leg was even attempted, so a pooled caller may still select a member —
        // though in practice this arm is unreachable from the routed path, which only builds
        // tool-shaped candidates.
        LegFailure {
            message: "a `tools/call` needs the tool's bound identity and this leg was authorised \
                      for a server-scoped verb, which names none"
                .to_string(),
            stage: busbar_substrate::failover::Stage::BeforeFirstByte,
        }
    })?;
    let plan =
        plan_credential(&auth.server, &auth.credential, &auth.caller, None, key).map_err(|e| {
            // The grant/credential plan refused BEFORE any socket: nothing left busbar.
            LegFailure {
                message: e.to_string(),
                stage: busbar_substrate::failover::Stage::BeforeFirstByte,
            }
        })?;
    let bearer = match plan {
        CredentialPlan::None => None,
        CredentialPlan::Bearer(b) => Some(b.expose_secret().to_string()),
        CredentialPlan::Exchange(req) => Some(
            exchange(pool, &req, auth.policy, auth.timeout)
                .await
                // The exchange is a leg against busbar's OWN authorization server, not against the
                // tool server: the TOOL CALL was never transmitted, whatever became of the
                // exchange, so the stage is honest — and nothing is recorded against the tool
                // server's cell for its AS being down.
                .map_err(|message| LegFailure {
                    message,
                    stage: busbar_substrate::failover::Stage::BeforeFirstByte,
                })?,
        ),
    };
    // The namespaced name is stripped to the bare tool inside the builder — the upstream has never
    // heard of busbar's namespacing and would answer `-32602` to it.
    let outbound = jsonrpc::tools_call(
        &auth.url,
        key,
        arguments,
        request_id,
        bearer.as_deref(),
        // Each capability is declared exactly when this deployment can answer it for THIS server:
        // the operator granted the ask AND declared its satisfier. See `jsonrpc::tools_call` for
        // why declaring anything else would be dishonest either way.
        jsonrpc::AdvertisedCaps {
            roots: auth.grants.roots && !auth.roots.is_empty(),
            sampling: auth.grants.sampling && auth.sampling.is_some(),
        },
        satisfaction.as_ref(),
    );
    // THE DISPATCH ARM, and it is a vtable lookup rather than a branch. `upstream_wire` is the only place
    // in the tree that asks the transport axis which variant it is; from here down the leg is bytes
    // out and bytes back, identically for an HTTPS POST and for a write to a child's stdin.
    let leg = WireLeg {
        pool,
        policy: auth.policy,
        timeout: auth.timeout,
        server: auth.server.as_str(),
        command: auth.stdio.as_ref(),
        grants: auth.grants,
    };
    // THE OUTCOME IS CLASSIFIED WHERE THE STRUCTURE STILL EXISTS — the Stage-1 normalizer for this
    // plane (the audit's closing design). One leg, one classified `outcome` handed back to the caller,
    // which SETTLES it against the ONE core breaker's cell for this target (CLUSTER-1: the sync leg
    // through its `DispatchScope` admission, the task leg through the runner's `DurableScope`); by the
    // time this function's failure reaches the caller the transport/status shape is gone, so
    // classifying later would be guessing — which is exactly why the classification stays HERE and
    // only the settle moves out.
    //
    // `wire::send`, not `wire_for().send`: the client leg's `busbar_upstream_attempts_total` /
    // `busbar_upstream_failures_total` count lives on that seam so a leg that is not counted is a
    // leg that did not happen. See `super::client::wire::send`. The breaker outcome and the counter
    // are DIFFERENT observers of the same leg — the breaker decides whether the next call is
    // attempted, the counter tells an operator which registration is the one failing — keyed
    // differently ON PURPOSE: the counter labels the operator's REGISTRATION (`leg.server`), the
    // breaker the POOL MEMBER cell the caller settles against.
    let response = match crate::mcp::client::wire::send(auth.transport, &leg, &outbound).await {
        Ok(r) => r,
        Err(e) => {
            let (stage, classified) = classify_wire_failure(&e);
            *outcome = classified;
            return Err(LegFailure {
                message: e.to_string(),
                stage,
            });
        }
    };
    if !(200..300).contains(&response.status) {
        // The status alone, claiming no provider vocabulary — `classify` still places the failure
        // (401/403 → Auth → hard down; 5xx → transient; true 4xx → ClientFault, never a penalty).
        // Classifying does NOT change what the caller is answered: the parse below renders exactly
        // what it always rendered. The SETTLE of this fact is the caller's (CLUSTER-1).
        *outcome = LegOutcome::Failure(busbar_substrate::breaker::normalize_raw_error(
            &busbar_substrate::breaker::RawUpstreamError::from_status(response.status),
            &std::collections::HashMap::new(),
        ));
    } else {
        // THE WIRE WORKED. A JSON-RPC error or a tool-level `isError` inside a 2xx is the SERVER
        // answering — protocol- or work-level, never availability — so the success is classified
        // here, on the status, before the body is interpreted. This is what closes a half-open
        // probe and what keeps a caller's bad arguments from ever penalizing the upstream.
        *outcome = LegOutcome::Success;
    }
    // `request_id` AGAIN, and that is the point: the id that went out in the body is the id the
    // answer must name. Both uses are on the screen together so a reader can see that they are the
    // same value, and neither of them outlives this function — see `jsonrpc::parse_response` on why
    // the correlation is a per-dispatch argument rather than a table of pending ids.
    match jsonrpc::parse_response(&response.body, request_id) {
        RpcOutcome::Result(value) => Ok(Round::Done(value)),
        RpcOutcome::Error { code, message } => Err(LegFailure::dispatched(format!(
            "MCP upstream answered JSON-RPC error {code}: {message}"
        ))),
        // The ask is handed back to the bounded, per-round-gated loop, which decides whether busbar
        // may satisfy it. It is NEVER returned to busbar's own caller — the loop's `Outcome` has no
        // arm that could carry it outward.
        RpcOutcome::InputRequired { kind } => Ok(Round::InputRequired(Ask {
            kind: kind.key().to_string(),
            payload: serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|v| v.get("result").cloned())
                .unwrap_or_else(|| serde_json::json!({})),
        })),
        RpcOutcome::Malformed(reason) => Err(LegFailure::dispatched(format!(
            "MCP upstream returned HTTP {} and a body that is not a JSON-RPC response: {reason}",
            response.status
        ))),
        // A RESPONSE TO SOMETHING ELSE. The dispatch fails rather than adopting it: serving it
        // would answer this caller with whatever the upstream was actually replying to, and the
        // result is NOT logged into the error, because it is another conversation's payload.
        RpcOutcome::Uncorrelated(reason) => Err(LegFailure::dispatched(format!(
            "MCP upstream returned HTTP {} and a JSON-RPC response busbar cannot correlate to this \
             call: {reason}",
            response.status
        ))),
    }
}

/// The TRANSPORT half of this plane's Stage-1 normalizer: how one failed wire leg is CLASSIFIED (the
/// caller settles it, CLUSTER-1), and (for the reroute loop) the [`busbar_substrate::failover::Stage`] the
/// failure leaves the request at.
///
/// - `Unreachable` — a connect-class failure: the destination never received a byte. Classified as
///   the same `Network` transient (a server that cannot be connected to is exactly what the
///   breaker exists for), and the ONE wire failure reported `BeforeFirstByte`: a reroute of it
///   duplicates nothing, by the transport's own testimony.
/// - `Io` — the socket failed, the deadline expired, or a stdio child died mid-exchange: the
///   transient the breaker exists for. `Network` rather than a guessed `Timeout` split, because
///   both classify to the same `TransientUpstream` disposition and the wire does not distinguish
///   them in structure. `AfterDispatch`: the request may have landed.
/// - `Supervision` — the stdio crash-loop supervisor refused (backoff, quarantine) and spawned
///   NOTHING. Recording it would be DOUBLE ACCOUNTING: the child crash that armed the supervisor
///   was already recorded here as the `Io` failure of the exchange it killed, and the supervisor's
///   refusal is busbar's own fast answer, not a new fact about the upstream. The two breakers
///   CO-EXIST and share no state — the core cell trips on the crashes, the supervisor guards the
///   respawns — exactly the audit's stdio row. Nothing left busbar, so `BeforeFirstByte`.
/// - `Refused` — busbar's OWN dispatch-time refusal (SSRF, a malformed target): nothing left
///   busbar and the upstream answered nothing, so nothing is recorded against it.
///   `BeforeFirstByte` for the same reason.
fn classify_wire_failure(err: &TransportError) -> (busbar_substrate::failover::Stage, LegOutcome) {
    let network = || {
        LegOutcome::Failure(busbar_substrate::breaker::CanonicalSignal {
            class: busbar_substrate::breaker::StatusClass::Network,
            provider_signal: None,
            retry_after: None,
        })
    };
    match err {
        TransportError::Unreachable(_) => (
            busbar_substrate::failover::Stage::BeforeFirstByte,
            network(),
        ),
        TransportError::Io(_) => (busbar_substrate::failover::Stage::AfterDispatch, network()),
        // Nothing left busbar (supervisor backoff / busbar's own dispatch refusal): `Nothing`, so no
        // fact is recorded against the target's cell. See the doc above for the double-accounting rule.
        TransportError::Supervision(_) | TransportError::Refused(_) => (
            busbar_substrate::failover::Stage::BeforeFirstByte,
            LegOutcome::Nothing,
        ),
    }
}

/// The classified breaker outcome of ONE upstream leg — built in [`call`], where the raw
/// transport/status structure still exists (Stage 1), and SETTLED by the CALLER through the host
/// scope it owns (CLUSTER-1): the sync leg through its per-leg [`DispatchScope`](busbar_substrate::plane_host::DispatchScope)
/// admission, the task leg through the runner's [`DurableScope`](busbar_substrate::plane_host::DurableScope).
/// Classification stays put; only the settle moves — [`busbar_substrate::plane_host::breaker::failure_signal`]
/// is the inverse of the host `classify`, so a settle folds through the SAME `record_signal`/`record_success`
/// disposition the in-place call ran.
pub(crate) enum LegOutcome {
    /// The wire worked (2xx): close the half-open probe / dilute the error window (`record_success`).
    Success,
    /// A wire or status failure to fold, carried as the plane's own canonical signal (`record_signal`).
    Failure(busbar_substrate::breaker::CanonicalSignal),
    /// Not an upstream health signal — a busbar-side refusal or a leg that never left busbar. Records
    /// nothing; a settled probe is released without a record, an unadmitted one is untouched.
    Nothing,
}

/// PERFORM the RFC 8693 exchange and return the access token.
///
/// The token endpoint goes through the SAME pool, and therefore the same resolve-then-pin SSRF
/// check, as the tool call. An authorization server reached without that check is a destination
/// busbar sends its own subject token to on the strength of a string comparison.
/// The DEADLINE is this server's, not a constant: the exchange is a leg of the same dispatch, and a
/// registration whose operator said "this peer is slow" meant the whole round trip.
pub(super) async fn exchange(
    pool: &McpConnectionPool,
    req: &ExchangeRequest,
    policy: SsrfPolicy,
    timeout: Duration,
) -> Result<String, String> {
    let (client, _target) = pool
        .client_for(&req.token_url, policy)
        .await
        .map_err(|e| format!("the token endpoint could not be reached: {e}"))?;
    // The form body: `serde_urlencoded::to_string` is BYTE-IDENTICAL to what reqwest's `.form()`
    // produced — that method was this exact call plus the content-type header set below.
    let form = serde_urlencoded::to_string(req.form_fields())
        .map_err(|e| format!("the RFC 8693 exchange form could not be encoded: {e}"))?;
    let uri: http::Uri = req
        .token_url
        .parse()
        .map_err(|e| format!("the token endpoint is not a valid URI: {e}"))?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let request = busbar_substrate::egress::engine::request(
        http::Method::POST,
        uri,
        headers,
        bytes::Bytes::from(form),
    );
    // The CALLER'S deadline, on the request: the pooled client is cached per destination and this
    // call site must not inherit somebody else's; the same ABSOLUTE deadline spans the body read
    // below, exactly as reqwest's per-request timeout did. The fault cause is URL-free by
    // construction (hyper errors never carry the URL — reqwest's did, which an operator may have
    // written userinfo into; that was the `without_url()` this path used to need).
    let deadline = tokio::time::Instant::now() + timeout;
    let response = busbar_substrate::egress::engine::send_bounded(&client, request, deadline)
        .await
        .map_err(|e| format!("the RFC 8693 exchange failed: {}", e.into_cause()))?;
    let status = response.status().as_u16();
    let body = {
        use http_body_util::BodyExt;
        let collected = tokio::time::timeout_at(deadline, response.into_body().collect())
            .await
            .map_err(|_| {
                format!(
                    "the RFC 8693 exchange body could not be read: {}",
                    busbar_substrate::egress::engine::HOP_DEADLINE_CAUSE
                )
            })?;
        collected
            .map_err(|e| format!("the RFC 8693 exchange body could not be read: {e}"))?
            .to_bytes()
    };
    if !(200..300).contains(&status) {
        // The BODY is deliberately not echoed: an authorization server's error body can carry the
        // subject token back in a diagnostic, and this string reaches busbar's own caller.
        return Err(format!(
            "the RFC 8693 exchange was refused by the authorization server with HTTP {status}"
        ));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| "the RFC 8693 exchange response is not JSON".to_string())?;
    match parsed.get("access_token").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        // A 200 with no usable token is a failure, not a call made with no credential: silently
        // dropping to an unauthenticated request is how an outage becomes an authorization bypass.
        _ => Err(
            "the RFC 8693 exchange returned 200 with no usable `access_token`; the call is refused \
             rather than made unauthenticated"
                .to_string(),
        ),
    }
}

// Shared fixtures for the upstream-leg batteries: a REAL fake MCP peer and a REAL fake RFC 8693
// token endpoint, both recording every byte they receive. Declared here rather than duplicated per
// file so a test that means to vary ONE thing varies one thing.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/upstream_support.rs"]
mod upstream_support;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/upstream_join_tests.rs"]
mod upstream_join_tests;

// A GRANTED, OPERATOR-DECLARED `roots/list` ask, satisfied on the wire — the coverage instrument
// for `mcp|streamable-http|client|server|roots/list`. Beside the join tests because its witness is
// the same recording peer.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/roots_satisfy_tests.rs"]
mod roots_satisfy_tests;

// A GRANTED, OPERATOR-DECLARED `sampling/createMessage` ask, satisfied through the governed LLM
// pipeline within the per-upstream budget — the coverage instrument for
// `mcp|streamable-http|client|server|sampling/createMessage`. Beside the roots battery because its
// witnesses are the same recording peer plus a recording fake provider.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sampling_satisfy_tests.rs"]
mod sampling_satisfy_tests;

// THE STDIO ARM, driven through the same front door. It hangs here rather than under `client/`
// because the claim is about the JOIN — an inbound `tools/call` reaching a child process — and the
// supervisor being reachable at all is the whole property under test.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/stdio_dispatch_tests.rs"]
mod stdio_dispatch_tests;

// THE STREAMABLE-HTTP CLIENT COLUMN, the sibling of `stdio_client_leg_tests.rs`. It hangs here for
// the same reason that one does: the claim is about the JOIN — a verb reaching a real peer through
// the real gate — and it asserts the half a child process has no analogue for, which is the mirrored
// headers and the exchanged credential.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/http_client_leg_tests.rs"]
mod http_client_leg_tests;

// THE WHOLE STDIO CLIENT COLUMN — every method busbar ISSUES and every message a child SENDS,
// against a real child process. It hangs here for the same reason its neighbour does: the claim is
// about the JOIN, and `Authorised` has exactly one constructor, which is the gate.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/stdio_client_leg_tests.rs"]
mod stdio_client_leg_tests;

// PROVEN AS A PAIR — this property is meaningless with only one direction built: an inbound
// surface with no upstream cannot demonstrate that the outbound credential followed the
// inbound grant, and an upstream with no inbound caller has no grant to follow.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/deputy_pair_tests.rs"]
mod deputy_pair_tests;

// KILL-THE-UPSTREAM — the breaker's trip + fast-fail on this plane, both transports, driven at the
// same front door as everything above. It hangs here because the recording site is `call` below.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/breaker_fastfail_tests.rs"]
mod breaker_fastfail_tests;

// KILL-THE-UPSTREAM-MID-POOL — the failover seam mounted on this plane: `tool_pools:` reroute
// before first byte, the pin rule, the repeatable safety rule, and the client-fault disposition,
// against TWO real fake peers. It hangs here for the same reason its sibling does.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/reroute_pool_tests.rs"]
mod reroute_pool_tests;

// THE PER-CALL LOG'S WRITER, proven from the dispatcher outwards rather than from the log inwards.
// It lives here, beside the upstream-leg batteries, because it needs the same real fake peer: the
// claim is about what a REAL `tools/call` leaves behind, and a call with no upstream to reach could
// only ever demonstrate the refusing half.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/calllog_dispatch_tests.rs"]
mod calllog_dispatch_tests;

// THE HOOK GATE ON THIS PLANE, proven the only way the claim can be made honestly: against the same
// real fake peer. "The call was rejected" is evidence only next to a control that REACHES the peer
// and is served, and only a real upstream can supply that control — which is why this battery sits
// here with the other upstream-leg files rather than beside the dispatcher it exercises.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/hook_gate_tests.rs"]
mod hook_gate_tests;

// THIS PLANE'S CLIENT LEG ON `/metrics`. Beside the other upstream-leg batteries for the same
// reason they are all here: the claim is about a leg that REACHED a peer, and a series emitted with
// no upstream to reach would prove only that a macro increments.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/client_leg_metrics_tests.rs"]
mod client_leg_metrics_tests;
