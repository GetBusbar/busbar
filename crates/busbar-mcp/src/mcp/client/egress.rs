// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OUTBOUND CREDENTIAL SELECTION: per-server injection, RFC 8707 audience binding, RFC 8693
//! down-scoping — and the rule that ties all three to the INBOUND principal's grant.
//!
//! ## The two rules, and why the second one only exists because busbar is bidirectional
//!
//! **Rule 1: the caller's busbar key NEVER reaches an upstream.** It is a credential minted by
//! busbar, for busbar, and forwarding it hands an upstream a token that spends against busbar's own
//! governance plane. This is enforced structurally: the credential planner
//! below is not given the caller's presented secret, and the request builder that IS given it never
//! reads it. That is asserted adversarially in `tests/no_key_passthrough_tests.rs` by planting a
//! sentinel and scanning the whole serialized request, rather than by reading the code and agreeing
//! with it.
//!
//! **Rule 2 — the TRANSITIVE CONFUSED DEPUTY: the outbound credential is bound to the inbound
//! principal's grant.**
//! A client-only gateway cannot have this bug — it has no inbound principal to be confused about.
//! busbar is both directions, so an authenticated inbound `tools/call` could cause busbar to mint an
//! outbound token from its OWN ambient upstream credentials and re-export a tool with more authority
//! than the caller holds. The whole argument for shipping both directions as one unit is that this
//! property is the one that only exists in the pair: the bundle creates the deputy, so the bundle
//! has to close it.
//!
//! The gate is [`busbar_substrate::egress_auth::gate::authorise`], reached here through
//! [`authorise_tool_egress`], and it runs at the CREDENTIAL SELECTION SITE rather than at the
//! catalogue. That placement is the point: a catalogue filter answers "what may this caller SEE",
//! and the confused deputy is about what busbar's own credentials may be spent on, which is a
//! different question asked at a different moment. Both checks exist; this module owns the second.
//!
//! ## Down-scoping is DERIVED from the grant, not configured beside it
//!
//! RFC 8693 gives a way to ask for a narrower token. What to ask FOR is the design decision, and the
//! answer here is: exactly the tools the inbound principal is granted on this server, and — for a
//! wildcard principal — exactly the one tool being called. A configured static scope list would be a
//! second place the authority is written down, and the two would drift; a wildcard principal getting
//! a wildcard token would make rule 2 vacuous for the most common key shape in a small deployment.
//!
//! ## RFC 8707 is not optional here
//!
//! Every minted or exchanged token carries `resource=<the upstream's canonical URI>`. That is the
//! same defence busbar demands of its OWN callers on the inbound side (`crate::mcp::McpResource`):
//! a token minted for one upstream must not be spendable at another. Asking for it on egress and
//! enforcing it on ingress is the same rule seen from both ends, which is what makes it a governance
//! boundary rather than a habit.

use super::identity::{ServerId, ToolKey};
use busbar_api::{Redacted, VirtualKey};
use busbar_substrate::egress_auth::gate::{EgressRefusal, EgressSubject, Requirement};

/// How ONE upstream server is authenticated to. Per server, never a plane-wide default: every MCP
/// server authenticates independently, so there is no all-plane auth scalar an operator could set
/// and no ambient credential for a misconfigured server to fall back to.
#[derive(Clone, Debug)]
#[allow(dead_code)] // `Static` is reachable from config; no in-tree caller constructs it directly.
pub(crate) enum UpstreamCredential {
    /// No credential. A public or network-authenticated upstream.
    None,
    /// A static per-server bearer, resolved from a `kind: secret` reference.
    Static(Redacted<String>),
    /// RFC 8693 token exchange against the operator's authorization server, down-scoped per backend
    /// and RFC 8707 audience-bound. busbar's OWN subject token is exchanged — never the caller's.
    Exchange(ExchangeCfg),
    /// The caller supplied its own credential FOR THIS UPSTREAM, and busbar forwards it.
    ///
    /// This is the config's `upstream_credentials: passthrough`, and the distinction that keeps it
    /// from violating rule 1 is that the forwarded value is a credential the caller holds for the
    /// UPSTREAM, carried in its own field, and is never the busbar key the caller authenticated to
    /// busbar with. See [`CallerContext`], where the two are separate fields precisely so that
    /// "forward the caller's credential" cannot accidentally mean the wrong one.
    Passthrough,
}

/// What an RFC 8693 exchange needs. The subject token is busbar's own, held `Redacted` so a `Debug`
/// of a server registration cannot print it.
#[derive(Clone, Debug)]
pub(crate) struct ExchangeCfg {
    /// The authorization server's token endpoint.
    pub(crate) token_url: String,
    /// busbar's own token, the SUBJECT of the exchange. Never the caller's.
    pub(crate) subject_token: Redacted<String>,
    /// RFC 8693 §2.1 `subject_token_type`.
    pub(crate) subject_token_type: String,
    /// RFC 8707 `resource`: the upstream's canonical URI, so the issued token is audience-bound to
    /// this backend and to no other.
    pub(crate) resource: String,
}

/// THE INBOUND CALLER, as the egress path sees it.
///
/// Two credential fields, deliberately, and the split is the whole of rule 1:
///
/// - `busbar_key` is what the caller authenticated to BUSBAR with. It exists on this struct because
///   the request builder legitimately needs a caller identity for attribution and metering, and
///   because a type that simply omitted it would prove nothing — the adversarial test needs the
///   secret to be REACHABLE from the builder in order for its absence downstream to mean anything.
/// - `upstream_credential` is what the caller holds for the UPSTREAM, present only under
///   `passthrough`. This is the only caller-supplied value that may leave.
///
/// Built by the CONNECT path, which has no verb yet: `mcp::upstream` passes the caller's
/// `VirtualKey` straight to `authorise_tool_egress` instead of assembling one of these.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct CallerContext {
    /// The caller's resolved governance row. `scope_allowed` on this is the egress gate's input.
    pub(crate) key: VirtualKey,
    /// The secret the caller presented to busbar. MUST NOT leave busbar.
    pub(crate) busbar_key: Redacted<String>,
    /// A credential the caller holds for the upstream, under `passthrough` only.
    pub(crate) upstream_credential: Option<Redacted<String>>,
}

/// WHICH OF THIS PLANE'S TWO GRANTS a refusal is about. One variant per check the gate makes, which
/// is what lets [`EgressDenied`]'s conversion give each check its own sentence exhaustively: a third
/// MCP requirement would be a compile error at the wording rather than a silent reuse of a nearby
/// arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolGrant {
    /// `mcp_server`: the caller may reach this upstream at all.
    Server,
    /// `mcp_tool`: which of the upstream's tools the caller may reach.
    Tool,
}

/// WHAT THIS PLANE SUPPLIES TO THE CORE GATE: two grants, in the order they are checked, and no key
/// liveness rule.
///
/// Two grants and not one, because they answer different questions and a deployment may legitimately
/// grant one without the other: `mcp_server` says the caller may reach this upstream at all,
/// `mcp_tool` says which of its tools. Requiring BOTH is what keeps a server-wide grant from
/// silently becoming a tool-wide one, and SERVER FIRST is what makes an ungranted caller learn that
/// it is ungranted for the server rather than for a tool it was never going to reach.
impl EgressSubject for &ToolKey {
    type Grant = ToolGrant;

    /// FALSE, and this is the divergence the unification found rather than introduced: the A2A lease
    /// mint refuses a dead key and this path never has. It is left FALSE because a gate that started
    /// refusing more on this plane during a refactor is a behaviour change nobody asked for; the
    /// const is where the difference is now written down instead of being a fact about which file a
    /// reader opened. The inbound authentication chain is what rejects a dead key on this path.
    const REQUIRE_LIVE_KEY: bool = false;

    fn grants_required(&self) -> Vec<Requirement<ToolGrant>> {
        vec![
            Requirement {
                grant: ToolGrant::Server,
                scope_kind: "mcp_server",
                value: self.server().to_string(),
            },
            Requirement {
                grant: ToolGrant::Tool,
                scope_kind: "mcp_tool",
                value: self.namespaced(),
            },
        ]
    }
}

/// Why an egress credential was refused. Each arm is a case where minting would hand the caller
/// authority it does not hold.
///
/// THE WORDING IS THIS PLANE'S and the DECISION is core's: the two grant arms are core's
/// [`EgressRefusal`] wearing MCP's sentences, produced by the total conversion below, so an operator
/// reads about `mcp_server` and `mcp_tool` rather than about an abstract requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EgressDenied {
    /// The inbound principal has no `mcp_server` grant for this upstream.
    NoServerGrant { caller: String, server: String },
    /// The inbound principal has no `mcp_tool` grant for this namespaced tool.
    NoToolGrant { caller: String, tool: String },
    /// The caller's key is disabled, tombstoned or expired.
    ///
    /// UNREACHABLE ON THIS PLANE TODAY, and present anyway because the conversion from core's
    /// refusal is TOTAL: a refusal core can produce must have a sentence here rather than being
    /// folded into a nearby arm. The day `REQUIRE_LIVE_KEY` above is turned on, the operator gets a
    /// sentence that says what happened instead of a denial blaming a grant the caller holds.
    KeyNotLive { caller: String },
    /// `passthrough` was configured and the caller supplied no upstream credential. Fail closed:
    /// falling back to busbar's ambient credential is exactly the deputy this gate exists to close.
    PassthroughWithoutCallerCredential { server: String },
}

/// THE PLANE'S WORDING, TOTAL over core's refusal.
///
/// Every sentence below is byte-identical to the one this module printed when it owned its own gate;
/// the tests that assert them are the reason it must stay that way. Total on purpose: `match` with no
/// wildcard, so a refusal core grows later cannot arrive here silently.
impl From<EgressRefusal<ToolGrant>> for EgressDenied {
    fn from(refusal: EgressRefusal<ToolGrant>) -> Self {
        match refusal {
            EgressRefusal::KeyNotLive { caller } => EgressDenied::KeyNotLive { caller },
            EgressRefusal::NoGrant {
                caller,
                grant: ToolGrant::Server,
                value,
                ..
            } => EgressDenied::NoServerGrant {
                caller,
                server: value,
            },
            EgressRefusal::NoGrant {
                caller,
                grant: ToolGrant::Tool,
                value,
                ..
            } => EgressDenied::NoToolGrant {
                caller,
                tool: value,
            },
        }
    }
}

impl std::fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressDenied::NoServerGrant { caller, server } => write!(
                f,
                "key `{caller}` holds no `mcp_server` grant for `{server}`, so no upstream \
                 credential is selected for it: busbar does not spend its own credentials on behalf \
                 of a caller that is not itself authorised for the upstream"
            ),
            EgressDenied::NoToolGrant { caller, tool } => write!(
                f,
                "key `{caller}` holds no `mcp_tool` grant for `{tool}`, so no upstream credential \
                 is selected for it"
            ),
            EgressDenied::KeyNotLive { caller } => write!(
                f,
                "key `{caller}` is not live, so no upstream credential is selected for it"
            ),
            EgressDenied::PassthroughWithoutCallerCredential { server } => write!(
                f,
                "server `{server}` is configured `upstream_credentials: passthrough` and the caller \
                 supplied no credential for it; busbar will not substitute its own"
            ),
        }
    }
}

/// THE EGRESS GATE FOR THIS PLANE: [`busbar_substrate::egress_auth::gate::authorise`] with MCP's grant kind and
/// MCP's wording, and nothing else.
///
/// The witness is discarded because this plane's credential planner reads the tool key it already
/// holds; the A2A plane keeps its witness because its mint reads the destination off it. Both are the
/// same gate.
pub(crate) fn authorise_tool_egress(
    caller: &VirtualKey,
    key: &ToolKey,
) -> Result<(), EgressDenied> {
    // `now` is unused on this plane: `REQUIRE_LIVE_KEY` is false, so no expiry is consulted. Passing
    // 0 rather than plumbing a clock says that plainly — a clock argument this plane never reads
    // would be a parameter a future edit could believe was doing something.
    busbar_substrate::egress_auth::gate::authorise(caller, key, 0)
        .map(|_witness| ())
        .map_err(EgressDenied::from)
}

/// A SERVER-SCOPED EGRESS SUBJECT: a method busbar issues that names no tool.
///
/// ## Why this exists and is not a `ToolKey` with an invented tool in it
///
/// `prompts/list`, `resources/read`, `ping`, `tasks/get` and the rest of the verbs in
/// [`super::verb::UpstreamVerb`] reach an upstream without naming a tool. The tool subject above
/// requires BOTH `mcp_server` and `mcp_tool`, so putting one of these through it would need a
/// `mcp_tool:` value to compare against — and every available choice is wrong. A literal
/// (`fs_prompts/list`) invents a grant no operator can write, because `mcp_tool` values are routing
/// keys and that is not one. A wildcard would make the tool grant vacuous. Reusing the tool of an
/// unrelated call would authorise a verb against a grant for something else.
///
/// So the honest subject is the SERVER, and the requirement list says exactly that: one grant, not
/// two. An operator who grants `mcp_server: fs` has said this caller may reach that upstream, and a
/// `prompts/list` is precisely reaching that upstream.
///
/// This is NOT a second gate. It is a second SUBJECT for the one gate in
/// [`busbar_substrate::egress_auth::gate`] — the same extension point the A2A plane uses for its own — so the
/// decision, the ordering and the refusal type are all core's.
#[derive(Clone, Debug)]
pub(crate) struct ServerVerb<'a> {
    /// The registration being reached.
    pub(crate) server: &'a ServerId,
    /// The method name. Carried for the refusal's wording and for the audit record; it is NOT a
    /// grant value and nothing compares it against a scope.
    pub(crate) method: &'a str,
}

impl EgressSubject for &ServerVerb<'_> {
    type Grant = ToolGrant;

    /// FALSE, matching the tool subject above. The two subjects of one plane answering differently
    /// about key liveness would make the answer a property of which verb a caller happened to use.
    const REQUIRE_LIVE_KEY: bool = false;

    fn grants_required(&self) -> Vec<Requirement<ToolGrant>> {
        vec![Requirement {
            grant: ToolGrant::Server,
            scope_kind: "mcp_server",
            value: self.server.to_string(),
        }]
    }
}

/// THE EGRESS GATE FOR A SERVER-SCOPED VERB. Same gate, same wording, one grant.
pub(crate) fn authorise_server_egress(
    caller: &VirtualKey,
    subject: &ServerVerb<'_>,
) -> Result<(), EgressDenied> {
    busbar_substrate::egress_auth::gate::authorise(caller, subject, 0)
        .map(|_witness| ())
        .map_err(|refusal| {
            let denied = EgressDenied::from(refusal);
            // THE METHOD IS LOGGED AND NOT PUT IN THE REFUSAL. `EgressDenied`'s sentences are
            // asserted byte-for-byte by the batteries that own them, and widening one to carry a
            // verb would change a message an operator's own tooling may already match on. An
            // operator debugging a denial needs to know WHICH verb was refused, and this is where
            // that lives.
            tracing::debug!(
                server = %subject.server,
                method = %subject.method,
                caller = %caller.id,
                "mcp egress: a server-scoped verb was refused by the egress gate"
            );
            denied
        })
}

/// The DOWN-SCOPE for a SERVER-SCOPED verb: every tool the caller is granted on THIS server.
///
/// A wildcard principal gets the EMPTY string, which asks the authorization server for no narrowing
/// beyond the RFC 8707 `resource` — and that is deliberate rather than a gap. The tool subject's
/// wildcard rule narrows to "the single tool being called", and there is no tool here to narrow to;
/// inventing one would ask for a token scoped to a tool this verb is not touching. The audience
/// binding still holds, so the token is spendable at this upstream and at no other.
pub(crate) fn server_downscope(caller: &VirtualKey, server: &ServerId) -> String {
    let Some(list) = &caller.allowed_scopes else {
        return String::new();
    };
    let mut scopes: Vec<String> = list
        .iter()
        .filter(|s| s.kind == "mcp_tool")
        .filter_map(|s| ToolKey::parse(&s.value).ok())
        .filter(|k| k.server() == server)
        .map(|k| k.namespaced())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes.join(" ")
}

/// The DOWN-SCOPE for an RFC 8693 exchange: the space-delimited scope string to request.
///
/// Derived from the caller's grant, per the module header. A wildcard principal (`allowed_scopes:
/// None`) gets the SINGLE tool being called rather than everything the server offers, because a
/// wildcard is an absence of a constraint on the INBOUND side and must not become a grant of
/// everything on the OUTBOUND one.
///
/// Returned sorted, so the same grant produces the same scope string every time — an exchange whose
/// request body varies by iteration order is an exchange whose responses cannot be cached and whose
/// audit rows cannot be compared.
pub(crate) fn downscope(caller: &VirtualKey, server: &ServerId, called: &ToolKey) -> String {
    let mut scopes: Vec<String> = match &caller.allowed_scopes {
        None => vec![called.namespaced()],
        Some(list) => list
            .iter()
            .filter(|s| s.kind == "mcp_tool")
            .filter_map(|s| ToolKey::parse(&s.value).ok())
            .filter(|k| k.server() == server)
            .map(|k| k.namespaced())
            .collect(),
    };
    scopes.sort();
    scopes.dedup();
    scopes.join(" ")
}

/// A CREDENTIAL DECISION, resolved but not yet spent.
///
/// The planner returns this rather than a header so the exchange (which does network I/O against a
/// token endpoint) is a separate, testable step from the decision about what to ask for. Every field
/// of an [`ExchangeRequest`] is therefore assertable in a unit test with no token endpoint at all,
/// which is where the RFC 8693/8707 shape is actually pinned.
#[derive(Clone, Debug)]
pub(crate) enum CredentialPlan {
    /// Send nothing.
    None,
    /// Send this bearer verbatim.
    Bearer(Redacted<String>),
    /// Perform this exchange, then send the resulting bearer.
    Exchange(ExchangeRequest),
}

/// The exact RFC 8693 token-exchange request. Field names are the RFC's, so a reader comparing this
/// against §2.1 of RFC 8693 is comparing like with like.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExchangeRequest {
    pub(crate) token_url: String,
    /// Always `urn:ietf:params:oauth:grant-type:token-exchange`.
    pub(crate) grant_type: &'static str,
    pub(crate) subject_token: Redacted<String>,
    pub(crate) subject_token_type: String,
    /// RFC 8707 `resource`, and RFC 8693 §2.1's audience-equivalent. The upstream's canonical URI.
    pub(crate) resource: String,
    /// The down-scoped scope string. See [`downscope`].
    pub(crate) scope: String,
    /// Always `urn:ietf:params:oauth:token-type:access_token`: we want an access token back, not
    /// another exchangeable subject token.
    pub(crate) requested_token_type: &'static str,
}

impl ExchangeRequest {
    /// The `application/x-www-form-urlencoded` field pairs, in RFC order. Built here rather than at
    /// the HTTP call site so the wire shape is unit-assertable.
    pub(crate) fn form_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", self.grant_type.to_string()),
            (
                "subject_token",
                self.subject_token.expose_secret().to_string(),
            ),
            ("subject_token_type", self.subject_token_type.clone()),
            (
                "requested_token_type",
                self.requested_token_type.to_string(),
            ),
            ("resource", self.resource.clone()),
            ("scope", self.scope.clone()),
        ]
    }
}

/// PLAN the outbound credential for one dispatch.
///
/// Note what this function is NOT given: the caller's `busbar_key`. That is rule 1 expressed in a
/// signature — the value cannot be forwarded by a function that never receives it — and it is why
/// the adversarial test scans the REQUEST rather than this function's output: the signature is the
/// design, the scan is the proof.
pub(crate) fn plan_credential(
    server: &ServerId,
    credential: &UpstreamCredential,
    caller_key: &VirtualKey,
    caller_upstream_credential: Option<&Redacted<String>>,
    called: &ToolKey,
) -> Result<CredentialPlan, EgressDenied> {
    // THE GATE FIRST. Nothing below runs for a caller that is not authorised, so an unauthorised
    // caller cannot even cause a token-endpoint round trip on busbar's credentials.
    authorise_tool_egress(caller_key, called)?;
    plan_after_gate(
        server,
        credential,
        caller_upstream_credential,
        downscope(caller_key, server, called),
    )
}

/// PLAN the outbound credential for a SERVER-SCOPED verb — one that names no tool.
///
/// The same shape as [`plan_credential`] and deliberately the same ORDER: gate first, so a caller
/// with no `mcp_server` grant cannot cause a token-endpoint round trip on busbar's own credentials.
/// Only the subject and the down-scope differ, and both differences are argued for at
/// [`ServerVerb`] and [`server_downscope`].
pub(crate) fn plan_verb_credential(
    server: &ServerId,
    method: &str,
    credential: &UpstreamCredential,
    caller_key: &VirtualKey,
    caller_upstream_credential: Option<&Redacted<String>>,
) -> Result<CredentialPlan, EgressDenied> {
    authorise_server_egress(caller_key, &ServerVerb { server, method })?;
    plan_after_gate(
        server,
        credential,
        caller_upstream_credential,
        server_downscope(caller_key, server),
    )
}

/// The credential decision itself, AFTER whichever gate applies has passed.
///
/// One function so the two planners cannot come to disagree about what `passthrough` with no caller
/// credential means, or about whether an absent exchange config falls back to something. Reached
/// only from the two functions above, each of which has already run a gate — which is why this one
/// takes no caller key: it has nothing left to decide about authority, and a parameter it did not
/// need would be a parameter a later edit could believe was a check.
fn plan_after_gate(
    server: &ServerId,
    credential: &UpstreamCredential,
    caller_upstream_credential: Option<&Redacted<String>>,
    scope: String,
) -> Result<CredentialPlan, EgressDenied> {
    match credential {
        UpstreamCredential::None => Ok(CredentialPlan::None),
        UpstreamCredential::Static(secret) => Ok(CredentialPlan::Bearer(secret.clone())),
        UpstreamCredential::Passthrough => match caller_upstream_credential {
            Some(c) => Ok(CredentialPlan::Bearer(c.clone())),
            None => Err(EgressDenied::PassthroughWithoutCallerCredential {
                server: server.to_string(),
            }),
        },
        UpstreamCredential::Exchange(cfg) => Ok(CredentialPlan::Exchange(ExchangeRequest {
            token_url: cfg.token_url.clone(),
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token: cfg.subject_token.clone(),
            subject_token_type: cfg.subject_token_type.clone(),
            resource: cfg.resource.clone(),
            scope,
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        })),
    }
}

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/egress_tests.rs"]
mod egress_tests;

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/deputy_tests.rs"]
mod deputy_tests;
