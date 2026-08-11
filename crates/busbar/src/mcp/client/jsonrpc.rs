// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND WIRE for MCP revision `2026-07-28`: the JSON-RPC envelope busbar sends to an
//! upstream, and the rules that govern what busbar does with the answer.
//!
//! ## Symmetry with the ingress, deliberately
//!
//! `crate::mcp::ingress` enforces this revision's transport MUSTs on requests busbar RECEIVES:
//! `_meta` at `params._meta`, `Mcp-Method` mirroring the body's method, `Mcp-Name` mirroring the
//! target, `MCP-Protocol-Version` mirroring `_meta`. This module produces requests that SATISFY the
//! same MUSTs, and the constants are imported from the ingress rather than restated. A second copy
//! of `"io.modelcontextprotocol/protocolVersion"` is a second thing to get wrong, and the failure
//! mode is silent: busbar would accept requests it could not itself send.
//!
//! There is no `initialize` and there is no session. Every request is self-describing, so there is
//! nothing to establish and nothing to invalidate — which is why nothing in this module caches a
//! negotiated fact across two requests.
//!
//! ## The namespaced name is BUSBAR'S, not the upstream's
//!
//! `{server}_{tool}` is how busbar names the tool internally and to its own callers. The upstream
//! has never heard of it and would answer `-32602` to it. So the outbound `params.name` is the
//! UN-namespaced tool, and the namespacing is stripped at exactly one point — here — rather than at
//! each call site. This is also why the routing key is a pair rather than a string (see
//! `super::identity`): stripping a prefix off a rendering would be parsing, and parsing is where the
//! ambiguity lives.
//!
//! ## An upstream's ask terminates at busbar
//!
//! Under this revision a server cannot send a request. Sampling, elicitation and roots come back
//! INLINE as an `InputRequiredResult` in the result of a call busbar made, and busbar decides
//! whether to satisfy it. Three rules, all here:
//!
//! 1. **Deny by default, per-server grant.** [`ServerRequestGrants`] is all-false at construction.
//! 2. **Re-checked on EVERY retry.** There is no handshake to check it once at, so
//!    [`InputRequiredLoop::may_satisfy`] takes the grants each round rather than capturing them.
//! 3. **The loop is BOUNDED and every round is metered.** Removing the handshake turned one call
//!    into a sequence, and a hostile upstream can return `InputRequiredResult` forever to amplify
//!    cost — every satisfied sampling round is a real LLM call against real budget.
//!
//! And the rule this revision creates, which a design written against server-initiated requests had
//! no reason to anticipate: an upstream's `InputRequiredResult` is NEVER proxied outward to
//! busbar's own caller. Doing so would launder an upstream's request for authority through the
//! party the caller actually trusts, and would ask that caller to satisfy, on the upstream's
//! behalf, an ask busbar itself declined.

use super::identity::ToolKey;
use crate::mcp::ingress::PROTOCOL_VERSION;

/// The `_meta` key a progress token travels under, both directions. Serialised as `null` when
/// absent, which `serde_json` omits from the object rather than sending — so a caller that asked for
/// no progress produces an outbound `_meta` byte-identical to the one busbar sent before this.
const META_PROGRESS_TOKEN: &str = "progressToken";

/// The `_meta` key carrying a request's protocol version. Imported semantics, restated as a private
/// constant only because the ingress keeps its own private; the ingress test suite and this module's
/// pin the same literal, and `tests/wire_tests.rs` asserts they agree.
pub(crate) const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// The `_meta` key carrying the client's capabilities for THIS request.
pub(crate) const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// A request busbar is about to send: everything, serialized, in one value.
///
/// One struct rather than a builder chain because it is what the adversarial no-passthrough test
/// scans. A test that has to reconstruct the request from a builder's intermediate state is a test
/// that can miss the field the builder added last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRequest {
    pub(crate) url: String,
    /// Header name/value pairs, lower-cased names, in the order they will be written.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl OutboundRequest {
    /// EVERY byte this request will put on the wire, concatenated: URL, then each header name and
    /// value, then the body.
    ///
    /// This exists for the adversarial scan and for nothing else. Its value is that it is derived
    /// from the same fields the transport writes, so a field added to `OutboundRequest` without
    /// being added here fails `wire_tests::every_field_is_scanned` — a scan that silently stops
    /// covering a new field is the exact false green this rule exists to prevent.
    /// Used by the tests that scan the whole wire for a leaked caller credential; the dispatch
    /// path hands the body to the transport directly.
    #[allow(dead_code)]
    pub(crate) fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.url.as_bytes());
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }
}

/// Build a `tools/call` for `key` against `url`.
///
/// `authorization` is the ALREADY-PLANNED credential header value (see `super::egress`). It arrives
/// as a plain `String` rather than as a caller context, which is rule 1 in the type system: this
/// function has no access to the caller's busbar key and therefore no way to send it.
pub(crate) fn tools_call(
    url: &str,
    key: &ToolKey,
    arguments: &serde_json::Value,
    request_id: u64,
    authorization: Option<&str>,
) -> OutboundRequest {
    // The UN-namespaced name: see the module header.
    let name = key.tool();
    // BUSBAR'S OWN TOKEN, not the caller's. Sent only when the caller asked for progress at all —
    // a server MUST NOT emit progress without a token, so sending none is how busbar says "this
    // caller did not ask". Derived from `request_id`, which is already unique per outbound call, so
    // two concurrent calls cannot be told apart by the upstream as one conversation.
    let progress_token: Option<String> = super::super::UPSTREAM_PROGRESS
        .try_with(|slot| {
            slot.lock().ok().and_then(|ch| {
                ch.caller_token
                    .as_ref()
                    .map(|_| format!("busbar-{request_id}"))
            })
        })
        .ok()
        .flatten();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
            "_meta": {
                META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                META_PROGRESS_TOKEN: progress_token,
                // busbar declares NO client capabilities. Sampling, elicitation and roots are
                // deny-by-default per server, and declaring a capability we then refuse to
                // honour invites an upstream to build a call sequence around it. Declaring the empty
                // set is the honest statement of a client that will not be answering.
                META_CLIENT_CAPABILITIES: {},
            },
        },
    });
    envelope(url, "tools/call", Some(name), body, authorization)
}

/// Build a `tools/list` for one server.
/// The CONNECT-path request. Nothing fetches a live tool list yet — that is the gap named in
/// `client::catalogue`.
#[allow(dead_code)]
pub(crate) fn tools_list(
    url: &str,
    request_id: u64,
    authorization: Option<&str>,
) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {
            "_meta": {
                META_PROTOCOL_VERSION: PROTOCOL_VERSION,
                META_CLIENT_CAPABILITIES: {},
            },
        },
    });
    envelope(url, "tools/list", None, body, authorization)
}

/// The shared envelope: the mirrored headers this revision REQUIRES, written from the same values
/// that went into the body so they cannot disagree.
///
/// Built from the body's own values rather than from the caller's arguments a second time. A
/// mirrored header whose value is computed twice is a mirrored header that can differ, which is the
/// request-smuggling primitive the mirroring exists to close — and busbar's own ingress answers
/// `-32020` to it, so a bug here would be caught only by an upstream strict enough to check.
fn envelope(
    url: &str,
    method: &str,
    name: Option<&str>,
    body: serde_json::Value,
    authorization: Option<&str>,
) -> OutboundRequest {
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        // SSE is a permitted content type for the RESPONSE to a POST in this revision, and nothing
        // more — there is no GET stream. Accepting both is what lets an upstream stream a long tool
        // result without busbar having to speak a second transport.
        (
            "accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
        (
            "mcp-protocol-version".to_string(),
            PROTOCOL_VERSION.to_string(),
        ),
        ("mcp-method".to_string(), method.to_string()),
    ];
    if let Some(name) = name {
        headers.push(("mcp-name".to_string(), encode_sentinel(name)));
    }
    if let Some(auth) = authorization {
        headers.push(("authorization".to_string(), format!("Bearer {auth}")));
    }
    OutboundRequest {
        url: url.to_string(),
        headers,
        body: serde_json::to_vec(&body).unwrap_or_default(),
    }
}

/// Encode a name for `Mcp-Name` using this revision's `=?base64?…?=` sentinel WHEN IT MUST BE.
///
/// A header value may carry only visible ASCII plus space. A tool name is validated to
/// `[A-Za-z0-9_.-]` at registration (`super::identity`), so in practice the sentinel is never
/// needed — but "in practice never" is exactly the branch that rots, so the encoder is written and
/// exercised rather than assumed away. The decision is on the VALUE, never on a flag, so an encoded
/// and a plain name cannot both describe the same request.
fn encode_sentinel(name: &str) -> String {
    use base64::Engine as _;
    if name
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'=' && b != b'?')
    {
        return name.to_string();
    }
    format!(
        "=?base64?{}?=",
        base64::engine::general_purpose::STANDARD.encode(name)
    )
}

/// The parsed shape of a JSON-RPC response, reduced to the three outcomes dispatch cares about.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RpcOutcome {
    /// A normal result.
    Result(serde_json::Value),
    /// A JSON-RPC error object.
    Error { code: i64, message: String },
    /// The upstream is asking busbar to spend busbar's OWN authority: an `InputRequiredResult`.
    /// Carries the kind of ask so the grant check names the right grant.
    InputRequired { kind: ServerAsk },
    /// The body was not a JSON-RPC response at all.
    Malformed(String),
}

/// The three things an upstream may ask for, kept as a closed enum so a fourth cannot be handled by
/// a default arm that says yes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServerAsk {
    /// `sampling/createMessage`: run an LLM completion on busbar's pools and budget.
    Sampling,
    /// Ask a human for input.
    Elicitation,
    /// Disclose filesystem roots.
    Roots,
}

impl ServerAsk {
    pub(crate) fn key(self) -> &'static str {
        match self {
            ServerAsk::Sampling => "sampling",
            ServerAsk::Elicitation => "elicitation",
            ServerAsk::Roots => "roots",
        }
    }

    /// The ORDER OF DANGER, used to collapse a multi-method `inputRequests` map to the one kind the
    /// grant gate will test. Ranked by what satisfying the ask would actually SPEND:
    ///
    /// - `sampling` is an LLM completion on busbar's own pools and budget — money, and unbounded;
    /// - `elicitation` interrupts a human;
    /// - `roots` discloses filesystem structure.
    ///
    /// Written as a rank rather than a `match` on pairs so a fourth kind cannot be added without
    /// giving it a position — which is the decision that would otherwise be made by whichever arm
    /// somebody happened to write first.
    fn rank(self) -> u8 {
        match self {
            ServerAsk::Roots => 0,
            ServerAsk::Elicitation => 1,
            ServerAsk::Sampling => 2,
        }
    }

    fn most_privileged(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Parse an upstream response body.
pub(crate) fn parse_response(body: &[u8]) -> RpcOutcome {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return RpcOutcome::Malformed("upstream response is not valid JSON".to_string());
    };
    let Some(obj) = value.as_object() else {
        return RpcOutcome::Malformed(
            "upstream response is not a JSON-RPC message object".to_string(),
        );
    };
    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return RpcOutcome::Malformed("upstream response `jsonrpc` is not \"2.0\"".to_string());
    }
    if let Some(err) = obj.get("error").and_then(|v| v.as_object()) {
        return RpcOutcome::Error {
            code: err.get("code").and_then(|v| v.as_i64()).unwrap_or(0),
            message: err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        };
    }
    let Some(result) = obj.get("result") else {
        return RpcOutcome::Malformed(
            "upstream response carries neither `result` nor `error`".to_string(),
        );
    };
    if let Some(ask) = input_required_kind(result) {
        return RpcOutcome::InputRequired { kind: ask };
    }
    RpcOutcome::Result(result.clone())
}

/// Recognise an `InputRequiredResult` and which authority it is asking for.
///
/// ## The shape this reads is the SPECIFICATION'S, and the correction matters more than it looks
///
/// This function used to test `result.type == "input_required"` and read `result.request` as a
/// string. Neither key exists in MRTR. `mrtr.mdx:126-180` and the schema's `InputRequiredResult`
/// agree: the discriminator is **`resultType`**, and the asks are a **map** at `inputRequests`
/// whose values are request objects each naming a `method`.
///
/// So a CONFORMANT upstream's ask failed this predicate, was returned as an ordinary
/// [`RpcOutcome::Result`], became `Outcome::Completed`, and was written onto the wire to busbar's
/// own caller verbatim — `resultType`, `inputRequests`, `requestState` and all. The type-level
/// guarantee in [`crate::mcp::inputreq`] (an `Outcome` with no arm that can carry an `Ask`) was real
/// and was never reached, because whether control reaches it is decided HERE. A rule enforced by a
/// missing enum variant still needs the predicate that routes to it to be correct.
///
/// The reason the tests did not catch it is worth recording next to the fix: the only fixtures that
/// exercised this minted busbar's own invented shape, so the parser and the fixture agreed with each
/// other and with no server in existence.
///
/// ## Why an ask with no `inputRequests` is still an ask
///
/// `mrtr.mdx:245` makes `inputRequests` and `requestState` individually OPTIONAL — a server must
/// include at least ONE of them. Keying recognition off `inputRequests` alone would therefore let an
/// upstream slip an ask past this gate by omitting the field the spec says it may omit.
///
/// ## Why the MOST PRIVILEGED method in the map decides
///
/// One `inputRequests` map may name several methods at once. Judging against the first key iterated
/// would let an upstream smuggle a `sampling/createMessage` — a real LLM call on busbar's pools and
/// budget — behind a `roots/list` it knows the operator granted. The gate downstream tests ONE kind,
/// so the kind reported here must be the one with the most to lose.
fn input_required_kind(result: &serde_json::Value) -> Option<ServerAsk> {
    let obj = result.as_object()?;
    let by_spec = obj.get("resultType").and_then(|v| v.as_str()) == Some("input_required");
    // The shape busbar itself once invented. No conformant server emits it, so this can only ever
    // catch a NON-conformant upstream — and refusing that upstream's ask is still the right answer,
    // which is the whole reason to keep a line that should never fire.
    let legacy = obj.get("type").and_then(|v| v.as_str()) == Some("input_required");
    if !by_spec && !legacy {
        return None;
    }

    let mut kind: Option<ServerAsk> = None;
    if let Some(requests) = obj.get("inputRequests").and_then(|v| v.as_object()) {
        for request in requests.values() {
            let named = match request.get("method").and_then(|v| v.as_str()) {
                Some("sampling/createMessage") => ServerAsk::Sampling,
                Some("elicitation/create") => ServerAsk::Elicitation,
                Some("roots/list") => ServerAsk::Roots,
                // An ask naming something we do not recognise is STILL AN ASK, and an unrecognised
                // ask is refused rather than passed through — which is what dropping it would do.
                // Mapping it to the most privileged kind makes the refusal land on a grant an
                // operator has to have set deliberately.
                _ => ServerAsk::Sampling,
            };
            kind = Some(match kind {
                None => named,
                Some(worst) => worst.most_privileged(named),
            });
        }
    }
    // An ask that names no method at all — `requestState` only, or the legacy shape — is judged
    // against the most privileged grant for the same reason.
    Some(kind.unwrap_or(ServerAsk::Sampling))
}

/// The per-server grants, unchanged by the stateless revision. What moved is WHERE they are
/// consulted: from refusing a server's inbound request to refusing to answer its inline ask.
///
/// All false at construction, and there is no `all()` constructor. Deny-by-default is a property of
/// the type, not of a config default somebody can invert.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServerRequestGrants {
    pub(crate) sampling: bool,
    pub(crate) elicitation: bool,
    pub(crate) roots: bool,
}

impl ServerRequestGrants {
    /// Read by the connect-path grant preview; the live gate reads the server plane's grants.
    #[allow(dead_code)]
    pub(crate) fn allows(&self, ask: ServerAsk) -> bool {
        match ask {
            ServerAsk::Sampling => self.sampling,
            ServerAsk::Elicitation => self.elicitation,
            ServerAsk::Roots => self.roots,
        }
    }
}

/// Why busbar refused to satisfy an upstream's ask.
#[derive(Clone, Debug, PartialEq, Eq)]
// Reached only by the connect/refresh path, which has no verb yet.
#[allow(dead_code)]
pub(crate) enum AskRefusal {
    /// The server's registry entry carries no grant for this ask.
    Ungranted { server: String, ask: &'static str },
    /// The bounded input-required loop is exhausted.
    LoopExhausted { server: String, max_rounds: u32 },
}

impl std::fmt::Display for AskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AskRefusal::Ungranted { server, ask } => write!(
                f,
                "upstream `{server}` asked busbar to satisfy `{ask}` and its registry entry carries \
                 no `{ask}` grant; the call fails here and the ask is not proxied to the caller"
            ),
            AskRefusal::LoopExhausted { server, max_rounds } => write!(
                f,
                "upstream `{server}` returned an input-required result more than {max_rounds} \
                 times for one dispatch; the sequence is capped because every satisfied round is a \
                 real, budgeted request"
            ),
        }
    }
}

/// THE BOUNDED, METERED INPUT-REQUIRED LOOP.
///
/// A hard cap, refused past it, not a warning. Constructed per logical dispatch, so the bound is per
/// dispatch and not per connection — there is no connection-scoped state under this revision, and a
/// counter that outlived a dispatch would be a session by another name.
#[derive(Debug)]
// Reached only by the connect/refresh path, which has no verb yet.
#[allow(dead_code)]
pub(crate) struct InputRequiredLoop {
    server: String,
    max_rounds: u32,
    rounds: u32,
}

impl InputRequiredLoop {
    // Reached only by the connect/refresh path, which has no verb yet.
    #[allow(dead_code)]
    pub(crate) fn new(server: &str, max_rounds: u32) -> Self {
        Self {
            server: server.to_string(),
            max_rounds,
            rounds: 0,
        }
    }

    /// May busbar satisfy this ask, right now?
    ///
    /// `grants` is a PARAMETER rather than a field, and that is the re-check-every-round rule
    /// written into a signature: the grant is re-derived from the live registry snapshot each time,
    /// so a revocation bites on the next retry, not at the end of a sequence that has no end.
    // Reached only by the connect/refresh path, which has no verb yet.
    #[allow(dead_code)]
    pub(crate) fn may_satisfy(
        &mut self,
        ask: ServerAsk,
        grants: ServerRequestGrants,
    ) -> Result<(), AskRefusal> {
        if !grants.allows(ask) {
            return Err(AskRefusal::Ungranted {
                server: self.server.clone(),
                ask: ask.key(),
            });
        }
        if self.rounds >= self.max_rounds {
            return Err(AskRefusal::LoopExhausted {
                server: self.server.clone(),
                max_rounds: self.max_rounds,
            });
        }
        self.rounds += 1;
        Ok(())
    }

    /// Rounds actually satisfied. Read by the metering call site, because each round has to be
    /// attributed and metered like any other request, and a count nobody reads is a count nobody
    /// meters.
    // Read by the connect-path preview; the live loop bound lives on the server plane.
    #[allow(dead_code)]
    pub(crate) fn rounds(&self) -> u32 {
        self.rounds
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod wire_tests;

#[cfg(test)]
#[path = "tests/ask_tests.rs"]
mod ask_tests;
