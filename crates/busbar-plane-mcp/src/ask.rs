// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S OWN ASK (elicitation): an `InputRequiredResult` composed entirely from operator
//! configuration, filtered by the caller's declared capabilities and sealed in a `requestState`
//! busbar mints. Pure: the decision is the served engine's, in its order and words; the seal, the
//! nonce and the one-time redemption are a [`Seal`] the door hands in.
//!
//! An [`CallerAsk`] is authored by the operator: its one constructor takes an
//! [`AskEntryCfg`](crate::tools_config::AskEntryCfg), and its fields exist only inside the private module
//! that declares it, so nothing an upstream said can become one.
//!
//! If filtering by the caller's capabilities removes every ask in a round, the answer is a refusal
//! and never "proceed": proceeding would let a caller strip the operator's confirmation gate by
//! declaring nothing.

use serde_json::{json, Map, Value};

use crate::tools_config::{AskRoundCfg, ASK_ELICITATION, ASK_ROOTS, ASK_SAMPLING};

pub use authored::CallerAsk;

/// THE PRIVACY BOUNDARY: outside this module a [`CallerAsk`]'s fields do not exist, so the one way
/// to make one is [`CallerAsk::from_config`].
mod authored {
    use crate::tools_config::AskEntryCfg;

    /// One ask busbar makes of its caller: an entry of the `inputRequests` map.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CallerAsk {
        key: String,
        method: String,
        params: serde_json::Value,
    }

    impl CallerAsk {
        /// THE ONLY CONSTRUCTOR: an operator-written map entry.
        #[must_use]
        pub fn from_config(key: &str, cfg: &AskEntryCfg) -> Self {
            CallerAsk {
                key: key.to_string(),
                method: cfg.method.clone(),
                params: cfg.params.clone().unwrap_or_else(|| serde_json::json!({})),
            }
        }

        /// The entry's key in `inputRequests`.
        #[must_use]
        pub fn key(&self) -> &str {
            &self.key
        }

        /// The client method asked for.
        #[must_use]
        pub fn method(&self) -> &str {
            &self.method
        }

        /// The request `params`, verbatim.
        #[must_use]
        pub fn params(&self) -> &serde_json::Value {
            &self.params
        }
    }
}

impl CallerAsk {
    /// The client capability that gates this ask.
    fn capability_key(&self) -> Option<&'static str> {
        match self.method() {
            ASK_ELICITATION => Some("elicitation"),
            ASK_SAMPLING => Some("sampling"),
            ASK_ROOTS => Some("roots"),
            _ => None,
        }
    }
}

/// How long a minted `requestState` stands, in seconds: a short replay window.
pub const DEFAULT_TTL_SECS: u64 = 300;

/// The notification a caller announces its roots moved with: every state it was sealed under that
/// carries a roots answer stops verifying.
pub const NOTIFY_ROOTS_LIST_CHANGED: &str = "notifications/roots/list_changed";

/// The principal an ungoverned deployment's state is bound to: it has exactly one.
pub const UNGOVERNED: &str = "<ungoverned>";

/// THE SEALED PAYLOAD: who, which request, which round, and when.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AskState {
    /// The authenticated principal.
    #[serde(rename = "p")]
    pub principal: String,
    /// `tools/call` or `prompts/get`.
    #[serde(rename = "m")]
    pub method: String,
    /// The published capability name.
    #[serde(rename = "c")]
    pub capability: String,
    /// The digest of the request's arguments.
    #[serde(rename = "d")]
    pub args_digest: String,
    /// The catalogue generation it was minted under.
    #[serde(rename = "g")]
    pub generation: u64,
    /// The round this state ends.
    #[serde(rename = "r")]
    pub round: u32,
    /// Fresh randomness.
    #[serde(rename = "n")]
    pub nonce: String,
    /// Unix seconds at mint.
    #[serde(rename = "i")]
    pub issued_at: u64,
    /// Seconds of validity.
    #[serde(rename = "t")]
    pub ttl_secs: u64,
    /// The principal's roots epoch at mint, when the exchange includes a roots ask.
    #[serde(rename = "e", default, skip_serializing_if = "Option::is_none")]
    pub roots_epoch: Option<u64>,
    /// THE UPSTREAM'S ASK RELAYED TO THE CALLER (Law 11: busbar answers nothing on the caller's
    /// behalf): the member that asked, and its own `requestState`, nested in this one sealed state.
    /// Present only on a state minted for a relayed ask; busbar's own rounds were already answered.
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamLeg>,
}

/// AN UPSTREAM'S ASK, RELAYED: the pool member that asked (the retry goes back to it), the state it
/// sealed for itself (handed back to it verbatim on the retry; `None` when it sealed none), and how
/// many of its rounds this call has relayed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamLeg {
    /// The registration that asked.
    #[serde(rename = "m")]
    pub member: String,
    /// The upstream's own `requestState`, verbatim.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    /// The upstream rounds relayed so far: the next request is round `round`.
    #[serde(rename = "r")]
    pub round: u32,
}

/// Why a presented `requestState` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Not the form this plane writes.
    Malformed,
    /// The seal did not verify.
    BadSignature,
    /// Past its window.
    Expired,
    /// Sealed for another principal.
    WrongPrincipal,
    /// Sealed for another method, capability or argument set.
    WrongRequest,
    /// Sealed under a generation that is no longer live.
    WrongGeneration,
    /// Already redeemed.
    AlreadySpent,
    /// Sealed under a roots epoch the caller has since moved.
    StaleRoots,
}

impl Rejected {
    /// The stable audit reason word.
    #[must_use]
    pub fn audit_reason(self) -> &'static str {
        match self {
            Rejected::Malformed => "state_malformed",
            Rejected::BadSignature => "state_bad_signature",
            Rejected::Expired => "state_expired",
            Rejected::WrongPrincipal => "state_wrong_principal",
            Rejected::WrongRequest => "state_wrong_request",
            Rejected::WrongGeneration => "state_wrong_generation",
            Rejected::AlreadySpent => "state_already_spent",
            Rejected::StaleRoots => "state_stale_roots",
        }
    }
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::StaleRoots => f.write_str(
                "`requestState` was minted before you sent `notifications/roots/list_changed`, and \
                 the exchange it continues includes a `roots/list` answer — which your notification \
                 declared stale. Retry the request without `requestState` to restart the exchange \
                 and answer with your current roots.",
            ),
            _ => f.write_str(
                "`requestState` failed integrity verification and was refused. It is an opaque \
                 value minted by this server for one caller, one request and a short window; it \
                 cannot be modified, reused by another caller, replayed after it lapses, or \
                 presented on a different request.",
            ),
        }
    }
}

impl AskState {
    /// Whether this state was minted for this principal, request and generation, and is still
    /// inside its window at `now`.
    ///
    /// # Errors
    ///
    /// The first check it fails.
    pub fn matches(
        &self,
        principal: &str,
        method: &str,
        capability: &str,
        args_digest: &str,
        generation: u64,
        now: u64,
    ) -> Result<(), Rejected> {
        if now > self.issued_at.saturating_add(self.ttl_secs) {
            return Err(Rejected::Expired);
        }
        if self.principal != principal {
            return Err(Rejected::WrongPrincipal);
        }
        if self.method != method || self.capability != capability || self.args_digest != args_digest
        {
            return Err(Rejected::WrongRequest);
        }
        if self.generation != generation {
            return Err(Rejected::WrongGeneration);
        }
        Ok(())
    }
}

/// THE SEAL THE DOOR HANDS IN: minting and opening the integrity-protected state, a fresh nonce,
/// and the one-time redemption of a completed exchange. The host's signing and one-time claim stand
/// behind it.
pub trait Seal {
    /// The sealed form of `state`; `None` when it cannot be sealed.
    fn mint(&mut self, state: &AskState) -> Option<String>;
    /// The state `blob` seals.
    ///
    /// # Errors
    ///
    /// [`Rejected::Malformed`] or [`Rejected::BadSignature`].
    fn open(&mut self, blob: &str) -> Result<AskState, Rejected>;
    /// A fresh nonce; `None` when no randomness is reachable.
    fn nonce(&mut self) -> Option<String>;
    /// Spend `nonce`, standing until `expires_at`, exactly once: `true` for the first spend.
    fn redeem(&mut self, nonce: &str, expires_at: u64, now: u64) -> bool;
}

/// What the ask decision answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskDecision {
    /// No ask stands between the caller and the call.
    Proceed,
    /// Ask the caller.
    Ask {
        /// The round's asks the caller can answer.
        asks: Vec<CallerAsk>,
        /// The sealed state the retry presents.
        request_state: String,
        /// The round.
        round: u32,
    },
    /// Refused.
    Refuse(AskRefusal),
    /// THE RETRY OF A RELAYED UPSTREAM ASK: the caller's answers go to the member that asked,
    /// with the upstream's own state, verbatim. Busbar's own rounds were answered before the call
    /// went out, and this state is spent once.
    Relayed(UpstreamLeg),
}

/// Why the caller's side of the exchange was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskRefusal {
    /// The caller declares none of the capabilities the round needs.
    NoDeclaredCapability {
        /// The capability.
        capability: String,
        /// The round.
        round: u32,
        /// The capabilities it needs.
        required: Vec<&'static str>,
    },
    /// The round cap was reached.
    RoundCapExceeded {
        /// The capability.
        capability: String,
        /// The cap.
        cap: u32,
    },
    /// The presented state was refused.
    StateRejected(Rejected),
    /// State or answers presented where nothing was asked.
    Unsolicited {
        /// The capability.
        capability: String,
    },
    /// A retry answered nothing.
    Unanswered {
        /// The capability.
        capability: String,
        /// What was asked.
        missing: String,
    },
    /// No seal: the state cannot be protected.
    NoSealer {
        /// The capability.
        capability: String,
    },
}

impl AskRefusal {
    /// The stable audit reason word.
    #[must_use]
    pub fn audit_reason(&self) -> &'static str {
        match self {
            AskRefusal::NoDeclaredCapability { .. } => "ask_no_declared_capability",
            AskRefusal::RoundCapExceeded { .. } => "ask_round_cap",
            AskRefusal::StateRejected(r) => r.audit_reason(),
            AskRefusal::Unsolicited { .. } => "ask_unsolicited_state",
            AskRefusal::Unanswered { .. } => "ask_unanswered",
            AskRefusal::NoSealer { .. } => "ask_no_sealer",
        }
    }

    /// The refusal as the caller is answered: `400` `-32602` for refused state, `400` `-32021`
    /// naming the capabilities for an undeclared one, `403` `-32000` otherwise.
    #[must_use]
    pub fn refusal(&self, id: &Value) -> crate::tool_arrival::Refusal {
        let reason = json!({ "reason": self.audit_reason() });
        let (status, code, data) = match self {
            AskRefusal::StateRejected(_) => (400, crate::codec::CODE_INVALID_PARAMS, reason),
            AskRefusal::NoDeclaredCapability { required, .. } => {
                let caps: Map<String, Value> = required
                    .iter()
                    .map(|k| ((*k).to_string(), json!({})))
                    .collect();
                (
                    400,
                    crate::codec::CODE_MISSING_CLIENT_CAPABILITY,
                    json!({ "reason": self.audit_reason(), "requiredCapabilities": caps }),
                )
            }
            _ => (403, crate::codec::CODE_REFUSED, reason),
        };
        crate::tool_arrival::Refusal {
            status,
            id: Some(id.clone()),
            code,
            message: self.to_string(),
            data: Some(data),
        }
    }
}

impl std::fmt::Display for AskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AskRefusal::NoDeclaredCapability {
                capability, round, ..
            } => write!(
                f,
                "`{capability}` requires input from you before it runs, and your \
                 `_meta.io.modelcontextprotocol/clientCapabilities` declares none of the \
                 capabilities round {round} of that exchange needs. Declaring no capabilities does \
                 not skip the operator's gate; it means the call cannot proceed."
            ),
            AskRefusal::RoundCapExceeded { capability, cap } => write!(
                f,
                "this exchange with `{capability}` has already used its {cap} input rounds. The cap \
                 is hard and it is carried inside the request state, so it cannot be reset by \
                 replaying an earlier one."
            ),
            AskRefusal::StateRejected(r) => write!(f, "{r}"),
            AskRefusal::Unsolicited { capability } => write!(
                f,
                "`{capability}` did not ask you for any input, so `inputResponses` and \
                 `requestState` have nothing to answer. This server does not accept request state it \
                 did not mint."
            ),
            AskRefusal::Unanswered {
                capability,
                missing,
            } => write!(
                f,
                "the retry of `{capability}` answered none of the requested inputs (expected \
                 `{missing}`)."
            ),
            AskRefusal::NoSealer { capability } => write!(
                f,
                "`{capability}` is configured to request input, but this deployment has no \
                 `auth.signing_key` and therefore cannot mint the integrity-protected `requestState` \
                 the protocol requires. The call is refused rather than served with unprotected \
                 state."
            ),
        }
    }
}

/// What the request presented on a retry.
#[derive(Clone, Copy, Debug, Default)]
pub struct Retry<'a> {
    /// `params.inputResponses`.
    pub responses: Option<&'a Value>,
    /// `params.requestState`.
    pub state: Option<&'a str>,
}

/// What the state is bound to.
#[derive(Clone, Copy, Debug)]
pub struct Bind<'a> {
    /// The authenticated principal.
    pub principal: &'a str,
    /// `tools/call` or `prompts/get`.
    pub method: &'a str,
    /// The published capability.
    pub capability: &'a str,
    /// The live catalogue generation.
    pub generation: u64,
    /// Unix seconds now.
    pub now: u64,
    /// The principal's roots epoch now.
    pub roots_epoch: u64,
}

/// The digest of a request's arguments: SHA-256 over their serialisation (key-ordered), hex.
#[must_use]
pub fn digest_arguments(arguments: &Value) -> String {
    busbar_contract::redacted::sha256_hex(&serde_json::to_vec(arguments).unwrap_or_default())
}

/// Whether the caller's capabilities declare `key`.
/// THE ASKS OF ONE ROUND busbar makes of its caller from inside a task, filtered to the capabilities
/// the caller declared (the served engine's `asks_for_round`): an ask whose capability the caller
/// did not declare is not made.
#[must_use]
pub fn asks_for_round(round: &AskRoundCfg, capabilities: &Value) -> Vec<CallerAsk> {
    round
        .iter()
        .map(|(key, cfg)| CallerAsk::from_config(key, cfg))
        .filter(|ask| {
            ask.capability_key()
                .is_some_and(|k| declared(capabilities, k))
        })
        .collect()
}

fn declared(capabilities: &Value, key: &str) -> bool {
    capabilities.get(key).is_some_and(|v| !v.is_null())
}

/// THE DECISION, in the engine's order: no rounds; the presented state opened and matched; the
/// cap; a completed exchange redeemed once; an unanswered retry; the round's asks filtered by the
/// caller's capabilities; a fresh state sealed. `seal` is `None` when the deployment cannot seal.
pub fn decide(
    rounds: &[AskRoundCfg],
    cap: u32,
    caller_capabilities: &Value,
    retry: Retry<'_>,
    bind: Bind<'_>,
    args_digest: &str,
    seal: Option<&mut dyn Seal>,
) -> AskDecision {
    let capability = || bind.capability.to_string();
    let mut seal = seal;
    // A RELAYED ASK'S RETRY: the state opened and matched as busbar's own is, then spent once.
    if let (Some(blob), Some(sealer)) = (retry.state, seal.as_deref_mut()) {
        if let Ok(opened) = sealer.open(blob) {
            if let Some(leg) = opened.upstream.clone() {
                if let Err(e) = opened.matches(
                    bind.principal,
                    bind.method,
                    bind.capability,
                    args_digest,
                    bind.generation,
                    bind.now,
                ) {
                    return AskDecision::Refuse(AskRefusal::StateRejected(e));
                }
                let expires_at = opened.issued_at.saturating_add(opened.ttl_secs);
                if !sealer.redeem(&opened.nonce, expires_at, bind.now) {
                    return AskDecision::Refuse(AskRefusal::StateRejected(Rejected::AlreadySpent));
                }
                return AskDecision::Relayed(leg);
            }
        }
    }
    if rounds.is_empty() {
        if retry.state.is_some() || retry.responses.is_some() {
            return AskDecision::Refuse(AskRefusal::Unsolicited {
                capability: capability(),
            });
        }
        return AskDecision::Proceed;
    }
    let no_sealer = || {
        AskDecision::Refuse(AskRefusal::NoSealer {
            capability: capability(),
        })
    };
    let mut presented: Option<(String, u64)> = None;
    let next_round = match retry.state {
        None => 0u32,
        Some(blob) => {
            let Some(seal) = seal.as_deref_mut() else {
                return no_sealer();
            };
            let opened = match seal.open(blob) {
                Ok(s) => s,
                Err(e) => return AskDecision::Refuse(AskRefusal::StateRejected(e)),
            };
            if let Err(e) = opened.matches(
                bind.principal,
                bind.method,
                bind.capability,
                args_digest,
                bind.generation,
                bind.now,
            ) {
                return AskDecision::Refuse(AskRefusal::StateRejected(e));
            }
            if opened
                .roots_epoch
                .is_some_and(|sealed| sealed != bind.roots_epoch)
            {
                return AskDecision::Refuse(AskRefusal::StateRejected(Rejected::StaleRoots));
            }
            presented = Some((
                opened.nonce.clone(),
                opened.issued_at.saturating_add(opened.ttl_secs),
            ));
            opened.round.saturating_add(1)
        }
    };
    if next_round >= cap && (next_round as usize) < rounds.len() {
        return AskDecision::Refuse(AskRefusal::RoundCapExceeded {
            capability: capability(),
            cap,
        });
    }
    let Some(this_round) = rounds.get(next_round as usize) else {
        let (Some((nonce, expires_at)), Some(seal)) = (presented, seal.as_deref_mut()) else {
            return AskDecision::Refuse(AskRefusal::StateRejected(Rejected::AlreadySpent));
        };
        if !seal.redeem(&nonce, expires_at, bind.now) {
            return AskDecision::Refuse(AskRefusal::StateRejected(Rejected::AlreadySpent));
        }
        return AskDecision::Proceed;
    };
    if next_round > 0 {
        let answered = retry
            .responses
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty());
        if !answered {
            let previous = rounds
                .get(next_round as usize - 1)
                .map(|r| r.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            return AskDecision::Refuse(AskRefusal::Unanswered {
                capability: capability(),
                missing: previous,
            });
        }
    }
    let asks: Vec<CallerAsk> = this_round
        .iter()
        .map(|(key, cfg)| CallerAsk::from_config(key, cfg))
        .filter(|a| {
            a.capability_key()
                .is_some_and(|k| declared(caller_capabilities, k))
        })
        .collect();
    if asks.is_empty() {
        let mut required: Vec<&'static str> = Vec::new();
        for (key, cfg) in this_round {
            if let Some(k) = CallerAsk::from_config(key, cfg).capability_key() {
                if !required.contains(&k) {
                    required.push(k);
                }
            }
        }
        return AskDecision::Refuse(AskRefusal::NoDeclaredCapability {
            capability: capability(),
            round: next_round,
            required,
        });
    }
    let Some(seal) = seal else {
        return no_sealer();
    };
    let Some(nonce) = seal.nonce() else {
        return no_sealer();
    };
    let exchange_asks_roots = rounds
        .iter()
        .flat_map(|round| round.values())
        .any(|cfg| cfg.method == ASK_ROOTS);
    let Some(request_state) = seal.mint(&AskState {
        principal: bind.principal.to_string(),
        method: bind.method.to_string(),
        capability: bind.capability.to_string(),
        args_digest: args_digest.to_string(),
        generation: bind.generation,
        round: next_round,
        nonce,
        issued_at: bind.now,
        ttl_secs: DEFAULT_TTL_SECS,
        roots_epoch: exchange_asks_roots.then_some(bind.roots_epoch),
        upstream: None,
    }) else {
        return no_sealer();
    };
    AskDecision::Ask {
        asks,
        request_state,
        round: next_round,
    }
}

/// The `input_required` result busbar composes from its own asks: `200`, the asks keyed as the
/// operator keyed them, and the sealed state.
#[must_use]
pub fn input_required_result(id: &Value, asks: &[CallerAsk], request_state: &str) -> Vec<u8> {
    let mut requests = Map::new();
    for ask in asks {
        requests.insert(
            ask.key().to_string(),
            json!({ "method": ask.method(), "params": ask.params() }),
        );
    }
    let mut value = Map::new();
    value.insert(
        "resultType".into(),
        crate::jsonrpc::RESULT_TYPE_INPUT_REQUIRED.into(),
    );
    value.insert("inputRequests".into(), Value::Object(requests));
    value.insert("requestState".into(), request_state.into());
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    envelope.insert("id".into(), id.clone());
    envelope.insert("result".into(), Value::Object(value));
    serde_json::to_vec(&Value::Object(envelope)).unwrap_or_default()
}

/// THE STATE A RELAYED UPSTREAM ASK IS ANSWERED UNDER: busbar's one sealed `requestState`, bound to
/// the principal, the call (method, tool, arguments as the caller sent them) and the catalogue
/// generation, nesting the member that asked and its own state. `None` when it cannot be sealed.
#[must_use]
pub fn relay_state(
    bind: Bind<'_>,
    args_digest: &str,
    leg: UpstreamLeg,
    seal: &mut dyn Seal,
) -> Option<String> {
    let nonce = seal.nonce()?;
    seal.mint(&AskState {
        principal: bind.principal.to_string(),
        method: bind.method.to_string(),
        capability: bind.capability.to_string(),
        args_digest: args_digest.to_string(),
        generation: bind.generation,
        round: 0,
        nonce,
        issued_at: bind.now,
        ttl_secs: DEFAULT_TTL_SECS,
        roots_epoch: None,
        upstream: Some(leg),
    })
}

/// THE UPSTREAM'S `InputRequiredResult`, RELAYED: its result as it came (`inputRequests` verbatim),
/// its own `requestState` replaced by busbar's sealed `state`.
#[must_use]
pub fn relayed_result(id: &Value, upstream: &Value, state: &str) -> Vec<u8> {
    let mut result = upstream.as_object().cloned().unwrap_or_default();
    result.insert("requestState".into(), state.into());
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": Value::Object(result) }))
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/ask.rs"]
mod tests;
