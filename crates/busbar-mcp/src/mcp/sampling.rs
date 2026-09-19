// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `sampling/createMessage`, ASKED BY AN UPSTREAM AND ANSWERED — the satisfier behind
//! `grants.sampling`, and the budget that was the whole reason it did not exist.
//!
//! ## What was missing was never plumbing
//!
//! The refusal this module replaces said: *"a granted `sampling` would be a real LLM request on
//! busbar's own pools with no per-upstream budget to charge it to."* Both halves of that sentence
//! are answered by the same config block, [`crate::mcp::config::SamplingCfg`]
//! (`tools.<server>.sampling`), which is the roots policy's shape on the other grant: the grant
//! ADMITS the ask, the policy says what may ANSWER it, and neither implies the other. The policy
//! is boot-vetted; a policy behind a closed grant refuses boot; a grant with no policy refuses the
//! ask as unsatisfiable naming the exact key.
//!
//! ## THE ONE PATHWAY, which is the sentence this module must keep true
//!
//! A sampling ask IS an LLM request, so it rides the LLM request's own pipeline —
//! [`EngineHost::synthesize_completion`](busbar_substrate::plane_host::EngineHost::synthesize_completion),
//! the neutral host seam over the same resolved core every arriving chat request enters after its
//! model is known. That buys, without a second implementation of any of them: the
//! INBOUND caller's governance (the completion is admitted under the caller's key, charged on the
//! caller's budget, refused by the caller's pool grant), the operator's hooks and gates, breaker
//! and failover, token-accurate metering, and the request log. There is deliberately no thinner
//! side channel — a completion that skipped any of those would be an upstream spending authority
//! no gate ever saw, which is the exact confused-deputy shape this plane exists to close.
//!
//! The model the completion runs on is the OPERATOR'S declaration, never the ask's
//! `modelPreferences`: the payload is attacker-controlled content, and letting it name the pool
//! lets a hostile upstream pick which of the operator's providers to spend on.
//!
//! ## THE PER-UPSTREAM BUDGET, and why it exists beside three other bounds
//!
//! Four bounds meet on one satisfied ask, and each answers a question the others cannot:
//! the ROUND CAP bounds one dispatch, the CALLER'S BUDGET bounds one principal, the declared
//! `max_tokens` bounds one completion — and [`SamplingSpend`] bounds THE UPSTREAM, across every
//! caller and every dispatch at once, because "how much may this server induce us to spend" is a
//! statement about the server and none of the other three can make it. It is spent BEFORE the
//! model leg is entered, so a refused completion costs nothing, and it is carried across config
//! applies on the engine snapshot like the spent-approval ledger, because spend that happened is
//! evidence, not intent, and an apply must not refill it.

use std::collections::HashMap;
use std::sync::Mutex;

/// PER-UPSTREAM SAMPLING SPEND — how many completions each registered server has induced in the
/// current minute window. One instance per deployment, Arc-shared across config applies.
///
/// A fixed one-minute window rather than a sliding one, deliberately: the cap is a budget, not a
/// rate shaper, and the failure mode it exists for — an upstream returning `InputRequiredResult`
/// for ever — is stopped just as dead by a window that resets on a minute boundary. The map is
/// bounded by the deployment's own registration population: the key is the registered server id,
/// never a value the upstream chooses.
#[derive(Debug, Default)]
pub(crate) struct SamplingSpend {
    windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl SamplingSpend {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// SPEND one completion from `server`'s per-minute budget, or refuse naming the key.
    ///
    /// Charged before the model leg for the same reason `inputreq::drive` charges before it calls:
    /// a completion the budget will not admit is a completion that never happens, rather than one
    /// that happens and is counted afterwards.
    pub(crate) fn try_spend(&self, server: &str, cap: u32, now_secs: u64) -> Result<(), String> {
        let minute = now_secs / 60;
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let slot = windows.entry(server.to_string()).or_insert((minute, 0));
        if slot.0 != minute {
            *slot = (minute, 0);
        }
        if slot.1 >= cap {
            return Err(format!(
                "the per-upstream sampling budget is exhausted: server `{server}` has already \
                 induced {cap} completion(s) this minute, which is the ceiling \
                 `tools.{server}.sampling.max_requests_per_minute` declares. The budget resets on \
                 the next minute; raise the key only if this server legitimately needs more."
            ));
        }
        slot.1 += 1;
        Ok(())
    }
}

/// SATISFY an upstream's granted `sampling/createMessage` ask: one governed completion per
/// `inputRequests` entry, on the operator's declared model, within the operator's declared budget.
///
/// ## The shape returned
///
/// `{ "inputResponses": { <key>: <CreateMessageResult> }, "requestState": <echoed> }` — MRTR's own
/// continuation members, copied onto the retry BY NAME by
/// [`crate::mcp::client::jsonrpc::tools_call`], exactly as the roots satisfier's answer is. The
/// `requestState` is the upstream's opaque blob, echoed exactly.
///
/// ## What each completion runs AS
///
/// The entry's params are translated to one non-streaming chat request in the tree's lingua-franca
/// chat wire shape — which every registered provider protocol has a translation from — and dispatched
/// through the resolved ingress pipeline behind
/// [`EngineHost::synthesize_completion`](busbar_substrate::plane_host::EngineHost::synthesize_completion)
/// under `gov`, the INBOUND caller's own governance context. The host resolves which chat dialect the
/// request drives as (the registry's residual-default), so this bridge names none. Text content only,
/// in this release: an image or
/// audio block in the ask is refused rather than silently dropped, because a completion computed
/// over less than the upstream sent is an answer to a question nobody asked.
pub(crate) async fn satisfy_upstream_ask(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    ask: &super::inputreq::Ask,
    server: &str,
    cfg: Option<&super::config::SamplingCfg>,
) -> Result<serde_json::Value, String> {
    let Some(cfg) = cfg else {
        return Err(format!(
            "busbar holds the `sampling` grant for server `{server}` and no \
             `tools.{server}.sampling` policy is declared, so there is no model busbar may spend \
             on its behalf; the ask terminates here and is not proxied to you. Declare \
             `tools.{server}.sampling:` (model, max_tokens, max_requests_per_minute) if the \
             operator intends this server to induce completions."
        ));
    };
    // The entries this ask actually made, by the map key the retry must address its answers to.
    // The kind was judged over the WHOLE map by `input_required_kind` (most privileged wins), so
    // `kind == "sampling"` proves the most privileged entry is sampling — a map that also names a
    // lesser method is refused rather than partially answered, mirroring the roots satisfier's
    // mixed-map arm.
    let Some(requests) = ask.payload.get("inputRequests").and_then(|v| v.as_object()) else {
        return Err(
            "the upstream's sampling ask names no `inputRequests` entry to address an answer to; \
             the ask terminates here"
                .to_string(),
        );
    };
    if requests.is_empty() {
        return Err(
            "the upstream's sampling ask carries an empty `inputRequests` map; the ask terminates \
             here"
                .to_string(),
        );
    }
    // ONE ask is judged at ONE instant: the clock is read once for the whole map, so whether a
    // multi-entry ask fits the budget is a fact about the ask rather than about how long its
    // earlier entries took to complete — an upstream must not be able to buy a fresh window by
    // being slow across a minute boundary.
    // D1: read the ask's single judging instant through the neutral host seam (the `clock_now` seam),
    // threaded in rather than minted here from the core factory.
    let now = host.clock_now_secs();
    let mut responses = serde_json::Map::new();
    for (entry, request) in requests {
        if request.get("method").and_then(|m| m.as_str()) != Some("sampling/createMessage") {
            return Err(format!(
                "the upstream's ask mixes `sampling/createMessage` with a method busbar has no \
                 satisfier for; the ask terminates here (entry `{entry}`)"
            ));
        }
        // THE PER-UPSTREAM BUDGET, spent per completion and BEFORE the model leg. One map entry is
        // one completion, so a map with many entries spends many units — an upstream cannot buy
        // more model calls by packing one round.
        super::runtime_of(host).sampling_spend.try_spend(
            server,
            cfg.max_requests_per_minute,
            now,
        )?;
        let body = chat_body(request.get("params"), cfg)?;
        let result = complete(host, gov, cfg, body).await?;
        responses.insert(entry.clone(), result);
    }
    let mut continuation = serde_json::Map::new();
    continuation.insert(
        "inputResponses".to_string(),
        serde_json::Value::Object(responses),
    );
    if let Some(state) = ask.payload.get("requestState") {
        continuation.insert("requestState".to_string(), state.clone());
    }
    Ok(serde_json::Value::Object(continuation))
}

/// HOW MANY MESSAGES one sampling ask may carry.
///
/// The output side of this satisfier was bounded from the first line it had (`max_tokens` is
/// clamped to the operator's ceiling) and the INPUT side was bounded by nothing at all: the
/// `messages` array arrives on an UPSTREAM'S ask — the least trusted input this plane handles — and
/// was copied into a chat body that is then charged to the INBOUND CALLER'S budget. So an upstream
/// could make a caller pay for a prompt of any size it liked, which inverts the whole point of
/// spending the caller's governance rather than a side channel: the caller's budget bounds what the
/// caller asked for, and it cannot bound what somebody else appended to it.
///
/// The per-upstream `max_requests_per_minute` budget does not stand in for this. It bounds HOW MANY
/// completions an upstream induces and says nothing about how large each one is, and prompt tokens
/// are the larger half of a completion's cost.
const MAX_SAMPLING_MESSAGES: usize = 64;

/// TOTAL prompt bytes one sampling ask may carry — the system prompt plus every message's text.
///
/// A total rather than a per-message limit because the cost is the sum: a thousand messages of a
/// kilobyte each and one message of a megabyte are the same bill.
const MAX_SAMPLING_PROMPT_BYTES: usize = 64 * 1024;

/// HOW MANY stop sequences, and how long each may be. Both forwarded verbatim to a provider before
/// this, so both were an upstream's choice about a request the caller pays for.
const MAX_STOP_SEQUENCES: usize = 8;
const MAX_STOP_SEQUENCE_BYTES: usize = 64;

/// Translate one `sampling/createMessage` params object into one non-streaming `openai`-dialect
/// chat body, under the operator's ceilings.
fn chat_body(
    params: Option<&serde_json::Value>,
    cfg: &super::config::SamplingCfg,
) -> Result<serde_json::Value, String> {
    let params = params.and_then(|p| p.as_object());
    let mut messages: Vec<serde_json::Value> = Vec::new();
    // THE RUNNING PROMPT SIZE, counted as it is built rather than measured afterwards: a body
    // measured after it exists has already been allocated at whatever size the upstream chose.
    let mut prompt_bytes = 0usize;
    if let Some(system) = params
        .and_then(|p| p.get("systemPrompt"))
        .and_then(|s| s.as_str())
    {
        if !system.is_empty() {
            prompt_bytes = prompt_bytes.saturating_add(system.len());
            if prompt_bytes > MAX_SAMPLING_PROMPT_BYTES {
                return Err(oversized_prompt());
            }
            messages.push(serde_json::json!({ "role": "system", "content": system }));
        }
    }
    let asked = params
        .and_then(|p| p.get("messages"))
        .and_then(|m| m.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    if asked > MAX_SAMPLING_MESSAGES {
        return Err(format!(
            "the sampling ask carries {asked} messages; busbar completes at most \
             {MAX_SAMPLING_MESSAGES} per ask. The prompt an upstream sends is spent against the \
             CALLER'S budget, so its size is bounded here rather than by the caller who never wrote \
             it. The ask terminates here."
        ));
    }
    for (i, message) in params
        .and_then(|p| p.get("messages"))
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .enumerate()
    {
        let role = match message.get("role").and_then(|r| r.as_str()) {
            Some(r @ ("user" | "assistant")) => r,
            other => {
                return Err(format!(
                    "the sampling ask's messages[{i}] carries role {other:?}, which is not a \
                     sampling role; the ask terminates here"
                ))
            }
        };
        let content = message.get("content");
        let text = match content.and_then(|c| c.get("type")).and_then(|t| t.as_str()) {
            Some("text") => content.and_then(|c| c.get("text")).and_then(|t| t.as_str()),
            other => {
                return Err(format!(
                    "the sampling ask's messages[{i}] carries content type {other:?}; busbar's \
                     sampling satisfier carries text content only in this release, and a \
                     completion computed over less than the upstream sent would be an answer to a \
                     question nobody asked. The ask terminates here."
                ))
            }
        };
        let Some(text) = text else {
            return Err(format!(
                "the sampling ask's messages[{i}] names text content and carries no `text`; the \
                 ask terminates here"
            ));
        };
        prompt_bytes = prompt_bytes.saturating_add(text.len());
        if prompt_bytes > MAX_SAMPLING_PROMPT_BYTES {
            return Err(oversized_prompt());
        }
        messages.push(serde_json::json!({ "role": role, "content": text }));
    }
    if messages.is_empty() {
        return Err(
            "the sampling ask carries no messages and no system prompt, so there is nothing to \
             complete; the ask terminates here"
                .to_string(),
        );
    }
    // CLAMPED, not refused: sampling fewer tokens than asked is conformant, and a hard refusal
    // would hand the upstream a probe for the operator's number.
    let max_tokens = params
        .and_then(|p| p.get("maxTokens"))
        .and_then(|m| m.as_u64())
        .map(|asked| asked.min(u64::from(cfg.max_tokens)) as u32)
        .unwrap_or(cfg.max_tokens);
    let mut body = serde_json::json!({
        "model": cfg.model,
        "messages": messages,
        "max_tokens": max_tokens,
    });
    // TEMPERATURE IS RANGE-CHECKED, not merely type-checked. `is_number()` admits `-1`, `1e308` and
    // every other value the protocol's own `0.0..=2.0` does not, and the number went verbatim into a
    // body a provider then answered with an error the caller paid the round trip for. A value
    // outside the range is the upstream's mistake, so it is refused here rather than forwarded.
    if let Some(t) = params.and_then(|p| p.get("temperature")) {
        let Some(value) = t
            .as_f64()
            .filter(|v| v.is_finite() && (0.0..=2.0).contains(v))
        else {
            return Err(format!(
                "the sampling ask names temperature {t}, which is not a number in `0.0..=2.0`; the \
                 ask terminates here"
            ));
        };
        body["temperature"] = serde_json::json!(value);
    }
    // STOP SEQUENCES ARE COUNTED AND MEASURED. They were copied through as whatever array arrived:
    // any length, any element type, any element size — an upstream's free hand on a request the
    // caller is charged for, and a non-string element is a body a provider refuses.
    if let Some(stop) = params.and_then(|p| p.get("stopSequences")) {
        let Some(list) = stop.as_array() else {
            return Err(
                "the sampling ask's `stopSequences` is not an array; the ask terminates here"
                    .to_string(),
            );
        };
        if list.len() > MAX_STOP_SEQUENCES {
            return Err(format!(
                "the sampling ask names {} stop sequences; busbar forwards at most \
                 {MAX_STOP_SEQUENCES}. The ask terminates here.",
                list.len()
            ));
        }
        for (i, entry) in list.iter().enumerate() {
            match entry.as_str() {
                Some(s) if s.len() <= MAX_STOP_SEQUENCE_BYTES => {}
                Some(_) => {
                    return Err(format!(
                        "the sampling ask's `stopSequences[{i}]` is longer than \
                         {MAX_STOP_SEQUENCE_BYTES} bytes; the ask terminates here"
                    ))
                }
                None => {
                    return Err(format!(
                        "the sampling ask's `stopSequences[{i}]` is not a string; the ask \
                         terminates here"
                    ))
                }
            }
        }
        body["stop"] = stop.clone();
    }
    Ok(body)
}

/// The one refusal both prompt-size arms return, so the system prompt and a message body cannot
/// come to say different things about the same bound.
fn oversized_prompt() -> String {
    format!(
        "the sampling ask's prompt exceeds {MAX_SAMPLING_PROMPT_BYTES} bytes. The prompt an \
         upstream sends is spent against the CALLER'S budget, so its size is bounded here rather \
         than by the caller who never wrote it. The ask terminates here."
    )
}

/// DRIVE one completion through the governed pipeline and shape the answer as the protocol's
/// `CreateMessageResult`.
async fn complete(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    cfg: &super::config::SamplingCfg,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let bytes = axum::body::Bytes::from(serde_json::to_vec(&body).map_err(|e| e.to_string())?);
    // THE ONE PATHWAY, reached through the neutral host seam: the completion rides the same resolved
    // ingress pipeline (`operation_resolved` with the residual-default chat handler the host resolves)
    // every arriving chat request enters, under `gov`, on the operator's declared model — governance,
    // breaker/failover, metering and the request log, byte-identically to the in-core dispatch. The
    // raw wire outcome (status + body bytes) comes back; the MCP-protocol translation below stays
    // plane-side. This bridge names NO LLM dialect — the host owns which chat protocol drives.
    let completion = host
        .synthesize_completion(gov, &cfg.model, bytes, MAX_COMPLETION_BYTES)
        .await?;
    let status = completion.status;
    let body = completion.body;
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        format!("the sampling completion answered HTTP {status} and a body that is not JSON")
    })?;
    if !(200..300).contains(&status) {
        // THE OPERATOR GETS THE REASON; THE CALLER GETS THE FACT.
        //
        // This relayed busbar's OWN pipeline error verbatim, unbounded, into a string that ends up
        // on a `Refusal::Unsatisfiable` returned to the party that made the tool call. That message
        // is busbar's internal admission/budget/pool answer, and it names internal things — the pool
        // that was selected, the provider behind it, the budget bucket, the breaker cell. None of
        // those are the caller's business: the caller asked a tool a question and an upstream's
        // sampling ask is a fact about the OPERATOR'S deployment. Relaying it turned every refused
        // completion into a probe an upstream could drive on demand (it chooses when to ask, and it
        // reads the caller's answer) for the operator's pool topology, and it was unbounded, so a
        // long provider error was also an amplifier.
        //
        // So the detail is LOGGED, where an operator debugging a refused grant reads it, and the
        // caller is told only that the completion was refused and by whom.
        let reason = value
            .pointer("/error/message")
            .and_then(|m| m.as_str())
            .unwrap_or("no reason was given");
        tracing::warn!(
            status,
            model = %cfg.model,
            reason = %reason,
            "an upstream's sampling ask was refused by busbar's own pipeline"
        );
        return Err(format!(
            "the sampling completion was refused by busbar's own pipeline (HTTP {status}); the \
             reason is recorded in busbar's log and is not relayed, because it describes this \
             deployment rather than your call"
        ));
    }
    let text = value
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .ok_or_else(|| "the sampling completion carried no assistant text to relay".to_string())?;
    let model = value
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(cfg.model.as_str());
    // The protocol's own stop-reason vocabulary, mapped from the chat dialect's. An unrecognised
    // reason rides through verbatim: it is a statement about how the completion ended, and
    // flattening it to a guess would erase the one fact the upstream asked this field for.
    let stop_reason = match value
        .pointer("/choices/0/finish_reason")
        .and_then(|f| f.as_str())
    {
        Some("stop") | None => "endTurn",
        Some("length") => "maxTokens",
        Some("stop_sequence") => "stopSequence",
        Some(other) => other,
    };
    Ok(serde_json::json!({
        "role": "assistant",
        "content": { "type": "text", "text": text },
        "model": model,
        "stopReason": stop_reason,
    }))
}

/// The cap on one completion's response body. Generous — a completion is text the operator's own
/// `max_tokens` already bounds — and present because a read with no bound is a promise about a
/// body this function did not write.
const MAX_COMPLETION_BYTES: usize = 8 * 1024 * 1024;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sampling_spend_tests.rs"]
mod sampling_spend_tests;

// The SATISFIER's battery hangs on `super::upstream` rather than here, exactly as the roots
// satisfier's does: its witness is the fake upstream peer plus a recording fake provider, and the
// claim is about what left busbar on both legs.
