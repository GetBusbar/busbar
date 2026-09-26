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
//! [`EngineHost::synthesize_completion`](busbar_kernel::plane_host::EngineHost::synthesize_completion),
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
//!
//! ## AND THE BOUND ALL FOUR OF THEM MISS: HOW LARGE ONE ASK IS (owner ruling Q22c / Q35)
//!
//! Read the four again and the hole is in plain sight. Every one of them limits HOW MANY
//! completions happen — one dispatch's rounds, one principal's budget, one upstream's minute, one
//! completion's output tokens — and not one of them limits HOW LARGE A SINGLE ASK IS. The
//! `messages` array, the system prompt, the stop list and the temperature arrive on an UPSTREAM'S
//! ask, which is the least trusted input this plane handles, and they are charged to the INBOUND
//! CALLER'S budget. A caller's budget bounds what the caller asked for; it cannot bound what
//! somebody else appended to it, and prompt tokens are the larger half of a completion's bill. So
//! the input side is bounded HERE, beside the translation that builds the body, CONFIGURABLY under
//! `tools.<server>.sampling` (see [`super::config::SamplingCfg::max_messages`] and its three
//! neighbours) — every one of them is a COUNT or a RANGE, never a price: what it is worth is the
//! money plane's business.

use busbar_kernel::plane_host::EngineHost;
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
/// [`EngineHost::synthesize_completion`](busbar_kernel::plane_host::EngineHost::synthesize_completion)
/// under `gov`, the INBOUND caller's own governance context. The host resolves which chat dialect the
/// request drives as (the registry's residual-default), so this bridge names none. Text content only,
/// in this release: an image or
/// audio block in the ask is refused rather than silently dropped, because a completion computed
/// over less than the upstream sent is an answer to a question nobody asked.
pub(crate) async fn satisfy_upstream_ask(
    host: &std::sync::Arc<dyn EngineHost>,
    gov: &busbar_contract::records::PlaneRequestCtx,
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
        let body = chat_body(request.get("params"), cfg, server)?;
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

/// Translate one `sampling/createMessage` params object into one non-streaming `openai`-dialect
/// chat body, under the operator's ceilings.
fn chat_body(
    params: Option<&serde_json::Value>,
    cfg: &super::config::SamplingCfg,
    server: &str,
) -> Result<serde_json::Value, String> {
    let params = params.and_then(|p| p.as_object());
    let mut messages: Vec<serde_json::Value> = Vec::new();
    // THE RUNNING PROMPT SIZE, accumulated as the body is built. A `usize` of BYTES — a count, not
    // a price, and no float anywhere near it. Checked as each piece is added, not after: refusing
    // after building a body of any size the upstream chose is refusing at the cost the bound exists
    // to avoid paying.
    let mut prompt_bytes = 0usize;
    if let Some(system) = params
        .and_then(|p| p.get("systemPrompt"))
        .and_then(|s| s.as_str())
    {
        if !system.is_empty() {
            // THE SYSTEM PROMPT COUNTS. It is prompt tokens like any other, and a bound that
            // skipped it would be a bound with a hole the upstream chooses the size of.
            prompt_bytes = prompt_bytes.saturating_add(system.len());
            if prompt_bytes > cfg.max_prompt_bytes as usize {
                return Err(oversized_prompt(cfg, server));
            }
            messages.push(serde_json::json!({ "role": "system", "content": system }));
        }
    }
    // THE MESSAGE COUNT, judged BEFORE the walk: refusing after building a large array is refusing
    // at the cost the bound exists to avoid paying.
    let asked = params
        .and_then(|p| p.get("messages"))
        .and_then(|m| m.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    if asked as u64 > u64::from(cfg.max_messages) {
        return Err(format!(
            "the sampling ask carries {asked} messages; busbar completes at most \
             {} per ask, which is the ceiling `tools.{server}.sampling.max_messages` declares. \
             The prompt an upstream sends is spent against the CALLER'S budget, so its size is \
             bounded here rather than by the caller who never wrote it. The ask terminates here.",
            cfg.max_messages
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
        if prompt_bytes > cfg.max_prompt_bytes as usize {
            return Err(oversized_prompt(cfg, server));
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
    // TEMPERATURE IS RANGE-CHECKED, not merely type-checked, against the OPERATOR'S configured
    // `temperature_min..=temperature_max` — `is_number()` alone admits `-1`, `1e308` and every
    // other value the range does not, and the number would then ride verbatim into a body a
    // provider answers with an error the CALLER paid the round trip for. A value outside the range
    // is the upstream's mistake, refused here rather than forwarded.
    //
    // The check reads an `f64` and the BODY still carries the caller's original `Value`: this
    // function converts nothing. A number that only ever rides through as the token it arrived as
    // cannot be re-rendered by a float round trip, which is the posture every numeric field on this
    // plane takes and the reason `t.clone()` stays rather than becoming a re-serialised `value`.
    if let Some(t) = params.and_then(|p| p.get("temperature")) {
        let (min, max) = (cfg.temperature_min(), cfg.temperature_max());
        if !t
            .as_f64()
            .is_some_and(|v| v.is_finite() && (min..=max).contains(&v))
        {
            return Err(format!(
                "the sampling ask names temperature {t}, which is not a number in `{min}..={max}`, \
                 the range `tools.{server}.sampling.temperature_min_milli`/\
                 `tools.{server}.sampling.temperature_max_milli` declares (in thousandths); the \
                 ask terminates here"
            ));
        }
        body["temperature"] = t.clone();
    }
    // STOP SEQUENCES ARE COUNTED, MEASURED AND TYPED, against the OPERATOR'S configured ceilings.
    // Forwarded through as whatever array arrived before this bound existed — any length, any
    // element type, any element size — which was an upstream's free hand on a request the caller is
    // charged for; and a non-string element is a body a provider refuses AFTER the caller has paid
    // for the leg.
    if let Some(stop) = params.and_then(|p| p.get("stopSequences")) {
        let Some(list) = stop.as_array() else {
            return Err(
                "the sampling ask's `stopSequences` is not an array; the ask terminates here"
                    .to_string(),
            );
        };
        if list.len() as u64 > u64::from(cfg.max_stop_sequences) {
            return Err(format!(
                "the sampling ask names {} stop sequences; busbar forwards at most {}, the \
                 ceiling `tools.{server}.sampling.max_stop_sequences` declares. The ask \
                 terminates here.",
                list.len(),
                cfg.max_stop_sequences
            ));
        }
        for (i, entry) in list.iter().enumerate() {
            match entry.as_str() {
                Some(s) if s.len() as u64 <= u64::from(cfg.max_stop_sequence_bytes) => {}
                Some(_) => {
                    return Err(format!(
                        "the sampling ask's `stopSequences[{i}]` is longer than {} bytes, the \
                         ceiling `tools.{server}.sampling.max_stop_sequence_bytes` declares; the \
                         ask terminates here",
                        cfg.max_stop_sequence_bytes
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

/// The ONE refusal both prompt-size arms (system prompt, message text) return, so they cannot come
/// to say different things about the same bound.
fn oversized_prompt(cfg: &super::config::SamplingCfg, server: &str) -> String {
    format!(
        "the sampling ask's prompt exceeds {} bytes, the ceiling \
         `tools.{server}.sampling.max_prompt_bytes` declares. The prompt an upstream sends is \
         spent against the CALLER'S budget, so its size is bounded here rather than by the caller \
         who never wrote it. The ask terminates here.",
        cfg.max_prompt_bytes
    )
}

/// DRIVE one completion through the governed pipeline and shape the answer as the protocol's
/// `CreateMessageResult`.
async fn complete(
    host: &std::sync::Arc<dyn EngineHost>,
    gov: &busbar_contract::records::PlaneRequestCtx,
    cfg: &super::config::SamplingCfg,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    // THE SERVING PLANE, resolved by OPERATION CLASS through the host: a deployment where no linked
    // or dropped-in plane declares the class refuses here, with the words it has always refused in
    // when no plane was there to drive the completion.
    if completion_server().is_none() {
        return Err(NO_COMPLETION_SERVER.to_string());
    }
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
        // The pipeline's OWN refusal, relayed by its reason: this is busbar's admission, budget or
        // pool answer, not upstream content, and an operator debugging a refused grant needs it.
        let reason = value
            .pointer("/error/message")
            .and_then(|m| m.as_str())
            .unwrap_or("no reason was given");
        return Err(format!(
            "the sampling completion was refused by busbar's own pipeline (HTTP {status}): {reason}"
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

/// THE PLANE THAT ANSWERS A SAMPLING ASK — the registered plane (linked or dropped in, both reach
/// the host's registry as one declaration) that declares it serves the operation class a sampling
/// ask completes as, with its DECLARED display name. Resolved by class, so this plane spells none
/// (#47/#49); `None` when no registered plane serves the class.
pub(crate) fn completion_server() -> Option<busbar_contract::plane::ServedOpClass> {
    let decls = busbar_kernel::plane::registry::plane_decls();
    busbar_contract::plane::plane_serving(
        busbar_plane_mcp::meta::SAMPLING_OP,
        decls.iter().map(|d| &d.declaration),
    )
    .map(|(_, served)| served)
}

/// The refusal a sampling ask gets when no registered plane serves its class — byte for byte what
/// the host's completion seam answers when no plane installed one.
pub(crate) const NO_COMPLETION_SERVER: &str = "no default chat protocol is installed";

/// The cap on one completion's response body. Generous — a completion is text the operator's own
/// `max_tokens` already bounds — and present because a read with no bound is a promise about a
/// body this function did not write.
const MAX_COMPLETION_BYTES: usize = 8 * 1024 * 1024;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sampling_spend_tests.rs"]
mod sampling_spend_tests;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sampling_bounds_tests.rs"]
mod sampling_bounds_tests;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/sampling_server_tests.rs"]
mod sampling_server_tests;

// The SATISFIER's battery hangs on `super::upstream` rather than here, exactly as the roots
// satisfier's does: its witness is the fake upstream peer plus a recording fake provider, and the
// claim is about what left busbar on both legs.
