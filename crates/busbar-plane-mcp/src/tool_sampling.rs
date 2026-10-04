// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `sampling/createMessage`, ASKED BY AN UPSTREAM AND ANSWERED — the satisfier behind
//! `grants.sampling` (ARCHITECT round 4, SURFACES (c): "SAMPLING → host `unit.nest`").
//!
//! ## The grant admits, the policy answers
//!
//! The operator's `tools.<server>.sampling` block ([`SamplingCfg`]) is the roots policy's shape on
//! the other grant: the grant ADMITS the ask ([`crate::call::settle_call`] judged the round cap and
//! the grant before this module is reached), the policy says what may ANSWER it, and neither implies
//! the other. A grant with no policy refuses the ask as unsatisfiable naming the exact key.
//!
//! ## THE ONE PATHWAY: a nested unit
//!
//! A sampling ask IS a model request, so it rides the model request's own pipeline: one
//! non-streaming chat body in the tree's lingua-franca chat wire shape, dispatched as a NESTED UNIT
//! (`unit.nest`, the host services' "unit (nested dispatch)" family) to whatever door plane claims
//! [`COMPLETION_VERB`] [`COMPLETION_TARGET`] on the data listener. The child is admitted under the
//! INBOUND caller's own key and charged on the caller's own budget, so an upstream can spend nothing
//! the caller could not have asked for itself, and the kernel's gates, metering and request log see
//! the completion as they see any other. Nothing serves the claim: the ask is refused in the words
//! a deployment with no completion server has always been refused in ([`NO_COMPLETION_SERVER`]).
//!
//! The model the completion runs on is the OPERATOR'S declaration, never the ask's
//! `modelPreferences`: the payload is upstream-controlled content, and letting it name the pool lets
//! a hostile upstream pick which of the operator's providers to spend on.
//!
//! ## THE PER-UPSTREAM BUDGET
//!
//! The round cap bounds one dispatch, the caller's budget one principal, the declared `max_tokens`
//! one completion — and the per-minute budget (`max_requests_per_minute`) bounds THE UPSTREAM,
//! across every caller and dispatch at once. It is spent BEFORE the model leg, so a refused
//! completion costs nothing. It is kept as [`crate::tool_records`] declares it: on the `approval`
//! kind's one-time claims ("a spend that a restart forgets is a cap that a restart lifts") — one
//! claim per completion slot of the server's minute window — with the instance's own window as the
//! local half, which is the whole gate where the host binds no store.
//!
//! ## AND HOW LARGE ONE ASK IS (owner ruling Q22c / Q35)
//!
//! The `messages` array, the system prompt, the stop list and the temperature arrive on an
//! UPSTREAM'S ask and are charged to the CALLER'S budget, so the input side is bounded here, beside
//! the translation that builds the body, under the operator's configured ceilings — every one a
//! COUNT or a RANGE, never a price.

use std::task::Poll;

use serde_json::{json, Map, Value};

use crate::tools_config::SamplingCfg;

/// The verb of the claim a completion is nested to.
pub const COMPLETION_VERB: &str = "POST";

/// The claim a completion is nested to: the public path of the lingua-franca chat wire shape the
/// body is written in ([`sampling_chat_body`]).
pub const COMPLETION_TARGET: &str = "/v1/chat/completions";

/// The refusal a sampling ask gets when nothing serves the completion's claim — byte for byte what
/// a deployment with no completion server has always answered.
pub const NO_COMPLETION_SERVER: &str = "no default chat protocol is installed";

/// The cap on one completion's reply body. Generous — a completion is text the operator's own
/// `max_tokens` already bounds — and present because a read with no bound is a promise about a body
/// this plane did not write.
pub const MAX_COMPLETION_BYTES: usize = 8 * 1024 * 1024;

/// How many host calls one round's sampling may number: the satisfier's handles are counted from
/// its own base, so none reads another exchange's stored answer.
pub const SAMPLE_SEQ_SPAN: u32 = 1 << 12;

/// How long one completion slot's claim lives on the host's ledger: past the end of its own minute
/// on every node whose clock is within a minute of this one's (the slot key names its minute, so a
/// longer life costs a row and never a completion).
const SLOT_TTL_MS: u64 = 120_000;

/// The FAILED answer of a completion the host's nested dispatch could not run.
pub const COMPLETION_FAILED: &str = "the host's nested dispatch could not run the completion";

/// The FAILED answer of a completion whose reply is larger than [`MAX_COMPLETION_BYTES`].
pub const COMPLETION_OVERSIZED: &str =
    "the completion's reply is larger than busbar reads for one sampling answer";

/// One server's local spend window: the minute it counts and how many completion slots this
/// instance has reserved in it.
pub type SampleWindow = (u64, u32);

/// What the host's ledger answered one completion slot's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotClaim {
    /// This claim took the slot.
    Won,
    /// The slot was already spent (another instance, or this one before a restart).
    Lost,
    /// No store is bound (or no claim is served): the local half was the whole gate.
    Unbound,
    /// The ledger could not say whether the slot was spent.
    Unreadable,
}

/// What the nested completion came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// The child unit answered: its status and whole body.
    Answered {
        /// The child's status.
        status: u64,
        /// The child's body.
        body: Vec<u8>,
    },
    /// Nothing serves the completion's claim (or the host refused the nested unit).
    Unserved,
    /// The nested unit could not be run or read, in these words.
    Failed(&'static str),
}

/// The host services one sampling ask is satisfied through. `seq` is the call's number within the
/// round's [`SAMPLE_SEQ_SPAN`]: a call that pends is re-issued under the number it was first
/// issued under.
pub trait SampleHost {
    /// The kernel's wall clock, in Unix seconds.
    fn now_secs(&mut self, seq: u32) -> u64;
    /// Reserve the next completion slot of `server`'s window locally, or refuse naming the key.
    ///
    /// # Errors
    ///
    /// The exhausted budget's refusal ([`sampling_exhausted`]).
    fn reserve(&mut self, server: &str, cap: u32, now: u64) -> Result<u32, String>;
    /// Claim `key` once on the host's ledger for `ttl_ms`.
    fn claim(&mut self, seq: u32, key: &str, ttl_ms: u64) -> Poll<SlotClaim>;
    /// Run one completion of `body` as a nested unit.
    fn complete(&mut self, seq: u32, body: &[u8]) -> Poll<Completion>;
}

/// RESERVE one completion slot of a server's minute `window`, or refuse naming the key: the window
/// resets on a minute boundary (a budget, not a rate shaper), and the slot is counted before its
/// claim is issued, so two units of one instance never claim one slot.
///
/// # Errors
///
/// The exhausted budget's refusal ([`sampling_exhausted`]).
pub fn reserve_sample_slot(
    window: &mut SampleWindow,
    server: &str,
    cap: u32,
    now_secs: u64,
) -> Result<u32, String> {
    let minute = now_secs / 60;
    if window.0 != minute {
        *window = (minute, 0);
    }
    if window.1 >= cap {
        return Err(sampling_exhausted(server, cap));
    }
    let slot = window.1;
    window.1 += 1;
    Ok(slot)
}

/// The per-upstream budget's refusal, naming the key an operator would raise.
#[must_use]
pub fn sampling_exhausted(server: &str, cap: u32) -> String {
    format!(
        "the per-upstream sampling budget is exhausted: server `{server}` has already \
         induced {cap} completion(s) this minute, which is the ceiling \
         `tools.{server}.sampling.max_requests_per_minute` declares. The budget resets on \
         the next minute; raise the key only if this server legitimately needs more."
    )
}

/// The ledger key one completion slot is claimed under: the server, its minute and the slot.
#[must_use]
pub fn sample_slot_key(server: &str, now_secs: u64, slot: u32) -> String {
    format!("sampling/{server}/{}/{slot}", now_secs / 60)
}

/// Where one entry of the ask stands across a pend.
#[derive(Debug, Clone, PartialEq)]
enum Stage {
    /// Its completion slot is reserved and being claimed.
    Claim { slot: u32, seq: u32 },
    /// Its completion is running as a nested unit.
    Complete { body: Vec<u8>, seq: u32 },
}

/// ONE SAMPLING ASK BEING SATISFIED, kept across the pends of its host calls: the ask, its one
/// judging instant, the answers so far and where the entry in hand stands.
#[derive(Debug, Clone, PartialEq)]
pub struct SampleRun {
    payload: Value,
    now: Option<u64>,
    responses: Map<String, Value>,
    entry: usize,
    seq: u32,
    stage: Option<Stage>,
}

impl SampleRun {
    /// The run of the ask whose input-required result is `payload`.
    #[must_use]
    pub fn new(payload: Value) -> Self {
        SampleRun {
            payload,
            now: None,
            responses: Map::new(),
            entry: 0,
            seq: 0,
            stage: None,
        }
    }

    /// The next call number, or the refusal of an ask that needs more than one round may number.
    fn next_seq(&mut self) -> Result<u32, String> {
        if self.seq >= SAMPLE_SEQ_SPAN {
            return Err(format!(
                "the sampling ask needs more host calls than one round may number \
                 ({SAMPLE_SEQ_SPAN}); the ask terminates here"
            ));
        }
        let seq = self.seq;
        self.seq += 1;
        Ok(seq)
    }

    /// SATISFY the ask for `server` under its declared policy `cfg`: one governed completion per
    /// `inputRequests` entry, on the operator's model, within the operator's budget. Ready: MRTR's
    /// continuation members, `{ "inputResponses": { <key>: <CreateMessageResult> },
    /// "requestState": <echoed> }`, or why the ask cannot be satisfied. PENDING while a host call
    /// pends; called again, it resumes where it stood.
    pub fn drive(
        &mut self,
        server: &str,
        cfg: Option<&SamplingCfg>,
        host: &mut dyn SampleHost,
    ) -> Poll<Result<Value, String>> {
        let Some(cfg) = cfg else {
            return Poll::Ready(Err(format!(
                "busbar holds the `sampling` grant for server `{server}` and no \
                 `tools.{server}.sampling` policy is declared, so there is no model busbar may \
                 spend on its behalf; the ask terminates here and is not proxied to you. Declare \
                 `tools.{server}.sampling:` (model, max_tokens, max_requests_per_minute) if the \
                 operator intends this server to induce completions."
            )));
        };
        // The entries this ask actually made, by the map key the retry must address its answers
        // to. A map that also names a lesser method is refused rather than partially answered.
        let Some(requests) = self
            .payload
            .get("inputRequests")
            .and_then(Value::as_object)
            .cloned()
        else {
            return Poll::Ready(Err(
                "the upstream's sampling ask names no `inputRequests` entry to address an answer \
                 to; the ask terminates here"
                    .to_string(),
            ));
        };
        if requests.is_empty() {
            return Poll::Ready(Err(
                "the upstream's sampling ask carries an empty `inputRequests` map; the ask \
                 terminates here"
                    .to_string(),
            ));
        }
        // ONE ask is judged at ONE instant: the clock is read once for the whole map, so whether a
        // multi-entry ask fits the budget is a fact about the ask rather than about how long its
        // earlier entries took — an upstream must not buy a fresh window by being slow.
        let now = match self.now {
            Some(now) => now,
            None => {
                let seq = match self.next_seq() {
                    Ok(s) => s,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                let now = host.now_secs(seq);
                self.now = Some(now);
                now
            }
        };
        loop {
            let Some((entry, request)) = requests.iter().nth(self.entry) else {
                let mut continuation = Map::new();
                continuation.insert(
                    "inputResponses".to_string(),
                    Value::Object(std::mem::take(&mut self.responses)),
                );
                if let Some(state) = self.payload.get("requestState") {
                    continuation.insert("requestState".to_string(), state.clone());
                }
                return Poll::Ready(Ok(Value::Object(continuation)));
            };
            if request.get("method").and_then(Value::as_str) != Some("sampling/createMessage") {
                return Poll::Ready(Err(format!(
                    "the upstream's ask mixes `sampling/createMessage` with a method busbar has \
                     no satisfier for; the ask terminates here (entry `{entry}`)"
                )));
            }
            match self.stage.take() {
                // THE PER-UPSTREAM BUDGET, spent per completion and BEFORE the model leg. One map
                // entry is one completion, so an upstream cannot buy more model calls by packing
                // one round.
                None => {
                    let slot = match host.reserve(server, cfg.max_requests_per_minute, now) {
                        Ok(s) => s,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let seq = match self.next_seq() {
                        Ok(s) => s,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    self.stage = Some(Stage::Claim { slot, seq });
                }
                Some(Stage::Claim { slot, seq }) => {
                    let key = sample_slot_key(server, now, slot);
                    match host.claim(seq, &key, SLOT_TTL_MS) {
                        Poll::Pending => {
                            self.stage = Some(Stage::Claim { slot, seq });
                            return Poll::Pending;
                        }
                        // Spent elsewhere: the next slot of the window is reserved in its place.
                        Poll::Ready(SlotClaim::Lost) => {}
                        Poll::Ready(SlotClaim::Unreadable) => {
                            return Poll::Ready(Err(format!(
                                "the per-upstream sampling budget of server `{server}` could not \
                                 be read from busbar's ledger, and a budget that cannot say \
                                 whether it is spent is not read as unspent; the ask terminates \
                                 here"
                            )))
                        }
                        Poll::Ready(SlotClaim::Won | SlotClaim::Unbound) => {
                            let body = match sampling_chat_body(request.get("params"), cfg, server)
                            {
                                Ok(b) => serde_json::to_vec(&b).unwrap_or_default(),
                                Err(e) => return Poll::Ready(Err(e)),
                            };
                            let seq = match self.next_seq() {
                                Ok(s) => s,
                                Err(e) => return Poll::Ready(Err(e)),
                            };
                            self.stage = Some(Stage::Complete { body, seq });
                        }
                    }
                }
                Some(Stage::Complete { body, seq }) => match host.complete(seq, &body) {
                    Poll::Pending => {
                        self.stage = Some(Stage::Complete { body, seq });
                        return Poll::Pending;
                    }
                    Poll::Ready(done) => match sampling_result(done, cfg) {
                        Ok(result) => {
                            self.responses.insert(entry.clone(), result);
                            self.entry += 1;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    },
                },
            }
        }
    }
}

/// TRANSLATE one `sampling/createMessage` params object into one non-streaming chat body in the
/// lingua-franca chat wire shape, under the operator's ceilings.
///
/// # Errors
///
/// The bound the ask breaks, naming the `tools.<server>.sampling.<key>` an operator would edit, or
/// the shape it does not have.
pub fn sampling_chat_body(
    params: Option<&Value>,
    cfg: &SamplingCfg,
    server: &str,
) -> Result<Value, String> {
    let params = params.and_then(Value::as_object);
    let mut messages: Vec<Value> = Vec::new();
    // THE RUNNING PROMPT SIZE, a `usize` of BYTES — a count, not a price — checked as each piece is
    // added: refusing after building a body of any size the upstream chose is refusing at the cost
    // the bound exists to avoid paying.
    let mut prompt_bytes = 0usize;
    if let Some(system) = params
        .and_then(|p| p.get("systemPrompt"))
        .and_then(Value::as_str)
    {
        if !system.is_empty() {
            // THE SYSTEM PROMPT COUNTS: it is prompt tokens like any other.
            prompt_bytes = prompt_bytes.saturating_add(system.len());
            if prompt_bytes > cfg.max_prompt_bytes as usize {
                return Err(oversized_prompt(cfg, server));
            }
            messages.push(json!({ "role": "system", "content": system }));
        }
    }
    // THE MESSAGE COUNT, judged BEFORE the walk.
    let asked = params
        .and_then(|p| p.get("messages"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
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
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let role = match message.get("role").and_then(Value::as_str) {
            Some(r @ ("user" | "assistant")) => r,
            other => {
                return Err(format!(
                    "the sampling ask's messages[{i}] carries role {other:?}, which is not a \
                     sampling role; the ask terminates here"
                ))
            }
        };
        let content = message.get("content");
        let text = match content.and_then(|c| c.get("type")).and_then(Value::as_str) {
            Some("text") => content.and_then(|c| c.get("text")).and_then(Value::as_str),
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
        messages.push(json!({ "role": role, "content": text }));
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
        .and_then(Value::as_u64)
        .map_or(cfg.max_tokens, |asked| {
            u32::try_from(asked.min(u64::from(cfg.max_tokens))).unwrap_or(cfg.max_tokens)
        });
    let mut body = json!({
        "model": cfg.model,
        "messages": messages,
        "max_tokens": max_tokens,
    });
    // TEMPERATURE IS RANGE-CHECKED against the operator's configured range. The check reads an
    // `f64` and the body carries the ask's original token: nothing is re-rendered.
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
    // STOP SEQUENCES ARE COUNTED, MEASURED AND TYPED against the operator's configured ceilings.
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

/// The ONE refusal both prompt-size arms (system prompt, message text) return.
fn oversized_prompt(cfg: &SamplingCfg, server: &str) -> String {
    format!(
        "the sampling ask's prompt exceeds {} bytes, the ceiling \
         `tools.{server}.sampling.max_prompt_bytes` declares. The prompt an upstream sends is \
         spent against the CALLER'S budget, so its size is bounded here rather than by the caller \
         who never wrote it. The ask terminates here.",
        cfg.max_prompt_bytes
    )
}

/// SHAPE one completion's answer as the protocol's `CreateMessageResult`: the assistant text, the
/// model the reply names (the declared one when it names none) and the stop reason in the
/// protocol's own vocabulary.
///
/// # Errors
///
/// Why the completion yields no answer: nothing serves it, it failed, or busbar's own pipeline
/// refused it (relayed by its reason).
pub fn sampling_result(done: Completion, cfg: &SamplingCfg) -> Result<Value, String> {
    let (status, body) = match done {
        Completion::Answered { status, body } => (status, body),
        Completion::Unserved => return Err(NO_COMPLETION_SERVER.to_string()),
        Completion::Failed(why) => {
            return Err(format!("the sampling completion could not be run: {why}"))
        }
    };
    let value: Value = serde_json::from_slice(&body).map_err(|_| {
        format!("the sampling completion answered HTTP {status} and a body that is not JSON")
    })?;
    if !(200..300).contains(&status) {
        // The pipeline's OWN refusal, relayed by its reason: busbar's admission, budget or pool
        // answer, not upstream content, and an operator debugging a refused grant needs it.
        let reason = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("no reason was given");
        return Err(format!(
            "the sampling completion was refused by busbar's own pipeline (HTTP {status}): {reason}"
        ));
    }
    let text = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| "the sampling completion carried no assistant text to relay".to_string())?;
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(cfg.model.as_str());
    // An unrecognised reason rides through verbatim: it is a statement about how the completion
    // ended, and flattening it to a guess would erase the one fact the upstream asked for.
    let stop_reason = match value
        .pointer("/choices/0/finish_reason")
        .and_then(Value::as_str)
    {
        Some("stop") | None => "endTurn",
        Some("length") => "maxTokens",
        Some("stop_sequence") => "stopSequence",
        Some(other) => other,
    };
    Ok(json!({
        "role": "assistant",
        "content": { "type": "text", "text": text },
        "model": model,
        "stopReason": stop_reason,
    }))
}

#[cfg(test)]
#[path = "tests/sampling.rs"]
mod tests;
