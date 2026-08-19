// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The superset intermediate representation (IR) — request and response/stream sides — that every
//! protocol's Reader/Writer maps to and from, so any ingress protocol can reach any backend
//! losslessly. (See `docs/adr/0005-ir-fidelity.md` for the fidelity contract.)
//!
//! OPACITY IS AN IR FACT, NOT A WIRE FACT. Three protocols carry assistant reasoning busbar cannot
//! decrypt, in three different shapes; [`IrBlock::is_opaque`] is the single place that knows all
//! three, so a consumer deciding "show this content or substitute a marker" never has to re-sniff
//! the wire body to get the answer right. It is a PREDICATE rather than a flag flip on
//! `Thinking.redacted` because `redacted` is a writer instruction with client-visible egress
//! consequences — the full reasoning is on `is_opaque` itself.

use serde_json::Value;

// Per-operation IR variants. Chat is the `IrRequest`/`IrResponse` below; the other
// operations live in submodules and are assembled into `enum IrReq`/`enum IrResp`.
pub mod audio;
pub mod embeddings;
/// THE ONE PROJECTION — what the shared pipeline (hooks, governance, taps) is allowed to know about
/// a request, read from the IR and from nothing else. Beside the IR rather than beside the hooks so
/// that "a hook sees the IR" is a compile-time fact; see the module header.
pub mod facts;
pub mod image;
pub mod invoke;
pub mod moderation;
pub mod rerank;
pub mod subscribe;
pub mod variant; // IrReq / IrResp enums + the operation-blind surface

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IrRequest {
    pub system: Vec<IrBlock>,
    pub messages: Vec<IrMessage>,
    pub tools: Vec<IrTool>,
    pub max_tokens: Option<u32>,
    // f64 (not ADR-0005's f32): JSON numbers are f64; an f32 round-trip silently mutates a
    // caller's temperature (0.7 → 0.699999988) — the exact lossiness busbar exists to avoid.
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff (`top_p`). A first-class IR field — NOT left in `extra` — because it
    /// is a UNIVERSALLY-modeled sampling control with a clean native shape in every protocol busbar
    /// speaks (OpenAI `top_p`, Anthropic `top_p`, Gemini `generationConfig.topP`, Bedrock
    /// `inferenceConfig.topP`, Cohere `p`). `extra` is cleared on the cross-protocol seam to stop
    /// source-only key leakage; a control that should TRANSLATE must be modeled here or it would be
    /// silently dropped on every cross-protocol hop. `f64` for the same lossless-number reason as
    /// `temperature`. `None` when the caller omitted it. Each reader populates it from its native
    /// shape; each writer emits it in its native shape when present.
    pub top_p: Option<f64>,
    /// Top-k sampling cutoff (`top_k`). First-class for the same reason as `top_p`: it has a real
    /// cross-protocol mapping in the protocols that model it (Anthropic `top_k`, Gemini
    /// `generationConfig.topK`, Cohere `k`, Bedrock via `additionalModelRequestFields`). OpenAI has
    /// NO top_k knob, so the OpenAI writer omits it (and its reader never sets it) — a lossy-by-target
    /// omission, not a leak. `u32`: top_k is a non-negative integer count. `None` when omitted.
    pub top_k: Option<u32>,
    /// Repetition penalty by token frequency (`frequency_penalty`). A cross-protocol-preserved
    /// sampling control: written only by protocols that natively model it (OpenAI/Responses/Cohere).
    /// `f64` for the same lossless-number reason as `temperature`. `None` == absent — never emitted.
    pub frequency_penalty: Option<f64>,
    /// Repetition penalty by token presence (`presence_penalty`). A cross-protocol-preserved
    /// sampling control: written only by protocols that natively model it (OpenAI/Responses/Cohere).
    /// `f64` for the same lossless-number reason as `temperature`. `None` == absent — never emitted.
    pub presence_penalty: Option<f64>,
    /// Deterministic-sampling seed (`seed`). A cross-protocol-preserved sampling control: written
    /// only by protocols that natively model it (OpenAI/Responses, Gemini). `i64` to carry
    /// the full JSON integer range losslessly. `None` == absent — never emitted.
    pub seed: Option<i64>,
    /// Number of candidate completions to generate (`n`). A cross-protocol-preserved output control:
    /// written only by protocols that natively model it (OpenAI `n`, Gemini `candidateCount`). NOT
    /// Cohere: the v2 `/v2/chat` API has NO `num_generations`/`n` parameter (it was a v1 Generate-API
    /// field, removed in v2 — the documented way to get N candidates is to call chat N times), so the
    /// Cohere reader/writer correctly omit `n` (like Anthropic/Bedrock/Responses). `u32`: a
    /// non-negative count. `None` == absent — never emitted.
    pub n: Option<u32>,
    /// The reasoning/thinking ASK, normalized: what the caller requested, in whichever spelling
    /// their protocol uses (OpenAI `reasoning_effort` word, Anthropic `thinking.budget_tokens`
    /// number, Gemini `thinkingConfig.thinkingBudget` number or -1 dynamic). Writers project it
    /// into their own spelling: number → number is a straight copy (Anthropic ↔ Gemini), word ↔
    /// number goes through the effort-budget table ([`IrRequest::reasoning_budgets`]). GATED at the
    /// egress seam by the per-lane `reasoning` capability flag — when the lane does not claim the
    /// capability, `prepare_for_egress` clears this with a warn, so a non-reasoning model never
    /// receives (and never 400s on) a thinking param. The response-side thinking CONTENT is carried
    /// by the Thinking blocks and is not gated. `None` == caller never asked.
    pub reasoning: Option<IrReasoningAsk>,
    /// The resolved effort-word → token-budget table [minimal, low, medium, high], stamped by the
    /// egress seam from `limits.reasoning_effort_budgets` (operator-overridable; defaults
    /// 1024/4096/8192/16384). Writers use it to project effort words to numeric budgets and to
    /// bucketize numeric budgets back to words; when `None` (e.g. unit tests calling a writer
    /// directly) writers fall back to the same defaults.
    pub reasoning_budgets: Option<[u32; 4]>,
    /// Per-token log-probability request (OpenAI `logprobs: bool`; Gemini
    /// `generationConfig.responseLogprobs`). First-class so the ask carries between the two
    /// protocols that model it; writers with no analog (Anthropic/Bedrock) never emit it. The
    /// RESPONSE data rides [`IrResponse::logprobs`] / [`IrDelta::LogprobsDelta`]. `None` == absent.
    pub logprobs: Option<bool>,
    /// How many top-alternative tokens to return per position (OpenAI `top_logprobs` 0–20; Gemini
    /// `generationConfig.logprobs`). `None` == absent.
    pub top_logprobs: Option<u32>,
    /// Structured-output / response-format directive — canonicalized into the typed
    /// [`IrResponseFormat`] on read (NOT a raw protocol-shaped `Value`), so a writer can only project
    /// it into its OWN native shape and can never echo a foreign one. `None` == absent, never emitted.
    pub response_format: Option<IrResponseFormat>,
    /// Stop sequences (`stop`). First-class because every protocol models it (OpenAI `stop` —
    /// string OR array; Anthropic `stop_sequences`; Gemini `generationConfig.stopSequences`; Bedrock
    /// `inferenceConfig.stopSequences`; Cohere `stop_sequences`). Normalized to a `Vec<String>` (the
    /// common shape); a writer whose native form is a bare string for the single-element case still
    /// round-trips because the SDKs accept the array form. Empty `Vec` == omitted (no `stop` field
    /// emitted), so a request that never carried stops does not gain an empty array on translation.
    pub stop: Vec<String>,
    /// Tool-selection directive (`tool_choice`). First-class — NOT left in `extra` — because it is a
    /// load-bearing, behavior-changing control that EVERY protocol busbar speaks models, just in a
    /// different native shape (OpenAI `tool_choice`, Anthropic `tool_choice`, Gemini
    /// `toolConfig.functionCallingConfig`, Bedrock `toolConfig.toolChoice`, Cohere/Responses
    /// `tool_choice`). `extra` is cleared on the cross-protocol seam, so leaving forced/targeted tool
    /// use in `extra` silently degrades it to the target's default (`auto`) on every cross-protocol
    /// hop — directly undercutting the lossless contract. Each reader normalizes its native shape into
    /// this union; each writer re-emits the union in its native shape when present. `None` when the
    /// caller omitted it (no `tool_choice` emitted, so a request that never carried one does not gain
    /// a spurious `auto` on translation).
    pub tool_choice: Option<IrToolChoice>,
    /// End-user identifier for provider-side abuse tracking. Two protocols model it, in different
    /// places: OpenAI top-level `user`, Anthropic `metadata.user_id`. First-class so it CARRIES
    /// between those two instead of dying in `extra` at the cross-protocol seam; writers for
    /// protocols with no analog (Gemini/Bedrock/Cohere) simply never emit it. `None` == absent.
    pub user: Option<String>,
    /// Tool-call parallelism switch, normalized as "parallel allowed?". OpenAI models it as
    /// top-level `parallel_tool_calls` (default true); Anthropic as
    /// `tool_choice.disable_parallel_tool_use` (default false) — the SAME switch, inverted, in a
    /// different location, so it carries between the two. `None` == caller never said, nothing
    /// emitted (both defaults are "parallel allowed", so absence round-trips as absence).
    pub parallel_tool_calls: Option<bool>,
    pub stream: bool,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Normalized cross-protocol tool-selection directive (`tool_choice`). Models the union every wire
/// protocol expresses, so forced/targeted tool use ROUND-TRIPS instead of degrading to `auto`:
///
/// | Variant    | OpenAI / Responses (Cohere)        | Anthropic                    | Gemini (`functionCallingConfig`)            | Bedrock (`toolChoice`) |
/// |------------|------------------------------------|------------------------------|---------------------------------------------|------------------------|
/// | `Auto`     | `"auto"` (Cohere: omit — default)  | `{type:"auto"}`              | `{mode:"AUTO"}`                             | `{auto:{}}`            |
/// | `None`     | `"none"` (Cohere: `"NONE"`)        | `{type:"none"}`*             | `{mode:"NONE"}`                             | (omit — no native)*    |
/// | `Required` | `"required"` (Cohere: `"REQUIRED"`)| `{type:"any"}`              | `{mode:"ANY"}`                             | `{any:{}}`             |
/// | `Tool{n}`  | `{type:"function",function:{name}}`| `{type:"tool",name:n}`      | `{mode:"ANY",allowedFunctionNames:[n]}`    | `{tool:{name:n}}`      |
///
/// *Anthropic gained `{type:"none"}` (2024-10+); older targets without a native "none" fall back to
/// omitting `tool_choice`. A reader maps an unknown/novel native value to `Auto` (the safe default)
/// rather than dropping the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrToolChoice {
    /// Model decides whether to call a tool. The universal default.
    Auto,
    /// Model must NOT call a tool (text only).
    None,
    /// Model MUST call SOME tool (any of the provided), but the caller does not pin which.
    /// (OpenAI/Cohere/Responses `"required"`, Anthropic `"any"`, Gemini `ANY`, Bedrock `any`.)
    Required,
    /// Model MUST call this SPECIFIC tool by name.
    Tool { name: String },
}

/// Normalize a protocol's native stop-sequence field into the IR's `Vec<String>`.
///
/// Stop sequences arrive in two native shapes across busbar's protocols: a bare string (OpenAI's
/// `stop` accepts a single string) or an array of strings (Anthropic `stop_sequences`, Gemini
/// `stopSequences`, Bedrock `stopSequences`, Cohere `stop_sequences`, and OpenAI's array form). This
/// collapses both into the IR's normalized `Vec<String>`: a string becomes a one-element vec, an
/// array keeps its string elements (non-string elements are skipped — a malformed entry should not
/// abort the whole request), and absent/`null`/any other type yields an empty vec (== omitted). Used
/// by every reader so the cross-protocol seam carries stops uniformly.
///
/// Empty-string elements are dropped in both arms: an empty stop sequence is meaningless (no protocol
/// matches on it) and would otherwise leave a one-element vec that defeats the "empty `Vec` ==
/// omitted" contract — a degenerate input of `""` or `[""]` collapses to an empty vec (== omitted)
/// rather than emitting a spurious `stop: [""]` on translation.
pub fn read_stop_sequences(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrStreamEvent {
    MessageStart {
        role: IrRole,
        usage: Option<IrUsage>,
        /// Stream identity, carried through from the egress backend's stream-start metadata so a
        /// writer can emit the SDK-required top-level identity fields a native stream carries
        /// (Anthropic `message_start.message.id`; OpenAI `chat.completion.chunk` top-level
        /// `id`/`created`/`model`). Default `None`; populated per-protocol by each reader and
        /// synthesized by the writer when the backend supplies none (see the synthesized-ID contract
        /// below).
        ///
        /// Synthesized-ID contract: on a CROSS-PROTOCOL stream the foreign-format identity is stripped
        /// (`StreamTranslate::translate_event` sets ONLY `id` and `created` to `None`) so the ingress
        /// writer mints a NATIVE-format id rather than leaking the backend's `chatcmpl-…`/`msg_…` to a
        /// different-protocol client. `model` is DELIBERATELY PRESERVED: it is the format-neutral lane
        /// model name, and ingress writers use a populated `model` as the anchor for synthesizing the
        /// full native stream-start skeleton — clearing it produced a degenerate Anthropic
        /// `message_start` (missing `id`/`type`/`content`/`stop_reason`/`stop_sequence`) and a Gemini
        /// frame missing `modelVersion` (see the explanation at `proto/mod.rs` `translate_event`). A
        /// same-protocol round-trip is untouched and stays byte-exact.
        id: Option<String>,
        /// Unix epoch seconds for the stream's creation time (OpenAI chunk top-level `created`).
        created: Option<u64>,
        /// The model that served the stream (OpenAI chunk top-level `model`; Anthropic
        /// `message_start.message.model`). Mirrors `IrResponse::model`.
        model: Option<String>,
    },
    BlockStart {
        index: usize,
        block: IrBlockMeta,
    },
    BlockDelta {
        index: usize,
        delta: IrDelta,
    },
    BlockStop {
        index: usize,
    },
    MessageDelta {
        stop_reason: Option<IrStopReason>,
        /// Anthropic's streaming `message_delta.delta.stop_sequence` — the matched stop string, or
        /// `None` when no stop sequence matched (or the source protocol has no analog). Only the
        /// Anthropic reader populates it and only the Anthropic writer emits it (and only when the
        /// source carried it), so a same-protocol Anthropic passthrough stays byte-faithful while
        /// other protocols' output is unchanged.
        stop_sequence: Option<String>,
        usage: IrUsage,
    },
    MessageStop,
    Error(crate::proto::IrError),
}

/// Canonical, protocol-neutral stop/finish reason — the typed IR carrier (closing the `stop_reason`
/// hole, the same way [`IrResponseFormat`] / [`IrToolChoice`] close theirs).
///
/// Previously `stop_reason` was a raw `String`. Each protocol READER lower-folded its native finish
/// token into a canonical string, and each WRITER matched those strings — but an unrecognized token
/// fell through and could be EMITTED VERBATIM into a different protocol's closed `finish_reason` enum,
/// which a strict client SDK rejects (the recurring "off-spec finish_reason" bug, fixed once per
/// writer). Typing it removes the bug class: a reader maps any unknown native token to [`Self::Other`]
/// (NO String payload — nothing foreign can be carried), and every writer's match is EXHAUSTIVE, so a
/// new protocol is FORCED by the compiler to map every variant to a value valid in its own enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrStopReason {
    /// Natural end of turn.
    EndTurn,
    /// A provided stop sequence was generated.
    StopSequence,
    /// The output token cap (or model max) was reached.
    MaxTokens,
    /// The model wants to call one or more tools.
    ToolUse,
    /// Content moderation / safety filter stopped generation.
    Safety,
    /// The model refused to continue (Anthropic `refusal`, Responses `incomplete_details:refusal`).
    Refusal,
    /// A long-running turn was paused (Anthropic `pause_turn`).
    PauseTurn,
    /// An upstream/server error terminated generation (Cohere `ERROR`).
    Error,
    /// An unrecognized or future native reason. Readers map any token they don't model here; every
    /// writer projects it to ITS natural-stop default. The absence of a `String` payload is what makes
    /// the bug class impossible — there is no foreign value to echo.
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrResponse {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
    pub stop_reason: Option<IrStopReason>,
    pub usage: IrUsage,
    /// The model that actually served the response, as reported by the upstream. Preserved across
    /// cross-protocol translation so a pool route's response still names the member that served it
    /// (same as a direct route). `None` if the upstream body carried no model field.
    pub model: Option<String>,
    /// Response identity, carried through from the egress backend's `read_response` so a writer can
    /// emit the SDK-required identity field a native response carries (OpenAI `id` =
    /// `"chatcmpl-..."`, Anthropic `id` = `"msg_..."`). Default `None`; populated per-protocol by
    /// each reader and synthesized by the writer when the backend supplies none, so the shape stays
    /// SDK-valid (see the synthesized-ID contract below).
    ///
    /// Synthesized-ID contract: on a CROSS-PROTOCOL non-stream response the foreign-format `id` is
    /// stripped (`proxy engine` sets `ir.id = None`) and the ingress writer mints a NATIVE-format id
    /// when `created` is `Some` (the cross-boundary signal) — so e.g. an OpenAI backend's
    /// `chatcmpl-…` id never reaches an Anthropic client. A same-protocol response preserves the
    /// native id verbatim.
    pub id: Option<String>,
    /// Unix epoch seconds for the response creation time (OpenAI `created`). Default `None`.
    pub created: Option<u64>,
    /// OpenAI's `system_fingerprint` (opaque backend config marker). Default `None`.
    pub system_fingerprint: Option<String>,
    /// Anthropic's `stop_sequence` (the matched stop string, or `null`). Default `None`.
    pub stop_sequence: Option<String>,
    /// Per-token log probabilities for the generated text, in generation order (OpenAI
    /// `choices[].logprobs.content`; Gemini `candidates[].logprobsResult`, chosen + top candidates
    /// zipped). Empty == the backend sent none (nothing emitted). Carried protocol-neutrally so a
    /// Gemini backend's logprobs reach an OpenAI-dialect caller in its own shape, and vice versa.
    pub logprobs: Vec<IrTokenLogprob>,
}

/// The normalized reasoning/thinking ask (see [`IrRequest::reasoning`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrReasoningAsk {
    /// A word-form ask (OpenAI `reasoning_effort` / Responses `reasoning.effort`).
    Effort(IrReasoningEffort),
    /// A numeric thinking-token budget (Anthropic `budget_tokens`, Gemini `thinkingBudget`).
    Budget(u32),
    /// Gemini's `thinkingBudget: -1` — "the model decides". Projected back to Gemini as -1
    /// verbatim; projected to protocols with no dynamic concept as the `medium` table entry
    /// (with a warn), since "model decides" has no closer analog than the middle of the road.
    Dynamic,
}

/// The four effort words, ordered by ascending budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrReasoningEffort {
    Minimal,
    Low,
    Medium,
    High,
}

/// The compiled-in effort table (mirrors the config defaults) — the writer fallback when the seam
/// did not stamp [`IrRequest::reasoning_budgets`].
pub const REASONING_BUDGET_DEFAULTS: [u32; 4] = [1024, 4096, 8192, 16384];

impl IrReasoningAsk {
    /// Project the ask to a NUMERIC budget using the effort table ([minimal, low, medium, high]).
    pub fn to_budget(self, table: [u32; 4]) -> u32 {
        match self {
            IrReasoningAsk::Budget(n) => n,
            IrReasoningAsk::Effort(IrReasoningEffort::Minimal) => table[0],
            IrReasoningAsk::Effort(IrReasoningEffort::Low) => table[1],
            IrReasoningAsk::Effort(IrReasoningEffort::Medium) => table[2],
            IrReasoningAsk::Effort(IrReasoningEffort::High) => table[3],
            IrReasoningAsk::Dynamic => table[2],
        }
    }

    /// Project the ask to a WORD using the same table as bucket thresholds (a numeric budget maps
    /// to the largest effort whose table entry it reaches), so word→number→word round-trips
    /// degrade predictably.
    pub fn to_effort(self, table: [u32; 4]) -> IrReasoningEffort {
        match self {
            IrReasoningAsk::Effort(e) => e,
            IrReasoningAsk::Dynamic => IrReasoningEffort::Medium,
            IrReasoningAsk::Budget(n) => {
                if n >= table[3] {
                    IrReasoningEffort::High
                } else if n >= table[2] {
                    IrReasoningEffort::Medium
                } else if n >= table[1] {
                    IrReasoningEffort::Low
                } else {
                    IrReasoningEffort::Minimal
                }
            }
        }
    }
}

impl IrReasoningEffort {
    /// The OpenAI-family `reasoning_effort` value. Identical to [`Self::as_str`] EXCEPT `Minimal`
    /// maps to `"low"`: `"minimal"` is only accepted by newer OpenAI reasoning models (gpt-5),
    /// while the o-series accepts only low/medium/high. `Minimal` reaches an OpenAI egress writer
    /// only via a small cross-protocol budget (Anthropic/Gemini source), and the lane's reasoning
    /// model is operator-declared, not known here — emitting the universally-valid `"low"` upholds
    /// the never-cause-a-400 translation invariant. (Same-protocol OpenAI is byte-exact and never
    /// reaches this projection.)
    pub fn as_openai_reasoning_effort(self) -> &'static str {
        match self {
            IrReasoningEffort::Minimal => "low",
            other => other.as_str(),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IrReasoningEffort::Minimal => "minimal",
            IrReasoningEffort::Low => "low",
            IrReasoningEffort::Medium => "medium",
            IrReasoningEffort::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "minimal" => Some(IrReasoningEffort::Minimal),
            "low" => Some(IrReasoningEffort::Low),
            "medium" => Some(IrReasoningEffort::Medium),
            "high" => Some(IrReasoningEffort::High),
            _ => None,
        }
    }
}

/// One generated token's log probability, plus the top alternatives at that position. The neutral
/// pivot between OpenAI's `{token, logprob, bytes, top_logprobs[]}` entries and Gemini's
/// `logprobsResult.{chosenCandidates[i], topCandidates[i].candidates[]}` pair of parallel arrays.
/// `bytes` is OpenAI-only fidelity (a token can be a partial UTF-8 fragment); a writer that needs
/// bytes and has none synthesizes them from the token's UTF-8 encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct IrTokenLogprob {
    pub token: String,
    pub logprob: f64,
    pub bytes: Option<Vec<u8>>,
    /// Top alternative tokens at this position (may include the chosen token itself, per both
    /// vendors' semantics). Empty when the caller did not ask for alternatives.
    pub top: Vec<IrTopLogprob>,
}

/// One alternative token candidate inside [`IrTokenLogprob::top`].
#[derive(Debug, Clone, PartialEq)]
pub struct IrTopLogprob {
    pub token: String,
    pub logprob: f64,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrBlock {
    Text {
        text: String,
        cache_control: Option<CacheControl>,
        citations: Vec<IrCitation>,
    },
    Thinking {
        text: String,
        signature: Option<String>,
        /// `true` when this is an opaque REDACTED/encrypted reasoning block (Anthropic
        /// `redacted_thinking`, Bedrock `redactedContent`) — `text` holds the opaque bytes, NOT
        /// plaintext. A TYPED flag rather than the old hack of marking it with a
        /// `__busbar_bedrock_redacted_reasoning` sentinel in `signature` (which leaked a
        /// protocol-specific marker into the agnostic IR and risked a foreign writer emitting it on
        /// the wire). Only the Anthropic/Bedrock readers set it; only those writers re-emit the
        /// redacted form; other writers drop a redacted block (no plaintext analog).
        redacted: bool,
        /// Anthropic cache breakpoint (`cache_control`) placed on a `thinking` block. First-class so
        /// an Anthropic breakpoint on a thinking block survives the seam instead of silently
        /// vanishing (a cache-hit cost/latency regression and a same-protocol byte difference). Only
        /// the Anthropic reader populates it and only the Anthropic writer emits it; other protocols
        /// have no native analog and leave it `None`.
        cache_control: Option<CacheControl>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
        /// Anthropic tool-use cache breakpoint (`cache_control`). First-class so an Anthropic cache
        /// breakpoint placed ON a tool_use block survives the seam instead of silently vanishing
        /// (cost/latency regression). Only the Anthropic reader populates it and only the Anthropic
        /// writer emits it; other protocols have no native analog and leave it `None`.
        cache_control: Option<CacheControl>,
        /// Opaque, vendor-scoped continuation token — Gemini 3's `thoughtSignature`, a sibling of
        /// `functionCall` on the wire `Part`, that MUST be echoed back verbatim on the next turn or
        /// the Gemini backend 400s ("missing a thought_signature"). Mirrors [`IrBlock::Thinking`]'s
        /// `signature` field, but scoped to a tool-use block instead of a thinking block. Populated
        /// two ways: (1) read off the wire by Gemini's own readers when Gemini is the SOURCE
        /// protocol (round-tripped verbatim; harmless to capture even though same-protocol
        /// Gemini→Gemini traffic never actually passes through the IR), and (2) INJECTED by
        /// [`IrReq::prepare_for_egress`] with Google's documented sentinel value when the egress lane
        /// is Gemini AI Studio and the block has no real signature — this is the path that matters
        /// for cross-protocol traffic (e.g. OpenAI history replayed against a Gemini backend), since
        /// no foreign protocol has a `thoughtSignature` concept of its own to read.
        thought_signature: Option<String>,
    },
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
        /// Anthropic tool-result cache breakpoint (`cache_control`). Same rationale as the
        /// `ToolUse` field — Anthropic places breakpoints on tool_result blocks to cache the
        /// (often large) result content; without an IR field that breakpoint is lost cross-hop.
        cache_control: Option<CacheControl>,
    },
    Image {
        /// The image source, typed (NOT a `media_type` String overloaded with magic sentinels). A
        /// writer can only project the variant it can represent and DROPS-with-warn the rest — it can
        /// never emit a corrupt block from a misread sentinel.
        source: IrImageSource,
        /// Anthropic cache breakpoint (`cache_control`) placed on an `image` block. First-class so an
        /// Anthropic breakpoint on a (often large) image block survives the seam instead of silently
        /// vanishing — the dominant cache-on-image use case. Only the Anthropic reader populates it
        /// and only the Anthropic writer emits it; other protocols leave it `None`.
        cache_control: Option<CacheControl>,
    },
    /// A non-image ATTACHMENT the caller sent for the model to reason over: a document (PDF, CSV,
    /// DOCX, …), an audio clip, or a video clip.
    ///
    /// # Why this variant exists
    ///
    /// Before it, `IrBlock` modelled `Text / Thinking / ToolUse / ToolResult / Image / Json` and
    /// nothing else, so every non-image attachment was destroyed on a cross-protocol hop and
    /// replaced with `{"type":"text","text":""}` — SILENTLY. An OpenAI caller's `input_audio` or
    /// `file` part, an Anthropic `document`, a Bedrock `document`/`video`, a Responses `input_file`
    /// all landed as an empty text block, so the model answered "transcribe what?" and nothing in
    /// the logs said why. That was not an untranslatable-concept problem: the targets have native
    /// slots for exactly these (Gemini `inlineData`/`fileData` carries ANY mime type, Bedrock has
    /// `document`/`video`, Anthropic has `document`). It was an unmodelled IR gap.
    ///
    /// The contract every writer honors: project the attachment into the target's native slot when
    /// the target HAS one, and when it genuinely does not, DROP IT WITH A `warn!` NAMING THE FIELD —
    /// never as an empty text block, which is indistinguishable from the caller having sent nothing.
    ///
    /// Deliberately NOT widened to hook/sidecar visibility: like [`IrBlock::Image`], a `Media` block
    /// contributes no item to `ir::facts` projections, so attachment bytes and filenames are not
    /// disclosed to a content hook. That is the same disclosure decision `ir/facts.rs` records for
    /// image provenance, kept rather than quietly reversed.
    Media {
        /// Which attachment class this is. Decides the target slot (a Bedrock `document` block vs a
        /// `video` block) and which targets can express it at all.
        kind: IrMediaKind,
        /// The attachment source, typed — the SAME carrier `Image` uses (inline base64 with a real
        /// mime type, a remote URL, or an opaque vendor-scoped reference re-emitted only by its own
        /// protocol). One type rather than a near-duplicate `IrMediaSource`, because the three ways
        /// a wire references bytes do not differ between an image and a PDF.
        source: IrImageSource,
        /// Filename / title where the wire carries one (OpenAI `file.filename`, Anthropic
        /// `document.title`, Bedrock `document.name`, Responses `input_file.filename`). Bedrock
        /// REQUIRES a name on a document block, so this is load-bearing on that egress, not cosmetic.
        name: Option<String>,
        /// Anthropic cache breakpoint (`cache_control`) placed on a `document` block — same rationale
        /// as the `Image` field; documents are the largest thing anyone caches.
        cache_control: Option<CacheControl>,
    },
    /// Structured JSON content — a Bedrock Converse `{"json": <value>}` tool-result content block (an
    /// arbitrary-structured-data member of the `ToolResultContentBlock` union). It is NOT an image;
    /// it previously rode inside an `Image` behind a `tool_result_json` media_type sentinel (the
    /// stringly-typed smell). Bedrock re-emits it natively; protocols whose tool-result content is
    /// text/image-only drop it with a warn (there is no lossless cross-protocol projection).
    Json(Value),
}

impl IrBlock {
    /// Is this block's content OPAQUE to busbar — carried through verbatim, never readable as
    /// plaintext, and therefore never disclosable to an operator's sidecar?
    ///
    /// THE ONE PLACE THAT KNOWS. Three wire shapes are opaque for the same reason, and until this
    /// predicate existed only two of them said so from the IR:
    ///
    /// | wire shape | how it lands in the IR |
    /// |---|---|
    /// | Anthropic `redacted_thinking` | `Thinking { redacted: true, text: <ciphertext> }` |
    /// | Bedrock `reasoningContent.redactedContent` | `Thinking { redacted: true, text: <ciphertext> }` |
    /// | Responses `reasoning` item with ONLY `encrypted_content` | `Thinking { redacted: false, text: "", signature: Some(<blob>) }` |
    ///
    /// The third one is why this method exists. The Responses reader admits that item to the
    /// provider on the blob ALONE, so the request goes upstream in full — but the block reads as
    /// `redacted: false` with EMPTY text, so anything keying a redaction decision off `redacted`
    /// sees an empty turn and passes it. That is a policy-enforcement-point bypass, and it was
    /// dialect-conditional: the same deployment behaved correctly on Anthropic/Bedrock ingress and
    /// wrongly on Responses ingress, with nothing in the code acknowledging the split.
    ///
    /// # Why a predicate and NOT `Thinking.redacted = true` on the Responses reader
    ///
    /// Because `redacted` is not an opacity flag — it is a **writer instruction**, and the writers
    /// read it that way today:
    ///
    /// * `proto/openai_responses/writer.rs` DROPS a `redacted` Thinking block on both the request
    ///   and response paths. Flipping the flag would delete `encrypted_content` from every
    ///   Responses→Responses round-trip — the exact reasoning-reuse blob the reader was taught to
    ///   preserve, silently lost.
    /// * `proto/anthropic/writer.rs` and `proto/bedrock/writer.rs` re-emit `redacted` blocks as
    ///   `redacted_thinking` / `redactedContent` with `text` as the payload. `text` is EMPTY for the
    ///   Responses shape, so the flip would have those writers emit an empty-ciphertext redacted
    ///   block on a cross-protocol hop.
    /// * `proto/gemini/writer.rs` drops `redacted` blocks outright.
    ///
    /// So `redacted` means "this block's OWN `text` is the opaque payload, and the writer that has
    /// a native redacted form should re-emit it from there". Overloading it with "busbar cannot
    /// read this" would change client-visible egress bytes on three protocols to state a fact the
    /// IR can state for free. The predicate states the fact and moves no bytes: this unit is
    /// observable to nothing but a caller that asks.
    ///
    /// The second arm — plaintext EMPTY but an opaque blob present — is deliberately general rather
    /// than Responses-shaped. It is true of any block whose entire content is a carrier blob
    /// (Gemini's `thoughtSignature` on a text-less thought part reaches the IR the same way), and a
    /// protocol-named condition here would be the wire-shape dispatch this predicate exists to
    /// delete. A block with real plaintext AND a signature is READABLE — the signature is a
    /// round-trip token beside content busbar can see — so it is not opaque.
    ///
    /// # The contract for a consumer
    ///
    /// `is_opaque()` is necessary AND sufficient to decide "substitute a marker rather than show
    /// the content". Note it does not coincide with "`text` is safe to read": when this returns
    /// true, `text` is either empty (Responses) or the ciphertext ITSELF (Anthropic/Bedrock), so a
    /// consumer must check this BEFORE touching `text`, never after.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_opaque(&self) -> bool {
        match self {
            // `text` holds the opaque bytes (Anthropic `redacted_thinking`, Bedrock
            // `redactedContent`) — opaque by the flag the readers already set.
            IrBlock::Thinking { redacted: true, .. } => true,
            // No plaintext at all, and a carrier blob in its place: the whole block is a blob
            // busbar cannot read (a Responses `encrypted_content`-only `reasoning` item).
            IrBlock::Thinking {
                text, signature, ..
            } => text.is_empty() && signature.is_some(),
            // Every other block is content busbar reads in the clear. Enumerated rather than
            // swallowed by `_` so a future variant that CAN carry an opaque payload has to decide
            // here instead of silently defaulting to "readable" — the failure direction that
            // produced this method.
            IrBlock::Text { .. }
            | IrBlock::ToolUse { .. }
            | IrBlock::ToolResult { .. }
            | IrBlock::Image { .. }
            | IrBlock::Media { .. }
            | IrBlock::Json(_) => false,
        }
    }
}

/// Which class of non-image attachment an [`IrBlock::Media`] carries.
///
/// Three variants and not one, because the TARGET SLOT differs per class and a writer must be able
/// to say "I can express a document but not a video" without sniffing mime-type strings at every
/// egress. Bedrock Converse, for instance, has a `document` block and a `video` block and NO audio
/// block; OpenAI Chat has `input_audio` and `file` and no video part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrMediaKind {
    /// PDF / CSV / DOCX / TXT / MD / HTML — something the model reads.
    Document,
    /// An audio clip (OpenAI `input_audio`, Gemini `inlineData` with an `audio/*` mime).
    Audio,
    /// A video clip (Bedrock `video`, Gemini `inlineData`/`fileData` with a `video/*` mime).
    Video,
}

impl IrMediaKind {
    /// Classify a mime type into a media kind — the ONE place the `audio/*` / `video/*` prefix
    /// convention lives, so a reader that only has a mime type (Gemini `inlineData`, a `data:` URI)
    /// does not hand-roll the same three-way match. `image/*` is NOT a `Media` kind (it is
    /// [`IrBlock::Image`]), so callers must check for it first; anything else is a Document, which is
    /// the correct default for `application/pdf`, `text/csv` and every future document mime.
    pub fn from_media_type(media_type: &str) -> Self {
        let lower = media_type.to_ascii_lowercase();
        if lower.starts_with("audio/") {
            IrMediaKind::Audio
        } else if lower.starts_with("video/") {
            IrMediaKind::Video
        } else {
            IrMediaKind::Document
        }
    }

    /// The field name to put in a drop `warn!`, so a log line names the caller's construct in the
    /// caller's own vocabulary rather than saying "media".
    pub fn as_str(self) -> &'static str {
        match self {
            IrMediaKind::Document => "document",
            IrMediaKind::Audio => "audio",
            IrMediaKind::Video => "video",
        }
    }
}

/// The image media types EVERY protocol in the matrix accepts on an `image` block.
///
/// Anthropic documents `image/{jpeg,png,gif,webp}` and 400s anything else; OpenAI's data-URI image
/// part is the same set; Bedrock's `ImageFormat` union is `{png, jpeg, gif, webp}`. Bedrock's writer
/// already validated against its union and coerced the rest — the OTHER writers emitted `media_type`
/// verbatim, so a Gemini `inlineData` of `audio/mp3` (which the Gemini reader mapped onto an `Image`
/// block regardless of mime) reached Anthropic as
/// `{"type":"image","source":{"type":"base64","media_type":"audio/mp3"}}` and 400'd the backend —
/// breaking the half of the losslessness definition that says the backend never rejects the request.
///
/// Returns `None` for a media type that is not a well-formed image mime or not in the accepted set,
/// so the caller drops the block with a warn; `Some(subtype)` (lowercased, `jpg` normalized to
/// `jpeg`) otherwise, which is also exactly what a writer needs to build a format token.
pub fn image_subtype_if_supported(media_type: &str) -> Option<&'static str> {
    let subtype = media_type.strip_prefix("image/").or_else(|| {
        // Tolerate a casing variant on the type half ("Image/PNG") without allocating in the
        // overwhelmingly common already-lowercase case.
        media_type
            .get(..6)
            .filter(|p| p.eq_ignore_ascii_case("image/"))
            .map(|_| &media_type[6..])
    })?;
    match subtype.to_ascii_lowercase().as_str() {
        "jpeg" | "jpg" => Some("jpeg"),
        "png" => Some("png"),
        "gif" => Some("gif"),
        "webp" => Some("webp"),
        _ => None,
    }
}

/// Typed source for an [`IrBlock::Image`] — replaces a `media_type: String` overloaded with
/// `image_url` / `file_id` / s3-location magic strings (the stringly-typed smell).
///
/// `Base64` and `Url` are PROTOCOL-NEUTRAL (any protocol can carry inline bytes or a URL). A
/// vendor-scoped reference that has NO neutral form (a Bedrock `s3Location`, a Responses
/// `input_image.file_id`) does NOT get a protocol-named variant here — that would leak a specific
/// vendor's concept into the agnostic IR. Instead it rides the opaque [`Self::Vendor`] escape: the
/// agnostic core never interprets it (like `IrRequest.extra`), the PRODUCING protocol recognizes its
/// own `vendor` tag and re-emits `value` on a same-protocol egress, and any OTHER protocol's writer
/// cannot represent it and drops it with a warn. So `ir.rs` names no vendor wire concept.
#[derive(Debug, Clone, PartialEq)]
pub enum IrImageSource {
    /// Inline base64 image bytes with a real `image/<fmt>` media type.
    Base64 { media_type: String, data: String },
    /// A remote image URL reference (an `https://…` the OpenAI/Responses/Anthropic-url forms carry).
    Url(String),
    /// An opaque vendor-scoped image reference with no neutral (base64/url) form — same-protocol-only.
    /// `vendor` is the producing protocol's name; `value` is its native reference object, opaque to
    /// the agnostic core. Only the matching protocol's writer re-emits it; others drop it.
    Vendor { vendor: &'static str, value: Value },
}

/// Canonical, protocol-neutral structured-output directive — the typed IR carrier for
/// `response_format`.
///
/// THE SMELL THIS REMOVES: `IrRequest.response_format` used to be an opaque `serde_json::Value`
/// holding WHATEVER shape the source reader read — OpenAI `{type,json_schema:{name,schema,strict}}`,
/// Cohere `{type:"json_object",json_schema:<schema>}`, Gemini `{responseMimeType,responseSchema}`, the
/// flat Responses `text.format`. Each writer then re-sniffed that blob and the lazy default was to
/// ECHO it; correct same-protocol, but cross-protocol that emits a FOREIGN shape the backend 400s. The
/// identical bug surfaced once per writer (openai → cohere → gemini → responses) because the field was
/// never canonicalized on the way IN.
///
/// This type is PROTOCOL-AGNOSTIC — it names no wire shape. Each protocol module owns the ONLY code
/// that knows its own `response_format` shape: a reader fn (native → this) and a writer fn (this →
/// native). The agnostic core never sees a foreign shape, so a writer cannot echo one — it has only
/// typed fields to project. (Same reason [`IrToolChoice`], a typed enum, never had this bug.)
#[derive(Debug, Clone, PartialEq)]
pub struct IrResponseFormat {
    /// `false` ⇒ plain text (no structured-output constraint). `true` ⇒ the model must emit JSON.
    pub json: bool,
    /// The JSON Schema the JSON output must conform to, if one was supplied (`None` ⇒ free-form JSON).
    pub schema: Option<Value>,
    /// Schema name (OpenAI/Responses `json_schema.name`), preserved when the source supplied it.
    pub name: Option<String>,
    /// Strict-schema flag (OpenAI/Responses `strict`), preserved when the source supplied it.
    pub strict: Option<bool>,
    /// Schema description (OpenAI/Responses `json_schema.description`), preserved when supplied.
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CacheControl {
    pub kind: CacheKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    Ephemeral,
}

/// Neutral, cross-protocol citation IR for grounding / web-search CITATIONS carried on a `Text`
/// block. Before this type the field was `Vec<serde_json::Value>` holding RAW Anthropic-shaped
/// citation objects: only Anthropic read/wrote them, Gemini's `citationMetadata` was never read, and
/// every other protocol left the vec empty — so a citation was LOST the moment it crossed a protocol
/// boundary. `IrCitation` captures the UNION of the protocol-native citation shapes so a citation can
/// be projected both ways.
///
/// ANTHROPIC FIDELITY (the load-bearing invariant): an Anthropic citation must round-trip BYTE-EXACT
/// on the same-protocol path. The Anthropic citation schema is a tagged union (`type` discriminator)
/// — `char_location`, `page_location`, `content_block_location`, and the web-search
/// `web_search_result_location` — each with its own field set, and the API may add fields/variants.
/// Rather than risk a lossy field-by-field reconstruction, the Anthropic READER stashes the source
/// object VERBATIM in [`IrCitation::raw`] (alongside the neutral fields it also fills), and the
/// Anthropic WRITER, whenever `raw` is present, re-emits it UNCHANGED. So Anthropic→IR→Anthropic is
/// guaranteed byte-exact regardless of how the neutral fields map. Only on a CROSS-protocol egress
/// (where `raw` is a foreign shape or absent) does the writer synthesize an Anthropic object from the
/// neutral fields — best-effort, never a regression to the same-protocol path.
///
/// Neutral fields are the intersection that travels cross-protocol: a human-readable `kind` tag plus
/// the location/source coordinates both Anthropic and Gemini expose.
#[derive(Debug, Clone, PartialEq)]
pub struct IrCitation {
    /// Citation-type discriminator. For Anthropic this is the `type` tag verbatim (`char_location`,
    /// `page_location`, `content_block_location`, `web_search_result_location`); for a Gemini
    /// `citationSources[]` entry it is `web_search_result_location` (a grounding source is a URL
    /// reference). `None` only if a source carried no recognizable type.
    pub kind: Option<String>,
    /// The quoted span of source text the citation refers to (Anthropic `cited_text`). Gemini
    /// `citationSources[]` carry no quoted text, so this is `None` for Gemini-sourced citations.
    pub cited_text: Option<String>,
    /// Human title of the cited document / web result (Anthropic `document_title` for the document
    /// location variants, `title` for `web_search_result_location`; Gemini has no title field today —
    /// reserved for forward compat).
    pub title: Option<String>,
    /// Source URL — Anthropic `web_search_result_location.url`, Gemini `citationSources[].uri`.
    pub url: Option<String>,
    /// Index of the cited document in the request's `documents` array (Anthropic
    /// `document_index`, present on the three document-location variants). Gemini: `None`.
    pub document_index: Option<i64>,
    /// Inclusive/exclusive start offset, interpreted per `kind`: char index (`char_location`), page
    /// number (`page_location`), or block index (`content_block_location`). For a Gemini
    /// `citationSources[]` this carries `startIndex` (a character offset into the response text).
    pub start_index: Option<i64>,
    /// End offset, paired with `start_index` per `kind` (end char / end page / end block; Gemini
    /// `endIndex`).
    pub end_index: Option<i64>,
    /// Anthropic web-search `encrypted_index` — an opaque cursor token. Carried so the web-search
    /// citation variant round-trips even on a cross-protocol synthesize-from-neutral path.
    pub encrypted_index: Option<String>,
    /// VERBATIM source citation object, for byte-exact same-protocol re-emission. The Anthropic
    /// reader stores the original Anthropic citation here; the Anthropic writer re-emits it unchanged
    /// when present (the no-regression guarantee). The Gemini reader stores the original
    /// `citationSources[]` entry here so a same-protocol Gemini path could re-emit it faithfully.
    /// `None` for a citation synthesized purely from neutral fields.
    pub raw: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    /// Anthropic tool-definition cache breakpoint (`cache_control`). Anthropic lets a `cache_control`
    /// marker sit on a tool definition to cache the (often large) tool schemas as a prefix; that
    /// breakpoint was being dropped on every hop. First-class so it survives the seam. Only the
    /// Anthropic reader populates it / writer emits it; other protocols leave it `None`.
    pub cache_control: Option<CacheControl>,
    /// HOSTED (built-in) tool passthrough spec. The OpenAI Responses API `tools` array
    /// mixes CUSTOM function tools with provider-HOSTED tools discriminated purely by a top-level
    /// `type` (`web_search`, `file_search`, `code_interpreter`, `computer_use_preview`, `mcp`, ...).
    /// A hosted tool carries NO `name`/`parameters`, so parsing it as a function tool yields an empty
    /// `{"type":"function","name":""}` that a Responses backend 400s on. When set, this holds the RAW
    /// hosted-tool JSON object verbatim; the Responses writer re-emits it unchanged (a same-protocol
    /// passthrough) and skips the function-tool projection. `None` for an ordinary function tool
    /// (`name`/`input_schema` carry it). Only the Responses reader populates it and only the Responses
    /// writer honors it. Every OTHER egress writer is `hosted`-BLIND: it projects an `IrTool` as a
    /// function tool keyed on `name`, so a hosted tool (whose `name` is empty) would be emitted as a
    /// MALFORMED empty-name `{"type":"function","name":""}` the backend rejects with a 400 - NOT
    /// silently ignored. To prevent that, `IrReq::prepare_for_egress` DROPS every hosted tool on the
    /// cross-protocol seam (drop-with-warn), so a hosted tool only ever reaches the Responses writer
    /// (same-protocol Responses->Responses, where the body is forwarded verbatim anyway).
    pub hosted: Option<Value>,
    /// STRICT function-calling flag (OpenAI Chat `tools[].function.strict`, Responses
    /// `tools[].strict`) — "constrain the model's arguments to this schema exactly".
    ///
    /// It is a BEHAVIOURAL contract, not bookkeeping: with `strict: true` the caller's downstream
    /// code may parse the tool arguments without validating them, because OpenAI guarantees schema
    /// conformance. Dropping it silently turned that guarantee off while the request still looked
    /// accepted, so the failure surfaced later as a parse error on an argument object nobody had
    /// asked to be lenient about.
    ///
    /// Carried across the OpenAI Chat ↔ Responses pair, which are the two dialects that model it.
    /// Anthropic, Gemini, Bedrock and Cohere have no per-tool strict flag (Cohere's `strict_tools` is
    /// a REQUEST-level switch, not a per-tool one), so their writers drop it with a `warn!` naming
    /// the tools affected — a genuine target-protocol limit, signalled rather than silent.
    pub strict: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrUsage {
    /// UNCACHED input tokens. Readers NORMALIZE to this convention: providers whose wire
    /// `input/prompt` total already INCLUDES the cached prefix (OpenAI, Gemini, Responses) subtract
    /// the cached count here; providers whose cache fields are already ADDITIVE (Anthropic, Bedrock)
    /// store the wire value as-is. This makes `cache_read_input_tokens` and
    /// `cache_creation_input_tokens` uniformly ADDITIVE across all protocols, so
    /// [`IrUsage::billable_tokens`] can sum them provider-agnostically.
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
    /// Per-bucket ATTRIBUTION of the totals above. Grouped into its own `Default`-able struct rather
    /// than four more fields on `IrUsage`, because a sub-bucket is by construction optional
    /// (`None` = "this provider did not report it", which is NOT the same as `Some(0)`) and every
    /// existing construction site should keep saying nothing about buckets it knows nothing about.
    pub detail: IrUsageDetail,
}

/// Sub-bucket attribution for [`IrUsage`]. Every field is a SLICE OF a total in `IrUsage`, never an
/// addition to one — [`IrUsage::billable_tokens`] deliberately ignores this struct, so carrying a
/// bucket can never change what busbar bills.
///
/// It exists because the totals were already right and the ATTRIBUTION was not, and attribution is
/// what a customer reconciles a bill against.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IrUsageDetail {
    /// Reasoning / thinking tokens, a SUB-BUCKET of `output_tokens` (never added to it — that would
    /// double-count and inflate the bill).
    ///
    /// Present on the wire as OpenAI `completion_tokens_details.reasoning_tokens`, Responses
    /// `output_tokens_details.reasoning_tokens`, Gemini `usageMetadata.thoughtsTokenCount`. Before
    /// this field the totals were right and the ATTRIBUTION was not: a customer reconciling a bill
    /// against `reasoning_tokens` got a hard `0` back from any cross-protocol reasoning call, which
    /// reads as "this model did no thinking" rather than "busbar did not carry the number".
    pub reasoning_tokens: Option<u64>,
    /// Anthropic's 5-minute-TTL slice of `cache_creation_input_tokens`
    /// (`usage.cache_creation.ephemeral_5m_input_tokens`).
    ///
    /// A SUB-BUCKET of `cache_creation_input_tokens`, not an addition to it. Split out because the
    /// two TTL tiers are PRICED DIFFERENTLY — collapsing them into one number makes a cache-write
    /// line item impossible to reconcile even though the total is correct.
    pub cache_creation_5m_input_tokens: Option<u64>,
    /// Anthropic's 1-hour-TTL slice of `cache_creation_input_tokens`
    /// (`usage.cache_creation.ephemeral_1h_input_tokens`). See the 5m field for why the split is
    /// carried.
    pub cache_creation_1h_input_tokens: Option<u64>,
    /// Cohere `usage.billed_units.search_units` — a SEPARATELY BILLED unit that is not a token count
    /// at all, so no token field can carry it and its loss is invisible in a token total that
    /// reconciles perfectly.
    pub search_units: Option<u64>,
}

impl IrUsage {
    /// Total billable tokens under the normalized additive-cache convention:
    /// `input_tokens` (uncached) + `cache_read_input_tokens` + `cache_creation_input_tokens` +
    /// `output_tokens`. Because every reader normalizes `input_tokens` to UNCACHED input and keeps
    /// the cache fields ADDITIVE, this sum is correct and provider-agnostic — it neither
    /// double-counts the OpenAI-family (whose wire prompt total includes the cache) nor under-counts
    /// the Anthropic/Bedrock family (whose cache reads/writes are separate from input). All adds are
    /// `saturating_add`: the operands are UPSTREAM-CONTROLLED counts, so an unchecked `+` could
    /// panic in debug / wrap in release.
    // Production billing now ledgers the TIER SPLIT (`proxy::usage::tier_tokens`); this total
    // survives as the normalization contract's test surface (stream translate/fanout tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn billable_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
            .saturating_add(self.output_tokens)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IrBlockMeta {
    Text,
    Thinking,
    ToolUse { id: String, name: String },
    Image,
}

#[derive(Debug, Clone, PartialEq)]
// Every variant is live on the production egress path: `read_response_events` emits `IrDelta`s
// inside `IrStreamEvent::BlockDelta`, and `StreamTranslate::feed` → `write_response_event` consumes
// them (see proto/{bedrock,gemini,cohere}.rs). The `enum_variant_names` allow stays because all
// variants share the `Delta` suffix by design (they mirror the wire delta-event names).
#[allow(clippy::enum_variant_names)]
pub enum IrDelta {
    TextDelta(String),
    ThinkingDelta(String),
    InputJsonDelta(String),
    SignatureDelta(String),
    /// Streamed opaque REDACTED-reasoning bytes (an Anthropic `redacted_thinking` / Bedrock
    /// `redactedContent` block arriving mid-stream). A TYPED variant rather than the old hack of
    /// stuffing a `__busbar_bedrock_redacted_reasoning` sentinel into a `SignatureDelta` String — the
    /// agnostic IR no longer carries a protocol-specific marker. The producing protocol's reader emits
    /// it; a writer that models redacted reasoning (Bedrock `redactedContent`) re-emits it, others drop
    /// it (the bytes are encrypted/opaque and have no plaintext analog).
    RedactedReasoningDelta(String),
    /// STREAMING grounding/web-search citations. ADDITIVE variant (no existing variant changed
    /// — 1.0-freeze-safe): a streamed citation that arrives mid-block is carried as a
    /// [`crate::ir::IrCitation`] (neutral fields + the byte-exact `raw` escape hatch) rather than
    /// dropped. The Anthropic reader maps a `citations_delta` content_block_delta here (one citation
    /// per delta, wrapped in the vec); the Gemini reader maps a late chunk's `citationMetadata`
    /// (which can carry several sources) here. Writers that model streaming citations (Anthropic
    /// `citations_delta`, Gemini `citationMetadata`) re-emit it; protocols with no streaming-citation
    /// shape simply don't emit it (no panic, no corrupt output). Carried inside
    /// `IrStreamEvent::BlockDelta`, attached to the active text block's index.
    CitationsDelta(Vec<IrCitation>),
    /// STREAMING per-token log probabilities, attached to the active text block's index (the same
    /// additive pattern as `CitationsDelta`). The OpenAI reader maps a chunk's
    /// `choices[].logprobs.content[]` here; the Gemini reader maps a chunk candidate's
    /// `logprobsResult`. Writers that model streaming logprobs (OpenAI, Gemini) re-emit natively;
    /// protocols with no shape for it simply don't emit it.
    LogprobsDelta(Vec<IrTokenLogprob>),
}

/// Per-request decode state for stateful stream fan-out.
/// Anthropic events are 1:1 and ignore this; OpenAI's flat stream uses it to synthesize the
/// IR's block boundaries (one chunk → 0..n events): whether MessageStart was emitted, whether
/// the text/thinking blocks are open, and which OpenAI tool_call indices have been opened.
#[derive(Debug, Clone, Default)]
pub struct StreamDecodeState {
    pub started: bool,
    pub text_block_open: bool,
    /// The IR block index the Gemini reader assigned to the text block, by order of FIRST appearance
    /// (not hardcoded 0). Gemini emits text and `functionCall` parts in any order across chunks; a
    /// block claims the next free index when it first opens, so text and tools never collide on an
    /// index regardless of arrival order (tool-only streams stay contiguous from 0; a tool that opens
    /// before text takes 0 and text takes the next slot). `None` until the text block opens. Gemini
    /// reader only; other readers leave it `None`.
    pub text_index: Option<usize>,
    /// One-way latch: set true once the text content block has been CLOSED (via `content-end` or, for a
    /// leading tool-plan block, the first `tool-call-start`). A closed text block must never be reopened
    /// — a second `content-start`/`content-delta`/`tool-plan-delta` after the close would otherwise emit
    /// a duplicate `BlockStart` at the same claimed index, an unbalanced stream (two `content_block_start`
    /// for one index) on an Anthropic egress. The open sites gate on `!text_block_closed` so an
    /// out-of-spec upstream that resumes text after tools is dropped rather than un-balancing the stream.
    /// Cohere reader only; other readers leave it false.
    pub text_block_closed: bool,
    pub open_tools: std::collections::BTreeSet<usize>,
    /// Set once a reasoning (chain-of-thought) delta is seen on the stream. When true, the
    /// thinking block occupies IR index 0 and the text/tool block indices shift up by one so the
    /// thinking block precedes the answer (used by the OpenAI AND Gemini streaming readers).
    pub reasoning_seen: bool,
    /// Whether the reasoning Thinking block (index 0) is currently open.
    pub thinking_block_open: bool,
    /// Set once a `delta.refusal` chunk is seen. A refusal reports `finish_reason: "stop"`, so
    /// without this latch the terminal frame maps to `EndTurn` and the refusal SIGNAL is lost even
    /// though the text survived. OpenAI Chat reader only; other readers leave it false.
    pub refusal_seen: bool,
    /// Stop reason buffered across two Bedrock stream frames. Native Bedrock ConverseStream splits
    /// the stop reason (`messageStop` frame) from the token usage (a following `metadata` frame). To
    /// emit ONE combined `MessageDelta{stop_reason, usage}` (so a cross-protocol ingress sees the
    /// single `message_delta`/usage event a native non-Bedrock stream carries, not two) the Bedrock
    /// reader stashes the `messageStop` stop_reason here and pairs it with the usage when `metadata`
    /// arrives. Used by the Bedrock reader only; other protocols leave it `None`.
    pub pending_stop_reason: Option<IrStopReason>,
    /// Maps each opened tool-call wire index (the OpenAI reader's `oai_idx` / the Cohere reader's
    /// `frame_idx`) to the IR block index its `BlockStart` was emitted with, giving O(log n)
    /// lookup/insert instead of a linear scan over `open_tools`. Every key inserted here is also
    /// inserted into `open_tools` at the same time (so `open_tools` remains the membership set this
    /// map indexes), but the reverse does not always hold: Cohere's `open_tools` additionally carries
    /// the `TEXT_BLOCK_SEEN_SENTINEL` (cohere.rs), which is deliberately never mirrored into this map.
    /// Neither map is shrunk for the ordinary duration of a stream, for the same reason `open_tools`
    /// is never shrunk, so a `tool-call-end`/finish path can replay the exact index a `BlockStart` was
    /// opened with — except the OpenAI Chat reader's terminal branch, which `mem::take`s BOTH maps
    /// together once the finish/close events have been emitted (see `openai_chat/reader.rs`).
    ///
    /// OpenAI reader: the flat stream lets text arrive AFTER tool calls, and the text block's
    /// presence shifts the tool index base — so the IR index a tool's BlockStart claimed at OPEN
    /// time can diverge from a value RECOMPUTED at finish/close time (where text is now `Some`).
    /// Recording the emitted IR index here and replaying it verbatim at close guarantees every tool
    /// `BlockStop` pairs with the SAME index as its `BlockStart`, regardless of later text arrival.
    ///
    /// Cohere reader: the index is assigned once at `tool-call-start` and never recomputed (no
    /// divergent base to reconcile), so this map exists purely as the O(log n) lookup counterpart to
    /// `open_tools`'s O(log n) membership check — replacing an O(n) linear scan that made a stream
    /// with many sequential tool calls cost O(n²) overall.
    ///
    /// Empty for every other reader (which assign IR indices 1:1 or via `open_tools`/`text_index`
    /// directly and never need this lookup).
    pub tool_ir_index: std::collections::BTreeMap<usize, usize>,
    /// One-way latch so the multi-candidate drop `warn!` fires ONCE per stream rather than once per
    /// SSE chunk. Set the first time a streaming chunk is seen to carry more than one
    /// choice/candidate (the single-candidate IR keeps `[0]` and drops the rest). Defense-in-depth:
    /// the engine now rejects `n>1`/`candidateCount>1` on a cross-protocol route up front, so this
    /// path should not be reached — but if a drop path survives, this makes it observable.
    pub multi_candidate_warned: bool,
    /// Monotone next-free IR block index, for readers that allocate slots by ORDER OF FIRST
    /// APPEARANCE. NEVER reset for the life of the stream. The terminal branch's `mem::take` of
    /// `open_tools`/`tool_ir_index` (openai_chat reader) clears WHO IS OPEN — it must not also be
    /// read as clearing WHICH SLOTS ARE SPENT: a chunk arriving after a finish chunk would then
    /// re-claim an index the client already has content in, reintroducing a block-index collision
    /// on the post-terminal path. OpenAI Chat reader only; other readers leave it 0.
    pub next_ir_index: usize,
}

impl StreamDecodeState {
    /// Claim the next free IR block index. `reasoning_seen` reserves index 0 for the thinking block
    /// (the OpenAI reader emits that one with a hardcoded 0), so the first claim after reasoning
    /// starts at 1.
    pub fn claim_ir_index(&mut self) -> usize {
        let idx = self.next_ir_index.max(usize::from(self.reasoning_seen));
        self.next_ir_index = idx + 1;
        idx
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
