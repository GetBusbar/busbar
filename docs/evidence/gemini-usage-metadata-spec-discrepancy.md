<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# Gemini `usageMetadata` — measured wire behaviour vs. the published spec

**Status:** measured, filed, not yet acted on for billing
**Measured:** 2026-09-07
**Endpoint:** Vertex AI, `us-central1`, `gemini-2.5-flash`,
`:generateContent` and `:streamGenerateContent?alt=sse`
**Evidence:** `crates/busbar-llm-codec/src/tests/proto/golden/vendor/` (seven raw
recordings + README with the full per-recording table)
**Replayed by:** `crates/busbar-llm-codec/src/gemini/tests/usage_identity_tests.rs`

## Why this was measured rather than read

busbar's Gemini usage decode rested on a sum identity it could not verify from the
published documentation. Two questions were genuinely open, and the identity is a
different equation depending on the answer to each:

1. Is `thoughtsTokenCount` counted *inside* `candidatesTokenCount` / `totalTokenCount`,
   or beside them?
2. Is `toolUsePromptTokenCount` counted *inside* `promptTokenCount`, or beside it?

The published `GenerateContentResponse.UsageMetadata` describes each counter's meaning
but does not state the arithmetic relationship between them. A hand-written test
fixture cannot settle this — it can only encode whichever answer its author assumed.
So one real tool-turn conversation and a set of surrounding turns were captured off the
live API and the arithmetic was read off the wire.

## The measured identity

Across all seven recordings, with no exceptions:

```
totalTokenCount == promptTokenCount
                 + candidatesTokenCount
                 + thoughtsTokenCount
                 + toolUsePromptTokenCount
```

Encoded as `GEMINI_USAGE_ADDITIVE_TERMS` in `crates/busbar-llm-codec/src/gemini/mod.rs`.

| recording | prompt | candidates | thoughts | toolUse | sum | stated total |
|---|---:|---:|---:|---:|---:|---:|
| `resp_g2g_vertex_tool_call.json`         | 47 | 7 | 67 | – | 121 | 121 |
| `resp_g2g_vertex_tool_result.json`       | 137 | 19 | – | – | 156 | 156 |
| `resp_g2g_vertex_thinking.json`          | 42 | 146 | 372 | – | 560 | 560 |
| `resp_g2g_vertex_grounding.json`         | 18 | 89 | 83 | **32** | 222 | 222 |
| `stream_g2g_vertex_tool_call.sse`        | 47 | 7 | 94 | – | 148 | 148 |
| `stream_g2g_vertex_grounding.sse`        | 18 | 43 | 44 | – | 105 | 105 |
| `stream_g2g_vertex_grounding_search.sse` | 27 | 95 | 202 | – | 324 | 324 |

## Discrepancy 1 — `toolUsePromptTokenCount` is additive, not a sub-bucket

**busbar believed:** a slice of `promptTokenCount`. Stated in
`IrUsageDetail::tool_use_prompt_tokens` ("A SUB-BUCKET of the prompt total …, never an
addition"), in `billing-usage-units.md` and in `billing-unified.md`
(`tool_use_prompt_tokens ⊂ prompt`).

**The wire says:** additive. On `resp_g2g_vertex_grounding.json` the field is **32**
while the entire `promptTokenCount` is **18**. No slice can exceed the total it is a
slice of, so the question needs no appeal to any document. Independently, Google's own
`totalTokenCount` (222) reconciles only when the term is added: the other three sum to
190.

**Consequence for money.** busbar folded `prompt + candidates + thoughts` into
`IrUsage` and excluded the tool-use term from `billable_tokens`. A Gemini turn that
used a server-side tool was therefore under-counted by exactly
`toolUsePromptTokenCount` — 32 of 222 tokens, **14%**, on the recording above. This is
not a rounding artefact; it scales with server-side tool use.

**FIXED IN 1.6.0 (registered money change; owner ruling 2026-09-07, "Gemini billing
must be right in 1.6.0").** Google charges the term at the input rate, so the reader
adds it to `IrUsage::input_tokens`:

| | 1.5.5 | 1.6.0 |
|---|---:|---:|
| `input_tokens` (grounding recording) | 18 | **50** |
| `output_tokens` | 172 | 172 |
| `billable_tokens` | 190 | **222** (= Google's `totalTokenCount`) |

The same fold landed in `GeminiReader::recover_truncated_usage`, so a response too
large to reassemble bills like its buffered twin. The Gemini WRITER is the exact
inverse: the term rides inside `input_tokens` in the IR but sits beside
`promptTokenCount` on the wire, so it is subtracted back out of the reconstructed
prompt count and added into the synthesized `totalTokenCount`, which now reproduces
Google's own number. `IrUsageDetail::tool_use_prompt_tokens` keeps the attribution and
is still not a billable key of its own, so the tokens are counted exactly once.

Registered in `testing/shadow-oracle/accepted-differences.json` with the CHANGELOG
line; pinned by `crates/busbar-llm-codec/src/gemini/tests/usage_identity_tests.rs`.

**The cross-check stays — as a metric, not a correction.** With all four terms billed,
`gemini_usage_identity_note` can fire only when Google states a `totalTokenCount` that
`GEMINI_USAGE_ADDITIVE_TERMS` cannot reach: a counter this dialect does not model yet,
whose answer is a new recording and a new table entry. It surfaces `reported_total`,
`summed_total`, `unaccounted`, `identity` plus a `tracing::warn!` carrying
`wire_sum`/`unmodelled_term`. Nothing is zeroed, clamped or back-filled; the decoded
buckets are exactly as received.

## Discrepancy 2 — the streaming path omits the field entirely

`resp_g2g_vertex_grounding.json` (non-streaming, grounded) reports
`toolUsePromptTokenCount: 32`. Both grounded SSE recordings carry `groundingMetadata`,
so the same server-side tool ran — yet **neither reports the field on any frame**,
including the trailing usage-bearing one.

`crates/busbar-llm-codec/src/proto_stream.rs` assumes the opposite ("a streamed Gemini
egress reports `toolUsePromptTokenCount` only on the trailing usage-bearing chunk"). On
these recordings it never arrives at all, so a streamed grounded turn cannot even be
measured for the under-count its buffered twin exhibits. Whether Vertex is under-
reporting on the stream, or genuinely not charging tool-use tokens there, is not
answerable from the client side.

## Discrepancy 3 — an early SSE frame carries a counterless `usageMetadata`

The first frame of `stream_g2g_vertex_grounding.sse` is:

```
"usageMetadata": {"trafficType": "ON_DEMAND"}
```

The object is **present** with no token counters in it. A decoder that treats "the
`usageMetadata` key exists" as "usage has arrived" reads every counter as a defaulted
zero and may latch that as the turn's usage. This is why the identity cross-check
treats an absent `totalTokenCount` as *nothing to check* rather than as zero — the
alternative reports a discrepancy on every ordinary streaming turn.

## Discrepancy 4 — fields on the wire that the pinned spec does not carry

Observed on the live API and absent from the vendored schema's `usageMetadata` /
response shape: `trafficType`, `promptTokensDetails`, `candidatesTokensDetails`,
`toolUsePromptTokensDetails`, `createTime`, `responseId`, `thoughtSignature`,
`avgLogprobs`.

`toolUsePromptTokensDetails` is notable: it mirrors `promptTokensDetails` in shape
(`[{modality, tokenCount}]`) and, on the grounding recording, carries the same 32
tokens under `TEXT`. The per-modality `*TokensDetails` breakdowns have no IR carrier at
all today — a known gap already noted for the voice side in
`plane4-voice-dialect-landscape.md`.

Recorded in `testing/llm-conformance/named-gaps.json`.

## What could not be measured

**`cachedContentTokenCount`.** Exercising it needs a `cachedContents` resource created
and paid for out of band, and the minimum cacheable context for `gemini-2.5-flash` is
far larger than any prompt here. No recording exercises the field, so the decoder's
existing subtractive normalization (`input_tokens = promptTokenCount −
cachedContentTokenCount`) remains **unverified against real bytes** — it is asserted
only by hand-written fixtures. It was left exactly as found. This is the obvious next
recording to take.

## Related known gap — the truncated path (CLOSED in 1.6.0)

`GeminiReader::recover_truncated_usage` (`gemini/reader.rs`) mirrored `gemini_usage` for
prompt / cached / candidates / thoughts but never read `toolUsePromptTokenCount`. A
head-truncated Gemini body therefore billed 32 tokens less than its complete twin and
lost the tool-use attribution. It now reads the term, bills it into `input_tokens` and
carries it as attribution, exactly as the buffered path does
(`a_truncated_grounded_turn_bills_the_tool_use_term_too`).

Still open there: the recovery path runs no identity cross-check, because the isolated
tail object is not the full `IrUsage` the note is computed against. A truncated body
whose `totalTokenCount` disagrees with the modelled terms reports no discrepancy.
