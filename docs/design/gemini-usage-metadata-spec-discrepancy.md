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

**Consequence for money.** busbar folds `prompt + candidates + thoughts` into
`IrUsage` and excludes the tool-use term from `billable_tokens`. A Gemini turn that
used a server-side tool is therefore under-counted by exactly
`toolUsePromptTokenCount` — 32 of 222 tokens, **14%**, on the recording above. This is
not a rounding artefact; it scales with server-side tool use.

**Not fixed here, deliberately.** Folding the term into `input_tokens` changes what
busbar bills. That is a registered money change requiring its own CHANGELOG entry and
owner sign-off, and it was not made unilaterally. What landed instead is a report: the
decoder cross-checks the billed figure against Google's stated `totalTokenCount` and
surfaces any shortfall on `IrUsageDetail::usage_identity_note`
(`reported_total`, `summed_total`, `unaccounted`, `identity`), plus a `tracing::warn!`.
Nothing is zeroed, clamped or back-filled; the decoded buckets are exactly as received.

**Open decision for the owner:** fold `toolUsePromptTokenCount` into `input_tokens`
(making busbar's total match Google's), or ratify the current under-count as intended.
The reporting field makes either choice explicit rather than accidental.

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

## Related known gap, unaddressed

`GeminiReader::recover_truncated_usage` (`gemini/reader.rs`) mirrors `gemini_usage` for
prompt / cached / candidates / thoughts but never reads `toolUsePromptTokenCount`, and
does not run the identity cross-check. A head-truncated Gemini body therefore loses the
tool-use attribution its complete twin carries, and reports no discrepancy. Out of
scope for this change; recorded here so it is not rediscovered from scratch.
