<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# VENDOR RECORDINGS — real Gemini bytes off Vertex AI

Everything else under `golden/` is a busbar OUTPUT, blessed by
`BUSBAR_BLESS_GOLDEN=1` and asserted byte-for-byte. **Nothing in this directory is
blessable.** These are the vendor's own bytes, captured once off the live API. They
are evidence, not expectations: a test may read them and assert what busbar's decoder
makes of them, but no test may ever rewrite them. If one of these files changes, the
only honest reason is that it was re-captured — and then the identity table below has
to be re-derived, not edited to match.

## Provenance

| | |
|---|---|
| endpoint | `https://us-central1-aiplatform.googleapis.com/v1/projects/$PROJECT/locations/us-central1/publishers/google/models/gemini-2.5-flash` |
| methods | `:generateContent`, `:streamGenerateContent?alt=sse` |
| model | `gemini-2.5-flash` (`modelVersion` in every response confirms it) |
| region | `us-central1` |
| captured | 2026-09-07 |

Request bodies are exactly what was sent; response bodies and SSE frames are exactly
what came back. The `Authorization: Bearer` header was never written to disk — the
token was interpolated inline at the curl call site and appears in no file here.

`req_g2g_vertex_tool_result.json` replays the model turn from
`resp_g2g_vertex_tool_call.json` (including its `thoughtSignature`) and appends the
`functionResponse`, so the pair is one real two-turn tool conversation, not two
unrelated calls.

## Why these were captured

The Gemini dialect's usage decode could not tell, from the published spec alone,
whether `toolUsePromptTokenCount` is counted INSIDE `promptTokenCount`, or whether
`thoughtsTokenCount` is counted inside `candidatesTokenCount`/`totalTokenCount`. The
sum identity the cross-check relies on is different in each case, so the question was
settled by measurement rather than by reading.

## THE MEASURED IDENTITY

Across all seven recordings, without exception:

```
totalTokenCount == promptTokenCount
                 + candidatesTokenCount
                 + thoughtsTokenCount
                 + toolUsePromptTokenCount
```

| recording | prompt | candidates | thoughts | toolUse | sum | total |
|---|---:|---:|---:|---:|---:|---:|
| `resp_g2g_vertex_tool_call.json`             | 47 | 7 | 67 | – | 121 | 121 |
| `resp_g2g_vertex_tool_result.json`           | 137 | 19 | – | – | 156 | 156 |
| `resp_g2g_vertex_thinking.json`              | 42 | 146 | 372 | – | 560 | 560 |
| `resp_g2g_vertex_grounding.json`             | 18 | 89 | 83 | **32** | 222 | 222 |
| `stream_g2g_vertex_tool_call.sse`            | 47 | 7 | 94 | – | 148 | 148 |
| `stream_g2g_vertex_grounding.sse`            | 18 | 43 | 44 | – | 105 | 105 |
| `stream_g2g_vertex_grounding_search.sse`     | 27 | 95 | 202 | – | 324 | 324 |

Two facts fall straight out of that table, and both contradict something busbar
believed:

1. **`thoughtsTokenCount` is ADDITIVE, not a slice of `candidatesTokenCount`.** This
   is what the decoder already assumed, and the recordings confirm it.

2. **`toolUsePromptTokenCount` is ADDITIVE, not a slice of `promptTokenCount`.** The
   grounding row settles it with no interpretation required: `toolUse` is **32** while
   the entire `promptTokenCount` is **18**. A sub-bucket cannot be larger than the
   bucket. It is a fourth independent term, and Google's own `totalTokenCount` only
   reconciles when it is added.

## The consequence, recorded and NOT silently fixed

`IrUsageDetail::tool_use_prompt_tokens` is documented in `ir/types.rs` as "a
SUB-BUCKET of the prompt total, never an addition, so `billable_tokens` ignores it."
The recording proves that wrong. Because busbar drops the term, a Gemini turn that
used a server-side tool is under-counted by exactly `toolUsePromptTokenCount` (32 of
222 tokens — 14% — on the grounding recording here).

Correcting that changes what busbar bills, so it is NOT done here. It is a registered
money change and needs its own CHANGELOG line and owner sign-off. What this corpus
does is make the discrepancy impossible to keep missing: the decoder now REPORTS it
(see `IrUsageDetail::usage_note`) instead of reconciling silently against a total it
cannot reach.

## Discrepancy 2 — the streaming path omits the field entirely

`resp_g2g_vertex_grounding.json` (non-streaming) reports
`toolUsePromptTokenCount: 32`. `stream_g2g_vertex_grounding.sse` and
`stream_g2g_vertex_grounding_search.sse` are the SAME grounded shape and BOTH carry
`groundingMetadata`, yet neither reports the field on any frame, including the
trailing usage-bearing one. `proto_stream.rs` assumes it arrives "only on the trailing
usage-bearing frame"; on these recordings it never arrives at all.

## Discrepancy 3 — an early SSE frame carries a countless `usageMetadata`

The first frame of `stream_g2g_vertex_grounding.sse` is literally:

```
"usageMetadata": {"trafficType": "ON_DEMAND"}
```

The object is PRESENT with no token counters in it. A decoder that treats "the
`usageMetadata` key exists" as "usage has arrived" reads every counter as a defaulted
zero and can latch that as the turn's usage. The counts arrive only on the final
frame.

## Fields on the wire that the pinned public schema does not carry

Observed here, from the live API: `trafficType`, `promptTokensDetails`,
`candidatesTokensDetails`, `toolUsePromptTokensDetails`, `createTime`, `responseId`,
`thoughtSignature`, `avgLogprobs`. Recorded in
`testing/llm-conformance/named-gaps.json` where they are the reason a row would
otherwise fail against the vendor's own published schema.
