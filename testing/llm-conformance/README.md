# LLM spec conformance

The gate that checks busbar's LLM plane — every ingress dialect it speaks — against the
providers' **published, machine-readable** API specifications, the way `testing/mcp-conformance/`
and `testing/a2a-tck/` hold the MCP and A2A planes to their specs. Until this existed the only
LLM-plane checks were `qa/field-schemas/*.json` (hand-derived field lists) and the internal
goldens under `crates/busbar-llm/src/tests/proto/golden/`: busbar was compared with busbar,
never with what OpenAI, Anthropic, Google, AWS or Cohere say the wire looks like.

## What is checked

Input: a recording made by `testing/shadow-oracle/record.sh` (the same recordings the shadow
oracle diffs). For every LLM cell in `testing/shadow-oracle/cells.json` the rig writes **one
ledger row per cell × direction**, ids `<cell-id>#request` and `<cell-id>#response`:

| direction | what | against |
|---|---|---|
| `#request` | the bytes the oracle sent busbar (`raw/<cell>/request.body`, or rebuilt with `build-request.py`) | the ingress dialect's request schema — proves the harness speaks the spec, so a refusal on the response row is busbar's |
| `#response`, 2xx JSON | busbar's body | the dialect's response schema |
| `#response`, 2xx `text/event-stream` | every `data:` event, parsed per the SSE spec | the dialect's stream-event union (discriminated on `type` where the spec does) |
| `#response`, 2xx `application/vnd.amazon.eventstream` | every frame (both CRCs verified; `:event-type` must be a `ConverseStreamOutput` member) | the member's shape |
| `#response`, non-2xx | busbar's error body | the response the spec declares for that status at that path, else the dialect's error envelope; for Bedrock, the exception shape named by `x-amzn-errortype`/`__type`, which must be one Converse declares and whose defined HTTP code must match |

Plus wire rules the schema alone cannot say: a `stream: true` request answered as
`application/json` (`stream.content-type`), a non-JSON error body (`body.json`), OpenAI chat's
`data: [DONE]` sentinel placement (`sse.sentinel`).

A row is **PASS** (valid), **FAIL** (one or more violations, each a JSON pointer + rule — e.g.
`/choices/0 required: missing property 'logprobs'`, `sse[4]:/usage required ...`,
`frame[1](contentBlockStart):/start minProperties ...`), or **SKIP** (a named gap). The verdict is
`testing/fleet-fixtures/verdict.sh` with `GATE_NAME="llm spec conformance"`: zero rows is red, an
owed id with no row is red, a FAIL is red.

Output (`--out`, default `target/llm-conformance/<recording>/`): `ledger.tsv`, `report.json`,
`report.md` (per-dialect counts and every distinct violation, pointer generalized), `owed.txt`,
`owed-gaps.txt`, `validate.log`.

## The specs, pinned

`spec-digests.tsv` pins one public document per provider by URL and sha256; `vendor.sh`
fetches with curl into `~/.cache/busbar-llm-specs/<spec>/<digest>/` and **refuses on mismatch**
(exit 3, download deleted), exactly as `testing/shadow-oracle/fetch-golden.sh` pins the 1.5.5
binary. The documents are not vendored into the repository (about 7 MB); the digests are.

| spec | dialects | document |
|---|---|---|
| openai | `openai` (chat completions), `responses` | `openai/openai-openapi` `openapi.yaml` at a pinned commit |
| anthropic | `anthropic` | the OpenAPI document Anthropic publishes through Stainless, at the content-addressed URL the official SDK pins in `anthropic-sdk-python/.stats.yml` |
| gemini | `gemini` | the `generativelanguage` v1beta discovery document (digest of the canonicalized JSON: Google varies key order per request) |
| bedrock | `bedrock` | botocore `bedrock-runtime/2023-09-30/service-2.json` at a pinned commit (Converse, ConverseStream, the event union, the exceptions) |
| cohere | `cohere` | `cohere-ai/cohere-developer-experience` `cohere-openapi.yaml` at a pinned commit |

To move a pin: `vendor.sh --repin <spec>` prints the row for the current upstream document;
paste it in and read what changed in the report before trusting it.

## What is a named gap (SKIP)

A SKIP is never a pass. It is printed with `::warning ... DID NOT VERIFY`, listed in
`owed-gaps.txt`, and removed from the owed set so the verdict can still judge the rows that exist.
The gaps that exist today:

* **Gemini error bodies.** The discovery document does not describe error responses. They are
  checked against `schemas/google-rpc-status.json`, a hand transcription of `google.rpc.Status`
  as the REST mapping wraps it; those rows say `transcribed google.rpc.Status (not a fetched
  spec)` in their title. This is the one check that is not against a fetched document.
* **Anthropic 5xx.** The spec declares only a `4XX` response for `/v1/messages`; a 5xx body is
  checked against the same `ErrorResponse` envelope (row title says `fallback envelope`).
* **A cell the recorder could not record** (its `ledger.tsv` says SKIP/FAIL) or that is in
  `cells.json` but absent from the recording: both directions SKIP with the recorder's reason.
* **A Bedrock event stream in a normalized-only cell.** The normalizer decodes the binary frames
  lossily; when `raw/<cell>/body` is absent the row SKIPs rather than judge mangled bytes.
* **The `#request` row of `malformed` cells** is not owed: that request is non-JSON by design.

Known spec-vs-docs discrepancy, reported as FAIL on purpose: Anthropic's published
`MessageStreamEvent` union has no `ping` member although the docs say `ping` events may occur.
1.5.5 emits `event: ping` in cross-protocol streams and the row fails the published union.
Decided 2026-09-04: `ping` stays — it is a documented event that real Anthropic streams carry, and
a client that cannot take it is not an Anthropic client. The row is a NAMED GAP of the published
spec (recorded here, not special-cased in the validator); it is re-judged whenever the pinned
spec is re-pinned, and disappears the day the union gains the member.

## Running it

```
testing/llm-conformance/selftest.sh                 # proves the rig cannot pass vacuously
testing/llm-conformance/run.sh --recording target/oracle/recordings/candidate
testing/llm-conformance/run.sh --recording target/oracle/recordings/golden   # what 1.5.5 does
```

`validate.py` is stdlib Python; the two YAML specs (openai, cohere) need PyYAML ≥ 6.0 the first
time they are parsed, after which the parsed document is cached as JSON beside the spec. The
checker is a small JSON-schema subset (`type`, `const`, `enum`, `required`, `properties`,
`additionalProperties`, `patternProperties`, `items`, `min/max*`, `pattern`, `allOf/anyOf/oneOf/not`,
`nullable`, `discriminator`) written here on purpose: a verdict must not move because a validator
package changed its mind. Discovery documents and botocore models are converted to that subset
with **closed** objects (a field the provider's proto does not name is one the provider rejects).

## Adding a dialect

1. Add the document to `spec-digests.tsv` (format `raw` or `json-canonical`) and run `vendor.sh`.
2. In `validate.py`: map the dialect to its spec in `DIALECT_SPEC`; add an entry to `DIALECTS`
   with the request, response and stream-event schema addresses (`#/...` refs into the document),
   `stream_kind` (`sse` or `eventstream`), the OpenAPI `path` (error responses are derived from
   its declared statuses) and the fallback `error` envelope. A new document format needs a
   converter like `botocore_to_schema` / `discovery_to_schema`.
3. Make sure `testing/shadow-oracle/cells.json` and `build-request.py` know the dialect; the owed
   set is derived from `cells.json`, so nothing here needs enumerating.
4. Run `selftest.sh`; if the dialect needs its own known-good fixture cell, add it to
   `fixtures/selftest-recording/` (three 1.5.5 cells today: cohere ok, cohere ok_stream, gemini ok).

## Proposed CI job (FAST tier)

Not applied to `.github/workflows/ci.yml` here. It depends on the `shadow-oracle` job's
`candidate` recording (uploaded as an artifact there, or run in the same job after `record.sh`);
the block below assumes the same-job form, appended after the candidate recording step. Specs
are cached by the digest file's own hash, so a re-pin is the only thing that invalidates it.

```yaml
      # ── LLM spec conformance: busbar's LLM wire vs the providers' published specs. FAST tier,
      # same as shadow-oracle: it reads the candidate recording that job already made. RED on any
      # schema violation, any owed row missing, or zero rows.
      - name: Cache provider specs (by pinned digest)
        uses: actions/cache@v4
        with:
          path: ~/.cache/busbar-llm-specs
          key: llm-specs-${{ hashFiles('testing/llm-conformance/spec-digests.tsv') }}
      - name: LLM spec conformance — selftest (the rig cannot pass vacuously)
        run: bash testing/llm-conformance/selftest.sh
      - name: LLM spec conformance — candidate vs published specs
        run: bash testing/llm-conformance/run.sh --recording target/oracle/recordings/candidate --out target/llm-conformance/candidate
      - name: LLM spec conformance — 1.5.5 reference (informational; where the baseline deviates)
        if: always()
        continue-on-error: true
        run: bash testing/llm-conformance/run.sh --recording target/oracle/recordings/golden --out target/llm-conformance/golden
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: llm-conformance-report
          path: target/llm-conformance/
```

If it is its own job instead, add `llm-conformance` to the `needs:` of the umbrella verdict job
and to `testing/verdict-covers-every-leg.py`'s expectations, and download the
`shadow-oracle-report`-style artifact that carries the recording.
