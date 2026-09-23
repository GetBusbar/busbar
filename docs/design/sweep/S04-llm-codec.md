# S04-llm-codec — sweep verdicts

Slice: `crates/busbar-llm-codec` — the six LLM dialect codecs (anthropic, openai-chat, gemini,
bedrock, openai-responses, cohere), the concrete chat + leaf-op IR, the stream translator and the
answer-normalization pass. **112 files.** X-id block **X-1300 .. X-1399**.

A DIALECT LIVES INSIDE A PLANE. It is not a plugin and not a kind, so the question asked of every
file here was not "does it register?" but "is the wire this file writes the wire 1.5.5 wrote, and is
every half of every pair still attached to its other half?"

Read-and-report only. No source edited. **No billed byte self-approved** — every money row is `PARK`
with the cell, the diff against the seam that exists to prevent it, the root cause and a
recommendation.

## Reachability, established once for the whole slice
* Crate is a workspace member (`grep -n busbar-llm-codec Cargo.toml` -> `:10`) with three
  dependents (`busbar-llm`, `busbar-substrate-values`, `busbar-plane-llm`).
* **34/34 non-test source files are module-declared** — scanner walked every `mod X;` in
  `src/` and matched each slice file to its declaring parent; 0 unmatched (only `lib.rs`, which is
  the `[lib] path`).
* **77/77 test files are `#[path]`-declared** — same scanner over every `#[path = "..."] mod`;
  0 undeclared.
* **1,455 `#[test]` fns**, 1 `#[ignore]` (a documented `--release` benchmark,
  `tests/proto/same_proto_fidelity_tests.rs:171-173`). A refined brace-matched scan for
  assertion-free non-`should_panic` tests returned 0 after correcting for helper asserts
  (`assert_ir_parse_reject`, `check_golden`, `assert_identity`, `assert_request_roundtrip`).
* Golden denominator checked, not assumed: the 84 golden names
  `tests/proto/translate_parity_cross_pairs_tests.rs` can emit were expanded from its 11 corpora and
  diffed against `src/tests/proto/golden/` -> **0 missing**; `check_golden` **panics** on a missing
  golden (`:76-77`), so the instrument can go red.
* The field-coverage gate's instruments live here: **all 97 distinct `carried <test_fn>` names in
  `qa/field-coverage.status` resolve to functions in this slice's 8 carry files** (cross-check ->
  0 missing).

## The zeros in this report carry controls
`--include='*.rs'` is quoted everywhere (unquoted, zsh glob-eats it and the command dies rc=1 with
no output — it fired twice during this sweep). One measured false zero is recorded rather than
hidden: `grep -E "(^|[^A-Za-z0-9_])NAME([^A-Za-z0-9_]|$)"` returns **rc=1 on a file that provably
contains `NAME`**, because BSD ERE treats `^` inside an alternation group as a literal. Every
`-> 0` below is paired with the same command shaped to return non-zero on something known to exist.

| FILE | VERDICT | EVIDENCE | ROWS |
| --- | --- | --- | --- |
| `crates/busbar-llm-codec/Cargo.toml` | FINDING | Workspace member: `grep -n busbar-llm-codec Cargo.toml` -> `:10`; dependents `grep -rln busbar-llm-codec --include='Cargo.toml' crates/` -> busbar-llm, busbar-substrate-values, busbar-plane-llm. `openapi-schema` is declared-but-empty AND consumed: `grep -rn 'busbar-llm-codec/openapi-schema' crates/` -> `busbar-llm/Cargo.toml:58` (so the empty declaration is required, not dead). `timing` is NOT what the manifest says: per-dialect `grep -rn 'timeit!' <dialect>/` -> anthropic 0, bedrock 4, cohere 4, gemini 0, openai_chat 0, openai_responses 0. | X-1314 |
| `crates/busbar-llm-codec/src/anthropic/handler.rs` | CLEAN | Read 59/59. `AnthropicRequestHandler` is reached via `anthropic::DECL.handler`; `CELLS` declares one verb and `DECL.verbs` declares one — matched by `registry_tests.rs:116` (declared==served). `PATH_MESSAGES` single-sources `upstream_path` and `resolve_operation`. | - |
| `crates/busbar-llm-codec/src/anthropic/tests/field_carry_tests.rs` | CLEAN | declared by `src/anthropic/mod.rs`; `grep -c '#[test]'` -> 20 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 108 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 9 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/anthropic/tests/handler_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/anthropic.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/anthropic/handler.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 8 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/anthropic/tests/input_hardening_tests.rs` | CLEAN | declared by `src/anthropic/mod.rs`; `grep -c '#[test]'` -> 7 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 9 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/anthropic/tests/reasoning_carry_tests.rs` | CLEAN | declared by `src/anthropic/mod.rs`; `grep -c '#[test]'` -> 11 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 33 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/anthropic/tests/usage_float_tests.rs` | CLEAN | declared by `src/anthropic/mod.rs`; `grep -c '#[test]'` -> 5 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 22 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/anthropic/tests/user_and_parallelism_carry_tests.rs` | CLEAN | declared by `src/anthropic/mod.rs`; `grep -c '#[test]'` -> 8 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 30 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/anthropic/writer.rs` | FINDING | Read 933/933. `:255-258` states 'DELIBERATE DIVERGENCE from the 1.5.5 golden: 1.5.5 DROPPED `response_format` here ... Emitting the tool + tool_choice changes the upstream request bytes ON PURPOSE.' Confirmed against the released tree: `diff <(git show v1.5.5:crates/busbar/src/proto/anthropic/writer.rs) writer.rs` shows the 1.5.5 arm was `if req.response_format.is_some() { warn!("dropping response_format ...") }` and is now a synthesized tool + forced `tool_choice`. The comment asserts an owner report; a sweep cannot verify a sign-off, so it is PARKed rather than blessed. | X-1322 |
| `crates/busbar-llm-codec/src/bedrock/handler.rs` | FINDING | Read 594/594. `read_embeddings_response` (`:531-538`) bills through `.and_then(read_count_u64)` (silent zero on unreadable) while the sibling leaf handlers use `billed_count`. `BedrockImage::taps_usage()->true` (`:152`) with a comment claiming it 'closes the same-protocol metering gap', but the default `extract_usage` path is `read_response(..).token_usage()` and `IrHandle::token_usage` (`substrate-values/src/ir/handle.rs:112-116`) returns `Some` only for `Billing::Tokens` — `ImageResp::billing()` (`ir/image.rs:193`) yields `Billing::Images`, so the tap returns `None`. `BedrockRerank` declares no `taps_usage` at all. | X-1300, X-1302 |
| `crates/busbar-llm-codec/src/bedrock/mod.rs` | CLEAN | Read 1930/1930. `DECL` fields all consumed; `error_kind_to_bedrock_type` covers every live `KIND_*` constant and falls back to a real AWS exception name. `BedrockConverseBodyTranslator` is installed via `same_protocol_buffered_response_translator` and its over-cap arm applies the shared `TRUNCATED_TAIL_BYTES_PER_TOKEN` floor with `.max(1)` (never bills zero). `derive_sigv4_region` accepts >=3-part region tokens (GovCloud/ISO) — the bug it documents is fixed here; the remaining fallback is in writer.rs (X-1311). | - |
| `crates/busbar-llm-codec/src/bedrock/reader.rs` | FINDING | Billed totals at `:1149-1156` (stream) and `:1374-1381` (buffered) read `inputTokens`/`outputTokens` through `.and_then(read_count_u64).unwrap_or(0)` — a present-but-unreadable count bills ZERO, where `usage_count::billed_count` (`usage_count.rs:116`, 'UNREADABLE IS A REFUSAL (#42: money-sacred, never a silent 0)') exists for exactly this. `grep -rn -w billed_count $(cat nontest)` -> 0 hits in this file (control: the same grep finds 10 hits in the leaf-op handlers). | X-1300 |
| `crates/busbar-llm-codec/src/bedrock/tests/field_carry_tests.rs` | CLEAN | declared by `src/bedrock/mod.rs`; `grep -c '#[test]'` -> 22 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 80 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 22 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/bedrock/tests/handler_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/bedrock.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/bedrock/handler.rs`; `grep -c '#[test]'` -> 9 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 19 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/bedrock/tests/input_hardening_tests.rs` | CLEAN | declared by `src/bedrock/mod.rs`; `grep -c '#[test]'` -> 6 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 8 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/bedrock/tests/tests.rs` | CLEAN | declared by `src/bedrock/mod.rs`; `grep -c '#[test]'` -> 140 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 517 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/bedrock/tests/titan_roundtrip_regression_tests.rs` | CLEAN | declared by `src/bedrock/handler.rs`; `grep -c '#[test]'` -> 6 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 16 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/bedrock/tests/usage_float_tests.rs` | CLEAN | declared by `src/bedrock/mod.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 12 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/bedrock/writer.rs` | FINDING | `sigv4_sign_headers` (`:31`): every other un-signable input returns `vec![]` (`:38` malformed key, `:54` un-encodable session token, `:104` un-encodable header) but an underivable region falls back to a hardcoded `"us-east-1"` (`:41-46`) and signs anyway. `dropped_egress_controls` (`:187-199`) pushes 2 controls and its doc says 'mirrors the TWO write_request warns'; `grep -n` over `write_request` finds FOUR drop-warns — `reasoning` (`:206`) and `parallel_tool_calls` (`:716`) are warned but never audited (control: `grep -rn 'dropped.push("seed")'` -> anthropic/writer.rs:146, openai_responses/writer.rs:40, dialects that do audit theirs). `:958` cites `proto/mod.rs`; `grep -rn 'pub struct StreamTranslate' crates/` -> `proto_stream.rs:24`. | X-1311, X-1312, X-1318 |
| `crates/busbar-llm-codec/src/chat_handle.rs` | CLEAN | Read 578/578. Every gate in `chat_prepare_for_egress` has a reachable false branch. `chat_usage` delegates to `IrUsage::to_token_usage` (the one projection) — pinned by `tests/proto/billing_parity_tests.rs:219-252`, which drives Cohere `billed_units` 120/50 against raw 100/40 and asserts buffered==streamed. `ChatRespHandle` deliberately does NOT override `fill_response_model_if_absent` and says why. | - |
| `crates/busbar-llm-codec/src/cohere/mod.rs` | FINDING | `ET_CITATION_START`/`ET_CITATION_END` declared at `:315,:320`. `grep -c -E 'ET_CITATION_START|ET_CITATION_END|citation-start|citation-end' cohere/reader.rs` -> 0 (positive control `grep -c -E 'ET_CONTENT_DELTA|ET_TOOL_CALL_START' cohere/reader.rs` -> 2). `grep -rn -w -e ET_CITATION_START -e ET_CITATION_END crates/busbar-llm-codec/src/ | grep -v _tests` -> writer-only (`cohere/writer.rs:708,900`). Doc drift: `:143`,`:649` cite `openai_chat.rs`/`anthropic.rs`/`gemini.rs`; `find . -name 'openai_chat.rs' -o -name 'anthropic.rs' -o -name 'gemini.rs'` -> no output (control: `grep -n 'openai_chat/reader.rs' cohere/mod.rs` -> `:599`, a path that does resolve). | X-1307, X-1318 |
| `crates/busbar-llm-codec/src/cohere/tests/egress_media_regression_tests.rs` | CLEAN | declared by `src/cohere/mod.rs`; `grep -c '#[test]'` -> 1 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 3 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/cohere/tests/field_carry_tests.rs` | CLEAN | declared by `src/cohere/mod.rs`; `grep -c '#[test]'` -> 10 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 60 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 9 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/cohere/tests/input_hardening_tests.rs` | CLEAN | declared by `src/cohere/mod.rs`; `grep -c '#[test]'` -> 6 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 8 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/cohere/tests/rerank_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/cohere.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/cohere/handler.rs`; `grep -c '#[test]'` -> 20 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 45 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/cohere/tests/tests.rs` | CLEAN | declared by `src/cohere/mod.rs`; `grep -c '#[test]'` -> 115 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 423 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 1 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/cohere/writer.rs` | FINDING | Emits `ET_CITATION_START` (`:708`) and `ET_CITATION_END` (`:900`) on the stream the cohere reader has no arm for (see X-1307). `:424` cites `ir/variant.rs`; `find . -name 'variant.rs' -not -path './target/*'` -> no output (control `find . -path '*/ir/*.rs'` -> 8 files). 10 `tracing::warn` drop-with-warn sites; `grep -c 'unwrap_or(0)' cohere/writer.rs` -> 0. | X-1307, X-1318 |
| `crates/busbar-llm-codec/src/gemini/handler.rs` | FINDING | All 16 `pub fn` dispatched from `leaf_codec.rs` (lines 36,48,76,86,95,104,113,122,161,179,226,243,258,274,289,305). `write_embeddings_response` (`:533-545`) never serializes `r.usage`: `sed -n '533,545p' | grep -c usage` -> 0 (control: the openai twin `openai_chat/handler.rs:672-697 | grep -c usage` -> 2; cohere `handler.rs:231` and bedrock `handler.rs:308` both emit it). `read_embeddings_response` (`:999-1007`) uses `.and_then(read_count_u64)` where `:673,675,901,903` in the SAME file use the refuse-don't-zero `billed_count`. `GeminiTranscription`/`GeminiSpeech` declare no `taps_usage` (`grep -n 'impl OperationHandler for\|fn taps_usage' gemini/handler.rs` -> 4 impls, 2 overrides). | X-1300, X-1302, X-1310, X-1315 |
| `crates/busbar-llm-codec/src/gemini/reader.rs` | FINDING | `recover_truncated_usage` (`:32-53`) builds `IrUsageDetail{reasoning_tokens, tool_use_prompt_tokens}` then calls `.to_token_usage()`; `busbar-substrate-values/src/billing.rs:32-45` shows `TokenUsage` has no such member, so the attribution is discarded (totals survive). Primary billed totals at `:32-41` read `.and_then(read_count_u64).unwrap_or(0)` (2 sites) rather than `billed_count`. Drift: `:899` cites `(~793-802)` which is the `IrRequest` literal (real site `:1297-1314`); `:107` claims 'the substring set mirrors `classify()`' — `extract_error` has 4 alternatives + a 400/413 gate (`:120-129`), `classify` has 2 and no gate (`:236-240`); `:839-840` cite `bedrock.rs`/`cohere.rs` (`find . -name bedrock.rs -o -name cohere.rs` -> no output). | X-1300, X-1316, X-1318 |
| `crates/busbar-llm-codec/src/gemini/tests/field_carry_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 16 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 92 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 16 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/gemini/tests/float_usage_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 7 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 21 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/tests/handler_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/gemini.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/gemini/handler.rs`; `grep -c '#[test]'` -> 43 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 83 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/gemini/tests/image_url_mime_regression_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 4 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/tests/input_hardening_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 5 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 7 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/tests/logprobs_carry_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 10 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 37 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/tests/tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 180 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 485 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/tests/usage_identity_tests.rs` | CLEAN | declared by `src/gemini/mod.rs`; `grep -c '#[test]'` -> 11 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 41 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/gemini/writer.rs` | FINDING | Drift only: `:442` cites `ir/variant.rs` (`find . -name 'variant.rs' -not -path './target/*'` -> no output; the stripper is `chat_handle.rs:346`); `:740` cites `auth.rs::auth_failure_status_and_kind` (real home `busbar-substrate-values/src/proxy/mod.rs:398`); `:1303` cites `src/proto/mod.rs::test_gemini_read_write_response_roundtrip` (real home `src/tests/proto/gemini_tests.rs:68`). Money scan: 12 `saturating_`/`checked_`, 0 `f64` on a billed quantity. | X-1318 |
| `crates/busbar-llm-codec/src/ir_encode.rs` | CLEAN | Read 138/138. All 6 `pub fn` have non-test callers (`warn_dropped_tool_strict` -> anthropic/bedrock/cohere/gemini writers; `ping_request` -> all six `probe_request`; `image_url_from_ir`/`parse_image_url` -> chat+responses codecs). `ping_request` spells every `IrRequest` field explicitly, so a new field is a compile error here. | - |
| `crates/busbar-llm-codec/src/ir/audio.rs` | FINDING | Read 258/258. `grep -rn --include='*.rs' -w timestamp_granularities .` outside `ir/` and `*_tests.rs` -> 0 hits (positive control `aspect_ratio` same command -> 2 hits in `gemini/handler.rs`). `TimestampGranularity::{Word,Segment}` carry `#[allow(dead_code)]` and their own 'no 1.5.0 reader constructs this'. `SpeechReq::billing` is the sole producer of `Billing::Characters` workspace-wide (`grep -rn 'Billing::Characters' $(git ls-files '*.rs')` -> 1 production site, `:176`). | X-1301, X-1304 |
| `crates/busbar-llm-codec/src/ir/embeddings.rs` | CLEAN | Read 196/196. Field scan outside `ir/`: every field has a producer or consumer (`input_type` -> cohere/handler.rs, `task_type`/`title` -> gemini/handler.rs, `priority` -> anthropic/mod.rs, `object_kind`/`input_echo` -> openai/cohere handlers). `EmbInput::{Tokens,Images}` carry `#[allow(dead_code)]` with a stated reason. | - |
| `crates/busbar-llm-codec/src/ir/facts_impl.rs` | CLEAN | Read 202/202. The block walk has NO catch-all arm, so a new `IrBlock` variant is a compile error (`:193-195` states this). The empty-turn rule is exercised; `author_of` is pinned byte-identical by `role_label_is_byte_identical_to_the_seam` (`grep -rn 'role_label_is_byte_identical_to_the_seam' $(git ls-files '*.rs')` -> the test exists). | - |
| `crates/busbar-llm-codec/src/ir/image.rs` | FINDING | Read 204/204. Per-field scan outside `ir/` and `*_tests.rs` (`grep -rn --include='*.rs' -w <field> . | grep -v '^ir/' | grep -v _tests`): `mask_prompt`, `input_images`, `add_watermark`, `output_uri`, `weighted_prompts`, `ImageResp.warnings` -> 0 hits each; `steps`/`strength`/`mask` -> comment-only hits. Positive controls in the same command: `aspect_ratio` -> 2, `background` -> 6 (real reads at `openai_chat/handler.rs:770,1388`). Denominator check: `python3` over `qa/field-inventory.json` -> 412 fields, prefixes are the 12 `<chat-dialect>/{request,response}` only; `ids containing 'embeddings'/'rerank'/'moderation'/'transcription'` -> 0 (control `messages` -> 18). | X-1303, X-1305 |
| `crates/busbar-llm-codec/src/ir/mod.rs` | CLEAN | Read 34/34. Declaration hub only. All 7 submodules + `types`/`facts_impl` resolve to files on disk; `pub use types::*` keeps the pre-split paths. | - |
| `crates/busbar-llm-codec/src/ir/moderation.rs` | CLEAN | Read 104/104. `ModerationResp` carries no `billing()` and `ModerationRespHandle::billing()` returns `Some(Billing::Flat)` — the module header says exactly that, so the pair agrees. Every field has a reader/writer in `openai_chat/handler.rs`. | - |
| `crates/busbar-llm-codec/src/ir/rerank.rs` | CLEAN | Read 107/107. `RerankResp::billing()` -> `Billing::Flat`, matching the header. `search_units` is populated by the cohere reader and merged by `proto_stream.rs:1519-1521`; `RerankResult.document` is emitted by both rerank writers (`bedrock/handler.rs:375`, cohere). | - |
| `crates/busbar-llm-codec/src/ir/tests/audio_tests.rs` | FINDING | Module header cites `crates/busbar/src/ir/audio.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/ir/audio.rs`; `grep -c '#[test]'` -> 9 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 19 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/ir/tests/embeddings_tests.rs` | FINDING | Module header cites `crates/busbar/src/ir/embeddings.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/ir/embeddings.rs`; `grep -c '#[test]'` -> 6 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 18 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/ir/tests/facts_tests.rs` | CLEAN | declared by `src/ir/facts_impl.rs`; `grep -c '#[test]'` -> 16 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 39 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/ir/tests/image_tests.rs` | FINDING | Module header cites `crates/busbar/src/ir/image.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/ir/image.rs`; `grep -c '#[test]'` -> 4 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 12 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/ir/tests/moderation_tests.rs` | FINDING | Module header cites `crates/busbar/src/ir/moderation.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/ir/moderation.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 12 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/ir/tests/rerank_tests.rs` | FINDING | Module header cites `crates/busbar/src/ir/rerank.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/ir/rerank.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 7 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/ir/tests/tests.rs` | CLEAN | declared by `src/ir/mod.rs`; `grep -c '#[test]'` -> 12 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 48 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/leaf_codec.rs` | CLEAN | Read 341/341. Every write dispatcher arm names a `pub fn` that exists in that dialect's handler; the 12 read dispatchers are `#[cfg(any(test, feature = "test-support"))]` and documented as test-only, so their `NO-NONTEST-USE` result is by declaration, not by accident. The `unreachable!` fallbacks are exercised by `tests/leaf_write_dispatch_tests.rs` (`#[should_panic]`). | - |
| `crates/busbar-llm-codec/src/leaf_handles.rs` | FINDING | Read 449/449. All 12 handles are constructed by their dialect cells. `SpeechReqHandle::billing()` (`:391-393`) is the ONLY request-side `billing()` override in the crate; `grep -rn 'billing()' $(git ls-files '*.rs') | grep -v busbar-llm-codec` -> 3 hits, all `substrate-values/src/handlers.rs:439,454` (both inside `translate_response`, reading a RESPONSE handle) and the trait default. So it is never invoked in production. | X-1301 |
| `crates/busbar-llm-codec/src/lib.rs` | FINDING | Read 225/225. All 18 `pub mod`/`pub` items resolve; `DECLS` order pinned by `registry_tests.rs:47`. `PLANE_KEY` claims to be the one literal the composition-root flip and `capability_key` share, but `grep -rn 'PLANE_DECL\.key' crates/` -> `busbar/src/root/gauntlet_install.rs:73` uses `busbar_llm::PLANE_DECL.key`, a SECOND literal at `busbar-llm/src/lib.rs:222` (`key: "llm"`). No test pins them equal: `grep -rn PLANE_KEY crates/ | grep -i 'assert'` -> hits only for plane-a2a/plane-mcp (`tests/meta.rs:13`), never LLM. | X-1313 |
| `crates/busbar-llm-codec/src/openai_annotations.rs` | FINDING | Read 201/201. `read_url_annotations` (`:188-198`) hardcodes `cited_text: None, start_index: None, end_index: None`; `citation_span` (`:110-139`) returns `None` for exactly that input; `url_annotations` (`:49-51`) `continue`s the whole citation when the span is `None`. `grep -rn 'url_annotations\|chat_url_annotations' --include='*.rs' .` -> `url_annotations` is called ONLY by `openai_responses/writer.rs:130,1106,1420`; `chat_url_annotations` (which keeps a span-less citation) only by `openai_chat/writer.rs:648,1014`. Duplicated comment line at `:170-171`. | X-1306 |
| `crates/busbar-llm-codec/src/openai_chat/handler.rs` | FINDING | `grep -n 'impl OperationHandler for\|fn taps_usage' openai_chat/handler.rs` -> 5 impls (247 Transcription, 534 Speech, 600 Embeddings, 706 Image, 831 Moderation), 2 overrides (613, 721). `parse_transcription_usage` (`:494`) is refusal-grade (reads `/usage/seconds` from raw bytes, `CodecError::Malformed` on an unreadable count) and is wired at `:1102-1105`, but with `taps_usage()==false` (default at `substrate-values/src/handlers.rs:150`) the same-protocol body is never buffered so it is never reached. `PATH_RERANK` (`:27`) is used only as the self-documented unreachable fallback at `:76`. `:1340` cites `handlers/openai.rs:79`; `find . -name 'openai.rs' -not -path './target/*'` -> no output. | X-1300, X-1302, X-1315, X-1318 |
| `crates/busbar-llm-codec/src/openai_chat/mod.rs` | FINDING | Read the DECL + helper surface. `openai_writer()` and `openai_classify()` are `#[cfg(test)] pub(crate)` (`:1352,:1394`) — correctly gated, not dead ship surface. `OPENAI_FAMILY_MAX_OPEN_TOOLS` is consumed by `proto_codec.rs:1128`. Drift: `:246` cites `ir/variant.rs`, which does not exist (`find . -name 'variant.rs' -not -path './target/*'` -> no output). | X-1318 |
| `crates/busbar-llm-codec/src/openai_chat/tests/audio_format_regression_tests.rs` | CLEAN | declared by `src/openai_chat/mod.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 4 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_chat/tests/field_carry_tests.rs` | CLEAN | declared by `src/openai_chat/mod.rs`; `grep -c '#[test]'` -> 8 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 78 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 8 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/openai_chat/tests/float_usage_tests.rs` | CLEAN | declared by `src/openai_chat/mod.rs`; `grep -c '#[test]'` -> 9 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 32 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_chat/tests/handler_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/openai.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/openai_chat/handler.rs`; `grep -c '#[test]'` -> 39 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 103 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/openai_chat/tests/input_hardening_tests.rs` | CLEAN | declared by `src/openai_chat/mod.rs`; `grep -c '#[test]'` -> 7 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 9 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_chat/tests/speech_mime_regression_tests.rs` | CLEAN | declared by `src/openai_chat/handler.rs`; `grep -c '#[test]'` -> 5 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 8 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_chat/tests/tests.rs` | CLEAN | declared by `src/openai_chat/mod.rs`; `grep -c '#[test]'` -> 163 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 483 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_chat/writer.rs` | FINDING | `grep -n 'usage\.detail\.' openai_chat/writer.rs` -> the STREAM leg (`write_response_event`, `:763`) emits `reasoning_tokens` ONLY; the buffered leg (`:1129,1145,1148,1151,1157`) emits five. `grep -n 'input_audio_tokens\|accepted_prediction_tokens' openai_chat/reader.rs` -> `:959,963,967,971` inside `read_response_events` (`:594`), so the STREAM reader populates all four, and `proto_stream.rs:1508-1517` merges them onto the terminal delta. Dead branch: `:1086-1088` `if let Some(ref fp) = resp.system_fingerprint` — `grep -rn '\.write_response(' $(cat nontest)` -> exactly 2 production sites (`chat_handle.rs:412`, `busbar-plane-llm/src/plane.rs:782`), each preceded by `chat_prepare_for_ingress`, which sets `ir.system_fingerprint = None` (`chat_handle.rs:304`). `:470` cites `ir/variant.rs`. | X-1309, X-1315, X-1318 |
| `crates/busbar-llm-codec/src/openai_responses/handler.rs` | CLEAN | Read 42/42. Same shape as the anthropic handler: one `Operation::CHAT` cell, `PATH_RESPONSES` single-sourced across both sides, no unreachable fallback (unlike `openai_chat/handler.rs:76`). | - |
| `crates/busbar-llm-codec/src/openai_responses/reader.rs` | FINDING | Billed totals at `:1215-1224` and `:1576-1585` read `.and_then(read_count_u64).unwrap_or(0)`; at `:1215-1220` the zero then survives `.saturating_sub(cached)` while `cache_read_input_tokens` still carries the real count. `grep -rn -w billed_count $(cat nontest) | grep -v usage_count.rs` -> 10 hits, ALL in gemini/openai_chat HANDLERS, none in any reader (control: same command for `read_count_u64` -> 112 hits). Empty `else if` at `:838-841` (`sed -n '838,841p'`). Self-contradicting comment: `:608-609` 'text is added to the modeled keys below' vs `:618` 'NOTE: `text` is NOT in the modeled-keys set' vs `:632` 'even though `text` is listed as modeled'. | X-1300, X-1315, X-1318 |
| `crates/busbar-llm-codec/src/openai_responses/tests/field_carry_tests.rs` | CLEAN | declared by `src/openai_responses/mod.rs`; `grep -c '#[test]'` -> 34 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 124 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 16 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/openai_responses/tests/float_usage_tests.rs` | CLEAN | declared by `src/openai_responses/mod.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 11 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_responses/tests/handler_tests.rs` | FINDING | Module header cites `crates/busbar/src/handlers/responses.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/openai_responses/handler.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 7 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/openai_responses/tests/input_hardening_tests.rs` | CLEAN | declared by `src/openai_responses/mod.rs`; `grep -c '#[test]'` -> 10 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 10 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_responses/tests/tests.rs` | CLEAN | declared by `src/openai_responses/mod.rs`; `grep -c '#[test]'` -> 165 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 735 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/openai_responses/writer.rs` | FINDING | `grep -c '"refusal"' openai_responses/writer.rs` -> 0, while the reader promotes `IrStopReason::Refusal` at `reader.rs:1196,1557` and `mod.rs:1043` maps wire `"refusal"` into it (positive control: `grep -n 'S::Refusal' anthropic/mod.rs` -> `:1420,:1438`, a dialect that both reads and writes it). `write_responses_status` (`mod.rs:1051-1056`) sends `Refusal` to `STATUS_COMPLETED` and the comment at `mod.rs:1049` justifies that with output items that are never written. Drift: `:487` cites `ir/variant.rs`; `:712-714` asserts the sequence reset 'deliberately does not clear the id cell' while `mod.rs:1563-1569` clears it. | X-1308, X-1318 |
| `crates/busbar-llm-codec/src/proto_codec.rs` | FINDING | Read 1284/1284. Ladder rungs are unique per ladder (`grep -rn 'ClaimStrength(' . | grep -v _tests` -> router {1..14} distinct, residual {10,20,25,30,40,50,55,60} distinct). `ToolIdRemap` cap reads `openai_chat::OPENAI_FAMILY_MAX_OPEN_TOOLS` (live). The `requested_candidate_count` doc (`:506`) asserts 'the engine REJECTS such a request up front (4xx)'; `grep -rn -w requested_candidate_count $(cat nontest)` -> the only production caller is `busbar-llm/src/engine/wire.rs:477: let _ = ...`, and `chat_handle.rs:53` clamps `ir.n = Some(1)` instead. | X-1319 |
| `crates/busbar-llm-codec/src/proto_stream.rs` | CLEAN | Read 1549/1549. `merge_trailing_usage_detail` (`:1462-1487`) destructures `IrUsageDetail` with NO `..` rest pattern, so a new attribution bucket is a compile error at that line — the strongest instrument in the slice. Abort path emits an in-band native error frame on both the eventstream and SSE legs. The same-proto Anthropic parse skip (`:832-855`) is a name-branch but is gated on the reader being stateless, which holds (`AnthropicReader::read_response_events` takes `_state`). | - |
| `crates/busbar-llm-codec/src/synth_rng.rs` | CLEAN | Read 109/109. `fill_entropy` is the single seam; failure leaves the pool drained and returns `false` (no stale/zero bytes served). Fork-safety is stated and bounded. Callers honour the `false` branch (`anthropic::synth_anthropic_request_id`, `bedrock::synth_amzn_request_id` both return `None`). | - |
| `crates/busbar-llm-codec/src/tests/bedrock_eventstream_tests.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 6 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 21 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/cache_tier_capture_tests.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 15 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 45 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/decode_native_tool_id_tests.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 9 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/detect_tests.rs` | FINDING | `grep -c '#\[test\]'` -> 5, ignore 0; each test calls `seeded()` first, and the header states why. `Registry` resolves a detection TIE by keeping the tightest strength in REGISTRATION order (`busbar-substrate-values/src/proto.rs:806`), so two dialects on one rung would be decided silently by `DECLS` order. No test asserts rung uniqueness: `grep -rn --include='*_tests.rs' 'ClaimStrength' .` -> 0 hits (control: `grep -rn 'ClaimStrength(' . | grep -v _tests` -> 22 declaration sites). Today the rungs ARE unique on both ladders, so this is a missing guard, not a live defect. | X-1321 |
| `crates/busbar-llm-codec/src/tests/leaf_write_dispatch_tests.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 1 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 1 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/merge_trailing_usage_tests.rs` | FINDING | Module header cites `crates/busbar/src/proto/stream.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/proto_stream.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 20 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/tests/proto/adversarial_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 13 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 21 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/billing_parity_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 9 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 13 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/context_length_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 4 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/cross_protocol_extra_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 14 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/gemini_integration_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 6 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/gemini_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 15 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 75 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/hook_ir_differential_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 4 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 15 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/image_source_matrix_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 4 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/max_tokens_precedence_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 9 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/mod.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 0 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 0 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/openai_family_tests.rs` | FINDING | Module header cites `crates/busbar-core/src/proto/openai_family.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 5 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 19 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/tests/proto/published_spec_shape_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 10 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 20 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/registry_tests.rs` | FINDING | `grep -c '#\[test\]'` -> 14, `#[ignore]` -> 0. Two sweeps iterate `builtins().decls()` (`:118`, `:182`) with no width assertion, so both report green over a shrunken denominator; the sibling instrument in this same slice (`tests/write_error_frame_tests.rs:52-56`) asserts `checked == 6` for exactly this reason and says so. Mitigated (not closed) by `:47-61`, which pins the six names on the process-global registry. | X-1320 |
| `crates/busbar-llm-codec/src/tests/proto/response_format_matrix_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 5 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 34 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/roundtrip_fidelity_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 30 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 124 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. Backs 16 `carried` rows of `qa/field-coverage.status` (all 97 distinct named instruments resolve: python cross-check -> 0 missing). | - |
| `crates/busbar-llm-codec/src/tests/proto/same_proto_fidelity_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 8 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 14 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/stop_reason_matrix_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 1 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 6 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/stream_fanout_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 8 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 20 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/stream_identity_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 12 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/stream_tap_usage_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 4 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 18 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 65 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 272 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/translate_parity_cross_pairs_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 30 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 35 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/proto/translate_parity_golden_tests.rs` | CLEAN | declared by `src/tests/proto/mod.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 5 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/rewrite_frame_strip_usage_tests.rs` | FINDING | Module header cites `crates/busbar/src/proto/stream.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/proto_stream.rs`; `grep -c '#[test]'` -> 2 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 6 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/tests/synth_rng_tests.rs` | FINDING | Module header cites `crates/busbar-llm/src/synth_rng.rs`; `test -f` on that path -> absent (positive control: the same test on `crates/busbar-llm-codec/src/lib.rs` -> present). Otherwise a live instrument: declared by `src/synth_rng.rs`; `grep -c '#[test]'` -> 3 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 8 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | X-1317 |
| `crates/busbar-llm-codec/src/tests/usage_count_tests.rs` | CLEAN | declared by `src/usage_count.rs`; `grep -c '#[test]'` -> 14 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 32 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/tests/write_error_frame_tests.rs` | CLEAN | declared by `src/lib.rs`; `grep -c '#[test]'` -> 1 tests, `grep -c '#[ignore'` -> 0; assertion scan (`assert*!`/`assert_*(`/`check_golden(`/`#[should_panic]`) -> 2 sites, i.e. >= 1 per test. Slice-wide refined scan found 0 genuinely assertion-free non-`should_panic` tests. | - |
| `crates/busbar-llm-codec/src/wire_shim.rs` | CLEAN | Read 111/111. All 4 items have non-test callers outside the crate (`grep -rnw <name> $(cat nontest)`): `strip_router_shim_keys` -> busbar-llm/engine/wire.rs:234; `max_translated_body_bytes` -> engine/attempt/buffered.rs:368,411; `TRUNCATED_TAIL_BYTES_PER_TOKEN` -> engine/response_body.rs:144; `tier_usage` -> engine/usage.rs:55, unit/meter.rs:373, unit/walk.rs:492. `tier_usage` omits zero tiers (sparse, no-zero-entry) and uses no float. | - |

## ROWS RAISED

### X-1300 · The chat readers bill a present-but-unreadable token count as ZERO; the refuse-don't-zero seam was adopted only on the leaf-op side
CLASS:     money
CERTAINTY: PARK
EVIDENCE:
```
$ grep -rn -w billed_count $(cat /tmp/nontest.txt) | grep -v usage_count.rs
crates/busbar-llm-codec/src/gemini/handler.rs:673,675,901,903
crates/busbar-llm-codec/src/openai_chat/handler.rs:520,522,1309,1445,1447
                                    # 10 hits -- ALL leaf-op handlers, ZERO readers
$ grep -rn -w read_count_u64 $(cat /tmp/nontest.txt) | wc -l
112                                 # POSITIVE CONTROL: same command shape, non-zero

$ for f in openai_responses bedrock anthropic cohere openai_chat gemini; do
    printf "%-18s " $f;
    grep -A1 read_count_u64 crates/busbar-llm-codec/src/$f/reader.rs | grep -c 'unwrap_or(0)';
  done
openai_responses   4      bedrock 4      anthropic 6
cohere             6      openai_chat 4  gemini  2        # 26 sites, all six chat readers

$ sed -n '86,115p' crates/busbar-llm-codec/src/usage_count.rs
/// READ ONE BILLED COUNT OUT OF A USAGE OBJECT -- ABSENT IS ZERO, UNREADABLE IS A REFUSAL.
/// # Why this exists rather than `.and_then(read_count_u64).unwrap_or(0)`
/// ... writing zero for it is the worst available answer: the ledger records that no work
/// happened, every money view over that row is faithfully derived and faithfully wrong ...
/// * present, not `null`, unreadable -- UnreadableCount, which the caller turns into a
///   refusal (#42: money-sacred, never a silent 0).
```
The sites are the PRIMARY billed totals, not an attribution bucket. In-slice cells:
`openai_responses/reader.rs:1215-1224` and `:1576-1585` (`input_tokens`/`output_tokens`),
`bedrock/reader.rs:1149-1156` and `:1374-1381` (`inputTokens`/`outputTokens`),
`gemini/reader.rs:32-41` (`promptTokenCount`/`candidatesTokenCount`), plus the leaf-op twins
`gemini/handler.rs:999-1007` and `bedrock/handler.rs:531-538` (`.map` over `None` -> `usage: None`
-> `billing()` -> `None` -> the embeddings turn bills nothing at all).

WORST CELL, `openai_responses/reader.rs:1215-1220`: an unreadable `input_tokens` yields `0`, the
`.saturating_sub(cached)` keeps it at `0`, and `cache_read_input_tokens` still carries the real
count — so the ledger records ZERO uncached input for a turn that demonstrably had some, and the
row is internally consistent, so nothing downstream can tell.

ROOT CAUSE: `billed_count` was written for #42 and landed in the LEAF-OP handlers only. The chat
half — the dominant billing path — never took it. This is the broken pair exactly: the guard exists,
the callers that need it most do not use it.

WHY THE EXISTING GATE DOES NOT CATCH IT: `tests/usage_count_tests.rs` bans
`as_u64().unwrap_or(0)` and bans a bare `as_u64`/`as_i64` near any of its 30 billed field names.
It does NOT ban `.and_then(read_count_u64).unwrap_or(0)`, which is the idiom in use. I ran the
gate's own scan over the crate: the control list returned **0 offenders** (the gate is green) while
the 26 sites above are live.

ACTION:    PARK for owner ruling. Recommendation: replace the 26 chat-reader sites and the 2
leaf-op sites with `crate::usage_count::billed_count(usage_obj, "<field>")?`, propagating
`UnreadableCount` as `CodecError::Malformed` exactly as `openai_chat/handler.rs:494-529` already
does; then extend `tests/usage_count_tests.rs` with a third scan banning
`read_count_u64` + `unwrap_or(0)` within the billed-field vocabulary, so the gate can produce a NO
for this shape.

### X-1301 · `Billing::Characters` is never constructed on a shipping path: the TTS request-seam meter has no caller
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -rn 'Billing::Characters' $(git ls-files '*.rs')
crates/busbar-llm-codec/src/ir/audio.rs:176          <- the ONE production producer
crates/busbar-llm/src/engine/attempt/buffered.rs:70  <- a match arm that maps it to None
crates/busbar-kernel/src/tests/billing_tests.rs:10 + 5 hits in ir/tests/audio_tests.rs

$ grep -rn 'billing()' $(git ls-files '*.rs') | grep -v busbar-llm-codec
crates/busbar-substrate-values/src/ir/handle.rs:113   (the token_usage default)
crates/busbar-substrate-values/src/handlers.rs:439    let usage = ir.billing();   <- translate_response
crates/busbar-substrate-values/src/handlers.rs:454    let usage = ir.billing();   <- translate_response
                                                      # POSITIVE CONTROL: the grep does find callers
$ sed -n '436,440p;451,455p' crates/busbar-substrate-values/src/handlers.rs
    let mut ir = self.read_response(bytes)?;      <- a RESPONSE handle, both arms
    let usage = ir.billing();
$ grep -rn 'token_usage()' $(git ls-files '*.rs') | grep -v to_token_usage
(no hits)                                             # the other route is dead too
```
`SpeechReqHandle::billing()` (`leaf_handles.rs:391-393`) is the ONLY request-side `billing()`
override in the crate, and its doc calls it "the TTS request-seam meter ... the exact character
count of the input, the true billable unit". The only seam that calls `IrHandle::billing()` is
`TranslateCodec::translate_response`, which always holds a RESPONSE handle. So the override is
never invoked, and what is actually recorded for a TTS turn is
`SpeechRespHandle::billing()` -> `SpeechResp.usage` -> `Some(Billing::Flat)`
(`openai_chat/handler.rs:1165`, `gemini/handler.rs:798,814`) — a marker whose own comment says it
"only records that a request was delivered".

IMPACT TODAY is observability, not revenue: `billing.rs:16-17` records that `Billing::Characters`
"is modelled by the IR but not yet priced". The defect is that the meter the code says is the true
unit is unreachable, so the day it IS priced the price will be applied to a value nothing produces.

ACTION:    Either call the request handle's `billing()` at the request seam
(`TranslateCodec::translate_request`, alongside `prepare_for_egress`) and carry it forward as the
turn's billable item, or delete `SpeechReqHandle::billing` + `SpeechReq::billing` and strike the
"true billable unit" claim. Do not leave a meter that cannot be read.

### X-1302 · Same-protocol leaf-op metering: five of eleven leaf cells never tap usage, and the image cells that do tap provably yield `None`
CLASS:     money
CERTAINTY: PARK
EVIDENCE:
```
$ grep -n 'impl OperationHandler for\|fn taps_usage' crates/busbar-llm-codec/src/openai_chat/handler.rs
247: OpenAiTranscription   534: OpenAiSpeech   600: OpenAiEmbeddings  613: fn taps_usage
706: OpenAiImage           721: fn taps_usage  831: OpenAiModeration
                                       # 5 cells, 2 overrides
$ grep -n 'impl OperationHandler for\|fn taps_usage' crates/busbar-llm-codec/src/gemini/handler.rs
145: GeminiTranscription 259: GeminiSpeech 348: GeminiImage 363: fn taps_usage
450: GeminiEmbeddings    463: fn taps_usage        # 4 cells, 2 overrides
$ grep -n 'struct BedrockRerank' -A14 crates/busbar-llm-codec/src/bedrock/handler.rs | grep -c taps_usage
0                                       # POSITIVE CONTROL: the same grep finds 152 and 234
$ sed -n '150,152p' crates/busbar-substrate-values/src/handlers.rs
    fn taps_usage(&self) -> bool { false }        <- the default
```
Consequence A — NO TAP AT ALL: a same-protocol openai->openai transcription or speech call, a
gemini->gemini transcription or speech call, an openai moderation call and a bedrock rerank call
never have their 2xx body buffered, so `extract_usage` is never reached and the turn bills nothing.
`openai_chat/handler.rs:494-529` (`parse_transcription_usage`) goes to refusal-grade lengths for
that body — reads `/usage/seconds` out of the raw bytes to avoid an `f64`, returns
`CodecError::Malformed` on an unreadable count — and is wired at `:1102-1105`. It is unreachable on
the same-protocol path.

Consequence B — A TAP THAT CANNOT REPORT: the image cells DO set `taps_usage()->true` with the
comment "closes the same-protocol metering gap" (`bedrock/handler.rs:148-151`,
`openai_chat/handler.rs:716-720`, `gemini/handler.rs:358-362`). But the default `extract_usage`
is `read_response(..).token_usage()`, and `IrHandle::token_usage`
(`substrate-values/src/ir/handle.rs:112-116`) returns `Some` only for `Billing::Tokens`, while
`ImageResp::billing()` (`ir/image.rs:189-199`) yields `Billing::Images` whenever there is no token
usage — i.e. for every per-image model (Titan/SDXL/dall-e/Imagen). So the tap returns `None` and a
same-protocol image generation bills zero.

STRUCTURAL ROOT CAUSE (outside this slice, stated not acted on): the same-protocol seam is typed
`Option<TokenUsage>` (`OperationHandler::extract_usage`, `StreamTranslator::usage`), while the
cross-protocol seam is typed `Option<Billing>`. A per-image, per-second or per-character charge is
UNREPRESENTABLE on the same-protocol seam. No amount of `taps_usage` fixes that.

ACTION:    PARK for owner ruling. Recommendation: widen the same-protocol usage seam to
`Option<Billing>` so `Images`/`Duration`/`Characters` can cross it, then add
`fn taps_usage(&self) -> bool { true }` to `OpenAiTranscription`, `OpenAiSpeech`,
`OpenAiModeration`, `GeminiTranscription`, `GeminiSpeech` and `BedrockRerank`. Until the seam is
widened, adding `taps_usage` alone would keep billing zero and make the claim true-looking.

### X-1303 · Nine `ImageReq`/`ImageResp` fields are declared, never populated by any reader, and never emitted by any writer
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ cd crates/busbar-llm-codec/src
$ for f in mask_prompt input_images add_watermark output_uri weighted_prompts warnings \
           steps strength mask aspect_ratio background; do
    printf "%-18s " $f
    grep -rn --include='*.rs' -w "$f" . | grep -v '^ir/' | grep -v _tests.rs | grep -c .
  done
mask_prompt        0      input_images     0      add_watermark 0
output_uri         0      weighted_prompts 0      warnings      0
steps              1 (a comment in openai_chat/reader.rs:782)
strength           5 (all comments)      mask  6 (all comments)
aspect_ratio       2  <- POSITIVE CONTROL: gemini/handler.rs:389,838 (real read + real write)
background         6  <- POSITIVE CONTROL: openai_chat/handler.rs:770,771,1388
```
So `ImageReq::{mask, mask_prompt, input_images, add_watermark, output_uri, weighted_prompts, steps,
strength}` and `ImageResp::warnings` are pure declaration. `ImageResp.warnings`' own comment names
its intended sources — "raiFilteredReason, finish_reasons, moderation notes" — and no reader reads
any of them, so a Gemini image response that Google RAI-filtered arrives at a client with the
reason stripped and nothing said.

Contrast: `ImageOp::{Edit, Variation}` are ALSO unconstructed but carry `#[allow(dead_code)]` and a
stated reason (`ir/image.rs:23-30`). The nine fields carry neither, so a reader cannot tell
"superset modelled ahead of the readers" from "we dropped this".

ACTION:    For each field either (a) wire the reader+writer pair, or (b) add the same
`#[allow(dead_code)]`-style note `ImageOp::Edit` carries, naming which provider surface it is
reserved for. And see X-1305: nothing enumerates these fields, so neither choice is currently
enforced.

### X-1304 · `TranscriptionReq.timestamp_granularities` and both `TimestampGranularity` variants are unreachable, so a whisper-1 `timestamp_granularities[]` ask is dropped in silence
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -rn --include='*.rs' -w -e timestamp_granularities -e TimestampGranularity \
    crates/busbar-llm-codec/src/ | grep -v '/ir/audio.rs'
(no output)
$ grep -rn --include='*.rs' -w aspect_ratio crates/busbar-llm-codec/src/ | grep -v '/ir/'
crates/busbar-llm-codec/src/gemini/handler.rs:389
crates/busbar-llm-codec/src/gemini/handler.rs:838     # POSITIVE CONTROL, same command shape
```
`ir/audio.rs:65` declares the field; `:20-28` declares the enum with `#[allow(dead_code)]` on both
variants. No transcription reader parses the multipart `timestamp_granularities[]` part and no
transcription writer emits it, so a caller who asks for word- or segment-level timestamps on a
cross-protocol hop gets a transcription without them and no warn — unlike every other
lossy-by-target drop in this crate, which warns (`ir_encode::warn_dropped_tool_strict` is the
pattern).

ACTION:    Parse `timestamp_granularities[]` in `openai_chat::handler::read_transcription_request`
and re-emit it in `write_transcription_request`; or, if it is genuinely out of scope, drop it with
a `tracing::warn!` at the reader and say so in the field's doc.

### X-1305 · The field-coverage gate's denominator is CHAT-ONLY, so the six leaf operations' IR fields cannot be classified — the gate is green over a set that excludes the fields X-1303/X-1304 found
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 -c "import json; i=json.load(open('qa/field-inventory.json')); \
   ids=[f['id'] for f in i['fields']]; print(i['field_count']); \
   print(sorted({'/'.join(x.split('/')[:2]) for x in ids}))"
412
['anthropic/request','anthropic/response','bedrock/request','bedrock/response',
 'cohere/request','cohere/response','gemini/request','gemini/response',
 'openai/request','openai/response','responses/request','responses/response']

$ python3 -c "... for op in ['embeddings','rerank','moderation','transcription']: \
   print(op, sum(1 for i in ids if op in i))"
embeddings 0     rerank 0     moderation 0     transcription 0
$ ... print('messages', sum(1 for i in ids if 'messages' in i))
messages 18                                   # POSITIVE CONTROL

$ grep -cvE '^#|^$' qa/field-coverage.missing
0                       # the pinned MISSING set is EMPTY -- the gate reports full coverage
$ grep -nE "input_images|mask_prompt|add_watermark|output_uri|weighted_prompts|\
timestamp_granularities|warnings" qa/field-coverage.status
(no output)
```
`qa/field-inventory.json`'s own header says it enumerates "Every request and response field of
every chat dialect busbar speaks", and it does — 412 chat fields, 249 `carried`, MISSING empty. The
six NON-chat operations (embeddings / image / rerank / moderation / transcription / speech), which
are 1.5/1.6 additions and are where all nine X-1303 fields and the X-1304 field live, are enumerated
NOWHERE. The gate whose stated purpose is "every field whose survival no test asserts is listed
rather than assumed" therefore cannot produce a NO for a leaf-op field that is never read and never
emitted — which is precisely the class it was built for, and precisely what I found by hand.

(The gate's own instruments are healthy: all 97 distinct `carried` test names resolve, and they all
live in this slice.)

ACTION:    Extend `xtask gate field-inventory` to enumerate the six leaf operations per dialect
(the `ir::{embeddings,image,rerank,moderation,audio}` structs are the source), regenerate
`qa/field-inventory.json`, and let the nine X-1303 fields + the X-1304 field land in
`qa/field-coverage.missing` where they belong. **Outside this slice — reported, not acted on.**

### X-1306 · An OpenAI-family citation cannot survive to a Responses egress: the reader deliberately drops the span, and the Responses writer drops any citation without one
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '188,198p' crates/busbar-llm-codec/src/openai_annotations.rs
        out.push(crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,          <- hardcoded
            ...
            start_index: None,         <- hardcoded
            end_index: None,           <- hardcoded
$ sed -n '110,124p' crates/busbar-llm-codec/src/openai_annotations.rs
fn citation_span(text, base, c) -> Option<(i64,i64)> {
    match (c.start_index, c.end_index) {
        (Some(s), Some(e)) if ... => Some(...),
        _ => c.cited_text.as_deref().filter(...).and_then(...)   <- None for None/None
$ sed -n '45,51p' crates/busbar-llm-codec/src/openai_annotations.rs
    for c in citations {
        let Some(url) = ... else { continue };
        let Some((start, end)) = citation_span(text, base, c) else { continue };   <- DROPS IT
$ grep -rn --include='*.rs' 'url_annotations\|chat_url_annotations' . | grep -v openai_annotations.rs | grep -v _tests
openai_responses/writer.rs:130,1106,1420   <- url_annotations  (span REQUIRED)
openai_chat/writer.rs:648,1014             <- chat_url_annotations (span OPTIONAL, :89-92)
openai_chat/reader.rs:1145 + openai_responses/reader.rs:244,1406  <- read_url_annotations
```
Compose the three: an OpenAI-Chat backend's `url_citation` annotations are read into an IR citation
with no `cited_text` and no offsets, and the Responses INGRESS writer then `continue`s past every
one of them. A Responses-dialect client on an openai-chat lane gets an answer with its web-search
citations **entirely absent**, at HTTP 200. The reverse hop (responses backend -> openai-chat
client) keeps them, because `chat_url_annotations` emits the citation without a span. The
asymmetry is the defect, not either half alone.

(Cosmetic, same file: the comment at `:170-171` is duplicated verbatim.)

ACTION:    Make `url_annotations` emit the `url_citation` entry with `start_index`/`end_index`
OMITTED when the span cannot be resolved (the shape `chat_url_annotations` already uses at
`:89-92`), rather than dropping the citation. The spec-required-members argument is weaker than
silently deleting the caller's evidence trail.

### X-1307 · Cohere streaming citations are written but never read: `ET_CITATION_START`/`ET_CITATION_END` have no reader arm, so a Cohere backend's grounding survives buffered and vanishes streamed
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -c -E 'ET_CITATION_START|ET_CITATION_END|citation-start|citation-end' \
    crates/busbar-llm-codec/src/cohere/reader.rs
0
$ grep -c -E 'ET_CONTENT_DELTA|ET_TOOL_CALL_START' crates/busbar-llm-codec/src/cohere/reader.rs
2                                            # POSITIVE CONTROL, same file, same grep shape
$ grep -rn -w -e ET_CITATION_START -e ET_CITATION_END crates/busbar-llm-codec/src/ | grep -v _tests
cohere/mod.rs:315:const ET_CITATION_START: &str = "citation-start";
cohere/mod.rs:320:const ET_CITATION_END:   &str = "citation-end";
cohere/writer.rs:708:  "type": ET_CITATION_START,
cohere/writer.rs:900:  serde_json::json!({ "type": ET_CITATION_END, "index": index }),
$ grep -rn read_cohere_citations crates/busbar-llm-codec/src/cohere/reader.rs
372:   (inside read_request)      1192:  (inside read_response)     # never read_response_events
```
`read_cohere_citations` exists (`cohere/mod.rs:164`) and is wired into the buffered response reader
and the request reader. The STREAM reader `read_response_events` has arms for
`message-start`/`content-start`/`content-delta`/`tool-plan-delta`/`content-end`/`message-end`/the
three `tool-call-*` frames and NONE for the two citation frames. So the same Cohere completion
carries its grounding citations to a foreign client when `stream:false` and loses them when
`stream:true` — the one difference being a flag the provider's own citations do not depend on.

(`cohere/reader.rs` is OUTSIDE this slice; the declaration and the emission are inside it.)

ACTION:    Add an `ET_CITATION_START` arm to `cohere/reader.rs::read_response_events` that folds
`delta.message.citations` through `read_cohere_citations` into an
`IrDelta::CitationsDelta`, mirroring the buffered arm at `cohere/reader.rs:1192`.

### X-1308 · A Responses refusal is read into the IR and has no writer on the same dialect: `Refusal` is re-emitted as `status: "completed"`
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -c '"refusal"' crates/busbar-llm-codec/src/openai_responses/writer.rs
0
$ grep -n 'S::Refusal' crates/busbar-llm-codec/src/anthropic/mod.rs
1420:        STOP_REFUSAL => S::Refusal      <- read
1438:        S::Refusal   => STOP_REFUSAL    <- written   # POSITIVE CONTROL: a dialect with both halves
$ grep -n 'S::Refusal\|IrStopReason::Refusal' crates/busbar-llm-codec/src/openai_responses/{reader,mod}.rs
openai_responses/mod.rs:1043:     "refusal" => S::Refusal
openai_responses/reader.rs:1196:  Some(crate::ir::IrStopReason::Refusal)
openai_responses/reader.rs:1557:  stop_reason = Some(crate::ir::IrStopReason::Refusal)
$ sed -n '1048,1057p' crates/busbar-llm-codec/src/openai_responses/mod.rs
/// ... everything else (incl. tool_use, refusal) is `completed`
/// (a refusal/tool-call is surfaced via output items, not the status).
fn write_responses_status(reason) { match reason { S::MaxTokens | S::Safety => STATUS_INCOMPLETE,
                                                   _ => STATUS_COMPLETED } }
```
The reader promotes a wire `incomplete_details.reason == "refusal"` into `IrStopReason::Refusal`
from two sites. The writer maps it to `completed`, emits no `refusal` content part anywhere, and
the comment justifying the status choice cites output items that do not exist. On a
Responses-ingress hop an upstream `{"status":"incomplete","incomplete_details":{"reason":"refusal"}}`
reaches the client as `{"status":"completed","incomplete_details":null}` with the refusal text as
ordinary `output_text` — a client whose policy branches on refusal is told the model complied.

(`openai_responses/mod.rs` is OUTSIDE this slice; the reader and the writer are inside it.)

ACTION:    Add `S::Refusal` to the `STATUS_INCOMPLETE` arm of `write_responses_status` and a
`S::Refusal => "refusal"` arm to `write_responses_incomplete_reason`, so the reader's promotion has
a consumer.

### X-1309 · The OpenAI streaming usage leg serializes one of five detail buckets the stream reader populates
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n 'usage\.detail\.' crates/busbar-llm-codec/src/openai_chat/writer.rs
763:   if let Some(rt) = usage.detail.reasoning_tokens {            <- write_response_event (STREAM)
1129:  if let Some(a)  = resp.usage.detail.input_audio_tokens {     <- write_response  (BUFFERED)
1145:  if let Some(rt) = resp.usage.detail.reasoning_tokens {
1148:  if let Some(a)  = resp.usage.detail.output_audio_tokens {
1151:  if let Some(t)  = resp.usage.detail.accepted_prediction_tokens {
1157:  if let Some(t)  = resp.usage.detail.rejected_prediction_tokens {
$ grep -n 'input_audio_tokens\|accepted_prediction_tokens' crates/busbar-llm-codec/src/openai_chat/reader.rs
959,963,967,971       <- inside fn read_response_events (declared :594) -- the STREAM reader
1300,1304,1308,1312   <- the buffered reader
$ grep -n 'input_audio_tokens\|accepted_prediction_tokens' crates/busbar-llm-codec/src/proto_stream.rs
1473,1475,1508,1514   <- merge_trailing_usage_detail carries them to the terminal MessageDelta
```
Every link is present except the last: the stream reader decodes the four audio /
predicted-outputs buckets, `proto_stream::merge_trailing_usage_detail` (whose own doc explains that
an unmerged bucket is "a number a customer finds missing from a bill") carries them onto the
terminal delta, and the OpenAI ingress writer then emits only `reasoning_tokens`. So an
`include_usage: true` OpenAI client is shown audio and predicted-outputs attribution when the same
request is buffered and never when it is streamed.

ACTION:    After `openai_chat/writer.rs:770`, add the same four inserts the buffered leg makes at
`:1129`, `:1148`, `:1151`, `:1157`.

### X-1310 · The Gemini embeddings writer never serializes the `usage` its own reader populates
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '533,545p' crates/busbar-llm-codec/src/gemini/handler.rs | grep -c usage
0
$ sed -n '672,697p' crates/busbar-llm-codec/src/openai_chat/handler.rs | grep -c usage
2                                                   # POSITIVE CONTROL: the openai twin emits it
$ grep -n 'inputTextTokenCount\|billed_units' crates/busbar-llm-codec/src/{bedrock,cohere}/handler.rs
bedrock/handler.rs:308: body["inputTextTokenCount"] = json!(u.input);
cohere/handler.rs:231:  body["meta"] = json!({ "billed_units": { "input_tokens": u.input } });
$ sed -n '999,1007p' crates/busbar-llm-codec/src/gemini/handler.rs
    let usage = v.get("usageMetadata").and_then(|u| u.get("promptTokenCount")) ...
```
Three of the four embeddings writers emit the token usage; Gemini alone drops it. A
Gemini-dialect client on any embeddings lane receives a body with no `usageMetadata` — a wire-shape
tell against a direct call, and the client's own accounting reads nothing.

ACTION:    In `gemini::handler::write_embeddings_response`, emit
`usageMetadata: { promptTokenCount, totalTokenCount }` from `r.usage` when present, mirroring the
image writer in the same file (`:433-443`).

### X-1311 · Bedrock SigV4 guesses `us-east-1` instead of failing closed, sending the credential on a scope that cannot verify
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '36,47p' crates/busbar-llm-codec/src/bedrock/writer.rs
    let (access, secret, token) = match (...) {
        (Some(a), Some(s), tok) if !a.is_empty() && !s.is_empty() => (a, s, tok),
        _ => return vec![],                                       <- REFUSES
    };
    let region = match derive_sigv4_region(ctx.host) {
        Some(r) => r,
        None => {
            tracing::warn!(host = %ctx.host, "could not derive AWS region ... defaulting SigV4
                            scope to us-east-1 ...");
            "us-east-1"                                           <- GUESSES
        }
    };
$ sed -n '52,58p;101,106p' crates/busbar-llm-codec/src/bedrock/writer.rs
    Err(_) => { tracing::warn!("... skipping signing ..."); return vec![]; }   <- REFUSES (:54)
    Err(_) => { ... return vec![]; }                                          <- REFUSES (:104)
```
Every other un-signable input in this function returns an empty header set. The region is the one
input that is guessed. A guessed scope yields a signature that cannot verify at any non-`us-east-1`
endpoint — the same end state as refusing, reached with the access key id and a full
`Authorization: AWS4-HMAC-SHA256 Credential=...` on the wire instead of held back, and surfaced to
the operator as an indistinguishable 403.

Everything else in `sigv4_sign_headers` is clean and worth recording: the signature is computed
over a real canonical request (no stub `Authorization` on any failure path), neither `access`,
`secret` nor `token` is ever formatted into a log line (the two `tracing::warn!` calls carry only
`ctx.host` and a fixed string), a missing or blank access/secret refuses at `:38`, and CRLF
injection via the key or the session token is blocked by the `HeaderValue::from_str` gates at `:51`
and `:99` (pinned by `bedrock/tests/tests.rs:697,704,1830,1838`).

ACTION:    Replace the `None =>` arm body with `return vec![];` so an underivable region fails
closed like every sibling error path in the same function.

### X-1312 · The Bedrock cross-protocol drop audit reports 2 of the 4 controls the writer actually drops
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '187,199p' crates/busbar-llm-codec/src/bedrock/writer.rs
    fn dropped_egress_controls(&self, req) -> Vec<&'static str> {
        // Mirrors the two `write_request` warns: ...
        if req.response_format.is_some()                 { dropped.push("response_format"); }
        if matches!(req.tool_choice, Some(...::None))    { dropped.push("tool_choice=none"); }
$ grep -n 'dropping .* on Bedrock egress\|req.reasoning.is_some()\|req.parallel_tool_calls.is_some()' \
    crates/busbar-llm-codec/src/bedrock/writer.rs
205:  if req.reasoning.is_some()            -> warn "dropping cross-protocol reasoning/thinking ask"
607:  ... response_format                   -> audited
699:  ... tool_choice=none                  -> audited
716:  if req.parallel_tool_calls.is_some()  -> warn "dropping parallel_tool_calls on Bedrock egress"
$ grep -rn 'dropped.push("reasoning")\|dropped.push("parallel_tool_calls")' crates/busbar-llm-codec/src/
(no output)
$ grep -rn 'dropped.push("seed")' crates/busbar-llm-codec/src/
anthropic/writer.rs:146      openai_responses/writer.rs:40    # POSITIVE CONTROL: dialects that do audit
```
`dropped_egress_controls` is the AUDIT-AND-ALLOW seam: the request still forwards, but each drop is
supposed to become a first-class audit event at the cross-protocol seam. Two real drops — the
reasoning ask and the parallelism flag — reach only `tracing::warn!` and never the audit. The doc
comment says "the two warns" where there are four, so the instrument's own description is what made
the gap invisible. `openai_responses/writer.rs:22-46` audits all six of its own.

ACTION:    Add `if req.reasoning.is_some() { dropped.push("reasoning"); }` and
`if req.parallel_tool_calls.is_some() { dropped.push("parallel_tool_calls"); }` at
`bedrock/writer.rs:197`, and correct the doc to "the four".

### X-1313 · `PLANE_KEY` is declared the single literal the flip and the capability key must share; the composition root reads a second, restated literal and nothing pins them equal
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '135,142p' crates/busbar-llm-codec/src/lib.rs
/// Named ONCE, here, ... because the plane's `capability_key` and the composition-root FLIP must
/// reference the SAME literal or a swap could drift onto two.
pub const PLANE_KEY: &str = "llm";
$ sed -n '68,75p' crates/busbar/src/root/gauntlet_install.rs
    // Routed through `PLANE_DECL.key` rather than a fresh `busbar_llm::PLANE_KEY` reach: ...
    flip_one_shot_to_kernel(busbar_llm::PLANE_DECL.key);
$ sed -n '220,222p' crates/busbar-llm/src/lib.rs
pub const PLANE_DECL: ... PlaneDecl {
        key: "llm",                    <- the SECOND literal
$ grep -rn PLANE_KEY crates/ | grep -iE 'assert'
crates/busbar-plane-a2a/src/tests/meta.rs:13: assert_eq!(A2aPlane::KEY, crate::PLANE_KEY);
crates/busbar-plane-mcp/src/tests/meta.rs:13: assert_eq!(McpPlane::KEY, crate::PLANE_KEY);
                              # POSITIVE CONTROL: two planes DO pin it; the LLM plane does not
```
`PLANE_KEY`'s only production consumer is `busbar-llm/src/native_ingress.rs:560`
(`GauntletPlane::capability_key`). The FLIP — the other half the doc says must not drift — reads
`PLANE_DECL.key`, a separate `"llm"` literal in a different crate. A rename applied to one and not
the other registers the kernel-loop runner under a key the plane does not report, and the plane
fails closed at `run_gauntlet` with nothing in the diff to have caught it. The sibling planes both
carry the one-line equality test.

ACTION:    Either set `busbar-llm/src/lib.rs:222` to `key: busbar_llm_codec::PLANE_KEY`, or add
`assert_eq!(busbar_llm::PLANE_DECL.key, busbar_llm_codec::PLANE_KEY)` to busbar-llm's
`plane_decl_identity_tests.rs`, matching `busbar-plane-a2a/src/tests/meta.rs:13`.

### X-1314 · The `timing` feature is declared as a per-dialect profiling seam; two of six dialects carry it
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '37,41p' crates/busbar-llm-codec/Cargo.toml
# Mirrors `busbar-llm`'s `timing` feature: the per-dialect reader/writer translate entry points
# carry `busbar_timing::timeit!` guards, so the flag exists in lock-step ...
timing = ["busbar-timing/timing"]
$ cd crates/busbar-llm-codec/src
$ for d in anthropic bedrock cohere gemini openai_chat openai_responses; do
    printf "%-18s %s\n" $d $(grep -rn 'timeit!' $d/ | grep -c .); done
anthropic          0        bedrock           4        cohere            4
gemini             0        openai_chat       0        openai_responses  0
$ grep -rhn 'timeit!("' . | sed 's/.*timeit!("\([^"]*\)".*/\1/' | sort
bedrock_read_request  bedrock_read_response  bedrock_write_request  bedrock_write_response
cohere_read_request   cohere_read_response   cohere_write_request   cohere_write_response
$ for d in ...; do git show v1.5.5:crates/busbar/src/proto/$d/{mod,reader,writer}.rs | grep -c timeit!; done
0 for all six                     # so this is a half-landed 1.6.0 change, not a 1.5.5 regression
```
Turning `timing` on profiles bedrock and cohere and reports nothing for anthropic, gemini,
openai-chat or openai-responses — including the two heaviest translate paths. An operator reading
the resulting profile concludes those dialects cost nothing.

ACTION:    Add the four `busbar_timing::timeit!` guards to each of the remaining four dialects'
`read_request`/`read_response`/`write_request`/`write_response`, or narrow the Cargo.toml comment to
name the two dialects that actually carry them.

### X-1315 · Four branches that cannot be taken, each with a comment describing a path that does not reach them
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
(a) crates/busbar-llm-codec/src/openai_chat/writer.rs:1086-1088
$ grep -rn '\.write_response(' $(cat /tmp/nontest.txt) | grep -v 'fn write_response'
crates/busbar-llm-codec/src/chat_handle.rs:412
crates/busbar-plane-llm/src/plane.rs:782                 # exactly two production sites
$ sed -n '444p' crates/busbar-substrate-values/src/handlers.rs   # precedes chat_handle.rs:412
                ir.prepare_for_ingress(ingress_protocol, now);
$ sed -n '774p' crates/busbar-plane-llm/src/plane.rs             # precedes plane.rs:782
        busbar_llm_codec::chat_handle::chat_prepare_for_ingress(
$ sed -n '302,305p' crates/busbar-llm-codec/src/chat_handle.rs
pub fn chat_prepare_for_ingress(...) { ir.id = None; ir.system_fingerprint = None; ... }
```
    -> `if let Some(ref fp) = resp.system_fingerprint` can never be `Some`. Its comment says the
       value comes from a "same-protocol passthrough", which never enters this writer at all.
       (The same reasoning makes `resp.id` at `:1069` always take its synth fallback; that one is
       still correct, just not the branch the comment describes.)

(b) crates/busbar-llm-codec/src/openai_responses/reader.rs:838-841
$ sed -n '838,841p' crates/busbar-llm-codec/src/openai_responses/reader.rs
                    } else if item_obj.get("type").and_then(|t| t.as_str())
                        == Some(ITEM_TYPE_MESSAGE)
                    {
                    }
    -> an empty branch in the `output_item.added` demux, with no comment, in a file whose stated
       convention is drop-with-warn.

(c) crates/busbar-llm-codec/src/gemini/handler.rs:505-512
$ grep -rn --include='*.rs' 'EmbInput::' . | grep -v '/tests/' | grep -v _tests.rs | grep -c 'Tokens\|Images'
0                     # (positive control: the same grep finds 9 `EmbInput::Text` sites)
    -> the `other =>` warn arm is unreachable because nothing constructs `Tokens`/`Images`
       (`ir/embeddings.rs:41-48` says so). A wildcard here also means a NEW variant is absorbed
       silently instead of failing the build.

(d) crates/busbar-llm-codec/src/openai_chat/handler.rs:76
$ grep -n PATH_RERANK crates/busbar-llm-codec/src/openai_chat/handler.rs
27:  const PATH_RERANK: &str = "/v1/rerank";
76:      .unwrap_or(PATH_RERANK)
    -> `PATHS` (`:56-63`) covers exactly `DECL.verbs`, so `path_of` cannot miss; the const's only
       use is an unreachable fallback naming an endpoint OpenAI does not serve. Self-documented at
       `:73-74`, but a dead const on the egress path is still a trap.

ACTION:    (a) delete the `if let` and state that `system_fingerprint` is always `None` here;
(b) delete the empty branch or give it the one-line reason (the message item is opened lazily by
its first `output_text.delta`); (c) change `other =>` to
`EmbInput::Tokens(_) | EmbInput::Images(_) =>`; (d) fall back to `PATH_CHAT_COMPLETIONS` and delete
`PATH_RERANK`.

### X-1316 · `gemini::recover_truncated_usage` builds a reasoning/tool-use attribution block that the very next call discards
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '44,54p' crates/busbar-llm-codec/src/gemini/reader.rs
                detail: crate::ir::IrUsageDetail {
                    reasoning_tokens: thoughts,
                    // Attribution only ... this records HOW MANY of them were server-side tool use.
                    tool_use_prompt_tokens: tool_use,
                    ..Default::default()
                },
            }
            .to_token_usage()                      <- returns a TokenUsage
$ sed -n '32,45p' crates/busbar-substrate-values/src/billing.rs | grep -o 'pub [a-z_]*'
pub input   pub output   pub cache_read   pub cache_creation
pub input_text   pub input_audio   pub input_image        # no reasoning/tool_use member
```
The totals survive, so the BILL is right; what is lost is the attribution the comment claims to
record. This path is also the only usage read in the crate that never computes
`usage_identity_note` (contrast `gemini/mod.rs:1775`), so a truncated Gemini response whose
`usageMetadata` violates Google's own sum identity is never flagged.

ACTION:    Replace `detail: IrUsageDetail { ... }` with `detail: Default::default()` and delete the
two comments that claim the attribution is recorded — or carry the two buckets into `TokenUsage`
and map them in `to_token_usage`.

### X-1317 · Fourteen relocated module headers still name the 1.5.5 file they were extracted from
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 - # extract every `crates/...`-shaped path from the 112 slice files, test each for existence
STALE PATH REFERENCES (path does not exist):
  crates/busbar-core/src/proto/openai_family.rs  <- src/tests/proto/openai_family_tests.rs
  crates/busbar-llm/src/synth_rng.rs             <- src/tests/synth_rng_tests.rs
  crates/busbar/src/handlers/anthropic.rs        <- src/anthropic/tests/handler_tests.rs
  crates/busbar/src/handlers/bedrock.rs          <- src/bedrock/tests/handler_tests.rs
  crates/busbar/src/handlers/cohere.rs           <- src/cohere/tests/rerank_tests.rs
  crates/busbar/src/handlers/gemini.rs           <- src/gemini/tests/handler_tests.rs
  crates/busbar/src/handlers/openai.rs           <- src/openai_chat/tests/handler_tests.rs
  crates/busbar/src/handlers/responses.rs        <- src/openai_responses/tests/handler_tests.rs
  crates/busbar/src/ir/audio.rs                  <- src/ir/tests/audio_tests.rs
  crates/busbar/src/ir/embeddings.rs             <- src/ir/tests/embeddings_tests.rs
  crates/busbar/src/ir/image.rs                  <- src/ir/tests/image_tests.rs
  crates/busbar/src/ir/moderation.rs             <- src/ir/tests/moderation_tests.rs
  crates/busbar/src/ir/rerank.rs                 <- src/ir/tests/rerank_tests.rs
  crates/busbar/src/proto/stream.rs              <- src/tests/{merge_trailing_usage,
                                                       rewrite_frame_strip_usage}_tests.rs
CONTROL: a path that DOES exist resolves -> True  (crates/busbar-llm-codec/src/lib.rs)
```
Each is the file's `//! Tests for <path>` header. Harmless at runtime, but these are the headers a
maintainer reads to find the code under test, and all fourteen point into the pre-split tree.

ACTION:    Rewrite each header to the current path (mechanical; the mapping above is exact).

### X-1318 · Twelve in-code doc references name symbols, files or invariants that do not exist or are contradicted by the code beside them
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ find . -path ./target -prune -o -name 'variant.rs' -print          ;# 5 citers
(no output)
$ find . -path ./target -prune -o -path '*/ir/*.rs' -print | wc -l   ;# POSITIVE CONTROL
8
```
  `ir/variant.rs` cited by: `cohere/writer.rs:424`, `openai_chat/writer.rs:470`,
  `openai_chat/mod.rs:246`, `gemini/writer.rs:442`, `openai_responses/writer.rs:487`.
  Real home of the hosted-tool strip: `chat_handle.rs:346` / `chat_prepare_for_egress`.
```
$ find . -path ./target -prune -o \( -name 'openai.rs' -o -name 'bedrock.rs' -o -name 'cohere.rs' \
        -o -name 'anthropic.rs' -o -name 'gemini.rs' -o -name 'openai_chat.rs' \) -print
(no output -- except crates/api/src/auth.rs etc. for unrelated names)
```
  `handlers/openai.rs:79` cited by `openai_chat/handler.rs:1340` (the fn is in that same file at
  `:79`). `bedrock.rs`/`cohere.rs` cited by `gemini/reader.rs:839-840`.
  `openai_chat.rs`/`anthropic.rs`/`gemini.rs` cited by `cohere/mod.rs:143,649`
  (control: `cohere/mod.rs:599` cites `openai_chat/reader.rs`, which DOES resolve).
```
$ grep -rn 'fn auth_failure_status_and_kind' crates/ ;# gemini/writer.rs:740 says `auth.rs::...`
crates/busbar-substrate-values/src/proxy/mod.rs:398
$ grep -rn 'pub struct StreamTranslate' crates/      ;# bedrock/writer.rs:958 says `proto/mod.rs`
crates/busbar-llm-codec/src/proto_stream.rs:24
$ grep -rn 'fn test_gemini_read_write_response_roundtrip' crates/ ;# gemini/writer.rs:1303 says src/proto/mod.rs
crates/busbar-llm-codec/src/tests/proto/gemini_tests.rs:68
$ sed -n '1563,1567p' crates/busbar-llm-codec/src/openai_responses/mod.rs
        // Clear the carried `response.id` alongside the sequence counter: ...
        if let Ok(mut id) = self.response_id.lock() { *id = None; }
   ;# contradicts openai_responses/writer.rs:712-714: "the reset ... deliberately does not clear
   ;# the id cell"
$ sed -n '608,609p;618p;632p' crates/busbar-llm-codec/src/openai_responses/reader.rs
608-609: "`text` is added to the modeled keys below so it does not also linger in `extra`"
618:     "NOTE: `text` is NOT in the modeled-keys set"
632:     "even though `text` is listed as modeled"
```
Two of those three statements about `text` are false; the code follows `:618`.

ACTION:    Mechanical rewrite of each citation to its real home, and delete the two false `text`
clauses (`:608-609`, `:632`) and the false reset claim (`writer.rs:712-714`).

### X-1319 · `proto_codec.rs` tells a maintainer the engine REFUSES a multi-candidate cross-protocol request; the engine clamps it and throws the detection away
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '501,507p' crates/busbar-llm-codec/src/proto_codec.rs
/// ... Rather than return 1-of-N, the engine REJECTS such a request up front (4xx).
$ grep -rn -w requested_candidate_count $(cat /tmp/nontest.txt)
crates/busbar-llm/src/engine/wire.rs:477:        let _ = ingress_dialect.requested_candidate_count(&body);
                                     # the ONLY production caller, and it discards the answer
$ sed -n '473,477p' crates/busbar-llm/src/engine/wire.rs
        // ... rather than rejecting with a 400 (fail-loud is a deliberate opt-in for a future
        // plane, not a 1.6.0 default). The `ProtocolWriter::requested_candidate_count` detection
        // machinery is retained for that future opt-in; only the outcome here reverts to the
        // silent 1-of-N degrade.
$ sed -n '46,54p' crates/busbar-llm-codec/src/chat_handle.rs
    if ir.n.is_some_and(|n| n > 1) { ... ir.n = Some(1); }     <- what actually happens
```
No billing exposure: the clamp means the backend is asked for one candidate, so the caller is not
charged for N-1 answers that are then dropped. The defect is that the vtable rung, both concrete
impls (`openai_chat/writer.rs:18`, `gemini/writer.rs:56`) and four doc sites
(`proto_codec.rs:506`, `openai_chat/writer.rs:16`, `ir/types.rs:1265`, `gemini/reader.rs:955`)
describe a refusal the build does not perform.

ACTION:    Correct the four doc sites to say `chat_prepare_for_egress` clamps `n` to 1
(`chat_handle.rs:53`), or act on `requested_candidate_count` at `wire.rs:477`. Leaving the doc as
written invites someone to remove the clamp on the belief a 4xx guard exists.

### X-1320 · Two registry sweeps iterate `builtins().decls()` with no width assertion, while the sibling instrument in the same slice says why one is required
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ grep -n 'decls()' crates/busbar-llm-codec/src/tests/proto/registry_tests.rs
118:    for decl in builtins().decls() {       <- the_declared_verbs_are_the_verbs_the_handler_serves
182:    for decl in builtins().decls() {       <- every_declared_verb_has_a_serving_handler
658:    assert!(empty.decls().is_empty());
$ sed -n '26,28p' crates/busbar-llm-codec/src/tests/proto/registry_tests.rs
fn builtins() -> Registry { Registry::new(crate::DECLS.iter().copied()) }
$ sed -n '50,56p' crates/busbar-llm-codec/src/tests/write_error_frame_tests.rs
    // The sweep asserts nothing if it iterates nothing. `DECLS` shrinking, or every row losing its
    // `codec`, would `continue` past every assertion and report this battery green over ZERO
    // protocols -- the silent downgrade it exists to catch, on all six at once.
    assert_eq!(checked, 6, ...);           # POSITIVE CONTROL: the pattern, in the same slice
```
Demoted to ADJUDICATE rather than left at VERIFIED because the shrink IS caught indirectly:
`registry_tests.rs:47-61` pins the six names on the process-global registry, so `DECLS` losing an
entry goes red there. The sweeps themselves still cannot produce a NO, which is law 1.

ACTION:    Add `let n = builtins().decls().count(); assert_eq!(n, 6, ...)` (or a running `checked`
counter) to both sweeps, matching `write_error_frame_tests.rs:52-56`.

### X-1321 · Nothing pins the detection ladder's rung uniqueness; a tie would be resolved silently by registration order
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ grep -rn --include='*.rs' 'ClaimStrength(' crates/busbar-llm-codec/src | grep -v _tests \
    | sed 's/:.*ClaimStrength(\([0-9]*\)).*/ -> \1/'
  router ladder (claims):   bedrock 1,12,13  anthropic 2,4,11  gemini 3,5,6
                            openai 7,14      cohere 8,9        responses 10      -> all distinct
  residual ladder:          gemini 10,20     openai 25,55      bedrock 30
                            anthropic 40     cohere 50         responses 60      -> all distinct
$ grep -rn --include='*_tests.rs' 'ClaimStrength' crates/busbar-llm-codec/src
(no output)
$ grep -rn --include='*.rs' 'ClaimStrength(' crates/busbar-llm-codec/src | grep -vc _tests
22                                              # POSITIVE CONTROL for the same command shape
$ sed -n '804,808p' crates/busbar-substrate-values/src/proto.rs
    /// registered protocol in registration order and keeps the tightest [`ClaimStrength`] ...
```
There is no tie today — I checked both ladders and both are injective. But "keeps the tightest, in
registration order" means a future tie is broken by `DECLS` order with no signal, and `DECLS`
order is itself a thing this crate documents as load-bearing and easy to move
(`lib.rs:160-178`). The sweep's slice owns `tests/detect_tests.rs`, which is where the guard
belongs.

ACTION:    Add a test to `tests/detect_tests.rs` asserting both ladders are injective across
`crate::DECLS` — drive each dialect's `claims`/`residual_claims` over the paths/headers it
recognises and assert no two dialects return the same `ClaimStrength`.

### X-1322 · The Anthropic writer states a DELIBERATE divergence from the 1.5.5 wire; the sweep cannot verify the sign-off it cites
CLASS:     customer-surface
CERTAINTY: PARK
EVIDENCE:
```
$ sed -n '255,258p' crates/busbar-llm-codec/src/anthropic/writer.rs
// DELIBERATE DIVERGENCE from the 1.5.5 golden: 1.5.5 DROPPED `response_format` here (the model
// got no schema and returned free-form prose -- the owner-reported bug). Emitting the tool +
// tool_choice changes the upstream request bytes ON PURPOSE. Only reachable cross-protocol:
// same-protocol Anthropic relays the raw upstream body and never enters this writer.
$ diff <(git show v1.5.5:crates/busbar/src/proto/anthropic/writer.rs) \
       crates/busbar-llm-codec/src/anthropic/writer.rs | sed -n '/response_format/p' | head -4
< if req.response_format.is_some() {           tracing::warn!( ... "dropping response_format ...")
> if let Some(rf) = &req.response_format { if rf.json { ...RESPONSE_FORMAT_TOOL_NAME... } }
```
Confirmed against the released tree: 1.5.5 dropped the field with a warn; 1.6.0 synthesizes a tool
whose `input_schema` IS the caller's JSON schema and pins `tool_choice` to it. The upstream request
bytes on every cross-protocol hop into an Anthropic lane therefore differ from 1.5.5. The
same-protocol claim holds (a same-protocol Anthropic request is a verbatim relay and never enters
this writer), so the blast radius is cross-protocol only.

This is listed not because it looks wrong — the change is well argued and the reader has the
matching `RESPONSE_FORMAT_TOOL_NAME` unwrap — but because my slice's rule is that customer-visible
behaviour matches 1.5.5 unless the owner signed off a SPECIFIC change, and a comment asserting an
owner report is not a sign-off a sweep can check.

ACTION:    PARK. Owner to confirm the `response_format` -> Anthropic tool-forcing change is the
signed-off one, and that it belongs in the 1.6.0 CHANGELOG as an upstream-request-bytes change.

## TALLY
```
files in slice:  112     (equals the S04-llm-codec.txt line count)
verdict lines:   112
CLEAN:            74
FINDING:          38     rows raised: 23  (X-1300 .. X-1322)
DELETABLE:         0
UNREADABLE:        0
```

Rows by class (23 total): **money 4** (X-1300, X-1301, X-1302, X-1309) · **auth 1** (X-1311) ·
**customer-surface 5** (X-1306, X-1307, X-1308, X-1310, X-1322) · **missing-code 3** (X-1303,
X-1304, X-1315) · **instrument-blind 6** (X-1305, X-1312, X-1314, X-1316, X-1320, X-1321) ·
**config 1** (X-1313) · **drift 3** (X-1317, X-1318, X-1319).

Rows by certainty: VERIFIED 18 · ADJUDICATE 2 (X-1320, X-1321) · PARK 3 (X-1300, X-1302, X-1322).
