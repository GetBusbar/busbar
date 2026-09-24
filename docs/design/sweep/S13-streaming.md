# S13-streaming — sweep verdicts

Slice: `busbar-voice`, `busbar-voice-codec`, `busbar-plane-streaming`. 55 files, 55 verdict lines.
X-id block: X-2200 .. X-2299.

Binding naming rule (spec #18) applied throughout: the fourth plane is **STREAMING**; `voice` is one
capability/dialect inside it. The `busbar-voice -> busbar-streaming` rename plus the feature flip is
ONE atomic change (#17) and is NOT made here — every surviving old noun is raised as a row instead.
Live realtime voice is IN for 1.6.0, so nothing in this slice is DELETABLE by default.
`busbar-voice/runtime/metering.rs` is not in this slice, but every billed byte this slice touches is
PARKed rather than adjudicated.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-voice/Cargo.toml | FINDING | `sed -n '11,14p' crates/busbar-voice/Cargo.toml` → "Boot-mounting into the composition root ... is separate, tracked work"; `git grep -n "busbar_voice::PLANE_DECL\|busbar_voice::DIAGNOSTICS" crates/busbar/src/main.rs` → 379, 392 (it landed). `git grep -nE "busbar[-_]core([^-_a-z]|$)" crates/busbar-voice/Cargo.toml` → 7 hits; `ls -d crates/busbar-core` → no such crate. | X-2200, X-2218 |
| crates/busbar-voice/src/config.rs | CLEAN | `git grep -n "session_max_secs\|context_window_tokens\|max_output_tokens" crates/busbar-voice/src/runtime/mod.rs` → 67-72, 96-98, 110-112, 231-232 (all three ceilings read); `grep -n -A6 "fn dispatch_runtime" crates/busbar-voice/src/mount.rs` → `.with_streams(&crate::config::configured())`; `git grep -n configured_session_model crates/busbar/src/main.rs` → 1209. Section is in the config-schema tracked set: `xtask/src/gates/config_schema/schema.rs:305`. | - |
| crates/busbar-voice/src/diagnostics.rs | FINDING | `git grep -n "VOICE_SESSION_LEASE_EXHAUSTED" -- crates/` → 2 hits, both in this file (declaration + the slice). Control: `git grep -n "crate::diagnostics::" -- crates/busbar-a2a/src` → 4 emit-side imports. Also `sed -n '15,16p'` → "Voice is not yet booted by the binary". | X-2200, X-2201 |
| crates/busbar-voice/src/lib.rs | FINDING | `git grep -nE "\.build_runtime" -- crates/` → dispatch only at `appbuild.rs:1482` (keyed `NAMED_MAP_SECTIONS[2]` == `"tools"`), `appbuild.rs:1570` and `test_support/mod.rs:1773` (both `fallback_key()`); this decl is `config_section: "streams"`, `fallback: false` (lib.rs:229,237) so neither predicate can select it. `sed -n '136p;218p'` → "the four neutral ingress routes" vs "mounts the five ingress routes"; `sed -n '553,660p' mount.rs \| grep -c "path:"` → 5. `sed -n '305,307p'` → "NOT YET MOUNTED". | X-2202, X-2206, X-2218, X-2219, X-2220 |
| crates/busbar-voice/src/runtime/carrier.rs | CLEAN | Read in full. `hard_close` is a `swap(true, SeqCst)` returning the transition once; `closed()` registers with `Notify` via `enable()` **before** re-reading the latch, closing the wake-race it documents. `send_downlink` is checked-then-forwarded and returns `false` past close. No money, no secret, no unreachable arm. Constructed in production at `mount.rs:772,1550,1578` and `telephony.rs:85,142`. | - |
| crates/busbar-voice/src/runtime/tests.rs | CLEAN | `grep -c "#\[tokio::test\]\|#\[test\]"` → 17 named cells covering the 5→4 usage fold, host lease reserve/settle/exhaust, settle-past-cap hard close, barge-in truncate, tool correlation and the governed-call sweep. Module declared at `runtime/mod.rs:255`; run by `.github/workflows/ci.yml:1107` (`--features runtime,test-support`). No `#[ignore]`, no tautological assert. | - |
| crates/busbar-voice/src/runtime/voice_d2_billing_oracle.rs | CLEAN | Read in full. Declared at `runtime/mod.rs:261-263` under `#[cfg(test)]`. Seven legs, every nanodollar scalar pinned (1200 reserved, 7/5/5 priced, 17 settled vs cap 15, close-once). It CAN go red: change any arithmetic and the literal asserts fail. Drives the PRODUCTION `HostMeteringPort`, not a stand-in port. | - |
| crates/busbar-voice/src/tests/audit_chain_tests.rs | CLEAN | Declared `mount.rs:1645` under `cfg(all(test, feature = "runtime"))`. Two cells: genesis-seal + reattach, and the front-door inbound open. Both read the chain back through the host seam rather than re-deriving it. | - |
| crates/busbar-voice/src/tests/billing_ledger_tests.rs | CLEAN | Declared `mount.rs:1663` under `runtime`+`test-support`. Drives `TurnMeter::record_turn` over a governed `FixtureHost` and reads `ledger_usage(key).tokens` back → asserts 420. The `requests == 0` assert is deliberately pinned to flip red when the Admit fee lands; that is a live tripwire, not a waiver. | - |
| crates/busbar-voice/src/tests/breaker_tests.rs | CLEAN | Declared `mount.rs:1612`. Both cells drive the real `dial_provider` + `stream_breaker_key` through a host double; the second asserts the OPEN cell refuses **before** the dial. Reds are constructible (change the admit order). | - |
| crates/busbar-voice/src/tests/config_tests.rs | CLEAN | Declared `config.rs:224`. Five cells including `unknown_key_is_refused` (the `deny_unknown_fields` proof) and `empty_section_equals_default` (the hand-written `Default` vs serde-default equality the file's own comment claims). | - |
| crates/busbar-voice/src/tests/diagnostics_tests.rs | FINDING | Read in full. `the_catalog_is_not_empty` is a genuine anti-vacuity floor for the four loop cells — good. But `grep -n "emit\|record\|fire" crates/busbar-voice/src/tests/diagnostics_tests.rs` → no match: nothing here asserts the one declared code is ever produced, which is why X-2201 survived. | X-2201 |
| crates/busbar-voice/src/tests/egress_tests.rs | FINDING | Read in full. Three of four asserts are real. The fourth — `!value.contains(CALLER_TOKEN)` at :55 — passes `PROVIDER_CREDENTIAL` into the builder and then asserts the output lacks a string never handed to it. No edit to `voice_provider_bearer` can make it red. | X-2215 |
| crates/busbar-voice/src/tests/governance_budget_tests.rs | CLEAN | Declared `mount.rs:1648` under `runtime`. Two cells: settle-past-cap hard-closes and refuses further spend; the presenting key is billed and refused at the cap. 15 asserts, all over observed lease state. | - |
| crates/busbar-voice/src/tests/governed_binding_tests.rs | CLEAN | Declared `mount.rs:1655` under `runtime`+`test-support`. Five cells. `:276` counts `open_admitted_telephony(` call sites in the accept path — a source-level census that pins served==governed; it pins `TOOL_REPLY_DEADLINE_SECS` against the plane crate's own const (`:33`) rather than restating 30. | - |
| crates/busbar-voice/src/tests/hook_gate_tests.rs | CLEAN | Declared `mount.rs:1615`. Both cells refuse: reject-all gate on session open, and a reject before the WS upgrade. The refusal is the assertion, so the instrument is red-capable by construction. | - |
| crates/busbar-voice/src/tests/hook_tap_tests.rs | CLEAN | Declared `mount.rs:1618`. Five cells including `a_committed_rewrite_busbar_cannot_read_back_refuses_the_session_open` — the fail-closed arm that `mount.rs:981-999` implements. Byte-identity cell present for the no-hook case. | - |
| crates/busbar-voice/src/tests/metering_lease_tests.rs | CLEAN | Declared `mount.rs:1632`. `a_sessions_ceiling_is_the_tightest_bucket_in_the_callers_chain` exercises the real `principal_cap_nanos` chain walk; the second opens on the host's own lease. | - |
| crates/busbar-voice/src/tests/metrics_tests.rs | CLEAN | Declared `mount.rs:1621`. Reads the plane-labelled counter back off the substrate's metrics capture, not off the emit call. | - |
| crates/busbar-voice/src/tests/mint_tests.rs | CLEAN | Declared `mount.rs:1635`. Drives the mint pass against a loopback provider and asserts the browser JSON shape; the second cell proves the credential comes through the deployment secret resolver. | - |
| crates/busbar-voice/src/tests/mount_tests.rs | CLEAN | Declared `mount.rs:1601`. Eight cells including `the_five_ingress_doors_mount_audience_checked_across_the_http_and_ws_seams` (the count that contradicts lib.rs:136 — see X-2219) and two log-redaction cells proving the provider key never reaches the log. | - |
| crates/busbar-voice/src/tests/scope_gate_tests.rs | CLEAN | Declared `mount.rs:1638`. Three cells: grant read off the key's own scope list, refusal without session scope, and the ungoverned-still-opens arm. The refusal cell is the red. | - |
| crates/busbar-voice/src/tests/sdp_tests.rs | CLEAN | Declared `mount.rs:1624`. Correlates the RTC call id from the `Location` header onto the durable row through the live broker path. | - |
| crates/busbar-voice/src/topology/minter_https.rs | FINDING | Read in full. `git grep -nE "expires_at_unix\s*(<\|>\|<=\|>=\|==\|!=)" -- crates/busbar-voice/src` → rc=1, no match (control: `retry_after_secs > 0` at voice-conform.rs:2177 matches). `#[serde(default)] expires_at: u64` at :89 makes an absent provider expiry read `0`, handed straight to the browser. `grep -n "HttpsTokenMinter::new" crates/busbar-voice/src/mount.rs` → :1019, `requested_ttl_secs` = `None` at the only production site. | X-2204, X-2205 |
| crates/busbar-voice/src/topology/mod.rs | CLEAN | Read in full. `dial_provider` probes the breaker BEFORE any socket, counts the attempt, and folds the outcome back into the same cell; the closed-axis `else` fails closed rather than panicking. `begin_session` runs `run_gauntlet_session` strictly before `open_lease` (verify-before-charge). Every pub item has a production caller: `stream_breaker_key`/`open_admitted_session` at `mount.rs:1503,1544`; `dial_provider` at `mount.rs:43`. | - |
| crates/busbar-voice/src/topology/telephony.rs | CLEAN | Read in full. `git grep -n "begin_telephony(" crates/busbar-voice/src \| grep -v tests` → `mount.rs:752`; `open_admitted_telephony` → `mount.rs:1491`; `g711_config` → `mount.rs:729,1427`. `run()` owns the `LeaseCloseGuard` by value so the reserve closes on every exit path including panic. | - |
| crates/busbar-voice/src/topology/tests/minter_https_tests.rs | FINDING | Read the cell roster: `ttl_over_ceiling_is_clamped_to_max`, `..._under_floor_...`, `ttl_unset_defaults_to_600`, `safety_identifier_header_is_stamped`, `returns_the_ek_value_and_expiry`, `value_without_ek_prefix_is_refused`, `the_real_key_never_appears_in_the_token`. The REQUEST-side TTL is pinned three ways; the RESPONSE-side expiry is only read back (`:145 assert_eq!(token.expires_at_unix, 1_700_000_600)`). No cell feeds a response with an absent, zero or past `expires_at` — so no cell can go red on X-2204. | X-2204 |
| crates/busbar-voice/src/topology/tests/mod.rs | FINDING | `git grep -n "attach(" crates/busbar-voice/src crates/busbar/src \| grep -v webrtc.rs` → 3 hits, ALL in this file (:251, :473, :509). Three cells — `webrtc_sideband_mints_token_locks_config_and_relays_no_media`, `the_gauntlet_refuses_before_the_mint_on_a_denied_destination`, `webrtc_attach_fails_closed_when_mint_fails` — prove govern-before-mint on a function with no production caller. The other five cells (telephony relay, both dial-provider cells, denied-destination, by-value guard) DO cover shipped paths. | X-2203 |
| crates/busbar-voice/src/topology/webrtc.rs | FINDING | `git grep -n "webrtc::attach\|Attached" crates/busbar-voice/src crates/busbar/src` → every hit is inside this file or inside `topology/tests/mod.rs`. Control: `git grep -n "begin_telephony(" ... \| grep -v tests` → `mount.rs:752`, so the sibling topology IS wired and the zero here is a measurement, not a grep artifact. `EphemeralToken.expires_at_unix` is declared here and never compared anywhere. | X-2203, X-2204 |
| crates/busbar-voice-codec/Cargo.toml | FINDING | `grep -n "serde_json" crates/busbar-voice-codec/Cargo.toml` → `:60` in `[dependencies]` AND `:69` in `[dev-dependencies]`. A dev-dep that restates an unconditional normal dep is a second declaration nothing needs and a second place a version pin can drift. | X-2221 |
| crates/busbar-voice-codec/src/ir/codec/gemini/mod.rs | FINDING | Read the usage path (`:353-420`). Every BILLED read goes through `ir::usage::read_count_u64` (`:366,:389,:416`) — correct. But `:394-408`: when the per-modality breakdown yields zero, the stated total is attributed **entirely to `text_in`/`text_out`**. The file's own comment claims that "only changes the audio/text LABEL, never the input/output lane" — true of `to_billing_usage`'s 5→4 fold, and FALSE of the streaming plane's own meter, which prices `audio_tokens_in` and `text_tokens_in` as separate classes (`crates/busbar-plane-streaming/src/plane.rs:589-593`). The three bare `as_u64` calls at `:198,:203,:244` are VAD timings and a response cap, not billed counts — correctly excluded from the seam. | X-2210 |
| crates/busbar-voice-codec/src/ir/config.rs | CLEAN | Read in full. `MaxOutputTokens` deserialize REFUSES an out-of-u32 number rather than defaulting to uncapped (`:61`) — the ceiling cannot move on its own. `deserialize_some` keeps absent/`null`/configured as three distinct `turn_detection` states; the comment at `:144-149` states exactly the failure collapsing them causes and the tests at `ir/codec/tests.rs:205-212` pin the drop path. | - |
| crates/busbar-voice-codec/src/ir/control.rs | CLEAN | Read in full. Every variant of `IrDuplexControl` and `IrVad` is constructed on a real wire path (`git grep -n "ItemTruncate\|ResponseCancel\|InputAudioClear\|SemanticVad" -- crates/` → hits in both dialect codecs and the plane). `threshold: f32` is a VAD amplitude, not a money quantity. | - |
| crates/busbar-voice-codec/src/ir/event.rs | CLEAN | `git grep -n "IrServerEvent::RateLimits\|::AudioDone\|::SpeechStopped\|::SessionCreated" -- crates/` → every variant is both produced by a reader and consumed by a writer/plane arm; `RateLimits` at `codec/mod.rs:779` (read) and `:1013` / `gemini:847` (written). No unreachable arm. | - |
| crates/busbar-voice-codec/src/ir/mod.rs | CLEAN | Module declarations only; all seven submodules exist on disk (`find crates/busbar-voice-codec/src/ir -name '*.rs'`), and every re-export at `:37-44` resolves to a type constructed elsewhere in the crate. | - |
| crates/busbar-voice-codec/src/ir/tool.rs | CLEAN | Read in full. All four `IrDuplexTool` variants are constructed (`git grep -n "IrDuplexTool::Call" -- crates/`). `call_ref()`/`call_id()` are exhaustive matches with no `_` arm, so a new variant fails to compile rather than silently falling through. | - |
| crates/busbar-voice-codec/src/ir/usage.rs | CLEAN | Read in full — money file. `to_billing_usage` nets `cached` out of the input lane with `saturating_sub` (floors at zero rather than wrapping), sums with `saturating_add`, and keys only the three EXISTING reserved units. `read_count_u64`'s `f64` use is bounded by `(0.0..2^53)` + `fract() == 0.0`, which also rejects NaN and both infinities. `git grep -n "as_u64" crates/busbar-voice-codec/src \| grep -v tests` → the only non-seam uses are VAD timings, a response cap, and the Twilio grammar's sequence numbers; no billed count bypasses the seam. The `unwrap_or_default()` caveat is already stated in-file and owned by decision #81. | - |
| crates/busbar-voice-codec/src/lib.rs | FINDING | `:31` declares `pub const PLANE_KEY: &str = "voice";` while `crates/busbar-plane-streaming/src/meta.rs:286` declares `const KEY: &'static str = "streaming";` for the same fourth plane. Two identities, two registries. `grep -rn "feature = \"plane-streaming\"" crates/` → only a doc comment; the live bin feature is `plane-voice` (`crates/busbar/Cargo.toml:221`). | X-2206 |
| crates/busbar-voice-codec/src/topology/tests/twilio_tests.rs | CLEAN | Eight named cells including `forgery_guard_rejects_mismatched_stream_sid`, `start_media_format_guard_refuses_non_g711` and `malformed_and_unknown_frames_fail_closed` — three refusal cells, so the instrument is red-capable. Gated on `runtime`, which `ci.yml:1108` names explicitly (`-p busbar-voice-codec --features runtime`). | - |
| crates/busbar-voice-codec/tests/alloc_gate.rs | FINDING | Instrument is sound: `the_borrowed_read_and_the_owned_read_agree` fixes the semantics before the count, and `owned == borrowed + 1` is an exact equality that fails in both directions. Runs under the default workspace `cargo test` (the `ir` module is unconditional). Defect is the header: `head -1` → `//! What reading one wire frame...`, no SPDX/copyright line, unlike all 10 sibling files in this crate. | X-2212 |
| crates/busbar-plane-streaming/Cargo.toml | CLEAN | "NO FEATURES, ON PURPOSE" is true of the manifest (`grep -n "^\[features\]"` → no match). The declared closure (`busbar-contract`, `busbar-voice-codec`, `serde_json`, `bytes`, `async-trait`) holds no async I/O; the `test-seal` dev-dep is the blessed #65 fixture. Workspace member at `Cargo.toml:33`. | - |
| crates/busbar-plane-streaming/src/governed.rs | CLEAN | Read in full. `ReplyRefusal`'s two arms are both produced (`git grep -n "ReplyRefusal::" -- crates/` → the root's own table and the voice runtime). `GovernedCalls` is dependency-inverted with exactly two methods and no widening. Re-exported into the shipped path at `crates/busbar-voice/src/runtime/mod.rs:31` and consumed at `runtime/session.rs:26`. | - |
| crates/busbar-plane-streaming/src/lib.rs | FINDING | `git grep -n "StreamingPlane::new(" -- crates/ \| grep -v tests` → one hit, `crates/busbar/src/main.rs:505`, with `&[]`. `crates/busbar/src/root/registry.rs:463` pushes `StreamingPlane::EMPTY`. So `Upstream`, `upstream_for_dialect` and every routing branch that reads them answer `None`/empty in every shipping build. `git grep -n plane_for_root -- crates/` → 2 hits, both the definition and its own re-export; the root never calls it. `head -1 src/lib.rs` → no SPDX line. | X-2207, X-2208, X-2212 |
| crates/busbar-plane-streaming/src/meta.rs | FINDING | Meter roster VERIFIED against the source of truth: `grep -n "audio_tokens_in" docs/design/ARCHITECTURE.md` → `:1185` names exactly `audio_tokens_in/out, text_tokens_in/text_tokens_out, cached_tokens, audio_seconds_in, tool_calls` — seven, matching `METER_CLASSES`. Every `CLASS_*` const has a real consumer in `plane.rs` and `crates/busbar/src/root/units_voice.rs`. `audio_seconds_in` rounds UP, so arrived audio never settles at zero. Defect: `git grep -n "CONFIG_SCHEMA" -- crates/busbar-kernel crates/busbar/src` → no reader (control: `PlaneMeta>::KEY` has 16 readers in `crates/busbar/src`), and nothing parses the `lanes`/`default_dialect` keys it declares. No SPDX header. | X-2209, X-2212 |
| crates/busbar-plane-streaming/src/tests/codec.rs | FINDING | 25 cells / 64 asserts over real openai-realtime and twilio wire fixtures; no `#[ignore]`, no tautology (`grep -n "assert!(true)\|#\[ignore\]"` → no match). Three cells (`:592,:649,:704,:748`) drive the twilio-media-streams dialect, which the boot registers no claim for. No SPDX header. | X-2212, X-2222 |
| crates/busbar-plane-streaming/src/tests/harness.rs | FINDING | `diff <(sed -n '1,90p' src/tests/harness.rs) <(sed -n '1,90p' tests/harness/mod.rs)` → `LeakPlaneAlloc`, `EmptyConfig`, `WsStack`, `TestSeal`, `ctx`, `frame`, `unit`, `destination` are near-verbatim twins across the two harnesses. `FreshSession` at `:98-118` carries `#[allow(dead_code)]` and its own doc admits "Not yet used by a test in this crate". No SPDX header. | X-2216, X-2217, X-2212 |
| crates/busbar-plane-streaming/src/tests/mod.rs | FINDING | The `style` walker at `:185-217` never asserts it visited a file (`find crates/busbar-plane-streaming/src -name '*.rs' \| wc -l` → 16 today, but a walker over an empty dir passes green) — unlike `busbar-voice/src/tests/diagnostics_tests.rs::the_catalog_is_not_empty`, the same anti-vacuity floor in this same slice. Its doc claims a general "two-letter prefix, a hyphen and digits" rule; `:208-211` matches only the literal bytes `P`,`B`,`-`,digit. `mod purity` at `:32-83` duplicates `tests/purity.rs:24-49`. No SPDX header. | X-2213, X-2214, X-2216, X-2212 |
| crates/busbar-plane-streaming/src/tests/twilio.rs | FINDING | Six cells, four of them refusals (empty sid, non-g711 format, and both at the plane entrypoint) — red-capable. But `<StreamingPlane as PlaneMeta>::CLAIMS.len() == 4` (asserted at `tests/conformance.rs:294`) and `claims.rs:24` states the twilio claim is dropped "until `busbar-transport-twilio-media` registers a key" — `ls -d crates/busbar-transport-*` → seven transports, no twilio-media; `crates/busbar/src/root/tests/registry.rs:528` asserts boot REFUSES a `twilio-media` claim. No SPDX header. | X-2222, X-2212 |
| crates/busbar-plane-streaming/src/tests/ulaw.rs | FINDING | Instrument is good — ITU-T reference vectors in both directions (`0xFF↔0`, `0x00↔-32124`) plus a 256-byte stability sweep, not round-trip fuzz. Same unreachable-dialect problem as the transform it covers. No SPDX header. | X-2222, X-2212 |
| crates/busbar-plane-streaming/src/tools.rs | CLEAN | Read in full. `ToolExecutor::serves` defaults to `true` — the safe end, documented as such. `EchoToolExecutor` is bound in production at `crates/busbar-voice/src/mount.rs:511` and `runtime/mod.rs`. The port is re-exported into the shipped path at `crates/busbar-voice/src/runtime/mod.rs:21`. Module doc is present, satisfying the crate's `#![deny(missing_docs)]`. | - |
| crates/busbar-plane-streaming/src/ulaw.rs | FINDING | Transform itself is correct against ITU-T G.711 and is exercised at `plane.rs:157,333,1303`. Two defects: `:15` documents "`CLIP = 8159`" while `:31` declares `const CLIP: i32 = 32635` (the 16-bit-domain value — the code is right, the prose is wrong); and the only lane that reaches it is `twilio-media-streams`, which has no registered claim. No SPDX header. | X-2211, X-2222, X-2212 |
| crates/busbar-plane-streaming/tests/alloc_gate.rs | FINDING | Instrument is strong: `the_rendered_envelope_is_the_one_the_serializer_produced` pins the bytes across five payload lengths and five identifiers (including `a"b\c` and non-ASCII) BEFORE the count; `RENDER_ALLOCS = 0` is an exact equality and `before > count` guards the reason the renderer exists. Subject is the twilio downlink renderer, whose dialect is unclaimed. No SPDX header. | X-2212, X-2222 |
| crates/busbar-plane-streaming/tests/conformance.rs | FINDING | The strongest cell in the slice: one reserve→turns→settle narrative pinning `audio_tokens_in=10`, `audio_tokens_out=20`, `text_tokens_in=3`, `text_tokens_out=4`, `cached_tokens=1` off real wire fixtures, with the in/out split called out as the money-relevant part. It runs against `StreamingPlane::new(UPSTREAMS)` (`:27-34`) — a configuration the composition root never builds (see X-2207). No SPDX header. | X-2207, X-2212 |
| crates/busbar-plane-streaming/tests/harness/mod.rs | FINDING | Near-verbatim twin of `src/tests/harness.rs` (same eight items, same bodies). No SPDX header. | X-2216, X-2212 |
| crates/busbar-plane-streaming/tests/purity.rs | FINDING | The forbid-list at `:112-140` IS red-capable (adding a kernel dep and using it trips it) and `is_comment` is load-bearing and documented. Zero verified with a positive control: `grep -rnE "busbar_kernel\|busbar_substrate\|busbar_plane_llm\|busbar_voice::" crates/busbar-plane-streaming/src --include='*.rs' \| grep -vE ":[0-9]+:[[:space:]]*(//\|\*)"` → rc=1, while the same command over `busbar_voice_codec` returns 3 hits. Defects: `walk` asserts nothing about file count; `:24-49` duplicates `src/tests/mod.rs::purity`. No SPDX header. | X-2213, X-2216, X-2212 |

## ROWS RAISED

### X-2200 · the crate manifest and the diagnostics module still say boot-mounting has not landed; `lib.rs` says it has
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '11,14p' crates/busbar-voice/Cargo.toml
# STATUS: ... Boot-mounting into the composition root (PLANE_DECL's build / admission / routes hooks) is
# separate, tracked work. It compiles, registers, and is strong-form deletable.

$ sed -n '15,16p' crates/busbar-voice/src/diagnostics.rs
//! names one stable path: `busbar_voice::DIAGNOSTICS`. Voice is not yet booted by the binary
//! (`register_diagnostics` includes it at M5); the export exists now so M5 is a one-line addition.

$ sed -n '13,14p' crates/busbar-voice/src/lib.rs
//! BOOT-MOUNTING HAS LANDED — this paragraph used to say it was separate, tracked work, and that is
//! no longer true.

$ git grep -n "busbar_voice::DIAGNOSTICS\|busbar_voice::PLANE_DECL" -- crates/busbar/src/main.rs
crates/busbar/src/main.rs:379:    installed.extend_from_slice(busbar_voice::DIAGNOSTICS);
```
The correction was applied to `lib.rs` and to nowhere else. Both sibling files still carry the
sentence `lib.rs` explicitly says is no longer true, and one of them names a milestone ("M5") as
future work that shipped.
ACTION:    Rewrite `crates/busbar-voice/Cargo.toml:11-14` and `crates/busbar-voice/src/diagnostics.rs:15-16` to the post-M5 wording `lib.rs:13-18` already carries (PLANE_DECL / DIAGNOSTICS / ws-arrivals / governed-calls installed under `plane-voice`, which is in `default`).

### X-2201 · `BUSBAR-7050` is declared, installed into the runtime catalog and documented to operators — and never emitted
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "VOICE_SESSION_LEASE_EXHAUSTED" -- crates/
crates/busbar-voice/src/diagnostics.rs:23:pub const VOICE_SESSION_LEASE_EXHAUSTED: Diagnostic = Diagnostic {
crates/busbar-voice/src/diagnostics.rs:41:pub static DIAGNOSTICS: &[&Diagnostic] = &[&VOICE_SESSION_LEASE_EXHAUSTED];

# positive control — a sibling plane's diagnostics ARE named from emit sites:
$ git grep -n "crate::diagnostics::" -- crates/busbar-a2a/src
crates/busbar-a2a/src/a2a/local.rs:91:use crate::diagnostics::{A2A_PUSH_CONFIG_UNDELETED, A2A_PUSH_CONFIG_UNRECORDED};
crates/busbar-a2a/src/a2a/originate.rs:27:use crate::diagnostics::{A2A_OUTBOUND_CRED_UNLEASED, A2A_PUSH_REARM_FAILED};
crates/busbar-a2a/src/a2a/plane.rs:43:use crate::diagnostics::A2A_REVERIFY_CADENCE_UNPARSED;

$ grep -n "BUSBAR-7050" docs/voice.md
docs/voice.md:332:  ... which is when the fail-closed D2 diagnostic (`BUSBAR-7050`, below) fires.
docs/voice.md:341:| `BUSBAR-7050` | Voice session hard-closed on metering-lease exhaustion | ...
```
The hard-close itself DOES happen — `runtime/tests.rs::settle_past_cap_hard_closes_the_carrier` and
`voice_d2_billing_oracle.rs` LEG 4 both prove `LeaseState::Exhausted ⇒ must_close()`. What is missing
is the emit: the code the operator is told to look for in `docs/voice.md:341` never appears. The
plane's own `diagnostics_tests.rs` cannot catch this — all five of its cells check catalog shape, not
production. `docs/design/playbook/voice-dod-finish-checklist.md:69` already lists this as item B5.
ACTION:    At the `LeaseState::Exhausted` branch that hard-closes the carrier (`crates/busbar-voice/src/runtime/session.rs`, the `settle` → `must_close()` arm), emit `diagnostics::VOICE_SESSION_LEASE_EXHAUSTED` through the neutral catalog seam the sibling planes use, and add one cell to `diagnostics_tests.rs` (or `governance_budget_tests.rs`) that drives a session past its cap and reads the emitted code back.

### X-2202 · the voice plane's `build_runtime` hook is wired to a real constructor the composition root cannot reach
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -nE "\.build_runtime" -- crates/
crates/busbar-kernel/src/appbuild.rs:1482:        d.build_runtime          # keyed on NAMED_MAP_SECTIONS[2]
crates/busbar-kernel/src/appbuild.rs:1570:            .and_then(|d| d.build_runtime)   # keyed on fallback_key()
crates/busbar-kernel/src/test_support/mod.rs:1773:                .and_then(|d| d.build_runtime)   # also fallback_key()
crates/busbar/tests/plane_isomorphism.rs:63:    ("build_runtime", |d| d.build_runtime.is_some()),

$ grep -n "pub const NAMED_MAP_SECTIONS" crates/busbar-kernel/src/plane/config.rs
757:pub const NAMED_MAP_SECTIONS: [&str; 4] = ["identity-providers", "export", "tools", "agents"];

$ grep -n "config_section:\|fallback:" crates/busbar-voice/src/lib.rs
229:        fallback: false,
237:        config_section: "streams",
```
There are exactly two dispatch predicates and voice matches neither: its section is `"streams"`
(absent from `NAMED_MAP_SECTIONS`) and it is not the fallback plane. `crates/busbar-voice/src/config.rs:170`
states the consequence in its own words — "nothing calls the plane's runtime-build hook". The served
runtime is built instead by `mount::voice_build` → `dispatch_runtime()` (`mount.rs:487-513`), which
DOES read the operator's `streams:` posture, so no behaviour is currently lost. What is lost is the
`prior`-generation carry-over that only the hook's signature can deliver, and the truth of the
`plane_isomorphism` row at `crates/busbar/tests/plane_isomorphism.rs:63`, which reads `is_some()` on a
field the host will never invoke — a green that proves nothing.
ACTION:    Either (a) give the host a third dispatch predicate that composes a runtime slot for any plane declaring a non-named-map `config_section` with a `build_runtime`, and make `voice_build` read that slot instead of calling `dispatch_runtime()` itself; or (b) set `VOICE_BUILD_RUNTIME = None` and delete `runtime::build_runtime`, keeping `build_runtime_hosted` (which IS the live path). Do not leave the field `Some` with no dispatcher — that is what makes the isomorphism row a false green.

### X-2203 · Topology A's assembly function `webrtc::attach` has no production caller; three security invariants are proven on code the served route does not run
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "attach(" -- crates/busbar-voice/src crates/busbar/src | grep -v webrtc.rs
crates/busbar-voice/src/topology/tests/mod.rs:251:    let attached = attach(
crates/busbar-voice/src/topology/tests/mod.rs:473:    let r = attach(
crates/busbar-voice/src/topology/tests/mod.rs:509:    let r = attach(

# positive control — the SIBLING topology's assembly fn is called from the mount:
$ git grep -n "begin_telephony(" -- crates/busbar-voice/src | grep -v tests
crates/busbar-voice/src/mount.rs:752:        Ingress::Telephony => match begin_telephony(

$ git grep -n "Attached" -- crates/busbar-voice/src crates/busbar/src
# every hit is inside topology/webrtc.rs itself
```
`attach()` carries the ordering invariant in a comment at `webrtc.rs:120-123`: "GOVERN FIRST, MINT
SECOND ... NOTHING is minted on a denied or budget-refused session". Three cells prove it —
`webrtc_sideband_mints_token_locks_config_and_relays_no_media`,
`the_gauntlet_refuses_before_the_mint_on_a_denied_destination`, `webrtc_attach_fails_closed_when_mint_fails`.
The SHIPPED sideband route does not use any of it: `mount.rs:772` builds its own `Carrier::sideband()`
session, and the `ek_` is minted separately by `serve_mint` at `mount.rs:1008-1030`, which constructs
`HttpsTokenMinter` directly and opens no metering lease. So the whole `Attached` bundle — including the
by-value `LeaseCloseGuard` whose field doc says it exists "so the reserve is never orphaned" — ships
in tests only, and the invariant the tests certify is certified about the wrong function.
ACTION:    Decide which is the real Topology A: either route `mount.rs`'s sideband + mint passes through `webrtc::attach` (so the three cells cover the served path), or delete `attach`/`Attached` and re-home those three cells onto the `mount.rs` passes that actually serve. Do not leave a second, tested, unreachable implementation of the govern-before-mint ordering beside an untested live one.

### X-2204 · the minted `ek_` secret's expiry is never validated, and an absent provider expiry becomes `0`
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -nE "expires_at_unix\s*(<|>|<=|>=|==|!=)|(<|>|<=|>=|==|!=)\s*.*expires_at_unix" -- crates/busbar-voice/src
$ echo $?
1
# positive control (same grep shape, a value that IS compared):
$ git grep -nE "retry_after_secs > 0" -- crates/busbar-voice
crates/busbar-voice/src/bin/voice-conform.rs:2177: ... if retry_after_secs > 0 => {}

$ sed -n '85,90p' crates/busbar-voice/src/topology/minter_https.rs
struct ClientSecretResponse {
    value: String,
    #[serde(default)]
    expires_at: u64,
}

$ sed -n '147,158p' crates/busbar-voice/src/topology/minter_https.rs
    if !parsed.value.starts_with(EK_PREFIX) { ...refuse... }
    Ok(EphemeralToken { value: parsed.value, expires_at_unix: parsed.expires_at })

$ sed -n '1019,1027p' crates/busbar-voice/src/mount.rs
    let minter = HttpsTokenMinter::new(egress_client(), &p.base_url, &p.api_key, owner, None);
    ... "expires_at_unix": token.expires_at_unix,
```
The mint clamps the REQUESTED lifetime to `[10, 7200]` and refuses a value lacking the `ek_` prefix —
both good, both tested. The RESPONSE's expiry is accepted verbatim and never checked: not against
`now`, not against `now + clamped_ttl_secs()`, not against zero. `#[serde(default)]` means a provider
response that omits `expires_at` (a schema change, a proxy that strips it, an error body that happens
to parse) yields `expires_at_unix: 0`, which busbar then publishes to the browser as the secret's
expiry. This is the "capability minted without a ceiling" shape: busbar asks for a ceiling, is handed
back an unverified one, and republishes it as if it had checked.
ACTION:    In `HttpsTokenMinter::mint`, after the `ek_` prefix check, refuse a response whose `expires_at` is `0`, is not in the future, or exceeds the requested window — `MintError::Provider("client-secret response carries no usable expiry")`. Add the red-first cell to `topology/tests/minter_https_tests.rs` (a `MockServer` reply with `expires_at` omitted, and one with a past timestamp).

### X-2205 · `HttpsTokenMinter::requested_ttl_secs` is a knob no deployment can turn
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "HttpsTokenMinter::new" -- crates/busbar-voice/src
crates/busbar-voice/src/mount.rs:1019:    let minter = HttpsTokenMinter::new(egress_client(), &p.base_url, &p.api_key, owner, None);
crates/busbar-voice/src/topology/tests/minter_https_tests.rs:44:    HttpsTokenMinter::new(

$ grep -n "session_max_secs\|max_output_tokens\|context_window_tokens" crates/busbar-voice/src/config.rs | head -3
# the `streams:` grammar carries three ceilings and no ek_ lifetime
```
The only production construction passes `None`, so every minted browser secret takes `DEFAULT_TTL_SECS
= 600` and an operator has no way to shorten it. Three of the seven cells in
`minter_https_tests.rs` exercise the clamp against values only a test can supply.
ACTION:    Either add an `ek_ttl_secs` field to `StreamsCfg` and plumb `config::configured().ek_ttl_secs` into `mount.rs:1019` (which also puts it in the config-schema tracked set), or drop the parameter and pin `DEFAULT_TTL_SECS` at the one call site. Note this touches `crates/busbar-voice/src/config.rs`, which is a `config-schema` SOURCES entry — the additive-only ratchet must be run, never blessed.

### X-2206 · the fourth plane still answers to two names, and the bin feature is `plane-voice`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "pub const PLANE_KEY" crates/busbar-voice-codec/src/lib.rs
31:pub const PLANE_KEY: &str = "voice";

$ grep -n "const KEY" crates/busbar-plane-streaming/src/meta.rs
286:    const KEY: &'static str = "streaming";

$ grep -n "^plane-voice\|^default =" crates/busbar/Cargo.toml
192:default = [... "plane-voice", ... "root-voice", ...]
221:plane-voice = ["dep:busbar-voice", "dep:busbar-transport-ws", "busbar-voice?/runtime", "busbar-kernel/plane-voice"]

$ grep -rn "feature = \"plane-streaming\"" crates/
crates/busbar-plane-streaming/src/register.rs:20://! #[cfg(feature = "plane-streaming")]     <- a doc comment; no such feature exists
$ grep -rn "feature = \"plane-voice\"" crates/busbar/src | head -3
crates/busbar/src/main.rs:299,378,392
```
`PLANE_DECL.key = "voice"` (lib.rs:227), `config_section = "streams"`, `PlaneMeta::KEY = "streaming"`,
feature `plane-voice`, root module `units_voice.rs`. Per spec #18 the plane is STREAMING and voice is
one dialect; per #17 the crate rename + feature flip is one atomic change, so this row records the
surviving nouns rather than touching them. `crates/busbar-plane-streaming/tests/purity.rs:54`
(`the_plane_key_is_streaming_never_voice`) already asserts the correct half.
ACTION:    Fold into the #17/#18 atomic rename wave: `busbar-voice` → `busbar-streaming`, `busbar-voice-codec` → `busbar-streaming-codec`, `PLANE_KEY`/`PLANE_DECL.key` `"voice"` → `"streaming"`, feature `plane-voice` → `plane-streaming`, `root-voice` → `root-streaming`, `crates/busbar/src/root/units_voice.rs` → `units_streaming.rs`. Not a standalone edit. `qa/kind-isolation.toml:2654` already records the exception this rename retires.

### X-2207 · the streaming plane is registered with zero upstreams in every shipping build
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "StreamingPlane::new(\|StreamingPlane::EMPTY" -- crates/ | grep -v "/tests"
crates/busbar-plane-streaming/src/register.rs:75:    Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>
crates/busbar/src/main.rs:505:        plane: busbar_plane_streaming::StreamingPlane::new(&[]),
crates/busbar/src/root/registry.rs:463:    planes.push(Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>);

$ grep -n "as_slice" crates/busbar/src/root/units_voice.rs
226:    pub fn as_slice(&self) -> [Upstream; 2] {     # its ONLY occurrence — never called
```
`ProviderEndpoints::new` (`units_voice.rs:204-222`) is the one place the root composes real
`Upstream` values, and `as_slice()` — the method whose doc says "The pair as the plane reads it" — has
no caller. So `upstream_for_dialect` returns `None` and `upstreams()` returns `&[]` at every live
call site: `plane.rs:208-212` (the dialect pick), `:531-534` (the paired-turn config index) and
`:752-758`. The 306-line `tests/conformance.rs` rig proves a full reserve→turns→settle narrative
against a plane the root does not build, and `src/tests/mod.rs::route` proves the gemini-lane routing
fix on the same never-built configuration.
ACTION:    Have `crates/busbar/src/root/registry.rs:463` register `StreamingPlane::new(...)` over the interned `ProviderEndpoints::as_slice()` (leaked once at registration, which is what the `&'static` field and the "leak-once rule" doc at `units_voice.rs:185-190` were written for), and make `main.rs:505` take the same value. Then add one cell asserting the registered plane's `upstreams()` is non-empty when endpoints are configured — the floor that would have caught this.

### X-2208 · `plane_for_root()` is exported for the composition root and the composition root does not call it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "plane_for_root" -- crates/
crates/busbar-plane-streaming/src/lib.rs:88:pub use register::{plane_for_root, CAP_KEY};
crates/busbar-plane-streaming/src/register.rs:74:pub fn plane_for_root() -> Arc<dyn Plugin> {

$ sed -n '460,464p' crates/busbar/src/root/registry.rs
    #[cfg(feature = "plane-voice")]
    planes.push(Arc::new(StreamingPlane::EMPTY) as Arc<dyn Plugin>);
```
`register.rs:70-72` says "Real, callable code — the plane side of S1/S4 is complete. The root calls
this under the `plane-streaming` feature." Neither half is true: the root hand-rolls the same
expression, and there is no `plane-streaming` feature (`grep -rn 'feature = "plane-streaming"'
crates/` → one doc comment). `register.rs:49` likewise says "The `plane-streaming` feature forwards to
that same transport edge"; the forward that exists is `plane-voice → dep:busbar-transport-ws`
(`crates/busbar/Cargo.toml:221`).
ACTION:    Make `registry.rs:463` call `busbar_plane_streaming::plane_for_root()` (which is also where the non-empty upstream list from X-2207 should be supplied), and correct `register.rs:20,49,71` to name the feature that exists until the #17/#18 rename flips it.

### X-2209 · `PlaneMeta::CONFIG_SCHEMA` has no reader, and the streaming plane's schema names keys nothing parses
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "CONFIG_SCHEMA" -- crates/busbar-kernel crates/busbar/src
crates/busbar/src/root/plane_decision.rs:94:/// ... and in that crate's `CONFIG_SCHEMA`, both as prose      <- a doc comment
# positive control, same shape, a sibling associated const that IS read:
$ git grep -c "PlaneMeta>::KEY" -- crates/busbar/src/main.rs
2

$ git grep -n "default_dialect" -- crates/
crates/busbar-plane-llm/src/meta.rs:202:    "default_dialect": { "type": "string" },
crates/busbar-plane-streaming/src/meta.rs:281:    "default_dialect": { "type": "string" }
# no parser, no validator, no boot check names either key
```
Six plane crates each declare a `CONFIG_SCHEMA` string; the kernel and the composition root read
none of them. The streaming plane's declares `lanes` and `default_dialect`, neither of which any code
parses. `busbar-plane-a2a` and `busbar-plane-decision` at least carry a cell that parses their own
schema as JSON; `busbar-plane-streaming` does not, so its schema is not even known to be well-formed.
Scope note: the unread trait const is a `busbar-contract` fact, larger than this slice — see the
out-of-slice section.
ACTION:    Either wire `PlaneMeta::CONFIG_SCHEMA` into the boot config validation (validate each plane's own block against the schema it declares), or remove the const from `busbar_contract::plane::PlaneMeta` and the six implementations. Minimum interim fix inside this slice: add a cell to `src/tests/mod.rs` that `serde_json::from_str`s `<StreamingPlane as PlaneMeta>::CONFIG_SCHEMA`, matching `busbar-plane-a2a/src/tests/meta.rs:60`.

### X-2210 · a Gemini turn with no per-modality breakdown bills its whole audio figure under the TEXT meter class
CLASS:     money
CERTAINTY: PARK
EVIDENCE:
```
$ sed -n '394,408p' crates/busbar-voice-codec/src/ir/codec/gemini/mod.rs
    let (audio_in, text_in) = {
        let (a, t) = (modality_tokens(pd, "AUDIO"), modality_tokens(pd, "TEXT"));
        if a.saturating_add(t) == 0 { (0, stated_total("promptTokenCount")) } else { (a, t) }
    };
    let (audio_out, text_out) = { ... (0, stated_total("responseTokenCount")) ... };

$ sed -n '588,594p' crates/busbar-plane-streaming/src/plane.rs
        let classes = [
            (meta::FACT_AUDIO_TOKENS_IN,  meta::CLASS_AUDIO_TOKENS_IN),
            (meta::FACT_AUDIO_TOKENS_OUT, meta::CLASS_AUDIO_TOKENS_OUT),
            (meta::FACT_TEXT_TOKENS_IN,   meta::CLASS_TEXT_TOKENS_IN),
            (meta::FACT_TEXT_TOKENS_OUT,  meta::CLASS_TEXT_TOKENS_OUT),

$ sed -n '958,962p' crates/busbar/src/root/units_voice.rs
            meta::CLASS_AUDIO_TOKENS_IN  => reported(self.audio_tokens_in),
            meta::CLASS_TEXT_TOKENS_IN   => reported(self.text_tokens_in),
```
CELL: `usage_from_metadata`, `crates/busbar-voice-codec/src/ir/codec/gemini/mod.rs:388-419`.
DIFF: a Gemini `usageMetadata` carrying `promptTokenCount: 1000` with no `promptTokensDetails` reads
as `audio_in = 0, text_in = 1000`, not `audio_in = 1000`.
ROOT CAUSE: the fallback's justification comment (`:381-386`) is "this only changes the audio/text
LABEL, never the input/output lane the billing fold sums onto". That is TRUE of
`IrDuplexUsage::to_billing_usage`, which folds 5 classes onto 3 reserved keys — and FALSE of the
streaming plane's own meter, which emits `audio_tokens_in` and `text_tokens_in` as SEPARATE
`MeterClassDecl`s (`meta.rs:85-108`) that a rate card prices independently. `meta.rs:76-83` states
the governing rule in the file's own words: "The class label is what selects the unit price, so a
mislabelled direction is a mispriced turn rather than a cosmetic one." The same argument applies to
a mislabelled MODALITY. The fallback is still strictly better than the zero it replaced (silent
under-billing, which #42 forbids) — this is a mispricing question, not a zeroing one.
RECOMMENDATION: owner ruling on which is correct for a breakdown-less Gemini turn — (a) keep the
conservative text attribution and state the exposure explicitly in `meta.rs` beside `METER_CLASSES`,
(b) attribute to `audio_*` instead (the dominant modality on a live voice turn, and the direction
that under-bills less often), or (c) emit a distinct `unattributed_tokens` class so the rate card
decides. Do not self-approve. Whichever is chosen, the justification comment at
`gemini/mod.rs:381-386` must stop claiming the label is lane-only, because one of this plane's two
pricing paths prices on the label.

### X-2211 · `ulaw.rs` documents `CLIP = 8159`; the constant is `32635`
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '14,16p' crates/busbar-plane-streaming/src/ulaw.rs
//! giving the position within the segment. The constants below (`BIAS = 0x84`, `CLIP = 8159`) and
//! the segment table are the values the ITU-T G.711 reference algorithm defines; ...

$ sed -n '29,31p' crates/busbar-plane-streaming/src/ulaw.rs
/// The largest linear magnitude (after removing the sign) a sample is clamped to before encoding.
/// The ITU-T G.711 reference value; every larger magnitude quantizes to this segment's top code.
const CLIP: i32 = 32635;
```
The CODE is right: `32635` is the G.711 reference clip for 16-bit linear input, which is what
`pcm16_to_ulaw_byte(sample: i16)` takes. `8159` is the 13-bit-domain clip. The prose invites a
"correction" that would clamp every sample above 8159 and destroy the top two segments of the
transform — a silent audio-quality regression the round-trip cell at `src/tests/ulaw.rs:28` would
NOT catch, because clamping preserves decode-stability. A reader checking the doc against the
standard finds the doc wrong and the code right, which is the worst ordering.
ACTION:    Correct `crates/busbar-plane-streaming/src/ulaw.rs:15` to `CLIP = 32635`, and say why (the 16-bit input domain) so the 8159 figure is not re-introduced.

### X-2212 · 13 of 55 slice files carry no SPDX/copyright header while the other 42 do
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ for f in $(cat .sweep/S13-streaming.txt); do case "$f" in *.rs) head -1 "$f" | grep -q SPDX || echo "NO SPDX: $f";; esac; done
NO SPDX: crates/busbar-voice-codec/tests/alloc_gate.rs
NO SPDX: crates/busbar-plane-streaming/src/lib.rs
NO SPDX: crates/busbar-plane-streaming/src/meta.rs
NO SPDX: crates/busbar-plane-streaming/src/tests/codec.rs
NO SPDX: crates/busbar-plane-streaming/src/tests/harness.rs
NO SPDX: crates/busbar-plane-streaming/src/tests/mod.rs
NO SPDX: crates/busbar-plane-streaming/src/tests/twilio.rs
NO SPDX: crates/busbar-plane-streaming/src/tests/ulaw.rs
NO SPDX: crates/busbar-plane-streaming/src/ulaw.rs
NO SPDX: crates/busbar-plane-streaming/tests/alloc_gate.rs
NO SPDX: crates/busbar-plane-streaming/tests/conformance.rs
NO SPDX: crates/busbar-plane-streaming/tests/harness/mod.rs
NO SPDX: crates/busbar-plane-streaming/tests/purity.rs

# and there is no gate that would ever have said so:
$ git grep -in "license.header\|license_header" -- xtask/src scripts/ .github/workflows/
$ echo $?
1
```
Note which files DO have the header inside the same crate: `governed.rs` and `tools.rs` — the two
`busbar-plane-streaming` source files that were MOVED in from `busbar-voice`, which had the header
already. Every file authored natively in this crate lacks it. All three manifests declare
`license = "Apache-2.0"`, so the shipped source disagrees with the shipped manifest, and nothing in
CI notices.
ACTION:    Add the two-line `// SPDX-License-Identifier: Apache-2.0` / `// Copyright (C) 2026 Busbar Inc and contributors` prelude to the 13 files above, and add a header check to the existing source-walking gates (it is one more predicate in `xtask/src/gates/`, sharing the walk that `construction`/`qa_names` already perform over `git ls-files '*.rs'`). A convention with no instrument is how this reached 13 files.

### X-2213 · both source walkers in `busbar-plane-streaming` pass green over an empty directory
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '77,90p' crates/busbar-plane-streaming/tests/purity.rs      # walk()
$ sed -n '185,196p' crates/busbar-plane-streaming/src/tests/mod.rs   # walk()
# both: for entry in read_dir(dir)...  { if .rs { f(path, text) } }
# neither counts what it visited; both assert only `offenders.is_empty()`

# the same slice already contains the correct shape:
$ sed -n '15,26p' crates/busbar-voice/src/tests/diagnostics_tests.rs
fn the_catalog_is_not_empty() {
    assert!(!DIAGNOSTICS.is_empty(),
        "the diagnostics catalog is empty, which makes every loop test in this file vacuous");
```
`the_plane_names_no_kernel_side_crate` and `no_section_sign_or_parity_binding_identifier_anywhere_in_source`
are both "collect offenders, assert empty" over a directory walk. A walk that visits zero files
collects zero offenders and passes — so a moved `src/`, a renamed crate directory, or a `CARGO_MANIFEST_DIR`
change would make both green while checking nothing. The zero they report today is real (verified
with a positive control: the same grep shape over `busbar_voice_codec` returns 3 non-comment hits),
but the instrument cannot tell a real zero from a vacuous one. The forbid list has a second, smaller
limitation its own header already concedes: every forbidden crate is a non-dependency, so the manifest
allow-list is the primary control and this is defence in depth.
ACTION:    In both `walk` helpers, thread a visited-file counter and assert it against a floor before asserting `offenders.is_empty()` — `assert!(visited >= 10, "the walker visited {visited} files; the offender check below is vacuous")`. Mirror the wording `diagnostics_tests.rs:19` already uses.

### X-2214 · the style gate's doc claims a general two-letter rule; the code matches one literal prefix
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '173,177p' crates/busbar-plane-streaming/src/tests/mod.rs
/// ... no parity-binding identifier (a two-letter prefix, a hyphen and
/// digits, e.g. a two-letter code followed by a hyphen and a number) anywhere in this crate's own source ...

$ sed -n '206,215p' crates/busbar-plane-streaming/src/tests/mod.rs
                for i in 0..bytes.len().saturating_sub(4) {
                    if bytes[i] == b'P' && bytes[i + 1] == b'B'
                        && bytes[i + 2] == b'-' && bytes[i + 3].is_ascii_digit()

$ grep -rnE "\b[A-Z]{2}-[0-9]+" crates/busbar-plane-streaming/src --include='*.rs'
$ echo $?
1
```
The doc describes the class; the code checks one member of it. Today the difference is invisible
because no two-letter-hyphen-digit identifier of ANY prefix appears in the crate — so the gate reads
as covering a rule it does not cover, and the first `XY-12` to land passes.
ACTION:    Replace the hand-rolled `PB-` byte scan with the general predicate the doc already states: two ASCII uppercase letters, a hyphen, then a digit. Add a negative control (a string constant carrying e.g. `ZZ-1` behind `#[cfg(FALSE)]` is not enough — assert the predicate directly in a unit test over a literal).

### X-2215 · the egress cell's caller-token assertion cannot fail
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '25,26p;35,36p;55,58p' crates/busbar-voice/src/tests/egress_tests.rs
    const PROVIDER_CREDENTIAL: &str = "ek_provider_scoped_secret_abc";
    const CALLER_TOKEN: &str = "caller-inbound-governance-bearer-xyz";
    let headers = builder(PROVIDER_CREDENTIAL, &ctx);
    assert!(
        !value.to_str().unwrap().contains(CALLER_TOKEN),
        "the caller's inbound governance token is never the value planned onto the provider dial"
    );
```
`CALLER_TOKEN` is never passed to `builder`, never placed on the `SigningContext`, and never reaches
any code under test. No edit to `voice_provider_bearer` or `voice_egress_auth_headers` can put a
string they were never given into their output. The cell's own comment half-concedes it: "a caller
token could reach the wire only by being the leased credential, which the egress gate is what
forbids" — i.e. the property lives somewhere else. The other three asserts in the file (header count,
exact `Bearer <credential>` value, `egress_auth_lane_constant`) are genuine and do go red.
ACTION:    Either delete the assert and keep the comment as the pointer to where the property is actually enforced, or make it real: put `CALLER_TOKEN` on the `SigningContext` (`upstream_creds` / an inbound-header field) and assert the builder — which is declared lane-constant and must read nothing off the context — does not surface it. The second form also becomes the lane-constant proof.

### X-2216 · the streaming plane carries two near-verbatim test harnesses and two copies of its purity cells
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ diff crates/busbar-plane-streaming/src/tests/harness.rs crates/busbar-plane-streaming/tests/harness/mod.rs
# differs only by: the module doc, `SessionId`/`SessionView` imports, `FreshSession`,
# `PairedSession` and `ctx_with_session`. LeakPlaneAlloc / EmptyConfig / WsStack / TestSeal /
# ctx / frame / unit / destination are byte-equivalent.

$ sed -n '24,49p' crates/busbar-plane-streaming/tests/purity.rs
$ sed -n '46,76p' crates/busbar-plane-streaming/src/tests/mod.rs
# same two cells (`same_configuration_answers_the_same_way_every_time`, `empty_plane_names_no_upstream`)
# and the same `const _: () = assert_copy::<StreamingPlane>();`, written twice
```
Rust's unit/integration split forces two harness crates, but it does not force two divergent copies:
the integration one has already fallen behind (no `PairedSession`, no `ctx_with_session`), which is
exactly how the next fixture change lands in one and not the other. The duplicated purity cells make
the `Copy` proof and the dialect-lookup determinism proof each count twice in a test-count floor
while proving one thing.
ACTION:    Move the shared half into one place — a `pub mod harness` inside `src/tests/` re-exported for integration use, or a `#[path]`-included file both entry points name — so the fixture is written once. Delete the duplicated cells from whichever side is not the canonical home; `tests/purity.rs` is the better one to keep, since it also holds `the_plane_key_is_streaming_never_voice` and the forbid list.

### X-2217 · `FreshSession` is a fixture nothing constructs
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '92,100p' crates/busbar-plane-streaming/src/tests/harness.rs
/// Not yet used by a test in this crate (every current test drives `decode_ingress`/`decode_response`
/// through a bare `Ctx` with no session), kept as shared harness for the session-bound tests a future
/// pass adds ...
#[allow(dead_code)]
pub struct FreshSession;

$ git grep -n "FreshSession" -- crates/
crates/busbar-plane-streaming/src/tests/harness.rs:100:pub struct FreshSession;
```
Its own doc admits it. The `#[allow(dead_code)]` is the tell: the compiler already raised this and
the warning was silenced rather than answered. Note that `PairedSession` — added later for the
paired-turn routing cells — IS used, so the future pass the comment anticipates arrived and brought
its own fixture, leaving this one stranded.
ACTION:    Delete `FreshSession` and its `SessionView` impl (`src/tests/harness.rs:92-118`), or write the zero-upstream session cell it was staged for. Do not leave the `#[allow(dead_code)]`.

### X-2218 · `busbar-voice` names two crates that do not exist in the workspace
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ for f in $(cat .sweep/S13-streaming.txt); do grep -Hn -E "busbar[-_]core([^-_a-z]|$)|busbar[-_]substrate([^-_a-z]|$)" "$f"; done
crates/busbar-voice/Cargo.toml:15,16,17,18,48,49,50,51,121,154
crates/busbar-voice/src/lib.rs:20,22
crates/busbar-voice-codec/Cargo.toml:42,46       # these two are correct — they CONTRAST -values against the parent
crates/busbar-plane-streaming/tests/purity.rs:117  # a forbid-list entry, deliberate

$ ls -d crates/busbar-core* crates/busbar-substrate*
crates/busbar-core-admin
crates/busbar-core-connsec
crates/busbar-substrate-values
```
There is no `crates/busbar-core` and no `crates/busbar-substrate`. `busbar-voice/Cargo.toml:48-51`
is titled "THE SEAL" and its whole argument — "busbar-core is NOT a dependency of this plugin at
all" — is now unfalsifiable prose about a crate that cannot be depended on by anyone. The real seal
today is the absence of a `busbar-kernel` default-features edge plus the `kind-isolation` gate, and
the doc points a reader at the wrong instrument. `Cargo.toml:18` names `busbar_substrate::testkit`
where the path is `busbar_kernel::testkit` (`crates/busbar-voice/src/tests/billing_ledger_tests.rs:21`).
ACTION:    Rewrite the 12 hits in `crates/busbar-voice/Cargo.toml` and `crates/busbar-voice/src/lib.rs` to name the crates that exist (`busbar-kernel`, `busbar-substrate-values`, `busbar_kernel::testkit`), and restate "THE SEAL" in terms of the gate that actually enforces it (`qa/kind-isolation.toml`). The two `busbar-voice-codec/Cargo.toml` hits and the `purity.rs` forbid entry are correct as written — leave them.

### X-2219 · `lib.rs` says four ingress routes in one place and five in another; the mount has five
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '136p' crates/busbar-voice/src/lib.rs
/// `PLANE_DECL.routes` — the four neutral ingress routes, or `None` (no data path) off-feature.

$ sed -n '218p;247p' crates/busbar-voice/src/lib.rs
/// ... and `routes` mounts the five ingress doors across both dialects ...
        // ... and mounts the five ingress routes across both dialects, whose

$ sed -n '553,660p' crates/busbar-voice/src/mount.rs | grep -c "path:"
5
$ sed -n '553,660p' crates/busbar-voice/src/mount.rs | grep "path:"
MINT_PATH  SDP_PATH  SIDEBAND_PATH  TELEPHONY_PATH  GEMINI_PATH
```
Five is right (`mount_tests.rs::the_five_ingress_doors_mount_audience_checked_across_the_http_and_ws_seams`
asserts it). `lib.rs:136` is the pre-Gemini count, left behind when the second dialect's route landed.
It sits directly on the `VOICE_ROUTES` const a reader consults to learn the door count.
ACTION:    Change "four" to "five" at `crates/busbar-voice/src/lib.rs:136`. Consider deriving the count in the doc from `VOICE_ROUTES` rather than restating it, as `VOICE_WIRE_FORMATS` already does for the dialect count.

### X-2220 · `DECLS` documents itself as "NOT YET MOUNTED" three times in a crate whose header says mounting landed
CLASS:     drift
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '305,318p' crates/busbar-voice/src/lib.rs
/// NOT YET MOUNTED: `handler: None` and `verbs: &[]` — route-mounting the duplex handler /
/// gauntlet-session entry is follow-on work. ...
    // NOT YET MOUNTED: no request handler wired here yet — the duplex pump exists in `crate::runtime`;
    // route-mounting its entry point is follow-on work.
    handler: None,
    // NOT YET MOUNTED: no verbs declared yet (the long-lived Subscribe/Control shapes arrive with the
    // boot-mounting pass).
    verbs: &[],
```
The fields themselves may well be correct — `lib.rs:220-224` argues, convincingly, that a long-lived
duplex SESSION is not a one-shot `RequestHandler`, which is a PERMANENT reason for `handler: None`,
not a pending one. If that argument holds, then "NOT YET MOUNTED ... follow-on work" is the wrong
label for a settled design decision, and it will read as an open TODO to every future reader — the
same way X-2200's sentence did. I did not find a design doc stating the intent either way, so this
is ADJUDICATE rather than VERIFIED.
ACTION:    Owner call: if `handler`/`verbs` stay empty by design (the session-is-not-a-request argument), replace all three "NOT YET MOUNTED ... follow-on work" comments with that reason. If the Subscribe/Control verbs are genuinely still owed, link the tracked slice so the label has a subject.

### X-2221 · `busbar-voice-codec` declares `serde_json` twice
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "serde_json" crates/busbar-voice-codec/Cargo.toml
60:serde_json = { workspace = true }      # [dependencies] — unconditional
69:serde_json = { workspace = true }      # [dev-dependencies]
```
A `[dev-dependencies]` entry that restates an unconditional normal dependency adds nothing to the
test build and creates a second place the declaration can drift. The workspace version table
(`Cargo.toml:57+`, written specifically because "three were already declared two different ways")
keeps the VERSION in sync today; a future `features = [...]` on one line and not the other would not
be caught. Compare `busbar-voice/Cargo.toml`, whose `[dev-dependencies]` says "None beyond the
workspace crates above" and means it.
ACTION:    Delete `crates/busbar-voice-codec/Cargo.toml:68-69` (the `[dev-dependencies]` block); `serde_json` is already unconditionally available to the test build via `[dependencies]`.

### X-2222 · the `twilio-media-streams` dialect, its grammar, its µ-law transcoder and four test files ship behind a claim the boot refuses
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '294,298p' crates/busbar-plane-streaming/tests/conformance.rs
    assert_eq!(<StreamingPlane as PlaneMeta>::CLAIMS.len(), 4,
        "streaming claims its four live dialect surfaces");

$ sed -n '24,26p' crates/busbar-plane-streaming/src/claims.rs
//!   ([`Dialect::TwilioMediaStreams`], [`crate::twilio`], [`crate::ulaw`]) is complete and untouched
//!   ... [`DIALECT_CLAIMS`] on the day `busbar-transport-twilio-media` registers a key.

$ ls -d crates/busbar-transport-*
grpc  http  sse  stdio  tcp  tls  ws          # no twilio-media

$ sed -n '526,529p' crates/busbar/src/root/tests/registry.rs
        .expect_err("`twilio-media` has no crate");
```
The root's own cell asserts that a `twilio-media` claim REFUSES boot. So `crate::twilio`,
`crate::ulaw` (97 lines of G.711), `src/tests/twilio.rs`, `src/tests/ulaw.rs`, the twilio half of
`src/tests/codec.rs`, and the whole of `tests/alloc_gate.rs` (whose subject is the twilio downlink
renderer) exercise a dialect no request can reach. This is NOT dead code — the dialect is IN for
1.6.0 per the ARCHITECTURE inventory row at `docs/design/ARCHITECTURE.md:1185`, and the transport is
named as the missing piece. It is a capability that is fully built, fully tested, and not
constructed, which is law 2 with the work on the right side of the line.
ACTION:    Do not delete. Track `busbar-transport-twilio-media` as the one remaining piece and, until it lands, make the gap legible rather than silent: state it in `crates/busbar-plane-streaming/src/ulaw.rs` and `src/twilio.rs` module docs (not only in `claims.rs`), and add one cell asserting `CLAIMS` contains no `twilio-media` claim today — so the day the transport registers, the count assertion at `conformance.rs:294` and that cell BOTH go red and point at the dialect list that needs updating.

## TALLY
```
files in slice:  55
verdict lines:   55
CLEAN:           30
FINDING:         25      rows raised: 23  (X-2200 .. X-2222)
DELETABLE:        0
UNREADABLE:       0
```

Row classes: money 1 (X-2210) · auth 1 (X-2204) · missing-code 6 (X-2201 is customer-surface;
X-2202, X-2203, X-2207, X-2208, X-2217, X-2222) · instrument-blind 3 (X-2213, X-2214, X-2215) ·
config 3 (X-2205, X-2209, X-2221) · drift 8 (X-2200, X-2206, X-2211, X-2212, X-2216, X-2218,
X-2219, X-2220) · customer-surface 1 (X-2201).

Certainty: VERIFIED 21 · ADJUDICATE 1 (X-2220) · PARK 1 (X-2210, the billed byte).

## PROVEN ABOUT FILES OUTSIDE THIS SLICE (reported, not acted on)

1. **`crates/busbar/src/root/units_voice.rs:226`** — `ProviderEndpoints::as_slice()` has no caller.
   It is the one method that would hand the streaming plane its real upstream pair. Evidence and
   consequence are in X-2207.
2. **`crates/busbar/src/root/registry.rs:463` / `crates/busbar/src/main.rs:505`** — both construct the
   streaming plane empty, and `registry.rs` guards it on `#[cfg(feature = "plane-voice")]` while the
   plane crate's own `register.rs` documents `plane-streaming`. X-2207 / X-2208.
3. **`crates/busbar-plane-streaming/src/register.rs`** (not in my file list) — `:20`, `:49` and `:71`
   name a `plane-streaming` cargo feature that does not exist anywhere in the workspace.
4. **`crates/busbar/tests/plane_isomorphism.rs:63`** — the `("build_runtime", |d| d.build_runtime.is_some())`
   row is green for the voice plane on a field the host has no predicate to dispatch. X-2202.
5. **`.github/workflows/ci.yml:1094-1127`** — `VOICE_MIN_TESTS: "100"` against
   `grep -rho '#\[test\]\|#\[tokio::test' crates/busbar-voice/src` → 82 and the same over
   `busbar-voice-codec` → 101 (183 authored cells across the two crates the step names). The floor is
   roughly half the suite. This is precisely the failure the SAME workflow calls out 20 lines above
   for `UNIX_MIN_TESTS` ("a floor that far under the suite defends nothing: this pair sat at
   5650/5723 against a 9,888-test suite for three weeks"), and unlike the workspace step this one has
   no companion `VOICE_EXPECTED_TESTS` drift check at all. Raise the floor and add the expected-count
   pair.
6. **`busbar_contract::plane::PlaneMeta::CONFIG_SCHEMA`** — declared by six plane crates, read by
   none. Larger than this slice; X-2209 records the streaming instance.
7. **`crates/busbar-voice/src/mount.rs:1008-1030`** (`serve_mint`) — mints an `ek_` with no metering
   lease and bypasses `webrtc::attach`'s govern-before-mint assembly. X-2203 / X-2204 / X-2205 all
   land here; the fix for each is a `mount.rs` edit, not a `webrtc.rs` one.
