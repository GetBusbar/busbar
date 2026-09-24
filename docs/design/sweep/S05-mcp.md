# S05-mcp — sweep report

Slice: `crates/busbar-mcp`, the 101 files of `.sweep/S05-mcp.txt` that no prior sweep had named.
X-id block: X-1400..X-1499. Rows raised: X-1400..X-1443.

Method: the crate's 118 tracked `.rs` files were partitioned; every one of the 101 slice files was
read or measured directly. Reachability, construction and drift claims were verified with
`git grep` / `sed` / a replicated parse — never taken from the file's own comments, which in this
crate are long, confident, and in 21 measured places wrong.

## Binding context — VERIFIED, not assumed

The task brief named three facts. All three were checked before any file was judged.

1. **`busbar-mcp-codec` was dissolved by fold #39 and is gone.** `ls -d crates/busbar-mcp-codec` →
   `No such file or directory`. Positive control: `ls -d crates/busbar-plane-mcp` → exists.
2. **Gates still scanning for it.** The two live money-path scan roots are already carried as
   LEDGER GS17/G34 (`xtask/src/gates/no_float_money.rs` `COUNT_READ_ROOTS`). NOT re-raised here —
   they are outside this slice and already open. What this slice adds is a THIRD dead-name class,
   below.
3. **The mcp plane has ZERO oracle witness.** Confirmed from the repo's own recorded measurement,
   not inferred: `docs/design/1.6.0-LEDGER.md:766` — *"replaying the committed golden against
   itself filtered to mcp produced 912 rows, not one of them `PASS`"* — and `:561` — *"mcp 912 / 0 /
   0"* (cells / with-a-driver / with-a-request). `docs/design/1.6.0-MAP.md:314`: *"mcp 912 cells /
   0 touch money"*. **Every behavioural claim in this slice is therefore unwitnessed by the 1.5.5
   byte-comparison, and every row below rests on reading and on commands run here.**

## Governing facts established once, cited by row rather than repeated

**(G1) The crate compiles and its `test-support` suites really do run.** The biggest hypothetical
finding — ~80 test files gated `#[cfg(all(test, feature = "test-support"))]` never being built —
is FALSE. Measured two ways:
- `cargo tree -e features -p busbar-mcp --workspace | grep 'busbar-mcp feature'` → prints
  `busbar-mcp feature "test-support"` and `busbar-mcp feature "auth-admin-tokens"`. Resolver v2
  unifies `busbar-kernel`'s dev-dependency `busbar-mcp = { features = ["test-support",
  "auth-admin-tokens"] }` (`busbar-kernel/Cargo.toml:291`) onto the workspace build, so
  `cargo test --workspace` (ci.yml:935) does compile and run them. The CI comment at
  ci.yml:878-881 asserting this is CORRECT.
- `cargo check -p busbar-mcp --features test-support --tests` → exit 0, and
  `grep -cE '^(error|warning)'` over its output → **0**. No unresolved symbol, no `dead_code`
  warning, in any slice file.
- The suites were RUN, not only built: `cargo test -p busbar-mcp --lib` → `39 passed; 0 failed;
  0 filtered out` (the bare-`cfg(test)` half), and
  `cargo test -p busbar-mcp --features test-support --lib` reports a 549-test denominator
  (e.g. `-- stdio_serve_tests::` → `18 passed … 531 filtered out`). A zero-warning build of this
  file set is also the dead-code proof cited in several CLEAN rows below.

**(G2) The plane is genuinely wired at the composition root.** `crates/busbar/src/main.rs:222`
pushes `&busbar_mcp::PROTO_DECL`, `:288` `&busbar_mcp::PLANE_DECL`, `:375`
`busbar_mcp::DIAGNOSTICS`; `root/gauntlet_install.rs:65` flips `busbar_mcp::PLANE_KEY`;
`main.rs:1531` calls `busbar_mcp::mcp::stdio_serve::serve_stdio(factory)` behind `--mcp-stdio`.
Nothing in this slice is an unlinked crate.

**(G3) Zero orphan modules.** A parse of every `#[path = "..."]` and plain `mod` declaration under
`crates/busbar-mcp/src`, resolved against the filesystem, found **117 declared entries and 0 slice
files with no declaration**. Positive control: `crates/busbar-mcp/src/mcp/tests/tasks_tests.rs` →
declared by `crates/busbar-mcp/src/mcp/tasks.rs`.

**(G4) The dead-code surface is not spread — it is one column.** 33 unconditional
`#[allow(dead_code)]` sites in `crates/busbar-mcp/src`: **25 under `src/mcp/client/`**, 5 in
`src/codec/`, 2 in `connect.rs`, 1 in `admin_view.rs` (a test-module gate). Across the eleven
server-side plane modules (`envelope`, `sse`, `subscribe`, `resource`, `roots`, `reroute`,
`demotion`, `stdio_serve`, `tasks`, `inputreq`, `method`) the count is **zero**. The unshipped half
of this crate is the CLIENT direction, and X-1406 is why it is still here.

**(G5) Secrets are handled correctly.** `git grep -nE '(format!|panic!|tracing::…!|expect\()[^;]*\{(secret|token|key|password|credential|authorization|bearer)[a-z_]*\}' -- crates/busbar-mcp/src`
→ one hit, `deputy_pair_tests.rs:323`, a test building an outbound header (correct). Positive
control: the same shape over `{server}`/`{host}` returns real hits. `UpstreamCredential::Static`
and `ExchangeCfg.subject_token` hold `Redacted<String>`, whose `Debug` and `Display` both write
`[REDACTED]` (`busbar-contract/src/redacted.rs:59-63`). `StdioChild::spawn` runs `env_clear()`, no
shell, `kill_on_drop(true)`, and names the VARIABLE not the value on a resolve failure. **No row.**

**(G6) No float money anywhere in the slice.** `xargs grep -nE 'f64|f32'` over all 101 files →
the only hits are `client/verb.rs:165-166` (`notifications/progress`, the wire type the spec gives
it, documented) and `sse.rs:165-193` (RFC 9110 Accept `q` values). Positive control:
`grep -nE 'f64' crates/busbar-kernel-budget/src/price.rs` → 3 hits. **No money row in this slice.**

## The verdict table

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| crates/busbar-mcp/Cargo.toml | FINDING | `grep -n '^busbar-' Cargo.toml` → 12 dep lines, none `busbar-core`, none `busbar-substrate`; `ls -d crates/busbar-core crates/busbar-substrate` → both `No such file or directory`, while the comments at :30-45,:107-149 describe both as live deps | X-1407 |
| crates/busbar-mcp/src/codec/handler.rs | FINDING | `git grep -n '"mcp"' -- crates/busbar-mcp/src/codec` → `handler.rs:90` returns the literal while `codec/mod.rs:65` uses `busbar_plane_mcp::PLANE_KEY`; `git grep -n 'protocol_name' -- crates/busbar-mcp` → 1 hit, the definition: no test in this crate pins the two together | X-1408 |
| crates/busbar-mcp/src/codec/invoke.rs | FINDING | `git grep -n 'invoke_write_request\|invoke_write_response' -- crates/` → definitions + `codec/tests/mcp_tests.rs` only; `grep -nE 'fn (read\|write)_' crates/busbar-substrate-values/src/handlers.rs` → the `OperationHandler` trait has NO write method, so these are not a trait obligation | X-1405 |
| crates/busbar-mcp/src/codec/mod.rs | FINDING | `:11` pins `git grep busbar_mcp crates/busbar-core/src` "at zero" over a directory `ls` says does not exist; `:14` names `busbar_substrate_values::proto::install_protocols` while `lib.rs:25` names `busbar_kernel::proto::install_protocols`, which `busbar-kernel/src/proto/registry.rs:62` says is "NOT re-exported" | X-1409 |
| crates/busbar-mcp/src/codec/subscribe.rs | FINDING | `:62` heads "WHY THE PARAMS ARE DESERIALIZED INTO `rmcp`'s STRUCTS" over `:130`/`:135` which deserialize into the LOCAL `SubscriptionParams` (`:31`); `:28` claims the SDK pins "every method name" — `git grep -n 'pub const METHOD_' -- crates/busbar-plane-mcp/` → 6, against 33 distinct method literals the crate speaks | X-1405, X-1409 |
| crates/busbar-mcp/src/codec/tests/mcp_tests.rs | CLEAN | 28 tests / 63 asserts / 35 `expect`; drives read AND the cfg-gated write for both cells, both polarities (`is_err()` arms at :50,:93,:127,:530). No `#[ignore]`, no `f64` | - |
| crates/busbar-mcp/src/lib.rs | CLEAN | Every re-export resolves and has a composition-root consumer — see G2. `pub use busbar_plane_mcp::{outputschema, sanitize}` and `pub use codec::DECL as PROTO_DECL` both land at `main.rs` | - |
| crates/busbar-mcp/src/mcp/admin_view.rs | FINDING | `git grep -n 'admin_view::' -- crates/busbar-mcp/src/mcp/mod.rs` → all 7 hooks wired at `mod.rs:168-174`; but `health_view` (:259) derives `contacted` from `observed>0 \|\| failure.is_some()` while `connect.rs:458-465` maps `Sighting::Demoted` into the `_` arm of both | X-1442 |
| crates/busbar-mcp/src/mcp/callerask.rs | CLEAN | The `authored` private-module constructor boundary is real (`:110` is the only `CallerAsk` constructor); `git grep -n 'ASK_METHODS' -- crates/` → the closed set IS enforced at boot (`config.rs:1369`). `saturating_add` on both seal arithmetic sites | - |
| crates/busbar-mcp/src/mcp/client/argguard.rs | FINDING | `argguard.rs:388` calls `ssrf_blocked_host(url, &[], false, &[])` — operator lists hard-coded empty; `git grep -c 'blocked_metadata_hosts\|allow_all_metadata\|allow_metadata_hosts' -- crates/busbar-mcp/` → rc=1, ZERO. Positive control: `busbar-kernel/src/appbuild.rs` → 5, `busbar-llm/src/engine/build_runtime.rs` → 8 | X-1402 |
| crates/busbar-mcp/src/mcp/client/identity.rs | CLEAN | `ToolKey::parse` is total and exact — `ServerId::new` refuses `_` (:101) so `split_once(SEP)` cannot be ambiguous; round-trip holds. Both `NameError` arms constructed (:93,:97,:102,:132,:135) | - |
| crates/busbar-mcp/src/mcp/client/peer.rs | FINDING | `AskOutcome` has exactly two arms (`:337-342`), BOTH refusals, and `answer()` (:349) refuses on both; `git grep -n 'satisfy_upstream_ask' -- crates/` → called only from `method.rs:1954,1957` and `tasks.rs:925,928`, never from the stdio leg | X-1404 |
| crates/busbar-mcp/src/mcp/client/pool.rs | FINDING | `ResourceUpdates.events` is ONE `VecDeque` for all servers (:181) with `pop_front()` at cap 256, while the sibling `RefreshTriggers.gates` (:88) is per-server *"so a chatty registration cannot starve a quiet one"*; `:186` justifies the bound as "evicts its OWN noise". Also `:261` "no verb yet" — see X-1406 | X-1403, X-1406 |
| crates/busbar-mcp/src/mcp/client/stdio.rs | CLEAN | `env_clear()` + no shell + `kill_on_drop(true)` (:394-401); secrets resolved at spawn naming the variable not the value (:376-388); `Debug` prints the pid only (:363); `MAX_INTERLEAVED_MESSAGES` bounds peer work; the breaker `reset()` IS wired to an operator `command:` edit (:1014-1023) | - |
| crates/busbar-mcp/src/mcp/client/tests/argguard_tests.rs | CLEAN | Asserts real non-zero floors on `ArgScan` (`declared_judged`, `strings_seen`) at :82,:123,:154,:380,:432 — so "the walker visited nothing" cannot pass. Refusal loops carry `assert_eq!(set.len(), N)` floors | - |
| crates/busbar-mcp/src/mcp/client/tests/ask_tests.rs | FINDING | `git grep -n 'struct ServerRequestGrants' -- crates/` → TWO: `client/jsonrpc.rs:536` and `config.rs:533`. This file imports the jsonrpc one (:10); the LIVE gate is `inputreq.rs:354 grants().allows(&ask.kind)` on the config one. `git grep -n 'InputRequiredLoop' -- crates/` → definition + doc lines only, zero production callers | X-1411 |
| crates/busbar-mcp/src/mcp/client/tests/catalogue_concurrency_tests.rs | CLEAN | Loops are `0..80`/`0..6`, bounded by consts, never empty; no tautologies (`git grep -nE 'assert!\(true\|assert_eq!\(([a-z_0-9]+), *\1\)'` → rc=1 with a live positive control) | - |
| crates/busbar-mcp/src/mcp/client/tests/catalogue_tests.rs | CLEAN | Carries explicit reader floors: `assert_eq!(reads, 2000)` (:56) and `assert_eq!(gate.rejected(), 50)` (:99) | - |
| crates/busbar-mcp/src/mcp/client/tests/deputy_tests.rs | CLEAN | 12 `assert_eq!`; `both_grants_produce_an_audience_bound_exchange` is the positive control that stops the battery passing by refusing everything | - |
| crates/busbar-mcp/src/mcp/client/tests/dispatch_tests.rs | FINDING | `sed -n '85,100p' \| grep -c generation` → `0`, against the doc at :82-83 "Deregistering a server bumps the generation". The body calls `cache.apply(...)` and never reads `cache.generation()` | X-1417 |
| crates/busbar-mcp/src/mcp/client/tests/egress_tests.rs | CLEAN | `assert_eq!(cases.len(), 2)` floor at :81; no money arithmetic (the one `spend`-shaped hit at :72 is prose) | - |
| crates/busbar-mcp/src/mcp/client/tests/engine_tests.rs | CLEAN | `assert_eq!(reg.max_input_required_rounds, 1)` (:28) matches the real default at `client/mod.rs:178` | - |
| crates/busbar-mcp/src/mcp/client/tests/generation_recheck_tests.rs | CLEAN | Both tests carry a control re-resolve proving the refusal is the generation, not the target | - |
| crates/busbar-mcp/src/mcp/client/tests/http_peer_tests.rs | FINDING | Header (:36) claims "the denominator is taken from `super::super::peer`'s own closed enums"; `git grep -nE 'fn all\(\)\|const ALL\|EnumIter\|strum' -- crates/busbar-mcp/src/mcp/client/peer.rs` → rc=1, nothing. The denominator is the hand-kept `ALL_NOTIFICATIONS`/`ALL_REQUESTS` at :168/:180 | X-1414 |
| crates/busbar-mcp/src/mcp/client/tests/identity_tests.rs | CLEAN | `assert_eq!(cases.len(), 4)` floor at :103 before the round-trip loop; no else-less `if let Some` in the whole client-test tree (`git grep -n 'if let Some(' -- …/tests/*.rs` → rc=1) | - |
| crates/busbar-mcp/src/mcp/client/tests/no_key_passthrough_tests.rs | CLEAN | Destructures `OutboundRequest { url, headers, body }` exhaustively (:237) so a new field breaks the build; `the_scan_finds_a_secret_that_is_legitimately_forwarded` is the scanner's own positive control | - |
| crates/busbar-mcp/src/mcp/client/tests/pool_tests.rs | CLEAN | `const N = 200 // below MAX_RESOURCE_UPDATES` checks out against `pool.rs:187 = 256`; `pool.len()` assertions at :35,:42,:53,:80,:93 are the reuse claim made measurable | - |
| crates/busbar-mcp/src/mcp/client/tests/routing_key_tests.rs | FINDING | `git grep -rn 'dispatch_never_reads_a_tool_description' -- .` → 2 hits, `client/dispatch.rs:27` (advertises it as live and "MACHINE-CHECKED") and this file's :120 tombstone recording its deletion. The `fn` exists nowhere | X-1418 |
| crates/busbar-mcp/src/mcp/client/tests/rugpull_tests.rs | CLEAN | The cross-language digest pin genuinely agrees: `git grep -n '9a5b7d62…' -- .` → this file :215 and `scripts/mcp-subject/tool-digest.mjs:55` | - |
| crates/busbar-mcp/src/mcp/client/tests/ssrf_tests.rs | FINDING | `azure_wireserver_and_oci_imds_are_refused` (:278) runs ONE policy and asserts only `is_err()`; both literals sit in `ipv4_is_internal` (net.rs:95,:123) AND `ip_is_cloud_metadata` (net.rs:181,:182), so under `allow_private:false` it cannot fail on the arm it names. The sibling at :145 does it right | X-1415, X-1416 |
| crates/busbar-mcp/src/mcp/client/tests/stdio_tests.rs | CLEAN | `git grep -n '#\[ignore' -- …/tests/*.rs` → rc=1; the `cfg(unix)` gate is documented at :207-218 and the state-machine half runs on every platform | - |
| crates/busbar-mcp/src/mcp/client/tests/support.rs | CLEAN | Dead-helper sweep over every declared helper, repo-wide reference counts: `approved_server`=38, `key_with_scopes`=32, `simple_tool`=46, `tkey`=27, `sid`=44, `tool`=140, `key_wildcard`=25. Each `expect()`s rather than returning a fallback | - |
| crates/busbar-mcp/src/mcp/client/tests/surface_tests.rs | CLEAN | `git grep -nE 'busbar[-_](core\|substrate)\|busbar[-_]mcp[-_]codec\|busbar[-_]plane[-_]mcp[-_]host' -- …/tests/*.rs` → rc=1; positive control `busbar_api\|busbar_kernel` → 2 in this file, both live crates | - |
| crates/busbar-mcp/src/mcp/client/tests/transport_tests.rs | CLEAN | The 5 `let _ =` are the loopback `TcpListener` fixture plus a pool warm that still `.expect()`s; correlation tests assert on captured request bytes with a same-id control | - |
| crates/busbar-mcp/src/mcp/client/tests/verb_tests.rs | FINDING | `every_variant_appears_in_all_exactly_once` (:79) is a DEDUP check (`before == names.len()` after `dedup()`), not a completeness check — dropping a variant from `all()` shortens both sides equally. `git grep -n 'UpstreamVerb::[A-Z]' -- verb_tests.rs` → rc=1, zero; positive control over `verb.rs` → 73 | X-1412 |
| crates/busbar-mcp/src/mcp/client/tests/wire_error_tests.rs | CLEAN | Both polarities of `is_own_refusal` asserted (2 true arms, 2 false arms) over the closed four-variant `TransportError` | - |
| crates/busbar-mcp/src/mcp/client/tests/wire_tests.rs | CLEAN | `assert_eq!(bad.len(), 5, "the malformed set must not shrink")` at :177 before the loop | - |
| crates/busbar-mcp/src/mcp/client/verb.rs | FINDING | `#[allow(dead_code)]` on the whole enum (:97) justified by "busbar's own FRONT DOOR does not yet expose a `prompts/list`"; 21 of 23 variants reach production through `client::issue::issue`, which `git grep -n 'client::issue\|issue::issue' -- crates/busbar-mcp/src ':!**/tests/*'` shows has ZERO production callers (6 hits, all doc lines). Also :370 names a test that does not exist | X-1406, X-1413 |
| crates/busbar-mcp/src/mcp/client/wire.rs | FINDING | `McpWire::notify` (:172) and the free `notify` (:277) both carry `#[allow(dead_code)]` justified by "`super::issue::issue`, which has no inbound caller yet"; :216 states "two callers today" when one of the two is test-only | X-1406 |
| crates/busbar-mcp/src/mcp/demotion.rs | FINDING | `sed -n '100,112p'` → `let Ok(id) = ServerId::new(&entry.id) else { continue; };` with no log and no count, three lines under a 17-line block (:56-72) whose whole subject is that this shape is a security bug. Every other production `ServerId::new` maps the error to a named refusal | X-1438 |
| crates/busbar-mcp/src/mcp/envelope.rs | FINDING | `grep -rn '"mcp-protocol-version"'` over the census `tree()` scope → 1 (`:111`); over `crates/busbar-plane-mcp/src/` → a SECOND live spelling at `plane.rs:62`, which `proto_root_of` (roots.rs:52-63) cannot match. Plus 3 further doc-vs-code splits | X-1430, X-1431, X-1432, X-1433 |
| crates/busbar-mcp/src/mcp/inputreq.rs | FINDING | Every `Outcome`/`Refusal` arm is constructed (:328,:336,:339,:346,:355,:372) and `Unsatisfiable` is genuinely reachable; but the header's "every round is metered before it is spent" (:35-39) is unqualified against `tasks.rs:939` passing an inert `\|_, _\| Ok(())` charge seam | X-1441 |
| crates/busbar-mcp/src/mcp/mod.rs | FINDING | `mcp_on_swap` (:505) retains over `runtime_slots(next).pool.children`, but `McpRuntime::build` (:316) constructs `McpConnectionPool::new()` fresh every apply — `git grep -n 'p\.pool'` → rc=1, never carried; positive control: the three fields that ARE carried do `p.<f>.clone()` at :320,:324,:337. Plus the `canonical_uri` guard asymmetry | X-1400, X-1401, X-1410 |
| crates/busbar-mcp/src/mcp/reroute.rs | FINDING | `git grep -n 'repeatability(' -- crates/` → the definition (`failover/mod.rs:190`) + 3 TEST call sites, zero production; `reroute.rs:214` re-spells the lookup while its own comment says "the same check `CandidatePoolCfg::repeatability` runs". Also `failover::walk` named at :5,:14 — 9 references tree-wide, every one prose | X-1436, X-1437 |
| crates/busbar-mcp/src/mcp/resource.rs | CLEAN | 48 lines, zero production items — header plus the `#[cfg(all(test, feature = "test-support"))] mod resource_tests`. The handler it documents (`envelope::metadata_route`) is live and mounted at `mod.rs:652` with `auth: RouteAuth::None`, exactly as stated | - |
| crates/busbar-mcp/src/mcp/roots.rs | CLEAN | `git grep -n 'RootsEpochs\|note_change\|satisfy_upstream_ask' -- crates/ \| grep -v /tests/` → all reached from production (`envelope.rs:337`, `stdio_serve.rs:629`, `method.rs:1957`, `tasks.rs:928`). The self-declared-unreachable arms at :140,:158,:166 check out against `jsonrpc.rs::input_required_kind` | - |
| crates/busbar-mcp/src/mcp/sse.rs | CLEAN | Every item has a production caller (`envelope.rs:586-610`, `stdio_serve.rs:589-1241`); the only `f32` is the RFC 9110 `q` value, the `q<=0` refusal branch is reachable, and the "only a 200 becomes a stream" claim matches `:217` | - |
| crates/busbar-mcp/src/mcp/stdio_serve.rs | FINDING | Entry point intact (`main.rs:112`,`:1531`; 11 hits). But `:1064` derives the task-lookup actor as `self.principal.actor_id()` while production creates tasks under `method.rs:301 task_principal` (the key id) — and the SAME file already uses the correct spelling at :608-612 | X-1439 |
| crates/busbar-mcp/src/mcp/subscribe.rs | FINDING | `MAX_LIFETIME`'s doc (:115-123) says a revoked key "keeps being honoured until the stream ends" and cites a test `git grep` shows was RENAMED away; the code at :462-472 re-resolves per poll and ends the stream on lapse — the doc states the inverse of the guard it annotates | X-1434, X-1435 |
| crates/busbar-mcp/src/mcp/tasks.rs | FINDING | `Runner.authorised`'s doc (:624-628) claims `TASK_TTL_MS`=300_000 bounds revocation exposure at 5 minutes; `is_expired` (:447) requires `status.is_terminal()`, which a Runner's task is not. The real bound is `ACTIVE_TASK_ABANDON_MS` = 86_400_000 (:99) — 288x — and `deliver` (:341) `touch`es it on every `tasks/update` | X-1440 |
| crates/busbar-mcp/src/mcp/tests/adminverbs_tests.rs | FINDING | `grep -nE 'busbar[-_]admin\|busbar[-_]core([^-_]\|$)'` → 7 doc lines naming `busbar-admin` / `busbar-core`; `ls -d crates/busbar-admin crates/busbar-core` → both absent, while the code four lines below calls `busbar_core_admin::install()` (:43) | X-1419, X-1420 |
| crates/busbar-mcp/src/mcp/tests/breaker_fastfail_tests.rs | CLEAN | Every wait-loop (:161,:167) is followed by a real assertion (`assert_eq!(s2, 503)`), so a loop that times out still goes red; `TRIP_MIN_REQUESTS` drives the real 5-failure trip predicate | - |
| crates/busbar-mcp/src/mcp/tests/callerask_tests.rs | FINDING | Header (:4,:10-13) advertises a source-scan gate and its planted-violation companion; `grep -c 'include_str\|file!()\|read_to_string'` → `0`. `callerask.rs:24` says outright that the scan was REPLACED by a type-system guarantee | X-1421, X-1422 |
| crates/busbar-mcp/src/mcp/tests/catalogue_tests.rs | CLEAN | Every `.any(`/`.all(` (:618,:622,:626) is guarded by `assert!(!mine.is_empty() && !theirs.is_empty())` at :613; every `for` iterates a literal array or a map the test just populated | - |
| crates/busbar-mcp/src/mcp/tests/client_leg_metrics_tests.rs | FINDING | `:27` cites `plane::tests::metrics_tests`; `git ls-files 'crates/busbar-kernel/src/plane/*'` → 8 test files, no `metrics_tests.rs`; the real module is `busbar_kernel::metrics::tests` (`metrics.rs:640-642`). Metric assertions themselves are sound | X-1423 |
| crates/busbar-mcp/src/mcp/tests/config_tests.rs | CLEAN | The `for (uri, expected) in cases` loop (:111) iterates a 9-element literal slice and `assert_eq!`s the exact `McpCfgError` variant, not `is_err()` — it is the instrument that made X-1400 findable | - |
| crates/busbar-mcp/src/mcp/tests/confirm_once_tests.rs | CLEAN | Every money-shaped case asserts on `peer.calls()` / `peer.call_arguments()` — the upstream's own bookkeeping — as well as the status, so a refusal that still reached the wire goes red | - |
| crates/busbar-mcp/src/mcp/tests/connect_support.rs | CLEAN | Dead-helper sweep over all 12 exports: every one has >=1 caller outside the file (`gov_with_key` → 7 sites, `list_calls` → 4, `mcp_url` → 5, …). Zero dead helpers | - |
| crates/busbar-mcp/src/mcp/tests/connect_tests.rs | CLEAN | The one `unwrap_or_default()` (:138) feeds `.contains("-32001")`, and an empty string makes `contains` FALSE — so it still produces a NO | - |
| crates/busbar-mcp/src/mcp/tests/content_tests.rs | FINDING | `sed -n '389,403p' \| grep -cE 'assert!\(text\.\|contains\("ignore previous"\)'` → **0**. `text` comes from `.unwrap_or_default()` and the ONLY assertion is `!text.contains("<script>")`, which is TRUE on `""`. Positive control: the sibling at :223-238 pairs `text.contains("123")` with `!text.contains("{id}")` | X-1424 |
| crates/busbar-mcp/src/mcp/tests/credential_secret_leak_tests.rs | CLEAN | The redaction assertion (:58) is paired with a positive control (:68 `rendered.contains("see the server log")`), so it cannot pass on an empty body; the narrow rule matches the narrow subject (`upstream.rs:208-218` redacts only the `Credential` arm) | - |
| crates/busbar-mcp/src/mcp/tests/deputy_pair_tests.rs | FINDING | `sed -n '430,437p'` → `assert_ne!("fs_read fs_write", "fs_read", "the server genuinely offers more than one tool…")` — two string literals. It can never fail. The file's other two `assert_ne!` compare runtime values | X-1425 |
| crates/busbar-mcp/src/mcp/tests/drift_dispatch_tests.rs | CLEAN | Every refusal case pairs with `assert_eq!(peer.calls(), before)` read off the peer; two genuine negative controls (`a_key_reorder_is_not_drift…`, `a_reused_unsighted_snapshot_dispatches…`) | - |
| crates/busbar-mcp/src/mcp/tests/engine.rs | CLEAN | Dead-helper sweep: `engine_host`=22, `engine_host_from_handle`=14, `app_handle`=22, `build_router`=18, `metrics_init`=133, `test_app`=107 references. Names `busbar_kernel::` only — the Cargo.toml comment calling this "the only `busbar_core::` line" is the drift, recorded under X-1407 | - |
| crates/busbar-mcp/src/mcp/tests/envelope_id_tests.rs | CLEAN | The `unwrap_or_default()` at :90 is deliberate and documented (:74-78) — the notification cases assert the body is empty AS TEXT — and the file carries the control `a_string_id_is_served_and_echoed_verbatim` | - |
| crates/busbar-mcp/src/mcp/tests/exchange_cap_tests.rs | CLEAN | The over-cap case IS driven (`"A".repeat(cap + 4096)` with a fixture guard `assert!(body.len() > cap)`), and the two refusals are mutually discriminating (`!err.contains("not JSON")` vs `!err.contains("cap")`). No float | - |
| crates/busbar-mcp/src/mcp/tests/hook_gate_tests.rs | CLEAN | Both tests carry a real control half (`ungated` 200 + `peer.mcp_hits()==1`); the cdylib absence is `.expect(...)`, never a skip | - |
| crates/busbar-mcp/src/mcp/tests/hook_tap_tests.rs | CLEAN | The source-scan at :259 carries its own falsifier (`has_lenient_reader(...)` must be `true`), so the scan cannot pass vacuously — the positive half X-1440's instrument lacks | - |
| crates/busbar-mcp/src/mcp/tests/http_client_leg_tests.rs | FINDING | `grep -n 'OUTCOME_\|REASON_'` → the five hits at :525-533 are ALL doc-comment or the `fn` name. The test named `…recorded_as_dispatched_with_the_upstream_failed_reason` asserts neither the outcome nor the reason — only `assert!(seq > 1)`. Positive control: the sibling `calllog_dispatch_tests.rs:595,:600` asserts both | X-1426 |
| crates/busbar-mcp/src/mcp/tests/ingress_tests.rs | CLEAN | Every refusal is paired with an accepting control; the one loop over a possibly-empty collection (:522) is backed by a real HTTP probe at :532-543 | - |
| crates/busbar-mcp/src/mcp/tests/inputreq_tests.rs | CLEAN | The cap test drives `cap ∈ {0,1,3}` against an upstream that NEVER returns a result and asserts `calls == cap+1`; the budget test drives past the charge limit. Both over-limit paths exercised | - |
| crates/busbar-mcp/src/mcp/tests/method_tests.rs | FINDING | `git grep -n 'fs.internal'` → `:593` explains the assertion with a host the fixture does not use: `:570` registers `meter` and `poisoned_server` builds `https://{id}.internal/mcp`, so the host is `meter.internal`. `MAX_TASK_ANSWERS` over-ceiling IS genuinely driven | X-1427 |
| crates/busbar-mcp/src/mcp/tests/progress_cap_tests.rs | CLEAN | The bare `#[cfg(test)]` gate at `mod.rs:1196` is CORRECT, not a defect: `cargo test -p busbar-mcp --lib progress_cap` with NO features → `1 passed; 38 filtered out`, exit 0. It drives the OVER-cap case (`0..(MAX_FRAMES + 50)`) and asserts len, first and last frame | - |
| crates/busbar-mcp/src/mcp/tests/prompt_args_tests.rs | CLEAN | The ordering test is the discriminator the header claims, and the expansion test bounds output against bytes-in | - |
| crates/busbar-mcp/src/mcp/tests/quarantine_boot_tests.rs | FINDING | `git grep -n hydrate` → exactly ONE value-producing call (:472); the doc at :429-430 says "The control is the second half: a well-formed row replays as one too". That second half does not exist, and the corrupt upsert reuses the genuine row's key so exactly one row remains | X-1428 |
| crates/busbar-mcp/src/mcp/tests/request_meta_tests.rs | CLEAN | Three refusals plus two controls (`a_complete_meta_still_reaches_the_method_table` → 200 + `/result/tools`), so "refuses everything" cannot pass | - |
| crates/busbar-mcp/src/mcp/tests/reroute_pool_tests.rs | FINDING | `awk '/^impl StdioPool/,/^}/' \| grep 'pub(crate) fn'` → only `slot`, `len`, `retain`. The swap assertion at :348 is `len() == 1`, which a `retain()` that kept the ORPHAN and dropped the SURVIVOR satisfies identically | X-1429 |
| crates/busbar-mcp/src/mcp/tests/resource_tests.rs | CLEAN | `the_metadata_document_is_public_on_an_otherwise_closed_deployment` asserts `/stats` → 401 FIRST, so the 200 is a property of the route; the confused-deputy test asserts the `aud`-matching control is 200 before the four refusals | - |
| crates/busbar-mcp/src/mcp/tests/resource_uri_tests.rs | CLEAN | Both ambiguity cases driven in BOTH declaration orders; `not_found_and_not_granted_are_indistinguishable` compares two real bodies rather than one shape | - |
| crates/busbar-mcp/src/mcp/tests/result_envelope_tests.rs | CLEAN | The `for (method, member) in CACHEABLE` loop (:94) iterates a 5-element `const` literal (:83-89), so it cannot be vacuous; the version test compares against `SUPPORTED_PROTOCOL_VERSIONS` itself | - |
| crates/busbar-mcp/src/mcp/tests/roots_changed_tests.rs | CLEAN | Four arms: bump bites, cross-principal does NOT, non-roots exchange does NOT, `id`-bearing spelling does NOT — the negative arms are what make the positive one falsifiable | - |
| crates/busbar-mcp/src/mcp/tests/roots_satisfy_tests.rs | CLEAN | It DOES drive both unsatisfied cases distinctly: `Ungranted` (:135, `peer.mcp_hits()==1`, no retry) and `Unsatisfiable` (:187, message must contain `tools.fs.roots`), plus a boot-time `validate_server` pair at :225 | - |
| crates/busbar-mcp/src/mcp/tests/sampling_satisfy_tests.rs | CLEAN | Both `unwrap_or_default()` sites (:254,:394) are followed by POSITIVE `message.contains(...)` assertions, which go red on `""` — not the X-1424 shape | - |
| crates/busbar-mcp/src/mcp/tests/sampling_spend_tests.rs | CLEAN | Low assert count is because `.expect()`/`.expect_err()` ARE the assertions. All three tests drive both polarities: under-cap admitted then over-cap refused naming the key, window reset (`now+60` against `now_secs/60` — units agree), and per-server isolation | - |
| crates/busbar-mcp/src/mcp/tests/sep2243_ask_merge_tests.rs | CLEAN | One focused security test with 3 assertions including an `assert_ne!` on runtime values plus the upstream-witness check the header promises; the other 5 `fn` are fixtures | - |
| crates/busbar-mcp/src/mcp/tests/sse_tests.rs | FINDING | 12 tests, 11 of them strong. But `the_stream_offers_no_resumption_it_cannot_honour` (:212) does `let (_, _, text) = post(...)` — discarding status AND content-type — then asserts only that no line starts `id:`/`retry:`. A JSON error body satisfies that, and the sibling at :188 proves this helper returns exactly such a body | X-1444 |
| crates/busbar-mcp/src/mcp/tests/stdio_client_leg_tests.rs | CLEAN | 6 tests against a REAL child process: every issued verb correlated, handshake once per child not per call, ungranted refused before the child, chatty child still answered correctly, granted-vs-ungranted distinguishable, peer signal rate-limited | - |
| crates/busbar-mcp/src/mcp/tests/stdio_dispatch_tests.rs | FINDING | Bodies are strong (`cargo test … -- stdio_dispatch_tests::` → `4 passed; 0 failed`), including the breaker driven end to end. But `:108` cites a staged claim `MCP_STDIO_TRANSPORT`; `grep -rl 'MCP_STDIO_TRANSPORT' --exclude-dir=.git --exclude-dir=target .` → that one file, and `qa/documented-claims.json` does not contain it | X-1445 |
| crates/busbar-mcp/src/mcp/tests/stdio_serve_tests.rs | FINDING | 18 tests, broad and mostly strong (ceilings, cancellation, budget, keepalive, drain failure). But `a_tasks_transition_is_pushed_over_the_channel` (:1235) manufactures the task under the WATCHER's spelling — `TASKS.create("anonymous", …)` at :1246 — instead of driving a real `tools/call`, which is what conceals X-1439 | X-1439 |
| crates/busbar-mcp/src/mcp/tests/subscribe_tests.rs | FINDING | The `include_str!` source-scan at :1033 is a GOOD instrument — negative half AND positive half (`code.contains("Standing::opened")`), so removing the re-resolution goes red; contrast X-1440. But `:1010` cites `scripts/plane-purity-lint.sh` in the present tense as a live ban, and `ls` says it does not exist | X-1446 |
| crates/busbar-mcp/src/mcp/tests/tasks_tests.rs | FINDING | `:431` is `include_str!("../tasks.rs")` + `assert!(field.contains("TASK_TTL_MS"))` — a substring search of the DOC COMMENT. Its own `RED:` note says "delete the `TASK_TTL_MS` reference from the field's doc and this fails": its only red is a prose edit. `git grep -n TASK_TTL_MS -- …/tests/` → no test asserts a running task is bounded at 300s, because it is not. Separately `:418` cites the deleted `scripts/plane-purity-lint.sh` as a live ban | X-1440, X-1446 |
| crates/busbar-mcp/src/mcp/tests/tools_config_tests.rs | CLEAN | 22 tests; collision cases driven in EITHER declaration order (:577), the admin write path asserted to refuse exactly what the file refuses (:321,:629,:761), and `an_override_equal_to_its_own_namespaced_default_is_not_a_collision` is the negative control | - |
| crates/busbar-mcp/src/mcp/tests/transport_pin_tests.rs | CLEAN | A genuine pin: 4 tests covering cert_spki match/mismatch AND mtls match/mismatch against a real `TlsFixture`, asserting `approved`/`quarantined` and `report.drift.pin_changed`. Both polarities, both mechanisms | - |
| crates/busbar-mcp/src/mcp/tests/trust_gate_tests.rs | CLEAN | A MODEL retirement: the tombstone at :313-330 names the deleted scan, why, and where both halves went — and both landed. `git grep -n 'I-trust-serve-derivation\|trust-serve-decision' -- xtask/` → `choke_points.rs:287` and `census.rs:119`. Contrast X-1418 | - |
| crates/busbar-mcp/src/mcp/tests/upstream_join_tests.rs | FINDING | 9 of 10 tests strong (refusal arms distinguishable by audit reason :215, laundering proven closed two ways :330/:379, metadata-URL-in-arguments witnessed at the peer :519). But `upstream_tool_output_is_markup_normalised…` (:481) asserts the peer's markup-free bytes unchanged and then calls `sanitize::normalise` directly — never `normalise_json`, the fn the dispatch path uses at `method.rs:2090` | X-1447 |
| crates/busbar-mcp/src/mcp/tests/upstream_support.rs | CLEAN | 33 `pub(super)` items, 14 importing files. Dead-helper sweep found 2 apparent orphans (`PeerLog`, `secret_file`) — **FALSE ZERO of my own grep**, which excluded the defining file; both are used in-file at :170/:180/:192 and :545. Zero dead helpers | - |
| crates/busbar-mcp/src/mcp/tests/verify_on_call_tests.rs | CLEAN | 5 tests driving drift-refused-with-no-tick, N-concurrent-coalesced-to-one-fetch, unreachable-at-verify fail-closed, `verify_ttl: 0` refetch-every-call, and within-ttl reuse — the cache and the refusal both falsifiable | - |
| crates/busbar-mcp/src/testkit.rs | FINDING | Every export has a live consumer (`mcp_runtime_with_servers` → busbar-core-admin, `mcp_cfg_at` → busbar-kernel, `prefresh_mcp_sightings` → 6 files) — no dead fixture. But 8 references attribute them to `busbar-core`, and `swap_test_http_server`'s "For core's plane-swap integration test" has exactly one consumer, inside this crate | X-1443 |
| crates/busbar-mcp/src/tests/diagnostics_tests.rs | FINDING | 7 tests, all sound, incl. two committed-artifact comparisons. But the regeneration command at :126 and — worse — in the ASSERT MESSAGE at :141 is `-p busbar-plane-mcp-host`; `cargo test -p busbar-plane-mcp-host` → `package ID specification … did not match any packages` | X-1448 |
| crates/busbar-mcp/src/tests/record_tests.rs | CLEAN | Round-trips the SHIPPING type (`super::*` from `record.rs`, itself a re-export of `busbar-plane-mcp`) through `McpCallRecord::from_journal_body` — the real reader path — against a hand-framed journal body. Not a shadow | - |
| crates/busbar-mcp/src/tests/sdk_vocabulary_tests.rs | FINDING | A real pin that CAN produce a NO (left side a literal in another crate, right side the SDK's own type), and complete over its own 6 `METHOD_*` consts. But its denominator is those consts, not the 13-entry served dispatch table: 11 served methods are unpinned literals and rmcp ships a `const_string!` for every one of them | X-1449 |

## ROWS RAISED

### X-1400 · `canonical_uri` refuses a query in the PATH and admits one in the AUTHORITY — the audience and the discovery URL both take it
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "contains('?')" crates/busbar-mcp/src/mcp/mod.rs` →
```
1056:        if path.contains('?') || path.contains('#') || origin.contains('#') {
```
The pair is asymmetric: `#` is checked on BOTH halves, `?` only on `path`. Replicating
`split_absolute` + `normalise_path` exactly (python, `/tmp/split_probe.py`):
```
'https://gateway.example.com/mcp?a=1'    -> path='/mcp?a=1'   REFUSED: query/fragment
'https://gateway.example.com#f/mcp'      -> origin='…#f'      REFUSED: query/fragment
'https://gateway.example.com?tenant=a/mcp' -> origin='https://gateway.example.com?tenant=a'
                                              path='/mcp'     ACCEPTED mount='/mcp'
```
The existing corpus proves the instrument only ever saw the path position:
`sed -n '88,100p' crates/busbar-mcp/src/mcp/tests/config_tests.rs` → the two
`CanonicalUriHasQueryOrFragment` cases are `…/mcp?tenant=a` and `…/mcp#frag`.
IMPACT: `canonical_uri` is THE token audience, compared for exact equality by the verifier
(`mod.rs:1152`), and `metadata_url` is composed from the same `origin` — so the accepted value
yields an RFC 9728 discovery URL of `https://gateway.example.com?tenant=a/.well-known/…`, which no
compliant client can fetch. The refusal arm exists and is unreachable for this input class.
ACTION:    add `|| origin.contains('?')` to the guard at `mod.rs:1056`, and add
`("https://gateway.example.com?tenant=a/mcp", McpCfgError::CanonicalUriHasQueryOrFragment(…))` to
the `cases` table at `config_tests.rs:90`.

### X-1401 · `split_absolute` documents a scheme-separator check it does not implement
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `mod.rs:1078-1080` — *"The authority must be non-empty, must not itself contain a scheme
separator, and must not be the whole string's remainder only because the string ended at the
scheme."* Only the first and third are coded. Same replication:
```
'https://a://b/mcp' -> origin='https://a:'  path='//b/mcp'  ACCEPTED mount='/b/mcp'
```
The header two lines up says the function is deliberately hand-written because *"what is needed is
a STRICT recogniser for one shape"* and *"recognise, do not normalise"*.
ACTION:    reject when the authority slice contains `:` other than as a port separator, or delete
the sentence. Same test table as X-1400.

### X-1402 · `security.blocked_metadata_hosts` / `allow_metadata_hosts` / `allow_all_metadata` are documented as global and read by NOTHING in the MCP plane
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  The config surface promises global scope —
`crates/busbar-kernel/src/config/sections.rs:61-68`:
> *"Global SURGICAL allow-override: hosts/IPs to UNBLOCK from the cloud-metadata denylist for ALL
> providers. Carves a single exception out of the denylist **everywhere**"* … *"Nuclear override:
> when true the cloud-metadata SSRF guard is FULLY DISABLED for **every provider**"*

and `:55-58` says `blocked_metadata_hosts` is *"the answer to 'an unknown cloud's metadata
IP/hostname is not in the built-in list' — add it here."*

Measured:
```
$ git grep -c "blocked_metadata_hosts\|allow_all_metadata\|allow_metadata_hosts" -- crates/busbar-mcp/
rc=1                                    # ZERO, whole crate, including tests
# POSITIVE CONTROL:
$ git grep -c "blocked_metadata_hosts\|allow_all_metadata\|allow_metadata_hosts" -- \
    crates/busbar-kernel/src/appbuild.rs crates/busbar-llm/
crates/busbar-kernel/src/appbuild.rs:5
crates/busbar-llm/src/engine/build_runtime.rs:8
```
The operator's lists ride `PlaneBuildInput` — the **LLM plane's** carrier (`appbuild.rs:1534-1537`)
— and there is no process-global install (`git grep -nE 'static .*Denylist|install_denylist'` →
only a `Denylist::default()` in a test fixture). Both MCP guards therefore run on the hardcoded
list alone: the argument guard hard-codes the empty lists —
```
crates/busbar-mcp/src/mcp/client/argguard.rs:388:
    if ssrf_blocked_host(&probe_url(&host), &[], false, &[]).is_some() {
```
— and the URL guard's `SsrfPolicy::guard()` builds a `GuardPolicy` carrying no denylist field at all.
IMPACT: an operator on a cloud whose metadata endpoint is not in the built-in list adds it to
`security.blocked_metadata_hosts`; the LLM egress honours it and every MCP `tools/call` — the path
that carries a model-authored URL to an operator-chosen destination — does not.
ACTION:    thread the resolved `blocked_metadata_hosts` / `allow_metadata_hosts` /
`allow_all_metadata` onto `SsrfPolicy` (built in `config.rs` from the same `RootCfg` fields
`appbuild.rs:1534` already reads), pass them through `argguard::judge_host`'s
`ssrf_blocked_host(..)` call in place of the two `&[]` and the `false`, and add a `tools_config`
test asserting a host added to `blocked_metadata_hosts` refuses an MCP tool argument.
NOTE: **this is not MCP-specific.** `git grep -c … -- crates/busbar-a2a/` → rc=1 also. Both
extracted planes ignore it. See the outside-slice section.

### X-1403 · `ResourceUpdates` is one global ring; its own doc justifies the bound with a per-server argument, and its sibling in the same file IS per-server
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/pool.rs:180-183` —
```rust
pub(crate) struct ResourceUpdates {
    events: Mutex<std::collections::VecDeque<(u64, String, String)>>,   // ONE deque, all servers
    next_seq: std::sync::atomic::AtomicU64,
}
```
`record()` evicts with a bare `events.pop_front()` at `MAX_RESOURCE_UPDATES` (256) regardless of
which server wrote the victim. The bound's stated justification (`:185-186`) is:
> *"small enough that a hostile upstream writing one notification per millisecond evicts its **OWN**
> noise."*

That is only true of a per-server ring. The sibling structure 90 lines up IS per-server and says
why (`:77-79`):
> *"there is one gate per server so a chatty registration cannot starve a quiet one's trigger by
> consuming a shared budget."*

The same starvation argument, implemented for `RefreshTriggers` and stated-but-not-implemented for
`ResourceUpdates`, in one file.
IMPACT: one noisy or hostile registered upstream emitting `notifications/resources/updated` evicts
every OTHER server's announcements before a `subscriptions/listen` subscriber polls, so a
subscriber silently misses updates for a server that never misbehaved.
ACTION:    key `events` by server (`BTreeMap<String, VecDeque<…>>`) with the 256 cap applied
per-server, as `RefreshTriggers.gates` already is — or correct `:185-186` to state that the ring is
shared and the eviction is cross-server.

### X-1404 · The stdio client leg has no arm that can SATISFY an authority ask, so `grants.*: true` only changes the wording of the refusal
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/peer.rs:337-342` — `AskOutcome` has exactly two
variants, `Ungranted` and `Unsatisfiable`, and `answer()` (:349-380) returns `error_reply(id,
ASK_REFUSED, …)` on BOTH. `decide_ask` (:308) returns `Unsatisfiable` precisely when the grant IS
held. The satisfiers exist and are wired elsewhere:
```
$ git grep -n "satisfy_upstream_ask" -- crates/
crates/busbar-mcp/src/mcp/method.rs:1954:   super::sampling::satisfy_upstream_ask(…)
crates/busbar-mcp/src/mcp/method.rs:1957:   super::roots::satisfy_upstream_ask(…)
crates/busbar-mcp/src/mcp/tasks.rs:925/928: (the task path)
crates/busbar-mcp/src/mcp/{roots,sampling}.rs: the definitions
$ git grep -n "roots::\|sampling::" -- .../client/peer.rs .../client/stdio.rs
rc=1                                        # the stdio leg reaches neither
```
The code is honest about it (`peer.rs:47-49`, and the refusal text says *"no satisfier for that ask
on the stdio leg in this release"*), which is why this is raised as a config-surface row rather
than a silent hole.
IMPACT: `tools.<server>.grants.{roots,sampling,elicitation}: true` means "satisfied" for an upstream
reached inline over the `input_required` path and "refused" for the same ask arriving out-of-band
from a stdio child. One key, two meanings, chosen by a transport the operator did not think they
were selecting.
ACTION:    owner ruling. Either wire `peer::answer`'s granted arm into
`roots::satisfy_upstream_ask` / `sampling::satisfy_upstream_ask` (adding a `Satisfied(Value)` arm to
`AskOutcome`), or document the transport dependency on `ServerRequestGrants` in `config.rs:528-545`
so the key's meaning is not transport-dependent by accident.

### X-1405 · The `(mcp, Invoke)` / `(mcp, Subscribe)` WRITE half cannot ship, and three unreconciled spellings of the `tools/call` wire exist
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `OperationHandler` no longer has a write method at all:
```
$ grep -nE "fn (write_request|write_response|read_request|read_response)" \
    crates/busbar-substrate-values/src/handlers.rs
223: fn read_request_value  228: fn read_response_value  238: fn read_request  245: fn read_response
```
so `invoke_write_request` / `invoke_write_response` / `subscribe_write_request` /
`subscribe_write_response` are not a trait obligation. All four are
`#[cfg(any(test, feature = "test-support"))] #[allow(dead_code)]`, and
`git grep -n 'invoke_write_request\|subscribe_write_request' -- crates/` returns only the
definitions and `codec/tests/mcp_tests.rs`. MCP additionally declares `codec: None`
(`codec/mod.rs:66`), and `busbar-llm-codec/src/tests/proto/registry_tests.rs:215` asserts
`protocol_for("mcp").is_none()` — *"no codec means no cross-dialect translation into or out of it"*
— so no egress path can ever reach them.

Meanwhile the production `tools/call` bytes are composed by a THIRD function,
`client/jsonrpc.rs:130 tools_call(...)`, which emits a materially different document (progress
token, advertised capabilities, continuation, `_meta`), and `client/verb.rs:230
UpstreamVerb::ToolsCall` composes a FOURTH. Nothing compares them:
```
$ for f in $(git grep -l "invoke_write_request" -- crates/); do grep -c "jsonrpc::tools_call" "$f"; done
0
0                                  # no file names both the codec writer and the plane composer
```
The doc on both writers says *"Byte-identical to the inline write"* — a write that no longer exists.
ACTION:    delete the four `*_write_*` free fns and the round-trip tests that are their only
callers, OR — if the round-trip proof is wanted — point it at `client::jsonrpc::tools_call`, the
document that actually goes on the wire. Either way, drop the "byte-identical to the inline write"
sentence, which names nothing.

### X-1406 · Ten `#[allow(dead_code)]` sites are justified by "the connect verb has no verb yet". The connect verb landed.
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  The justification, tree-wide:
```
$ git grep -n "has no verb yet\|which does not exist yet\|Until the \`connect\` verb lands\|connect-path grant preview\|no inbound caller yet" -- crates/busbar-mcp/src
client/dispatch.rs:47   client/egress.rs:101   client/jsonrpc.rs:543,556,589,598,613
client/mod.rs:115       client/pool.rs:261     client/wire.rs:170
```
`client/mod.rs:113-117` states it plainly: *"The three items below are the CONNECT path, which does
not exist yet … Until the `connect` verb lands there is nothing to construct them from."*

The verb is live, audited, and `AdminScope::Full`:
```
crates/busbar-mcp/src/mcp/mod.rs:180:  on_swap/admin_routes installed on PLANE_DECL
crates/busbar-mcp/src/mcp/mod.rs:697-705:
    AdminRouteSpec { method: Post, path: "/tools/{name}/connect",
                     scope: AdminScope::Full, kind: AdminVerbKind::Audited { verb: "connect" },
                     handler: connect_reply::<McpServers> }
crates/busbar-mcp/src/mcp/mod.rs:735:  published in the OpenAPI fragment
crates/busbar-mcp/src/mcp/admin_view.rs:348-354:
    async fn look(...) { crate::mcp::connect::refresh(&subject.pool, &subject.sightings, &subject.entry) }
crates/busbar/src/main.rs:288:         installed.push(&busbar_mcp::PLANE_DECL);
```
It reaches `crate::mcp::connect::refresh` — a DIFFERENT implementation from the one these ten sites
are preserved for. The waiting half is `client/{issue,jsonrpc,mod,verb}.rs` (1,634 non-test lines)
plus `wire::notify` and `McpWire::notify`; `issue::issue`'s only callers are
`stdio_client_leg_tests.rs` and `http_client_leg_tests.rs`.
IMPACT: this is the load-bearing row of the slice. It is why 25 of the crate's 33 dead-code allows
sit in one directory (G4), and it is the reason X-1411 exists — the security batteries for
deny-by-default and the anti-amplification round cap are aimed at this half, not at the live one.
ACTION:    owner ruling, and it is a fork: either (a) retire the parallel half — delete
`client/issue.rs`, `client::jsonrpc::{InputRequiredLoop, ServerRequestGrants, AskRefusal}`,
`client::mod::{Endpoint, McpServerRegistration, McpClientEngine}`, `wire::notify`,
`McpWire::notify` and the 21 unreached `UpstreamVerb` variants, and re-point `ask_tests.rs` and
`verb_tests.rs` at the live path; or (b) wire the front door the verbs are waiting for. What must
not survive is the third state: kept alive by a reason that expired, with the tests pointed at it.

### X-1407 · The manifest describes two dependencies that do not exist, a weak forward that is not weak, and 51,587 lines as "Shell only"
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "^busbar-" crates/busbar-mcp/Cargo.toml
41: busbar-kernel  53: busbar-plane-mcp  55: busbar-api  56: busbar-substrate-values
57: busbar-contract  66: busbar-plugin  67: busbar-plugin-loader  87: busbar-store-memory
158: busbar-llm  165: busbar-store-memory  166: busbar-secret-ref  177: busbar-core-admin
$ ls -d crates/busbar-core crates/busbar-substrate
ls: crates/busbar-core: No such file or directory
ls: crates/busbar-substrate: No such file or directory
```
Against that, the comments assert:
- `:30-40` — *"busbar-core stays an OPTIONAL dep, pulled ONLY by the `test-support` feature"* and
  *"`src/mcp/tests/engine.rs`, the only `busbar_core::` line in the test tree"*. There is no
  `busbar-core` dep line, and `engine.rs` names `busbar_kernel::` only (`:14`, `:24`).
- `:42-45` — describes a `busbar-substrate` dependency. No such line, no such crate.
- `:126-131` — *"the openapi-schema forward now points at SUBSTRATE"*. `:132` is
  `openapi-schema = ["busbar-kernel/openapi-schema", "dep:schemars"]`.
- `:133-136` — *"Forwarded WEAKLY (`?`)"*. `:136` is `auth-admin-tokens =
  ["busbar-kernel/auth-admin-tokens"]`, no `?` — and could not be weak, since `busbar-kernel` is
  not optional.
- `:137-143` — *"Pulls busbar-core (the optional dep)"*. `test-support` pulls
  `busbar-kernel/{test-support,plane-mcp,plane-a2a}`, `dep:reqwest`, `dep:busbar-store-memory`.
- `:22` — `description = "… Shell only — code has not moved here yet."` against
  `git ls-files 'crates/busbar-mcp/**/*.rs' | xargs wc -l` → **51,587**.
`description` is package metadata, so this one is a published-surface string, not only a comment.
ACTION:    rewrite the `[dependencies]` and `[features]` comment blocks to name `busbar-kernel` /
`busbar-substrate-values` (the crates that are actually there), drop the `?`/optional-dep narrative,
and replace the `description` with what the crate is.

### X-1408 · `protocol_name()` restates the literal the crate has a constant for, and the only check that would catch it is test-order dependent
CLASS:     drift
CERTAINTY: VERIFIED (measurement) · ADJUDICATE (severity)
EVIDENCE:  `codec/mod.rs:65` sets `name: busbar_plane_mcp::PLANE_KEY`; `codec/handler.rs:89-91`
returns the literal `"mcp"`. `lib.rs:86-91` says PLANE_KEY exists *"so the `busbar` binary names ONE
stable path … and the plane and the flip cannot drift onto two different literals."*
The pin exists but not reliably for MCP:
```
crates/busbar-llm-codec/src/tests/proto/registry_tests.rs:149-153
    assert_eq!(handler.protocol_name(), decl.name,
               "a handler filed under a name it does not answer to is a registry key that means nothing");
```
…inside `the_declared_verbs_are_the_verbs_the_handler_serves`, which loops `builtins().decls()`
after `crate::ensure_test_protocols_registered()`. That fn registers `DECLS` — the six LLM dialects
only (`busbar-llm-codec/src/lib.rs:156-159`). MCP enters the shared process registry from a
DIFFERENT test (`registry_tests.rs:211 register_test_protocol(&busbar_mcp::PROTO_DECL)`), so whether
the loop sees MCP depends on test order. The loop's own comment at :131 (*"MCP declares
`invoke`/`subscribe`"*) shows the author expected it to be covered.
ACTION:    return `busbar_plane_mcp::PLANE_KEY` from `handler.rs:90`, and register
`busbar_mcp::PROTO_DECL` inside `ensure_test_protocols_registered()` so the pin's coverage is not a
function of scheduling.

### X-1409 · The codec's two "the SDK is the acceptance test" claims name a mechanism that moved and a path that was deleted
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
(a) `codec/subscribe.rs:62` heads the section *"WHY THE PARAMS ARE DESERIALIZED INTO `rmcp`'s
STRUCTS RATHER THAN READ FIELD BY FIELD"* and argues *"Deserializing into the SDK's own parameter
type makes the SDK's schema the acceptance test."* The code below (`:130`, `:135`) deserializes into
the LOCAL `SubscriptionParams` declared at `:31` — which `:17-21` explains, 40 lines up, was
introduced precisely because the SDK types *"stayed behind with `rmcp`"*. The heading survived the
change it describes.
(b) `codec/subscribe.rs:27-29` — *"`busbar-mcp` … pins this shape and **every method name** against
the SDK's own types in its own test binary."* The pin is real and complete over its subject, but
its subject is 6 names:
```
$ git grep -n "pub const METHOD_" -- crates/busbar-plane-mcp/ | wc -l
6
$ git grep -ohE '"(tools|prompts|resources|tasks|notifications|sampling|elicitation|roots|completion|subscriptions|server|logging)/[a-zA-Z/_]+"|"ping"|"initialize"' \
    -- crates/busbar-mcp/src ':!crates/busbar-mcp/src/**/tests/*' | sort -u | wc -l
33
```
27 of the 33 method names the plane speaks are raw literals (`client/verb.rs:181-206`,
`client/peer.rs:266-290`) with no constant and therefore no SDK pin.
(c) `codec/mod.rs:11` cites *"`git grep busbar_mcp crates/busbar-core/src` is pinned at zero"* — a
pin over a directory `ls` reports does not exist. A grep over a missing path returns zero for the
wrong reason.
ACTION:    retitle `subscribe.rs:62`; narrow `:27-29` to "the six method constants"; either promote
the remaining 27 literals to constants so the pin can cover them or say plainly that it does not;
and repoint `codec/mod.rs:11` at `crates/busbar-kernel/src`.

### X-1410 · `mcp_on_swap` reconciles a connection pool that `McpRuntime::build` constructed empty microseconds earlier — the hook is a guaranteed no-op, and every stdio child, TLS client, rate-limiter and subscriber cursor is discarded on every config apply
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Two doc comments in one file state contradictory facts about one field, and the code
sides with one of them.

`McpRuntime::build` (`crates/busbar-mcp/src/mcp/mod.rs:310` doc, `:316` code):
```rust
/// `catalogue`/`servers`/`pool` are fresh (a new pin generation, a fresh pool), while
/// `sightings`/`roots_epochs`/`sampling_spend` are ACCUMULATED evidence and are carried from `prior`
    pool: std::sync::Arc::new(client::pool::McpConnectionPool::new()),
```
`mcp_on_swap` (`:490-503` doc, `:505-514` code):
```rust
/// CARRY THE MCP CONNECTION POOL ACROSS A CONFIG SWAP … The pool deliberately outlives an apply
/// … the pool is Arc-carried onto the next snapshot by `App::clone` (a live-config mutation)
/// already, so the work is a reconciliation of the carried pool to the next catalogue
pub(crate) fn mcp_on_swap(_prior: &dyn PlaneSlots, next: &dyn PlaneSlots) {
    let rt = runtime_slots(next);
    rt.pool.children.retain(&rt.catalogue.servers().map(|s| s.id.clone()).collect::<BTreeSet<_>>());
}
```
The pool is never carried:
```
$ git grep -n "\.pool\.clone()\|pool: prior\|p\.pool" -- crates/busbar-mcp/src
crates/busbar-mcp/src/mcp/admin_view.rs:340:  pool: rt.pool.clone(),     # within-generation read
crates/busbar-mcp/src/mcp/method.rs:1136:     let pool = rt.pool.clone(); # within-generation read
# POSITIVE CONTROL — the three fields that ARE carried:
crates/busbar-mcp/src/mcp/mod.rs:320: |p| p.sightings.clone(),
crates/busbar-mcp/src/mcp/mod.rs:324: |p| p.roots_epochs.clone(),
crates/busbar-mcp/src/mcp/mod.rs:337: |p| p.verify.clone(),
```
`PLANE_DECL.on_swap = Some(mcp_on_swap)` (`:180`), and `build_runtime` is invoked unconditionally
during App composition (`busbar-kernel/src/appbuild.rs:1478-1490`), i.e. on EVERY apply — not only
when `tools:` changed.

What the rebuilt `McpConnectionPool` was holding (`client/pool.rs:49-62`):
1. `clients` — the pinned-address TLS client pool. Discarded ⇒ full reconnect + handshake to every
   registered upstream on the next call.
2. `children` — the supervised stdio child processes. `StdioChild::spawn` sets
   `.kill_on_drop(true)` (`client/stdio.rs:401`), so dropping the prior pool **kills every live
   child**, not only the deregistered one. `client/pool.rs:26-29` asserts the opposite: *"The pool
   deliberately outlives an apply … so reusing it across a config edit is safe and desirable."*
3. `children` also carries `ChildSlot.supervisor` (`client/stdio.rs:744-745`) — the crash-loop
   breaker. `Supervisor::reset`'s doc (`stdio.rs:300-302`) is explicit: *"An explicit act, never a
   timeout. A breaker that resets itself turns 'this child is broken' into 'this child is broken
   every few minutes', which is the same fork bomb on a longer period."* A config apply resets every
   breaker wholesale without being that act.
4. `triggers` — the per-server 60 s peer-signalled-refresh floor (`PEER_TRIGGER_FLOOR_MS`,
   `pool.rs:99`), whose stated purpose is stopping *"an amplifier with a config file behind it"*.
   Reset to empty.
5. `updates` — the `ResourceUpdates` ring AND its `next_seq` counter, reset to 0 while live
   `subscriptions/listen` streams still hold cursors from the retired ring (see X-1435, found
   independently from the reader side).
ACTION:    carry the pool in `McpRuntime::build` the way `sightings`/`roots_epochs`/`verify`
already are — `pool: prior.map_or_else(|| Arc::new(McpConnectionPool::new()), |p| p.pool.clone())`
— which restores `mcp_on_swap` to the reconciliation its doc describes and makes `_prior`'s absence
correct. Then add a test that applies a config twice and asserts the same stdio child pid serves
both generations. If instead the fresh-pool behaviour is intended, `mcp_on_swap` should be deleted
(it can do nothing) and `pool.rs:26-29` plus `mod.rs:490-503` rewritten to say children are
recycled on every apply.

### X-1411 · Seven deny-by-default and cost-cap tests are green against a duplicate type with no production caller
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "struct ServerRequestGrants" -- crates/
crates/busbar-mcp/src/mcp/client/jsonrpc.rs:536:pub(crate) struct ServerRequestGrants {
crates/busbar-mcp/src/mcp/config.rs:533:pub(crate) struct ServerRequestGrants {
```
Two independent structs, same name, same three bools. The `config.rs` one is serde-derived from the
operator's `tools:` block and is the LIVE gate:
```
crates/busbar-mcp/src/mcp/inputreq.rs:354:  if !grants().allows(&ask.kind) {        # takes &str
crates/busbar-mcp/src/mcp/client/peer.rs:71: use crate::mcp::config::ServerRequestGrants;
crates/busbar-mcp/src/mcp/client/wire.rs:135: grants: crate::mcp::config::ServerRequestGrants,
```
The `jsonrpc.rs` one takes `ServerAsk`, carries `#[allow(dead_code)]` on its `allows()` (`:544`),
and is reached only through `client/mod.rs:106,160,177` — the `McpServerRegistration` of X-1406.
Its partner loop has no production caller at all:
```
$ git grep -n "InputRequiredLoop" -- 'crates/**/*.rs' | grep -v tests/ask_tests.rs
… jsonrpc.rs:591 (struct)  :597 (impl)  :615 (may_satisfy)
… approvals.rs:44, jsonrpc.rs:41, peer.rs:305, wire.rs:132   # all doc lines
```
`ask_tests.rs:10` imports the shadow. Seven of its twelve tests —
`grants_are_all_false_at_construction…` (:135), `an_ungranted_ask_is_refused…` (:147),
`a_revoked_grant_bites_on_the_very_next_retry` (:171), `each_grant_is_independent` (:189),
`a_hostile_upstream_cannot_amplify_cost_by_asking_forever` (:207), `the_bound_is_per_dispatch`
(:238), `a_cap_of_zero_denies_every_round` (:253) — therefore prove nothing about the live path.
The live cap is built at `method.rs:2301 max_rounds: server.max_input_required_rounds`.
ACTION:    make `client::jsonrpc::ServerRequestGrants` a
`pub(crate) use crate::mcp::config::ServerRequestGrants;` re-export so there is ONE type and
`allows()` loses its `#[allow(dead_code)]`; re-point `ask_tests.rs` at `inputreq::drive` and the
`method.rs` round cap. Sequence this AFTER the X-1406 ruling, since (a) there deletes the shadow.

### X-1412 · `every_variant_appears_in_all_exactly_once` checks for duplicates, not completeness — the exact blindness its own doc says it prevents
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/tests/verb_tests.rs:73-90`. The doc:
> *"Without this, a variant added to the enum and forgotten in `all()` would narrow every test above
> and below silently — the exact shape of the four batteries this release found reporting green over
> a shrinking denominator."*

The body:
```rust
let all = UpstreamVerb::all();
let mut names: Vec<&str> = all.iter().map(UpstreamVerb::method).collect();
let before = names.len();
names.sort_unstable(); names.dedup();
assert_eq!(before, names.len(), "`UpstreamVerb::all()` lists a method twice, …");
```
Dropping a variant from `all()` shortens `before` and `names.len()` equally ⇒ still green.
```
$ git grep -n "UpstreamVerb::[A-Z]" -- crates/busbar-mcp/src/mcp/client/tests/verb_tests.rs
(rc=1, no output)
$ git grep -c "UpstreamVerb::[A-Z]" -- crates/busbar-mcp/src/mcp/client/verb.rs
73                                    # POSITIVE CONTROL: the pattern matches real code
```
`all()` is a hand-written `vec![]` (`verb.rs:373`), so there is no compiler exhaustiveness behind it
either. The enum and `all()` both list 23 today — counted by hand, not by any instrument.
ACTION:    add `assert_eq!(all.len(), 23)`, or make `all()` a `match` over a unit-discriminant
companion so rustc enforces it; rename the test to what the body proves; and correct the doc at
`verb_tests.rs:73-77`.

### X-1413 · `UpstreamVerb::all()`'s doc names a test that does not exist and calls a `Vec` a `const` array
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -rn "every_issued_method_is_in_the_inventory" -- .
crates/busbar-mcp/src/mcp/client/verb.rs:370   # one hit: the stale doc line itself
# POSITIVE CONTROL — a live test name resolves to a fn:
$ git grep -rn "the_issued_set_is_exactly_the_inventory_column" -- .
crates/busbar-mcp/src/mcp/client/tests/verb_tests.rs:47:fn the_issued_set_is_exactly_the_inventory_column() {
crates/busbar-mcp/src/mcp/client/verb.rs:13
```
The same doc calls `all()` *"a `const` array rather than a derive"*; `verb.rs:373` is
`pub(crate) fn all() -> Vec<UpstreamVerb> { vec![ … ] }`.
ACTION:    repoint `verb.rs:370` at `the_issued_set_is_exactly_the_inventory_column` and drop
"const array". Also `verb.rs:82-83` names only `stdio_client_leg_tests.rs` as `issue::issue`'s
caller; `http_client_leg_tests.rs` is a second one.

### X-1414 · `http_peer_tests.rs`'s header claims a compiler-backed denominator; it is a hand-kept const
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/tests/http_peer_tests.rs:36-37` —
> *"the denominator is taken from `super::super::peer`'s own closed enums rather than from a list
> this file keeps."*
```
$ git grep -nE "fn all\(\)|const ALL|EnumIter|strum" -- crates/busbar-mcp/src/mcp/client/peer.rs
(rc=1, no output)
$ git grep -n "ALL_NOTIFICATIONS\|ALL_REQUESTS" -- crates/busbar-mcp/src/mcp/client/
…/tests/http_peer_tests.rs:168:const ALL_NOTIFICATIONS: [ServerNotification; 9] = [
…/tests/http_peer_tests.rs:180:const ALL_REQUESTS: [ServerRequestVerb; 4] = [
# POSITIVE CONTROL that an enumeration CAN live beside an enum:
crates/busbar-mcp/src/mcp/client/verb.rs:373: pub(crate) fn all() -> Vec<UpstreamVerb>
```
Counts match today (9 and 4), but nothing ties them. A tenth `ServerNotification` silently narrows
all four sweeps in the file AND misaligns the hardcoded `seen[13]`/`seen[14]` indices at :262-271.
`peer_tests.rs:317-325` keeps its own separate 9-row copy.
ACTION:    add `pub(crate) const ALL: [ServerNotification; N]` / `[ServerRequestVerb; M]` to
`peer.rs`, built from a `match self { … }` so the compiler enforces completeness, and have both
test files read it.

### X-1415 · `azure_wireserver_and_oci_imds_are_refused` cannot fail on the regression it names
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/tests/ssrf_tests.rs:276-290` drives ONE policy
(`SsrfPolicy { allow_private: false }`) and its `unwrap_err_or_else_msg` helper (:292-302) asserts
nothing but `self.is_err()`. Both literals are in BOTH predicates:
```
$ git grep -n "168, 63, 129, 16" -- crates/busbar-kernel-egress/src/trust/net.rs
net.rs:95:   const AZURE_WIRESERVER: Ipv4Addr = …     <- inside ipv4_is_internal
net.rs:181:  Ipv4Addr::new(168, 63, 129, 16),          <- inside ip_is_cloud_metadata
$ git grep -n "o\[0\] == 192 && o\[1\] == 0 && o\[2\] == 0\|Ipv4Addr::new(192, 0, 0, 192)" -- …/net.rs
net.rs:123:  || (o[0] == 192 && o[1] == 0 && o[2] == 0) <- inside ipv4_is_internal
net.rs:182:  Ipv4Addr::new(192, 0, 0, 192),            <- inside ip_is_cloud_metadata
```
Under `allow_private: false` the internal-address arm refuses them anyway, so the test stays green
even if the CloudMetadata arm stopped naming them — which is exactly the *"refused
unconditionally, `allow_private` or not"* property it exists to hold. The sibling
`cloud_metadata_is_refused_unconditionally` (:145) does it right: it loops
`for policy in [public(), private_ok()]` AND matches `SsrfRefusal::CloudMetadata { .. }`.
IMPACT: if that arm regressed, a server with `allow_private: true` would reach Azure WireServer and
OCI IMDS, and this test would not say so.
ACTION:    loop both policies and replace the helper with
`assert!(matches!(err, SsrfRefusal::CloudMetadata { .. }))`. The `UnwrapErrMsg` trait then has no
caller and should go with it.

### X-1416 · An assertion message with an uninterpolated `{a}` placeholder
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -nE '\.(expect|expect_err)\("[^"]*\{[a-z_]+\}' -- 'crates/busbar-mcp/src/mcp/client/tests/*.rs'
crates/busbar-mcp/src/mcp/client/tests/ssrf_tests.rs:156:  .expect_err("{a} must be refused under every policy");
```
Exactly one hit; positive control `git grep -cE '\.expect_err\("'` returns 16/8/3/3/… across twelve
sibling files. `expect_err` takes a plain `&str`, so on failure the operator reads the literal
characters `{a}` instead of the address that was admitted.
ACTION:    `.unwrap_or_else(|_| panic!("{a} must be refused under every policy"))`, matching
`argguard_tests.rs:211`.

### X-1417 · `a_snapshot_is_immutable_once_handed_out`'s doc describes a generation bump the body never checks
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `dispatch_tests.rs:82-83` — *"Deregistering a server bumps the generation, which is what
makes an already-resolved call fail its re-validation rather than dispatching into a hole."*
```
$ sed -n '85,100p' crates/busbar-mcp/src/mcp/client/tests/dispatch_tests.rs | grep -c "generation"
0
```
The body calls `cache.apply(|servers| { servers.remove("fs"); })` and asserts only that the old
snapshot still holds `fs` and the live one does not — read-copy-update isolation, not the
generation claim. That claim is proven in `engine_tests.rs:60`.
ACTION:    replace the two doc lines with one describing snapshot isolation, which is what the body
proves and what the test name already says.

### X-1418 · `dispatch.rs` advertises a "MACHINE-CHECKED" source scan that `routing_key_tests.rs` deleted
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -rn "dispatch_never_reads_a_tool_description" -- .
crates/busbar-mcp/src/mcp/client/dispatch.rs:27       # advertises it as live
crates/busbar-mcp/src/mcp/client/tests/routing_key_tests.rs:120  # the tombstone recording its deletion
```
Two hits, neither a `fn`. `dispatch.rs:24-28` reads *"MACHINE-CHECKED. … That second half is a test
(`tests/routing_key_tests.rs::dispatch_never_reads_a_tool_description`) that scans this module's
[source]"*. Positive control: `the_issued_set_is_exactly_the_inventory_column` resolves to a real
`fn`. The invariant itself is fine — `routing_key_tests.rs:126-134` says both halves moved to
`structure-lint` — but only one side of the move was written down.
NOTE: `trust_gate_tests.rs:313-330` is the same retirement done correctly, in the same tree: it
names the deleted scan, why, and where both halves went, and both DID land
(`xtask/.../choke_points.rs:287`, `xtask/.../census.rs:119`, verified). The pattern is known; this
is the miss.
ACTION:    rewrite `dispatch.rs:24-29` to name the `structure-lint` rows.

### X-1419 · `adminverbs_tests.rs` names three crates and one module path that are not in the tree
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -nE 'busbar[-_]admin|busbar[-_]core([^-_]|$)' crates/busbar-mcp/src/mcp/tests/adminverbs_tests.rs
27,28,34,35,36,37,39   # busbar-admin / busbar-core / busbar_admin::install()
$ ls -d crates/busbar-admin crates/busbar-core
ls: crates/busbar-admin: No such file or directory
ls: crates/busbar-core: No such file or directory
# POSITIVE CONTROL:
$ git grep -n '^name = "busbar-core-admin"' -- '*/Cargo.toml'
crates/busbar-core-admin/Cargo.toml:15
```
The code four lines below the comment already uses the right name (`:43
busbar_core_admin::install();`). Separately `:310` cites an include site in `adminverbs.rs`;
`git ls-files 'crates/busbar-mcp/src/mcp/*.rs'` has no such file — it is `admin_view.rs:429`.
ACTION:    `busbar-admin` → `busbar-core-admin`, `busbar-core` → `busbar-kernel`, and
`adminverbs.rs` → `admin_view.rs` at :310.

### X-1420 · The ledger control asserts a property of `Default`, not of the deployment it just booted
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `adminverbs_tests.rs:353-361` reads the pre-connect ledger with
`…map(|s| s.ledger.clone()).unwrap_or_default()` and then asserts
`due(&fresh, &policy, now, false) == Due::NeverChecked`. But:
```
$ git grep -n -B4 -A14 'pub struct .*Ledger' -- crates/busbar-kernel/src/trust/reverify.rs
reverify.rs:30: #[derive(Clone, Debug, Default, PartialEq, Eq)]
reverify.rs:31: pub struct Ledger {  :33  pub last_checked_ms: Option<u64>,
$ git grep -n -A30 'pub fn due' -- crates/busbar-kernel/src/trust/reverify.rs
reverify.rs:111: let Some(last) = ledger.last_checked_ms else {
reverify.rs:112:     return Due::NeverChecked;
```
`due(&Ledger::default(), …)` is `Due::NeverChecked` unconditionally, so `unwrap_or_default()`
collapses "the cache has no `fs` entry at all" and "the cache has an unstamped `fs` entry" into one
green answer. The same test's post-connect read (:372-376) uses `.expect(...)` and WOULD go red on
an absent entry — the two halves are written differently for no stated reason.
ACTION:    change the control to `.expect("the registration is in the sightings cache before any
operator look")`.

### X-1421 · `callerask_tests.rs`'s header advertises a source-scan gate and its planted-violation companion; both were deleted
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Header (:4, :10-13): *"THE ASK DECISION, and the source-scan gate that keeps it unable to
launder. … That is asserted by scanning the source, and the scan has a companion test that plants a
violation in a copy of the source and proves the scan catches it."*
```
$ grep -c 'include_str\|file!()\|std::fs::read_to_string' crates/busbar-mcp/src/mcp/tests/callerask_tests.rs
0
# POSITIVE CONTROL — real source scans exist in sibling trees:
$ git grep -c 'include_str!' -- 'crates/*/src/**/tests/*.rs' | head -3
crates/busbar-a2a/src/a2a/tests/hook_tap_tests.rs:1
crates/busbar-contract/src/caps/tests/mod.rs:1
…
# And the production file says so outright:
crates/busbar-mcp/src/mcp/callerask.rs:24: This REPLACES `tests/callerask_tests.rs::callerask_names_nothing_upstream_derived`, which
crates/busbar-mcp/src/mcp/callerask.rs:25: `include_str!`-scanned this file …
```
The scan was retired in favour of a real type-system guarantee (the private `authored` module — and
that guarantee holds; `callerask.rs` is CLEAN). Two further production files repeat the stale claim:
`config.rs:378` (*"scanned at test time"*) and `mcp/mod.rs:112`.
ACTION:    rewrite `callerask_tests.rs:4,10-13` to state the unconstructibility guarantee, and fix
`config.rs:378` and `mod.rs:112` in the same pass.

### X-1422 · Doc citations point at a spec file and a test module that are not in the tree
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'mod spentledger'
(rc=1)
$ git ls-files | grep spentledger
crates/busbar-kernel/tests/spentledger_cross_plane.rs   # "Relocated here VERBATIM from src/plane/tests/spentledger_tests.rs"
$ find . -path ./target -prune -o -iname '*mrtr*' -print
./.mcp-conformance/sdk/examples/mrtr   ./…/mrtr.test.ts    # no .mdx anywhere
```
`callerask_tests.rs:78` cites `spentledger_tests`; `:156`, `:203`, `:269` cite `mrtr.mdx:246` /
`:235` — line numbers into a document the repo does not contain. `callerask.rs` itself cites
`mrtr.mdx` at 6 further sites. Positive control: the conformance ids this file also cites DO
resolve (`git grep -c 'PAT.MRTR.NO-UNDECLARED-CAPABILITY'` → 4 files).
ACTION:    repoint `:78` at `crates/busbar-kernel/tests/spentledger_cross_plane.rs`, and replace
the bare `mrtr.mdx:NNN` citations with the in-repo conformance anchors that resolve, or vendor the
clause text so the citation is self-contained.

### X-1423 · A module path cited from three files does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `client_leg_metrics_tests.rs:27` cites `plane::tests::metrics_tests`.
```
$ git ls-files 'crates/busbar-kernel/src/plane/*'
…/plane/tests/{askstate,auditlog,config,cost,demotion,handle_engine,sections,store_seam}_tests.rs
                                                       # no metrics_tests.rs
$ git grep -n 'mod metrics_tests' -- crates/busbar-kernel/src
(rc=1)
$ sed -n '640,642p' crates/busbar-kernel/src/metrics.rs
#[path = "tests/metrics_tests.rs"] mod tests;          # the real module: busbar_kernel::metrics::tests
```
Positive control: the other paths this file cites DO resolve (`qa/capability-equality.json`,
`telemetry.rs:421`). Repeated at `busbar-a2a/.../relay_tests.rs:1449` and
`busbar-kernel/src/tests/telemetry_tests.rs:25`.
ACTION:    `plane::tests::metrics_tests` → `busbar_kernel::metrics::tests`, all three sites.

### X-1424 · The typed-prompt sanitisation test passes on an ABSENT string — it has only the negative half of the pair
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/tests/content_tests.rs:396-402`:
```rust
let text = body["result"]["messages"][0]["content"]["text"].as_str().unwrap_or_default();
assert!(!text.contains("<script>"), "typed prompt content reached the client with its markup intact: {text:?}");
```
```
$ sed -n '389,403p' … | grep -cE 'assert!\(text\.|contains\("ignore previous"\)|assert_eq!\(text'
0
# POSITIVE CONTROL — the sibling 170 lines up, same file, pairs its halves:
$ sed -n '223,238p' … | grep -cE 'text\.contains\("123"\)'
1
```
`unwrap_or_default()` yields `""` whenever the pointer misses — an empty `messages` array, a renamed
content key, a dropped `text` field, a prompt that returned nothing — and `!"".contains("<script>")`
is TRUE. The only other assertion is `status == 200`, which the harness returns for an empty result
too. So `typed_prompt_text_is_markup_normalised_like_a_template` cannot distinguish "the markup was
stripped" from "no text came back" — the exact failure its own doc says it exists to catch (*"a new
content type that skipped the normaliser"*).
Checked and NOT a pervasive style: the other five `unwrap_or_default()` sites in the plane test tree
(`sampling_satisfy_tests.rs:254,:394`, `subscribe_tests.rs:339,:421`, `upstream_join_tests.rs:198`)
are each followed by a POSITIVE `contains(...)`/`len()` assertion that goes red on `""`.
ACTION:    add the positive half, matching the file's own convention at :228-237:
`assert!(text.contains("ignore previous"), "the surviving prompt text never reached the client — the
strip assertion below is vacuous on an empty string: {body}");`

### X-1425 · `assert_ne!` between two string literals
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/tests/deputy_pair_tests.rs:433-436`:
```rust
assert_ne!(
    "fs_read fs_write", "fs_read",
    "the server genuinely offers more than one tool, so the down-scope above is a narrowing"
);
```
It can never fail. The claim it is labelled with is a fact about the `exchanging_server()` fixture,
and this statement observes nothing about it. Positive control: the file's other two `assert_ne!`
(:148, :174) compare runtime values.
IMPACT: if `exchanging_server` were reduced to one tool, the sibling
`a_wildcard_principal_is_down_scoped_to_the_single_tool_it_called` would go vacuous and this guard
would stay green.
ACTION:    assert the fixture's real arity —
`assert!(exchanging_server(&peer, SUBJECT).tools_allow.len() > 1, …)`.

### X-1426 · A test named for an outcome and a reason asserts neither
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `http_client_leg_tests.rs:533
async fn an_upstream_error_is_recorded_as_dispatched_with_the_upstream_failed_reason()`.
```
$ grep -n 'dispatched\|upstream_failed\|OUTCOME_\|REASON_' crates/busbar-mcp/src/mcp/tests/http_client_leg_tests.rs
369: busbar_contract::vocab::REASON_NOT_GRANTED,
410: busbar_contract::vocab::REASON_NOT_SERVING,
525,527,528,530,533:   # ALL doc-comment or the fn name — no assertion
# POSITIVE CONTROL — the sibling battery that DOES assert them:
$ git grep -n 'REASON_UPSTREAM_FAILED\|OUTCOME_DISPATCHED' -- …/tests/calllog_dispatch_tests.rs
49: use busbar_contract::vocab::{OUTCOME_DISPATCHED, OUTCOME_REFUSED, REASON_UPSTREAM_FAILED};
595: records[0].outcome, OUTCOME_DISPATCHED,
600: records[0].reason, REASON_UPSTREAM_FAILED,
```
The body asserts only `err.contains("-32003")`, `peer.mcp_hits()==1` and `assert!(seq > 1)` — "a row
exists". The defect its own doc comment describes (*"the reason token was being written into the
`outcome` field … Nothing asserted it, which is why it survived"*) would still not be caught.
Severity is reduced — not removed — by `calllog_dispatch_tests.rs:519` covering the same
`issue()` leg.
ACTION:    replace `assert!(seq > 1)` with the record read-back the sibling already uses
(`list_mcp_calls(&app, &caller.id)`) and assert both `outcome` and `reason`; or rename the test.

### X-1427 · A comment explains an assertion with a hostname the fixture does not use
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'fs.internal' -- crates/busbar-mcp/src/mcp/tests/method_tests.rs
593:    // The call is refused at the ROUND TRIP: `fs.internal` does not resolve, so the dispatch-time
```
The deployment under test registers `meter`, not `fs` (`:570 .mcp_server("meter",
poisoned_server("meter", "probe"))`, and `poisoned_server` builds `https://{id}.internal/mcp` at
`:99`) — so the host that fails to resolve is `meter.internal`. The comment at :564-569 immediately
above explains at length why this test was moved OFF the shared `fs` fixture.
ACTION:    `fs.internal` → `meter.internal` at :593.

### X-1428 · The stated control for a quarantine-replay count is not in the body
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'hydrate' -- crates/busbar-mcp/src/mcp/tests/quarantine_boot_tests.rs
92:  (comment)   98: (inside boot(), return value discarded)   424: (doc)
472: let replayed = crate::mcp::demotion::hydrate(&host, Some(&plane_store));
```
Exactly one value-producing `hydrate` call, and the test at :432 builds `restarted` by hand
(:463-468) rather than through `boot()`, so `:98` is not reached by it. The doc at :429-430 says:
> *"The control is the second half: a well-formed row replays as one too, so the count is a count of
> demotions held and not a constant."*

There is no second half, and the corrupt upsert at :447-455 uses `kind=KIND_DEMOTION / id="fs"` —
the key the genuine demotion was written under — so it REPLACES it, leaving exactly one row.
`assert_eq!(replayed, 1)` therefore cannot distinguish "one held quarantine" from "a constant 1".
ACTION:    write the corrupt row under a SECOND id with a second registration so the genuine row
survives and the expected count becomes 2 — which no constant satisfies.

### X-1429 · The pool-swap assertion cannot tell the orphan from the survivor
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ awk '/^impl StdioPool/,/^}/' crates/busbar-mcp/src/mcp/client/stdio.rs | grep -n 'pub(crate) fn'
slot(&self, server: &str)    len(&self)    retain(&self, keep: &BTreeSet<String>)
$ git grep -n 'fn contains\|fn names\|fn keys' -- crates/busbar-mcp/src/mcp/client/stdio.rs
(rc=1)
$ git grep -c 'fn ' -- crates/busbar-mcp/src/mcp/client/stdio.rs      # POSITIVE CONTROL
32
```
`reroute_pool_tests.rs` seeds slots `keep` and `orphan` (:334-335), asserts `len()==2` as a fixture
control (:336), swaps, then asserts only `len() == 1` (:348) with the message *"the swap retires the
orphan … and keeps the survivor"*. A `retain()` that kept `orphan` and dropped `keep` produces
`len()==1` too.
NOTE: read with X-1410 — the hook under test is currently a no-op against a freshly-built pool, so
what this test observes is the test's own direct `StdioPool` manipulation, not the production swap.
ACTION:    after the swap, re-request `slot("keep")` (create-if-missing) and assert `len()` stays 1;
if `keep` had been retired, `len()` would go to 2. No new `StdioPool` API needed.

### X-1430 · The wire-word census cannot see the second spelling of `mcp-protocol-version`
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `envelope.rs:72-74` states the invariant: *"each of these literals must occur EXACTLY
ONCE in production code. A second spelling anywhere in the tree is RED."*
```
$ grep -rn --include='*.rs' '"mcp-protocol-version"' crates/busbar-kernel/src/ crates/busbar/src/ \
    crates/busbar-mcp/src/ crates/busbar-a2a/src/a2a/ crates/busbar-llm/src/ crates/busbar-llm-codec/src/ | grep -v /tests/
crates/busbar-mcp/src/mcp/envelope.rs:111:pub(crate) const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";
$ grep -rn --include='*.rs' '"mcp-protocol-version"' crates/busbar-plane-mcp/src/
crates/busbar-plane-mcp/src/plane.rs:62:const FIELD_PROTOCOL_VERSION: &str = "mcp-protocol-version";
```
The second const is LIVE (`plane.rs:549` uses it as the outbound envelope field name). The census
row is scoped to `tree`:
```
xtask/src/gates/structure_lint/census.rs:109
  r("wire-word-header-protocol-version", "WIRE-WORD-RESPELT", r#""mcp-protocol-version""#, 1, tree.clone(), …)
```
and `proto_root_of` (`xtask/src/gates/structure_lint/roots.rs:52-63`) matches only `busbar-llm`,
`busbar-mcp`, `busbar-*-codec`, `busbar-proto-*` — **not `busbar-plane-mcp`**. So `want: 1` is
satisfied by `envelope.rs:111` alone and the row is structurally blind to the second literal.
(`cargo xtask gate structure-lint` could not be run red/green: the xtask lib does not compile on
this branch — `error[E0425]: cannot find function 'cell_subst'` at
`xtask/src/gates/kind_isolation.rs:5021,5611` — a pre-existing break unrelated to this slice.)
ACTION:    make `plane.rs:62` read the one const by identity (as `envelope.rs:89,104` already do
for the two `_meta` keys), or add `crates/busbar-plane-mcp/src/` to the row's scope and raise `want`
only after the duplicate is removed.

### X-1431 · `Mcp-Name` is enforced on six methods and the refusal names three
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "required on tools/call, resources/read and prompts/get" -- crates/
crates/busbar-mcp/src/mcp/envelope.rs:468
$ git grep -n '"tasks/get"' -- crates/busbar-plane-mcp/src/codec.rs
codec.rs:236: "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
$ git grep -n '"tasks/get" =>' -- crates/busbar-mcp/src/mcp/method.rs
method.rs:210,211,212   # all three are live dispatch arms
```
`envelope.rs:460` gates on `if let Some(source) = name_source_of(method)` with no other condition,
so all three `tasks/*` methods take the branch and are refused by a sentence naming three methods
none of which they are. The same three-method claim is stated as fact in two further doc comments
(`:108-109`, `:458-459`). The rule gained `tasks/*` on the codec side only.
ACTION:    make the refusal derive from the source rule —
`format!("The `Mcp-Name` header is required on `{method}` (it mirrors `params.{source}`).")` — and
fix the two doc comments to say "the methods `name_source_of` names".

### X-1432 · `envelope.rs`'s header says the method table is empty and every method takes `-32601`; it has 13 entries
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `envelope.rs:38-43` — *"## What this module does NOT do / It looks nothing up. The method
table is empty here, and every method therefore takes the `-32601` arm."*
```
$ sed -n '190,235p' crates/busbar-mcp/src/mcp/method.rs | grep -cE '^\s*"[a-z]+/'
12                                   # + the METHOD_SUBSCRIPTIONS_LISTEN const arm = 13
```
The same file already contradicts its own header at `:505-508` (*"The method table owns everything
from here … did not have to change when the table gained entries"*), and the header's step
numbering (1-8) no longer matches the body's (9-13, `:307`).
ACTION:    delete the "What this module does NOT do" section; `:505-508` is the true statement.

### X-1433 · The `"MCP method refused"` log record is built on every refusal and can never reach a client
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `envelope.rs:647-654` builds a `LogRecord` with
`level: if ok { "info" } else { "warning" }` and
`"message": if ok { "MCP method completed" } else { "MCP method refused" }`. Its sole consumer is
`envelope.rs:610 sse::as_event_stream(response, &logs, &progress)`, and `sse.rs:217-219` is
`if response.status() != StatusCode::OK { return response; }` — for any non-200 the whole `logs`
vec is discarded untouched. `ok` is `response.status() == StatusCode::OK` (`:636`), so the `else`
half is only ever computed on a response whose logs are then thrown away.
```
$ git grep -n "MCP method refused" -- crates/
crates/busbar-mcp/src/mcp/envelope.rs:651      # one hit: no consumer, no test
# POSITIVE CONTROL that the grep shape finds test occurrences:
$ git grep -n "busbar.mcp.dispatch" -- crates/
envelope.rs:640, :649    tests/sse_tests.rs:260
```
ACTION:    drop the refusal half (making `request_log` unconditionally `info`/`"MCP method
completed"` and losing the `ok`/`status` plumbing at :632-636), or emit it before `sse.rs:217`'s
early return. Either way `:615-619` (*"the second states how it ended"*) needs rewriting, since
"how it ended" can only ever be "completed".

### X-1434 · `MAX_LIFETIME`'s doc states the opposite of the code it guards and cites a test that was renamed away
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `subscribe.rs:115-123` —
> *"**THIS BOUND IS LOAD-BEARING FOR AUTHORISATION** … The caller's key is FROZEN at open, so a key
> that is revoked, tombstoned or re-scoped mid-stream keeps being honoured until the stream ends.
> This constant is therefore the ONLY thing bounding how long a dead credential can still be served:
> the exposure window IS this number. … see the characterisation test
> `a_revoked_key_keeps_being_served_until_the_lifetime_bound`, which pins today's behaviour."*

The code does the opposite: `:462-472` re-resolves the principal on EVERY poll via
`host.principal_standing(&self.standing, …)` and ends the stream on `Err(lapsed)`; `caller_of`
(:379-393) takes the freshly resolved key as a parameter and captures nothing. The module header at
`:65-80` says so in as many words.
```
$ git grep -rn "a_revoked_key_keeps_being_served_until_the_lifetime_bound" -- crates/
subscribe.rs:123                                    # the doc
tests/subscribe_tests.rs:825: "This WAS `a_revoked_key_keeps_being_served_until_the_lifetime_bound`…"
$ git grep -rn "a_revoked_key_stops_being_served_on_the_next_poll" -- crates/
tests/subscribe_tests.rs:850: fn a_revoked_key_stops_being_served_on_the_next_poll() {
```
IMPACT: the doc tells the next maintainer that revocation does not bite mid-stream — the one thing
`Standing` was added to make false.
ACTION:    rewrite `:115-123` and repoint the citation at
`a_revoked_key_stops_being_served_on_the_next_poll`.

### X-1435 · A listen stream's update cursor indexes a ring that is rebuilt on every apply, silently dropping announcements
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `subscribe.rs:673` seeds `cursor: super::runtime_of(&ctx.host).pool.updates.latest()` at
open; `:453` + `:523` then poll `super::runtime_live(&self.host)` → `rt.pool.updates.since(cursor)`.
`runtime_live` (`mod.rs:382-391`) is a `plane_slot_live` read, so the stream DOES observe the
swapped runtime. But per X-1410 the pool — and therefore `ResourceUpdates`, `#[derive(Default)]`
with `next_seq: AtomicU64` — is rebuilt from zero on every apply. `since` (`pool.rs:228-239`)
filters `*seq > cursor`, so after an apply every event in the new ring with `seq <= cursor` is
dropped and never returned, and `self.cursor = latest` (:524) then snaps the cursor down.
```
$ grep -rn "cursor" crates/busbar-mcp/src/mcp/tests/subscribe_tests.rs
703:  cursor: 0,   901:  cursor: 0,      # the only two constructions — the one value that masks it
```
ACTION:    closed by X-1410's fix (carrying the pool). If that ruling goes the other way, give
`ResourceUpdates` a per-instance epoch that `since` compares, so a cursor from a retired ring resets
to `latest()` instead of silently filtering.

### X-1436 · `CandidatePoolCfg::repeatability` — "the one reader of `repeatable:`" — has no production caller, and `reroute.rs` spells the lookup a second time
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "repeatability(" -- crates/
crates/busbar-kernel/src/config/tests/tests.rs:3783,3787,3792    # TEST call sites
crates/busbar-kernel/src/failover/mod.rs:190                     # the definition
# POSITIVE CONTROL that the grep shape finds production callers:
$ git grep -n "pool_members_repeatable(" -- crates/ | grep -v '/tests/'
crates/busbar-mcp/src/mcp/reroute.rs:124
# the second spelling:
$ grep -rnE "repeatable\.iter\(\)\.any" crates/ | grep -v '/tests/'
crates/busbar-mcp/src/mcp/reroute.rs:214       crates/busbar-kernel/src/failover/mod.rs:191
```
The fn carries `#[allow(dead_code)]` (`failover/mod.rs:189`) while its own doc (`:184-185`) says:
*"The one reader of `repeatable:`, so the default can never be got wrong by a second caller spelling
the lookup differently."* `reroute.rs:213-214`'s comment asserts *"the same check
`CandidatePoolCfg::repeatability` runs"* — it is not that check, it is a copy of it.
IMPACT: `repeatable:` decides whether a leg may be replayed AFTER a dispatch has gone out
(`failover/mod.rs:678-686`), so two copies drifting means a non-idempotent tool replayed.
ACTION:    have the host seam `pool_members_repeatable` return `Repeatable` computed by
`CandidatePoolCfg::repeatability` core-side, or expose a neutral
`busbar_kernel::failover::repeatability(&[String], &str) -> Repeatable` both sites call. Then drop
the `#[allow(dead_code)]`.

### X-1437 · `reroute.rs` names `failover::walk` as "the ONE selection loop"; nothing calls it
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -rn "failover::walk\b" crates/ --include='*.rs' | grep -v walk_with | grep -v '/tests/'
busbar-a2a/src/a2a/relay.rs:295  route.rs:11  busbar-mcp/src/mcp/method.rs:1843
upstream.rs:421  reroute.rs:5  reroute.rs:14  busbar-kernel/src/store/planes.rs:16,161,187
# nine references, every one prose. POSITIVE CONTROL:
$ grep -rn "failover::walk_with" crates/ --include='*.rs' | grep -v '/tests/'
busbar-llm/src/engine/select.rs:382   busbar-a2a/src/a2a/route.rs:183   busbar-mcp/src/mcp/reroute.rs:294
```
`walk` (`failover/mod.rs:211`) is a wrapper that forwards to `walk_with` and is reached by nothing.
The rustdoc link still resolves, so the `doc-links` gate stays green — the instrument cannot say NO
here.
ACTION:    repoint `reroute.rs:5,:14` at `walk_with` (which this file's own inline comment at
:274-275 already names) and delete `failover::walk`.

### X-1438 · A durable quarantine is dropped with no log and no count — the exact shape the file's own doctrine block forbids
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '100,110p' crates/busbar-mcp/src/mcp/demotion.rs
  let Some(entry) = rt.catalogue.server(&row.server) else {
      tracing::info!(server = %row.server, "… it is not replayed");
      continue;
  };
  let Ok(id) = crate::mcp::client::identity::ServerId::new(&entry.id) else {
      continue;
  };
```
The neighbouring skip logs; this one does not, and `replayed` is not incremented. `demotion.rs:56-72`
is a 17-line block whose entire subject is that this shape is a security bug: *"This was `Err(_) =>
continue`: a row that would not decode was dropped on the floor with no log line and no count …
Skipping the row re-opened it exactly that way."* The fix was applied to the decode `continue` and
not to this one. Every other production `ServerId::new` treats the failure as first-class:
```
$ grep -rn "ServerId::new" crates/busbar-mcp/src/ --include='*.rs' | grep -v '/tests/'
upstream.rs:232 → SetupRefusal::Malformed   upstream.rs:318 → SetupRefusal::Malformed
connect.rs:229  → RefreshRefusal::Malformed demotion.rs:108 → bare `continue`
```
Reachable, not theoretical: `ServerId::new` rejects empty, non-`[A-Za-z0-9_.-]` and `_`
(`identity.rs:80-104`), while the only name check a `tools:` key gets is the `_` rule
(`config.rs:1402`) — no charset check, no empty check. Mitigating: such a server also cannot be
dispatched to (`upstream.rs:232` refuses it), so the dropped quarantine is currently
unexploitable; the missing diagnostic is the live defect.
ACTION:    give `:108-110` the treatment the decode arm got — a `tracing::warn!` naming the server
and saying the quarantine is NOT in force — and add the `legal()` charset + non-empty check to
`validate_server` (`config.rs:1384`) so an unconstructible id is refused at config time.

### X-1439 · The stdio task watcher looks tasks up under a principal spelling the registry never stores them under
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Four production registry accesses; three use `task_principal`, one does not.
```
$ git grep -n "TASKS\.\(create\|get\|update\|cancel\)" -- crates/busbar-mcp/src | grep -v /tests/
method.rs:353  method.rs:390  method.rs:2280      # all task_principal(ctx)
stdio_serve.rs:1076: let Some(task) = super::tasks::TASKS.get(&task_id, &actor) else {
$ sed -n '301,306p' crates/busbar-mcp/src/mcp/method.rs
fn task_principal<'a>(ctx: &'a Ctx<'_>) -> &'a str {
    ctx.gov.key.as_ref().map_or("<ungoverned>", |k| k.id.as_str())
}
$ sed -n '1064p' crates/busbar-mcp/src/mcp/stdio_serve.rs
        let actor = self.principal.actor_id().to_string();
$ sed -n '53,58p' crates/api/src/auth.rs
pub fn actor_id(&self) -> &str { self.0.as_ref().map(|p| p.id.as_str()).unwrap_or("anonymous") }
```
`VirtualKey.id` != `Principal.id` in general, and on the ungoverned arm they are literally
`"<ungoverned>"` vs `"anonymous"`. `Registry::get` filters `t.principal == principal`
(`tasks.rs:517`), so the watcher's first tick returns `None`, hits `return` at `:1077` ("expired or
swept"), and **no `notifications/tasks` is ever emitted on the stdio binding**. The author knew the
other spelling — `stdio_serve.rs:608-612` builds `notify_principal` with the identical
`map_or_else(|| "<ungoverned>", |k| k.id.clone())` for roots epochs, 450 lines up in the same file,
commented *"The SAME principal name the HTTP observer binds roots epochs under"*.
The instrument that should have caught it manufactures the task under the WATCHER's spelling:
```
$ sed -n '1244,1246p' crates/busbar-mcp/src/mcp/tests/stdio_serve_tests.rs
// The session's actor is `anonymous` (ungoverned fixture); create its task in the registry.
let task = crate::mcp::tasks::TASKS.create("anonymous", busbar_kernel::store::now_ms());
$ git grep -n "TASKS.create(task_principal" -- crates/busbar-mcp/src/mcp/tests/
(rc=1)        # all 17 test creations pass a hand-written string; none passes what production passes
```
ACTION:    replace `stdio_serve.rs:1064` with the expression already at `:608-612`; better, lift
`task_principal` to `pub(crate)` so the two sides cannot drift again. Then rewrite
`a_tasks_transition_is_pushed_over_the_channel` to create the task through a real `tools/call` over
the session.

### X-1440 · A frozen authorisation's stated 5-minute containment is 288x larger in reality, is caller-refreshable, and is guarded by a test that greps the claim
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `tasks.rs:624-628`, on `Runner.authorised`:
> *"WHAT MAKES IT SURVIVABLE, and it is a real property rather than an accident: [`TASK_TTL_MS`] is
> 300 000. Nothing on this path can outlive a revocation by more than five minutes, and that bound
> is enforced by the registry's own sweep."*
```
$ grep -nE "const (TASK_TTL_MS|ACTIVE_TASK_ABANDON_MS)" crates/busbar-mcp/src/mcp/tasks.rs
76: const TASK_TTL_MS: u64 = 300_000;
99: const ACTIVE_TASK_ABANDON_MS: u64 = 86_400_000;
$ sed -n '447,456p' crates/busbar-mcp/src/mcp/tasks.rs
fn is_expired(&self, now: u64) -> bool {
    state.status.is_terminal() && now.saturating_sub(state.updated_ms) > TASK_TTL_MS
}
fn is_abandoned(&self, now: u64) -> bool {
    !state.status.is_terminal() && now.saturating_sub(state.updated_ms) > ACTIVE_TASK_ABANDON_MS
}
```
`is_expired` requires `is_terminal()`. A `Runner`'s task is by definition NOT terminal, so
`TASK_TTL_MS` never touches the frozen key. The only bound on a running task is
`ACTIVE_TASK_ABANDON_MS` — 24 hours, **288x the stated bound** — and it is keyed on `updated_ms`,
which the caller refreshes for free:
```
$ sed -n '335,341p' crates/busbar-mcp/src/mcp/tasks.rs
for (key, value) in responses { … }
Self::touch(&mut state, now_ms);                       # deliver() <- Registry::update <- tasks/update
$ sed -n '343,349p' crates/busbar-mcp/src/mcp/method.rs
// ABSENT is treated as empty rather than refused. …
let responses = params.and_then(|p| p.get("inputResponses")).and_then(|v| v.as_object())
    .cloned().unwrap_or_default();
```
So an empty `tasks/update {}` costs nothing, adds no answer key, and resets `updated_ms`. The sweep
runs only at create time (`grep -n "sweep" tasks.rs` → one call site, `:507`), so with no new task
creations nothing ages out at all.

**THE INSTRUMENT.** `tests/tasks_tests.rs:431-445`:
```rust
let source = include_str!("../tasks.rs");
let field = source.split("pub(crate) struct Runner {").nth(1)…split("pub(crate) authorised:").next()…;
assert!(field.contains("TASK_TTL_MS"), "…");
```
The whole guard on this security claim is a substring search of the DOC COMMENT. Its own `RED:` note
says *"delete the `TASK_TTL_MS` reference from the field's doc and this fails"* — its only red is a
prose edit. It cannot produce a NO about the bound, only about the sentence.
```
$ git grep -n "TASK_TTL_MS" -- crates/busbar-mcp/src/mcp/tests/
:402 (used only on an already-CANCELLED task)   :430, :442 (the doc-grep)
$ git grep -c "ACTIVE_TASK_ABANDON_MS" -- crates/busbar-mcp/src/mcp/tests/    # POSITIVE CONTROL
tasks_tests.rs:3                                # the real bound IS testable, and is tested elsewhere
```
No test asserts a running task is bounded at 300 s, because it is not.
CONTRAST: `subscribe_tests.rs:1033` is the same `include_str!` technique done correctly — it has a
negative half AND a positive half (`code.contains("Standing::opened")`,
`contains("principal_standing")`), so removing the guarded behaviour goes red.
ACTION:    either (a) correct the disclosure to name `ACTIVE_TASK_ABANDON_MS` as the real bound and
state that `tasks/update` refreshes it, or (b) make the bound real: add a `created_ms`-anchored hard
ceiling the sweep applies to ACTIVE tasks too, independent of `updated_ms`, so no caller action can
extend it. Replace the doc-grep with a red-capable test over a local `Registry`: create a task,
advance the clock past the claimed bound while issuing empty `tasks/update`s, assert it is cancelled.

### X-1441 · "every round is metered before it is spent" is unqualified; one of two call sites passes a charge seam that cannot say no
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `inputreq.rs:35-39` — *"there is a hard cap on rounds per logical dispatch (refused past
it, not warned), and every round is metered before it is spent, not after."*
```
$ sed -n '939,940p' crates/busbar-mcp/src/mcp/tasks.rs
let mut charge_seam =
    |_: &super::inputreq::RoundRecord, _: &busbar_kernel::plane_host::DispatchScope| Ok(());
# against the synchronous path's real seam:
$ sed -n '1966,1968p' crates/busbar-mcp/src/mcp/method.rs
let mut charge_seam = |rec: &RoundRecord, round_scope: &…DispatchScope| {
        charge_round(ctx, &selected.namespaced, rec, round_scope) };
```
On the task path `Refusal::BudgetExhausted` (`inputreq.rs:156`, *"THE RUNAWAY-LOOP COST CAP …
Per-key budgets ARE the loop cap"*) is unconstructible. Mitigating and verified, not assumed:
`tasks.rs:933-938` documents the deviation at length, `max_rounds` still bounds the loop, and
granted sampling has its own ceiling (`sampling.rs:177 sampling_spend.try_spend(…)`). This is a
doc-scope defect, not an unbounded-cost hole — listed accordingly.
ACTION:    scope the claim at `inputreq.rs:35-39` to the synchronous path and add the same caveat to
`Refusal::BudgetExhausted`'s doc at `:152-155`.

### X-1442 · The health endpoint answers "never contacted, no reason" for a quarantined server whose reason it is holding
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  The endpoint's own published summary (`mcp/mod.rs:763`) is *"Whether one MCP server
currently serves, **and why not when it does not**"*.
```
$ sed -n '256,260p' crates/busbar-mcp/src/mcp/admin_view.rs
    serving: report.state == TrustState::Approved,
    contacted: report.observed > 0 || report.failure.is_some(),
    failure: report.failure.clone(),
$ sed -n '458,465p' crates/busbar-mcp/src/mcp/connect.rs
let observed = match &sighting { Sighting::Seen(o) => o.capabilities.len(), _ => 0 };
let failure  = match &sighting { Sighting::Failed(reason) => Some(reason.clone()), _ => None };
```
`Sighting` has four arms (`busbar-kernel/src/trust/mod.rs:96-116`), and `Demoted(String)` — whose
own doc says *"CONTACTED BEFORE THIS PROCESS EXISTED"* and which carries *"the operator-visible word
for why"* — falls into the `_` of BOTH matches. So `contacted: false`, `failure: null`.
Reachable on every boot after a durable demotion:
```
$ git grep -n "Sighting::Demoted" -- crates/ | grep -v /tests/
crates/busbar-mcp/src/mcp/demotion.rs:117: sc.sighting = Sighting::Demoted(reason);
$ git grep -n "hydrate: Some(mcp_hydrate)" -- crates/busbar-mcp/src/mcp/mod.rs
mod.rs:174
```
The `adminverbs_tests` quarantined arm (:215-222) asserts `serving` only — `contacted` is not
asserted there, and nobody drove the `Demoted` arm.
ACTION:    widen `connect::changes`'s failure match to
`Sighting::Failed(r) | Sighting::Demoted(r) => Some(r.clone())`, and set `contacted` from
`!matches!(sighting, Sighting::Never)` rather than deriving it from `observed`/`failure` (which is
also wrong for a `Seen` server that legitimately offers zero tools). Add an adminverbs test that
hydrates a demotion row and asserts `contacted == true` and `failure == Some(reason)`.

### X-1443 · `testkit.rs` attributes five exports to a deleted crate, one of them to a consumer that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Every export IS reachable — this is prose drift, not a dead capability:
`mcp_runtime_with_servers` → `busbar-core-admin/src/tests/tests.rs:13547` +
`v1/tests/service_tests.rs:142`; `default_mcp_runtime` → `busbar-core-admin/src/lib.rs:113`;
`mcp_cfg_at` → `busbar-kernel/tests/plane_integration.rs:92,125,172`; `prefresh_mcp_sightings` → 6
files; `tools_hooks`/`with_mcp_sightings` → 9 files.
```
$ grep -n "busbar-core\|busbar_core" crates/busbar-mcp/src/testkit.rs
5, 7, 37, 70, 178, 193, 209, 257
$ ls -d crates/busbar-core
ls: crates/busbar-core: No such file or directory
$ git grep -n "swap_test_http_server" -- crates/ | grep -v testkit.rs
crates/busbar-mcp/src/mcp/tests/reroute_pool_tests.rs:327      # the ONLY consumer — inside this crate
```
`:224` calls it *"For core's plane-swap integration test"*. No core test calls it.
ACTION:    repoint the four attributions at `busbar-core-admin` / `busbar-kernel`; change
`swap_test_http_server`'s doc to name `mcp::tests::reroute_pool_tests`, or demote it to
`pub(crate)`. The historical narrative at :5/:7/:37/:70 is fine as history but should say "the
pre-1.6.0 busbar-core crate (now split into busbar-kernel / busbar-core-admin)".

### X-1444 · `the_stream_offers_no_resumption_it_cannot_honour` is green when there is no stream
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/tests/sse_tests.rs:212-221`:
```rust
let (_, _, text) = post(&url, "text/event-stream", &body("resources/list", None)).await;
for line in text.lines() {
    assert!(!line.starts_with("id:") && !line.starts_with("retry:"), "…");
}
```
Both facts that establish a stream exists — the status AND the content-type — are discarded at the
destructure. A JSON error body satisfies the loop trivially:
```
$ printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}' \
  | while IFS= read -r line; do case "$line" in id:*|retry:*) echo "WOULD FAIL";; *) echo "PASSES";; esac; done
PASSES
```
And that body is not hypothetical: the SIBLING test `an_error_is_never_framed_as_a_stream` (:188)
posts through the same helper and receives exactly that shape (asserted `404` / `-32601` at
:196-201). So if the SSE branch regressed and `resources/list` answered JSON — or 404 — this test
reports green while the stream it is named for does not exist.
POSITIVE CONTROL, the file's own convention: `a_client_that_prefers_event_stream_gets_an_sse_response`
(:107) asserts `status == 200`, `ct.starts_with("text/event-stream")` and
`text.contains("event: message\ndata: ")` BEFORE reading frames (:113-123).
ACTION:    capture the status and content-type at :214 and assert all three preconditions before the
loop, reusing the three-line preamble at :113-123.

### X-1445 · `MCP_STDIO_TRANSPORT` is a dangling staged-claim citation — neither the claim nor the mechanism exists
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -rl "MCP_STDIO_TRANSPORT" . --exclude-dir=.git --exclude-dir=target
crates/busbar-mcp/src/mcp/tests/stdio_dispatch_tests.rs
$ git grep -n "staged claim" -- crates qa xtask
crates/busbar-mcp/src/mcp/tests/stdio_dispatch_tests.rs:108
$ python3 -c "import json;print('MCP_STDIO_TRANSPORT' in json.dumps(json.load(open('qa/documented-claims.json'))))"
False
```
One file in the tree names it, and names it as a pointer into a registry that does not contain it;
the phrase "staged claim" appears nowhere else in `crates/`, `qa/` or `xtask/`, so the staging
mechanism is gone too. Nothing goes red when such a pointer rots, which is why it already has.
ACTION:    repoint :108 at the live evidence surface — the `mcp|stdio|*` cells of
`qa/method-inventory.json`, which `client/tests/verb_tests.rs:19-38` already reads and enforces in
both directions — or delete the staged-claim clause.

### X-1446 · Two test files cite a deleted gate script as a live, currently-enforced ban
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -la scripts/plane-purity-lint.sh
ls: scripts/plane-purity-lint.sh: No such file or directory
$ grep -n "plane-purity-lint" crates/busbar-mcp/src/mcp/tests/{subscribe_tests,tasks_tests}.rs
subscribe_tests.rs:1010: … the PATH-INCLUDE side channel scripts/plane-purity-lint.sh bans
tasks_tests.rs:418:      … the PATH-INCLUDE side channel scripts/plane-purity-lint.sh bans
```
Both state, in the present tense, that a script "bans outright, test scope included" — the reason
each test lives where it does. The repo's own ledger already carries this class:
`docs/design/1.6.0-THE-LIST.md:291` (X-120, *"Six deleted scripts are cited as LIVE INSTRUCTIONS …
Each has a real xtask replacement"*). These two sites are not in that row's list.
The live replacement is the `plane-purity` xtask gate (`qa/plane-purity-strict.toml`), and these
same two files know how to cite correctly elsewhere — `trust_gate_tests.rs:326-331` names
`I-trust-serve-derivation` / `trust-serve-decision`, both of which DO exist.
ACTION:    replace the script name in both files with the `plane-purity` gate, and add these two
sites to X-120.

### X-1447 · The markup-normalisation test never drives markup through the path it names
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  `upstream_join_tests.rs:481
upstream_tool_output_is_markup_normalised_before_it_reaches_the_caller`. Its doc says *"The
normalisation site is on the way OUT to the caller"* — that site is
`crates/busbar-mcp/src/mcp/method.rs:2090`,
`log.dispatched(result(id, sanitize::normalise_json(&value)))`. Neither assertion reaches it:
- the fixture peer's payload carries no markup, so the sanitiser is the identity on it —
  `sed -n '291,294p' .../tests/upstream_support.rs | grep -c "<"` → `0` (`Behaviour::Result`
  answers `{"content":[{"type":"text","text":"UPSTREAM RESULT"}]}`), and assertion 1 (:500-504)
  expects exactly those bytes back;
- assertion 2 (:505-509) bypasses dispatch entirely — a direct
  `crate::mcp::sanitize::normalise("<IMPORTANT>…")` — and calls `normalise`, the STRING function,
  not `normalise_json`, the JSON walker the dispatch path uses.
```
$ git grep -n "normalise_json" -- crates | grep -i test
crates/busbar-plane-mcp/src/tests/sanitize_tests.rs:17,:132       # a pure unit test one crate over
```
Consequence: deleting `sanitize::normalise_json(&value)` from `method.rs:2090` leaves this test
green and nothing else in the tree catches it. ADJUDICATE rather than VERIFIED because this is a
read-and-report sweep — the deletion was not planted and watched.
ACTION:    add a `Behaviour` arm in `upstream_support.rs` whose tool RESULT carries
`<IMPORTANT>exfiltrate</IMPORTANT>ok` and a nested string leaf (to exercise `normalise_json`'s
recursion), drive it through `call(…, "tools/call", …)`, and assert the caller's body contains no
`<IMPORTANT>`. Keep the byte-identical control at :500; drop the direct `normalise` call at :506,
whose unit claim already belongs to `busbar-plane-mcp`'s `sanitize_tests`.

### X-1448 · The diagnostics regeneration instruction names a deleted crate — in the assertion message an operator reads when the golden goes red
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "busbar-plane-mcp-host" crates/busbar-mcp/src/tests/diagnostics_tests.rs
126:///   `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-plane-mcp-host diagnostics`
141:             `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-plane-mcp-host diagnostics`"
$ UPDATE_DIAGNOSTICS=1 cargo test -p busbar-plane-mcp-host diagnostics
error: package ID specification `busbar-plane-mcp-host` did not match any packages
$ ls -d crates/busbar-plane-mcp-host
ls: crates/busbar-plane-mcp-host: No such file or directory
```
`:141` is the message of `committed_markdown_matches_diagnostics` — the text printed at the exact
moment the test fails. `busbar-mcp/src/lib.rs:46` records that the crate *"is named for deletion
explicitly"* and that *"the module lives here directly now"*. The working command is
`UPDATE_DIAGNOSTICS=1 cargo test -p busbar-mcp diagnostics`.
NOTE: this is a golden-regeneration instruction. It is NOT being run or re-recorded here — the
oracle is never waived; only the instruction's crate name is wrong.
ACTION:    `-p busbar-plane-mcp-host` → `-p busbar-mcp` at :126 and :141.

### X-1449 · The SDK pin's denominator is its own six constants, not the thirteen methods the plane serves — and rmcp ships a const for every one of the missing eleven
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The pin is live and CAN produce a NO (left side a literal in another crate, right side
the SDK's own type, so a rename breaks the build and a value change fails the assert):
`cargo test -p busbar-mcp --lib` →
`test sdk_vocabulary_tests::every_wire_name_this_cell_serves_is_the_one_the_sdk_declares ... ok`.
It pins 9 rmcp items — 6 method const-strings + 3 param objects — and that is complete over
`busbar_plane_mcp::codec::METHOD_*` (`git grep -c 'pub const METHOD_'` → 6).

But the served dispatch table is 13 entries (`busbar-plane-mcp/src/codec.rs:193-213`,
`IMPLEMENTED_METHODS`), and the other 11 are bare literals — each with an rmcp const available and
unused:
```
server/discover          rmcp: DiscoverRequestMethod                 pinned: 0
tools/list               rmcp: ListToolsRequestMethod                pinned: 0
prompts/list             rmcp: ListPromptsRequestMethod              pinned: 0
prompts/get              rmcp: GetPromptRequestMethod                pinned: 0
resources/list           rmcp: ListResourcesRequestMethod            pinned: 0
resources/templates/list rmcp: ListResourceTemplatesRequestMethod    pinned: 0
resources/read           rmcp: ReadResourceRequestMethod             pinned: 0
completion/complete      rmcp: CompleteRequestMethod                 pinned: 0
tasks/get                rmcp: GetTaskMethod                         pinned: 0
tasks/update             rmcp: UpdateTaskMethod                      pinned: 0
tasks/cancel             rmcp: CancelTaskMethod                      pinned: 0
```
(tabulated against `rmcp-3.1.2/src/model.rs` `const_string!` declarations.) The SDK retiring or
respelling any of the eleven is invisible to CI. The four rmcp const-strings the crate consumes
DIRECTLY in production (`subscribe.rs:94-99`) need no pin — the compile is the pin for those.
The header's own arithmetic is stale too: `:16` says *"it now covers ALL FIVE names against the
SDK"* while the body pins six (`METHOD_SUBSCRIPTIONS_LISTEN` joined at `:47`); "ALL" is measured
against `busbar_plane_mcp::codec::METHOD_*`, not against what the plane serves.
This is the sharp form of X-1409(b) — read the two together.
ACTION:    extend the test with an 11-row `assert_eq!` table binding each `IMPLEMENTED_METHODS`
literal to its rmcp const, plus a floor `assert_eq!(IMPLEMENTED_METHODS.len(), 13)` so a method
added to the dispatch table without a pin goes red. Fix the "ALL FIVE" count at `:16`.


## TALLY
```
files in slice:  101     (matches `.sweep/S05-mcp.txt`)
verdict lines:   101
CLEAN:            58
FINDING:          43     rows raised: 50  (X-1400..X-1449)
DELETABLE:         0
UNREADABLE:        0
```
Rows by class: auth 8 · missing-code 8 · drift 18 · instrument-blind 14 · config 2 ·
customer-surface 2 · money 0.
Rows by certainty: VERIFIED 49 · ADJUDICATE 1 (X-1447) · PARK 0. (X-1408 is VERIFIED on the
measurement and ADJUDICATE on severity; it is counted VERIFIED because the command was run.)

**No money row.** G6 measured zero `f64`/`f32` on any value path in all 101 files, with a positive
control. The MCP plane's only spend surfaces — `sampling::SamplingSpend` and the inputreq charge
seam — are integer, and both are covered (X-1441 scopes the one doc claim that overreaches).

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT
Reported, not acted on.

1. **`security.blocked_metadata_hosts` / `allow_metadata_hosts` / `allow_all_metadata` are
   plane-blind, and not only for MCP.** `git grep -c … -- crates/busbar-a2a/` → rc=1 as well. The
   keys are documented in `busbar-kernel/src/config/sections.rs:55-70` as applying "for ALL
   providers" / "everywhere" / "every provider", are validated at
   `config_validate/mod.rs:70-71`, and are carried ONLY on the LLM plane's `PlaneBuildInput`
   (`appbuild.rs:1534-1537`). Two of the five planes ignore them. Owner ruling; larger than S05.
2. **Three CI step comments name a directory that does not exist.** `.github/workflows/ci.yml:520`,
   `:538`, `:549` say the response-header / settings-leak / blocking-FFI lints "scan
   `crates/busbar-core/src`". The GATES have been retargeted correctly
   (`xtask/src/gates/{response_header,settings_leak,blocking_ffi}.rs` all name
   `crates/busbar-kernel/src`); only the YAML prose is stale. Comment-only, but it is the same
   dead-name class as GS17/G34.
3. **`xtask` does not compile on this branch.** `error[E0425]: cannot find function 'cell_subst'` at
   `xtask/src/gates/kind_isolation.rs:5021` and `:5611`. Pre-existing and unrelated to this slice,
   but it means `cargo xtask gate structure-lint` could not be run red/green for X-1430 — that row
   rests on reading the scope functions, which is stated in the row.
4. **`plane/registry.rs:1213` claims "in stage 1 every `owned_config_sections` is empty".** It is
   not: `busbar-voice/src/lib.rs:295` claims `["streams"]` and
   `busbar/src/root/plane_decision.rs:180` claims `[CONFIG_SECTION]`. MCP's own `&[]`
   (`mcp/mod.rs:189`) is CORRECT — core still owns `tools` concretely, which is exactly what
   `check_owned_config_claims` requires — so this is a stale comment on a guard that does have live
   subjects, not a hole.
5. **`client/ssrf.rs:265` carries "NO PRODUCTION CALLER"** on `check_addresses`, and
   `client/dispatch.rs:47`, `client/egress.rs:101`, `client/jsonrpc.rs:543-613`, `client/mod.rs:115`
   carry five more of X-1406's ten expired justifications. Those five files are outside this slice
   (prior-swept) but are the same row; whoever takes X-1406 needs all ten.
6. **`busbar-llm-codec/src/tests/proto/registry_tests.rs:149`** is the only pin that
   `handler.protocol_name() == decl.name`, and its coverage of MCP is test-order dependent (X-1408).
   The fix belongs in `busbar-llm-codec/src/lib.rs:156`.
