# S11-root-loader — sweep verdicts

Slice: `crates/busbar` (the composition root — the binary an operator actually runs) and
`crates/plugin-loader`. 75 files, 36,244 lines. X-id block: **X-2000 .. X-2099**.

Read-and-report only. No source was edited. Every zero below carries a positive control.

## Method note — a false zero this slice hit and corrected

`git grep -n "skip" -- $FILES` returned **0** while `git grep -n "skip" -- <one file from $FILES>`
returned a hit. Cause: **zsh does not word-split an unquoted parameter expansion**, so `-- $FILES`
passed ONE pathspec containing 74 spaces. Inline `-- $(cat list)` DOES split and works. Every
slice-wide grep below therefore uses `-- $(cat /Users/matthew/Developer/GetBusbar/.sweep/S11-root-loader.txt)`.
Control run each time: the same command over a known hit returns non-zero.

## Slice-wide commands run once, cited by many rows

| # | command | result |
|---|---|---|
| R1 | `git grep -n 'path = "tests/' -- crates/plugin-loader` + `grep -n -B4 '^mod tests;' crates/busbar/src/root/*.rs` | every test file in the slice is declared by a `#[cfg(test)] #[path=...] mod` on a compiled module; 0 orphans |
| R2 | `git grep -n '#\[ignore' -- $(cat .sweep/S11-root-loader.txt)` | 2 real `#[ignore]`d tests (`field_coverage`, `method_coverage`), both self-declared red-by-design |
| R3 | python re-implementation of the `read_dir` walk + `qa/field-coverage.status` parse | 114 `carried` claims, 0 ghosts under current roots, 0 found in `crates/busbar-kernel/src` |
| R4 | python path-existence scan over every `crates/… scripts/… qa/… testing/… docs/…` literal in the 75 files, checked against `git ls-files` + `os.path.exists` | 9 files carry references to paths that do not exist |
| R5 | `git grep -n 'var_os("CI")' -- crates/plugin-loader crates/busbar` | 11 CI hard-fail guards; `cached_published_sqlite_tarball` is the one fixture locator with none |
| R6 | python scan for `#[test]`/`#[tokio::test]` bodies with no `assert`/`panic!`/`expect` | 3 hits, 2 false positives (`#[should_panic]`, brace-matching), 1 real (`dlopen_notify_never_errors`) |
| R7 | `git grep -n "f64" -- $(cat .sweep/S11-root-loader.txt)` | 3 hits, all test fixtures; 0 `f64` in any production file in this slice |
| R8 | `grep -o "root::[a-z_]*" crates/busbar/src/main.rs \| sort -u` | main() names 14 root modules; `adapters auth_bindings gauntlet_kernel harness ledger_identity money_book vocabulary a2a_kernel_rider` are not among them |

---

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `crates/busbar/benches/hook_path.rs` | FINDING | `git grep -in "bench" -- .github` → 11 hits, **none of them a `cargo bench` invocation**; control `git grep -c "cargo test" -- .github/workflows/ci.yml` → 41. The file's own header calls C1 "the regression gate"; nothing in CI runs it. | X-2003 |
| `crates/busbar/build.rs` | CLEAN | Read in full. Every `println!("cargo:rustc-env=…")` key is consumed by `main.rs::build_info_line()` (`grep -n "BUSBAR_BUILD_" crates/busbar/src/main.rs` → all 7 read). `pgo_from_flags`/`flag_value` come from `src/build_stamp.rs` via `include!`. No stale env-var claim: the `BUSBAR_PGO` rerun-if hook is documented as deliberately non-authoritative. | - |
| `crates/busbar/src/build_stamp.rs` | CLEAN | Read in full. Both `pub(crate) fn`s are constructed twice — by `build.rs`'s `include!` and by `main.rs`'s `#[cfg(test)] mod build_stamp` (`grep -n "mod build_stamp" crates/busbar/src/main.rs` → `:2067`). Pure functions, no I/O, no env read. | - |
| `crates/busbar/src/root/cli.rs` | FINDING | Read in full. `handle_cli_flags()` matches on `args.next()` — the FIRST argument only (`:48-49`). `--safe-mode` is absent from the match arms yet documented in `--help` at `:171`; `--validate` is first-arg-only while `-c`/`--providers`/`--safe-mode`/`--mcp-stdio` are scanned across the whole arg list. `grep -n '&\["' crates/busbar/tests/cli_validate.rs` → every one of 30 cases puts `--validate` first, so the reversed order is untested. | X-2012 |
| `crates/busbar/src/root/gauntlet_install.rs` | FINDING | Read in full. Module header: *"DORMANT: [`install`] registers ZERO planes"*. The body of `install()` registers FOUR (`flip_one_shot_to_kernel` ×3 + `flip_session_to_kernel`). `crates/busbar/src/root/tests/gauntlet_kernel.rs:279-331` asserts all four ARE registered. `git grep -n "gauntlet_install" -- crates` → `main.rs:638` calls it unconditionally at boot. | X-2000 |
| `crates/busbar/src/root/gauntlet_kernel.rs` | FINDING | Read in full. Three separate "DORMANT — reachable, not the shipped path" claims (`:19-22`, the doc on `run_gauntlet_via_kernel`, the doc on `open_gauntlet_via_kernel`), plus *"`tools_call_via_gauntlet` still rides the substrate gauntlet"*. `sed -n '2352,2360p' crates/busbar-kernel/src/plane_host/mod.rs` shows `run_gauntlet` dispatching to `one_shot_runner(key)` first — and `install()` registers this file's fns under all four plane keys. | X-2000 |
| `crates/busbar/src/root/mod.rs` | FINDING | Read in full. `:74-75` = `#[cfg(any(test, feature = "test-harness"))] pub mod harness;`. `grep -n "^\[lib\]" crates/busbar/Cargo.toml` → **no output**; `ls crates/busbar/src/lib.rs` → No such file. The crate is bin-only, so no `tests/` target can link "the library" the feature exists to serve. `git grep -n "root::harness\|harness::" -- crates/busbar` → the only hit is the `pub mod harness;` declaration itself. Also confirms R8: `money_book` has zero non-self references repo-wide (already ratcheted at `qa/reachability-evidence.md:134`). | X-2002 |
| `crates/busbar/src/root/tests/a2a_kernel_rider.rs` | FINDING | Read in full. `:143` labels `run_gauntlet(...)` as `leg_legacy` = *"the shipped authority"*. `A2aMeterStandin` does not implement `capability_key`, and the trait default is `None` (`crates/busbar-kernel/src/plane_host/mod.rs:2233-2235`), so `leg_legacy` takes the inline fallback. The real plane returns `Some(crate::PLANE_KEY)` (`crates/busbar-a2a/src/a2a/receive.rs:859-861`), which `install()` registers — so production A2A rides `leg_loop`, and the arm being compared against is one no request takes. | X-2001 |
| `crates/busbar/src/root/tests/adapters.rs` | CLEAN | R1 (declared at `adapters.rs:467-469`). 17 tests / 48 asserts. `git grep -ln "root::adapters" -- crates/busbar/src` → reached from `root/kernel.rs`, which `main.rs` names (R8). R6 → no assertion-free test. | - |
| `crates/busbar/src/root/tests/auth_bindings.rs` | CLEAN | Read in full. 4 tests / 11 asserts, each with a stated negative half (`keys().is_none()`, `verify_token("tok-unknown") == None`, `!is_revoked("vk_1")`), and the digest test asserts against the published `busbar_api::sha256_hex` rather than a literal. Reached via `root/kernel.rs` + `root/units_admin/mod.rs` (R8). Nit: the only file in `root/tests/` with no SPDX header — `git grep -ln SPDX -- crates/busbar/src/root/tests \| wc -l` → 4 of 18, so no gate covers it. | - |
| `crates/busbar/src/root/tests/durability.rs` | CLEAN | R1 (`durability.rs:793-795`). 15 tests / 72 asserts over the WAL branch, the ledger dual write and the audit unit's two streams. `root::durability` is named by `main.rs` (R8). R4 → no stale path. R6 → no assertion-free test. | - |
| `crates/busbar/src/root/tests/gauntlet_kernel.rs` | CLEAN | Read `:270-348`. This file is the **positive evidence for X-2000**: four `install_flips_*_onto_the_unified_kernel_loop` tests assert `gauntlet_runner_registered`/`session_runner_registered` for mcp/a2a/llm/voice, each with a stated red-before-green recipe. 12 tests / 25 asserts, including a registered-vs-fallback discriminator (`host_selection_seam_routes_session_to_registered_runner_when_set`). | - |
| `crates/busbar/src/root/tests/migration.rs` | CLEAN | R1 (`migration.rs:206-208`). 4 tests / 19 asserts. `root::migration` is named by `main.rs` (R8). R4/R6 clean. | - |
| `crates/busbar/src/root/tests/plane_decision.rs` | CLEAN | Read the test list. 11 tests / 26 asserts; proves the key is read off `PlaneMeta` (not restated), that `decisions:` reaches `config_sections()`, that a scalar and a typo'd member are both REFUSED, and that a valid block lands as the plane's own typed section. `the_declaration_mounts_nothing_and_admits_nobody` pins the inert trio honestly. `root::plane_decision` is named by `main.rs:310`. | - |
| `crates/busbar/src/root/tests/policy.rs` | CLEAN | R1 (`policy.rs:391-393`). 20 tests / 50 asserts. `root::policy` is named by `main.rs` (R8). R4/R6/R7 clean. | - |
| `crates/busbar/src/root/tests/transports.rs` | CLEAN | R1 (`transports.rs:637-639`). 12 tests / 35 asserts over the transport-key unit's resolve/journal/handle path. `root::transports` is named by `main.rs:610` (`provision_servers`). R4/R6 clean; R7 → no `f64`. | - |
| `crates/busbar/src/root/tests/units_llm.rs` | CLEAN | R1 (`units_llm.rs:1988-1990`). 11 tests / 112 asserts. R7 flags `:735 fn history_of(entries: &[(u64, f64)])` — a test fixture feeding `root::kernel::PinnedHistory`; the production type is not in this slice and takes the pair, so no `f64` is introduced on a money path by this file. R6 clean. | - |
| `crates/busbar/src/root/tests/units_mcp.rs` | CLEAN | R1 (`units_mcp.rs:1882-1884`). 46 tests / 157 asserts — the densest per-line coverage in the slice. `root::units_mcp` is named by `main.rs` (R8). R4/R6/R7 clean. | - |
| `crates/busbar/src/root/tests/units_voice.rs` | CLEAN | R1 (`units_voice.rs:2051-2053`). 50 tests / 183 asserts. `root::units_voice` is named by `main.rs` (R8), and `plane-voice`/`root-voice` are both in `default` (`sed -n '/^\[features\]/,/^\[/p' crates/busbar/Cargo.toml`). R4/R6/R7 clean. | - |
| `crates/busbar/src/root/tests/vocabulary.rs` | CLEAN | Read `:88-110`. 8 tests / 22 asserts. R6 flagged `interning_after_the_seal_is_a_defect` as assertion-free — false positive: it carries `#[should_panic(expected = "root vocabulary sealed")]`, and its doc states why there is no `cfg(debug_assertions)` on it. The seal's refusal is therefore proven in release shape too. | - |
| `crates/busbar/src/root/units_admin/tests/admin_path_without_plane_face.rs` | CLEAN | `git grep -n "admin_path_without_plane_face"` → declared at `units_admin/admin_mount.rs:698-699` (not an orphan; it is the one file in `root/tests/` reached through a `#[path]` on a sibling rather than `mod.rs`). 5 tests / 30 asserts. | - |
| `crates/busbar/src/root/units_admin/tests/units_admin.rs` | CLEAN | R1 (`units_admin/mod.rs:3105-3107`). 71 tests / 373 asserts — the largest instrument in the slice. R7 flags `:3684 fn a_card_at(micro_per_unit: f64, …)`, which forwards to the PRODUCTION signature `RateCard::from_micro_rates_in` (`crates/busbar-kernel-ledger/src/cost/rate.rs`) — the `f64` originates outside this slice; see OUT-OF-SLICE below. | - |
| `crates/busbar/src/tests/tests.rs` | CLEAN | `grep -n -B4 "^mod tests;" crates/busbar/src/main.rs` → `:2069-2071`. 19 tests / 95 asserts over worker-thread sizing, `--safe-mode` detection and the serve/shutdown lifecycle. `safe_mode_requested_matches_the_exact_flag_only` pins exact-match (`--safe-mode=true` is NOT a match) with both arms. | - |
| `crates/busbar/tests/body_chunk_bounds.rs` | CLEAN | Read header + 3 tests / 16 asserts. Pins "a body is bounded by BYTES and nothing else" against the frame ceiling it has historically been confused with — both halves asserted. R4/R6 clean. | - |
| `crates/busbar/tests/boot_lines_neutrality.rs` | FINDING | R4 → 4 references (`:15`, `:106`, `:107`, `:281`, `:387`) to `testing/shadow-oracle/normalize.py` and `capture-exec.py`. `git ls-files \| grep -c "normalize.py\|capture-exec.py"` → 0; control `git ls-files \| grep -c shadow-oracle` → non-zero. The normalisation rules the test says it mirrors live in a file that is gone. | X-2010 |
| `crates/busbar/tests/capability_equality.rs` | FINDING | `git grep -cin "decision" -- crates/busbar/tests/capability_equality.rs` → **0**; control `git grep -cin "voice"` on the same file → 18. The `PLANES` table at `:115-118` has 4 rows (llm/mcp/a2a/voice); `grep -n -A40 "fn register_planes" crates/busbar/src/main.rs` shows the root installs **5** (`:310` `root::plane_decision::PLANE_DECL`). R4's other hits in this file (`crates/x/src`, `units_a.rs`) are deliberate illustrative placeholders in fixture strings — not drift. | X-2006 |
| `crates/busbar/tests/cli_validate.rs` | FINDING | R4 → `:225` cites `crates/busbar-core/src/config_validate/tests/tests.rs`; `ls -d crates/busbar-core` → No such file, `git ls-files \| grep -c "^crates/busbar-core/"` → 0, control `^crates/busbar-core-admin/` → 58. `:1004` names the crate again. Also the instrument gap behind X-2012: all 30 `run_busbar` cases lead with `--validate`. | X-2011 |
| `crates/busbar/tests/field_coverage.rs` | FINDING | R4 + read `:200-265`. `:229` = `repo_root().join("crates/busbar-core/src")` — **live code, not a comment** — and `:239-241` swallows the `read_dir` Err with `continue`. `crates/busbar-kernel/src` (where the absorbed engine now lives) is not in the stack. R3 reproduction: 114 carried claims, 0 ghosts today, 0 of them resident in `busbar-kernel` — green by luck, not by construction. | X-2004 |
| `crates/busbar/tests/inbound_concurrency_shed.rs` | CLEAN | 1 test / 10 asserts; the `return;` at `:221` is inside a stub-server reader loop (`read_line == 0`), not a test skip. R4/R6 clean. | - |
| `crates/busbar/tests/ledger_admin_views_legacy_leg.rs` | CLEAN | Read in full. Money-adjacent and controlled in **both** directions: the unknown-path control is asserted to be 404 before comparison, a known path (`/api/v1/admin/info`) is asserted NOT to be 404, and the document test asserts a known path IS present so the absence is not vacuous. No transcribed literal anywhere. | - |
| `crates/busbar/tests/mcp_open_front_door.rs` | CLEAN | Read header. Drives the real binary + a real config through `--validate` AND an actual boot; the claim (an MCP deployment may not have an open front door) is asserted at the outermost surface. 3 tests / 11 asserts. R4/R6 clean. | - |
| `crates/busbar/tests/mcp_stdio_serve.rs` | CLEAN | Read `:72-115`. `record_skip()` is the house gold standard: **panics under `CI`**, otherwise appends to a durable skip ledger and writes to the real stderr, with the reasoning for why `eprintln!` alone is insufficient stated in the doc. 5 tests / 26 asserts. | - |
| `crates/busbar/tests/method_coverage.rs` | FINDING | R2 + R4. `:552` `#[ignore = "RED BY DESIGN until 1.6.0: cells are still MISSING because crates/busbar-core/src/{mcp,a2a}/ …"` and `:44` cites `crates/busbar/src/mcp/` and `crates/busbar/src/a2a/`. `ls -d crates/busbar/src/mcp crates/busbar/src/a2a` → No such file (both); `crates/busbar-core` → No such file. The stated cause of the pinned red names three directories that do not exist. | X-2008 |
| `crates/busbar/tests/metrics_scrape_boot_window.rs` | CLEAN | Read header + assert sites (`:188`, `:216`). Low assert count is correct for its shape: it races a real boot across SO_REUSEPORT workers and asserts the closed `# HELP`/`# TYPE` set OR a non-200 — never an empty 200. The `let Some(split) = … else` at `:272` is an HTTP-parse helper, not a skip. | - |
| `crates/busbar/tests/migration_corpus.rs` | FINDING | R4 → `:408` blames `crates/busbar-core/src/config/migrate.rs`; that crate does not exist (evidence as for `cli_validate.rs`). The two `return;`s at `:365`/`:527` are feature-conditional and printed loudly ("SKIP: built without `auth-admin-tokens` … The default-features build covers this") — that half is honest. | X-2011 |
| `crates/busbar/tests/net_guard_one_judge.rs` | CLEAN | Read header. Explicitly converted FROM a two-copy parity gate INTO a one-judge gate — the anti-drift direction. 5 tests / 13 asserts. R4/R6/R7 clean. | - |
| `crates/busbar/tests/no_data_dir_neutrality.rs` | CLEAN | 1 test / 12 asserts. `:325`'s `return` is inside the recursive `walk` helper (unreadable dir), not a skip; the doc at `:317-322` states why the walk is recursive (a node that persists inside a directory it made). R4/R6 clean. | - |
| `crates/busbar/tests/no_state_persist.rs` | CLEAN | 1 test / 6 asserts; `:191`'s `return` is in the `collect` tree-walk helper. R4/R6 clean. | - |
| `crates/busbar/tests/plane_isomorphism.rs` | FINDING | `git grep -in "decision" -- crates/busbar/tests/plane_isomorphism.rs` → **rc=1, no output**; control `git grep -c "voice"` on the same file → 8. `installed_decls()` (`:101-112`) pushes 4; `register_planes()` installs 5. The header additionally says *"`{llm, mcp, a2a}`"* and *"The VOICE plane is off-default, feature-gated, and NOT linked"* — both false: the code pushes voice, and `plane-voice` is in `default`. | X-2005 |
| `crates/busbar/tests/plane_transport_neutrality.rs` | FINDING | R4 → `:5` cites `scripts/plane-transport-neutrality.sh`. `ls scripts/ \| grep -i plane` → `plane-config-noun-gate.sh plane-delete-test.sh plane-grep-gate.sh plane-keys.sh plane-noun-gate.sh plane-roots.sh` — the named script is not among them. The 4 tests / 15 asserts themselves are sound (a real source scan over the neutral crates with a named noun list). | X-2009 |
| `crates/busbar/tests/scrape_shape_1_5_5.rs` | CLEAN | Read `:100-190`. The `continue`s at `:137`/`:145` are covered by an explicit **non-vacuity floor** at `:157-163` (`prefixes.len() >= 4`) whose message says exactly why. `expand_alternation` refuses rather than guesses on an unrecognised pattern, which trips the same floor. Derives from the golden instead of transcribing it. | - |
| `crates/busbar/tests/source_classifier.rs` | CLEAN | Read `:102-120`. R6's hit here is a false positive from my brace matcher — the asserts follow the fixture string. This is the gate on the gate: it drives `tests/common/mod.rs`'s production/test classifier directly, which is the right place to put it. 11 tests / 15 asserts. | - |
| `crates/busbar/tests/thread_per_core_serves.rs` | CLEAN | Read header. Real binary, real SO_REUSEPORT binds, a live request, a clean SIGTERM drain. 1 test / 6 asserts. R4/R6 clean. | - |
| `crates/busbar/tests/transport_composed_over_consistency.rs` | CLEAN | Read in full. Both halves asserted for all 7 transports: `composed_over() == None` for the socket-openers, and for the composed ones both the exact parent AND membership in that transport's own `COMPOSES_OVER`. Nit, not raised: the comment says "The three that open their own socket" above **four** `assert_root` calls, and the `[`busbar::root::registry`]` intra-doc link at `:6` cannot resolve (bin-only crate, and integration-test doc comments are not rustdoc'd). | - |
| `crates/busbar/tests/voice_boot.rs` | CLEAN | Read in full. `#![cfg(feature = "plane-voice")]`, which IS in `default`, so it runs on the shipped build. Carries its own planted RED arm (`dup_claim_guard_refuses_a_planted_streams_collision`, a synthetic rival decl built by functional update off the real one) beside the green one, and the refusal message is asserted to name the section and both claimants. | - |
| `crates/plugin-loader/Cargo.toml` | FINDING | Read in full. `[dev-dependencies]` names exactly two both-ways fixtures — `busbar-plugin-example-plane` and `busbar-export-example-plugin`. `git ls-files \| grep -i conformance` → only `export_conformance_tests.rs` + `plane_conformance_tests.rs` in this crate. `kind::{STORE,SECRET,AUTH,HOOK}` (`crates/busbar-plugin/src/cold/mod.rs:88-109`) have no witness, though all four fixture crates carry `crate-type = ["cdylib","rlib"]` and `crates/auth-static-plugin/Cargo.toml:12-24` states the gap in its own words. | X-2015 |
| `crates/plugin-loader/src/auth.rs` | CLEAN | Read in full. Every non-verdict response shape and every transport error is FAIL-CLOSED to `Reject`/`LoginOutcome::Reject` on all four entry points (`authenticate`, `login_kind`→`Redirect`, `map_begin_login`, `map_complete_login`); the warn-once latch gates the LOG LEVEL only and is cleared on a clean verdict, never the verdict. `name`/`cacheable` resolved once at load; `intern_name` bounds the `'static` leak to one per distinct plugin name. No secret reaches an error string. | - |
| `crates/plugin-loader/src/export.rs` | CLEAN | Read in full. `routes` is additive on exactly one arm (`e.is_unsupported()` → empty table); every other failure fails the load, with the reason stated ("mounting a sink whose route table nobody has heard from mounts a gate that is not there"). Its only caller is `registry::open_export`, which `git grep -n "open_export" -- .` shows has zero callers of any kind — **already X-133 on THE-LIST and a live row at `qa/unconstructed.toml:262`**, so no new id is raised here. | - |
| `crates/plugin-loader/src/fetch.rs` | CLEAN | Read in full. `filename_is_single_component` refuses anything that is not exactly one `Component::Normal` BEFORE any `dir.join`, closing the config-driven arbitrary write; verify-before-write is unconditional when a pin exists; the write goes through `busbar_api::durable::write` (temp→fsync→rename→parent fsync). `fatal_on_miss` is threaded from the caller's boot/reload discriminator and both arms leave `dir` untouched. | - |
| `crates/plugin-loader/src/ffi_thread.rs` | CLEAN | Read in full. The `unsafe impl Send for Job` is justified by the rendezvous (caller blocks on `done` for the whole window), `catch_unwind` is on the WORKER so a panic cannot skip the `done` send, `pool().all` never shrinks so a worker's `recv` can never disconnect, and `acquire()` grows rather than caps so plugin re-entrancy cannot deadlock. The residual (inline `busbar_call`/`busbar_free`) is stated with its measurement and its concrete break case. | - |
| `crates/plugin-loader/src/hook.rs` | FINDING | Read in full. `MAX_INFLIGHT_HOOK_CALLS`'s doc claims the pool-exhaustion bound is *"this many threads per loaded hook, and a deployment loads a handful"* — but the semaphore is constructed inside `load_hook_from_bytes`, i.e. **once per open**, and `crates/busbar-kernel/src/hooks/mod.rs:750-756` routes a hook whose settings carry a `SecretRef` to `gate_transport_uncached` on every call because `resolution::key` returns `None` for it. One instance per call is one semaphore per call. | X-2016 |
| `crates/plugin-loader/src/hostlog.rs` | CLEAN | Read in full. `host_log_sink` is `extern "C"` (not `-unwind`) with everything inside `catch_unwind`, null/zero-length guarded, length-capped at 64 KiB before any slice is formed, lossy-UTF8 rather than erroring, and an unrecognised level clamps to `info` rather than dropping the record. `intern_log_ctx` bounds the leak to one per distinct name, with the reason it cannot reuse `intern_name` stated. | - |
| `crates/plugin-loader/src/stage.rs` | CLEAN | Read in full. `create_dir` (not `create_dir_all`) so a pre-planted directory is never adopted; `create_new` + `0600` for the file; `0700` for the dir; the `live` refcount is decremented on the dlopen-failure path explicitly (with the leak it fixes documented); `sweep_dead_staging` uses `symlink_metadata` so a planted symlink in the world-writable temp base cannot aim `remove_dir_all` elsewhere, and the Windows no-op is stated with its cost (disk, never integrity). | - |
| `crates/plugin-loader/src/tarball.rs` | FINDING | Read in full. `unpack`'s doc promises *"EXACTLY one `manifest.json` and EXACTLY one other regular file, nothing else — no directories, links, absolute paths, or parent references"*, but the guard at `:158-168` only rejects non-`Normal`/non-`CurDir` components, then keys on `file_name()` — so a regular file at a NESTED path (`a/manifest.json`) passes and is accepted under its basename. Bounds themselves are sound (`MEMBER_RESERVE_CEILING` split from the `size > cap` rejection, `take(cap+1)`). | X-2017 |
| `crates/plugin-loader/src/tests/abi2_store_ops_tests.rs` | CLEAN | Declared at `lib_tests.rs:2307-2308`. Both `return;`s (`:108`, `:222`) gate on `dyn_example_store_with_fake_call`, which resolves through `store_example_plugin_path()` — and that **panics under `CI`** (`lib_tests.rs:1926-1933`). 2 tests / 4 asserts, and the second is the anti-latch control ("the defaults are not a warn-once latch that merely happened to be silent on the first pass"). | - |
| `crates/plugin-loader/src/tests/export_conformance_tests.rs` | FINDING | Read in full. Two separate instrument problems: `the_rendered_exposition_equivalence_is_owed_at_the_composition_root` has an **empty body** and says so (*"It fails only if deleted"*), and `git grep -n "rendered_exposition\|run_dropped_in\|dispatch_compiled_in" -- crates/busbar crates/busbar-kernel` → **no output** (control: the same symbols return 4 hits in plugin-loader), so the owed assertion has not landed at the composition root. Separately, the RED arm is two `std::cell::Cell<u64>`s and touches no product code. The equivalence test itself is sound and CI-hard-failed (`:166`). | X-2013, X-2014 |
| `crates/plugin-loader/src/tests/export_tests.rs` | CLEAN | Declared at `export.rs:159-161`. `:83` carries the `var_os("CI")` hard-fail, so the three `return;`s cannot silently disappear where coverage is owed. 4 tests / 7 asserts. | - |
| `crates/plugin-loader/src/tests/fetch_tests.rs` | CLEAN | Declared at `fetch.rs:170-172`. 5 tests / 13 asserts driven through an injected fake downloader, so the cache/verify/atomic-write/boot-vs-reload matrix is exercised without a network. No skip arm. | - |
| `crates/plugin-loader/src/tests/ffi_guard_tests.rs` | CLEAN | Declared at `lib_tests.rs:2309-2310`. Read header — it exists **precisely because** the end-to-end unload test skips under a scoped `cargo test -p`, so a regression that guts `dlclose_on_worker`/`free_guarded` to a no-op would otherwise be invisible. That is the correct answer to a skip. 4 tests / 6 asserts. | - |
| `crates/plugin-loader/src/tests/ffi_thread_tests.rs` | CLEAN | Declared at `ffi_thread.rs:233-235`. 7 tests / 17 asserts, no fixture dependency (the primitives are pure Rust), so no skip arm exists. R6 clean. | - |
| `crates/plugin-loader/src/tests/highwater_tests.rs` | CLEAN | Declared at `highwater.rs:237-239`. 7 tests / 26 asserts — the densest ratio in the loader's test set. No skip arm; R4/R6/R7 clean. | - |
| `crates/plugin-loader/src/tests/hook_panic_status_tests.rs` | CLEAN | Declared at `hook.rs:324-326`. Its one skip guard is `hook_plugin_path()`, which panics under `CI` (`hook_tests.rs:40`). 2 tests / 8 asserts over the panic→fail-closed path. | - |
| `crates/plugin-loader/src/tests/hook_tests.rs` | CLEAN | Declared at `hook.rs:328-330`. `:40` is the CI hard-fail that covers all 18 skip guards in this file and the two sibling hook test modules. 17 tests / 37 asserts. Noted, not raised: `dlopen_notify_never_errors` (`:344`) is the slice's one genuinely assertion-free test — its only failure mode is a panic, which is defensible for a `-> ()` fire-and-forget method, but it cannot distinguish "swallowed" from "never crossed the ABI". | - |
| `crates/plugin-loader/src/tests/hook_transform_failure_tests.rs` | CLEAN | Read in full. Declared at `hook.rs:320-322`. Carries its own control in the same file: a failing rewrite hook must be `Failed` **and** a quiet one must still `Abstain`, so the new arm cannot fail-close every quiet gate. Both drive the real cdylib over the real dlopen seam. | - |
| `crates/plugin-loader/src/tests/legacy_default_tests.rs` | CLEAN | Declared at `lib_tests.rs:2311-2312`. All 5 skip guards route through `store_example_plugin_path()` (CI hard-fail). 5 tests / 31 asserts, and the set is complete in the hard direction: `redeem_plane_token` is pinned as the one verb that must FAIL CLOSED on `unsupported`, and `every_other_failure_shape_propagates_on_every_verb` proves nothing but the unsupported signal opens a default. | - |
| `crates/plugin-loader/src/tests/login_tests.rs` | CLEAN | Read in full. Declared at `auth.rs:284-286`. Pure — drives `map_begin_login`/`map_complete_login` with no FFI — and each test asserts both the fail-closed shapes and the happy path, so it cannot pass by rejecting everything. | - |
| `crates/plugin-loader/src/tests/observe_tests.rs` | CLEAN | Declared at `observe.rs:173-175`. 5 tests / 15 asserts over the fold the #85 envelope carries. No fixture skip arm. R6 clean. | - |
| `crates/plugin-loader/src/tests/plane_sidecar_tests.rs` | CLEAN | Declared at `lib_tests.rs:2315-2316`. Both skip guards are `store_example_plugin_path()` (CI hard-fail). 3 tests / 7 asserts, each with its defect stated in the doc ("when the wire drops `ts` all three land at 0 and the sweep takes the whole log"). | - |
| `crates/plugin-loader/src/tests/registry_tests.rs` | CLEAN | Declared at `registry.rs:806-808`. `:592` carries a `var_os("CI")` hard-fail. 27 tests / 99 asserts covering every `open_*` kind-mismatch refusal by its exact message. | - |
| `crates/plugin-loader/src/tests/stage_tests.rs` | CLEAN | Declared at `stage.rs:345-347`. 5 tests / 15 asserts. Uses `Staged::temp_path()` — an exact per-instance path — rather than a process-wide directory count, with the doc stating why the count is both flaky and weak. No skip arm. | - |
| `crates/plugin-loader/src/tests/store_adapter_migration_tests.rs` | FINDING | Declared at `lib_tests.rs:2317-2318`. `an_opening_sealed_off_the_published_sqlite_store` (`:773`) gates on `cached_published_sqlite_tarball()`, which has **no `CI` hard-fail** (R5), and its skip message names `testing/shadow-oracle/fetch-plugin.sh` — `git ls-files \| grep -i fetch-plugin` → **rc=1, no output** (control: `git ls-files \| grep shadow-oracle` → many). The other 7 tests / 52 asserts are sound, including write-refusing `panic!` stubs on the migration handle. | X-2007 |
| `crates/plugin-loader/src/tests/store_adapter_seam_tests.rs` | CLEAN | Declared at `store_adapter.rs:918-920`. 3 tests / 8 asserts on what the migration's head read does with a store that will not answer — the refusal side, which is the side that matters. No fixture skip arm. | - |
| `crates/plugin-loader/src/tests/store_adapter_tests.rs` | FINDING | Declared at `lib_tests.rs:2319-2320`. 17 of its 18 skip guards route through `store_example_plugin_path()` (CI hard-fail, fine); `a_round_trip_through_the_published_sqlite_store` (`:722`) is the exception — `cached_published_sqlite_tarball` (`:685-712`) has no CI guard and prints the same deleted-script remedy. 20 tests / 75 asserts otherwise. | X-2007 |
| `crates/plugin-loader/src/tests/tarball_tests.rs` | CLEAN | Declared at `tarball.rs:196-198`. 8 tests / 24 asserts over the hostile-archive refusals (entry flood, oversize member, non-regular entry, traversal name). No skip arm. | - |
| `crates/plugin-loader/tests/tarball_reserve_bound.rs` | CLEAN | Auto-discovered integration target (`grep -n "autotests" crates/plugin-loader/Cargo.toml` → no output, so cargo discovers `tests/*.rs`). Read header: a separate binary specifically so it can install its own allocator and MEASURE the reservation rather than assert about it. 2 tests / 7 asserts. | - |

---

## ROWS RAISED

### X-2000 · Four "DORMANT" claims in the composition root are false — every plane is flipped onto the kernel loop at boot
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "gauntlet_install" -- crates
crates/busbar/src/main.rs:638:    root::gauntlet_install::install();
...
$ sed -n '634,638p' crates/busbar/src/main.rs
  // ... DORMANT — it registers ZERO planes, so every gauntlet/session path
  // stays on the substrate loop, byte-identical. ...
  root::gauntlet_install::install();

$ sed -n '63,76p' crates/busbar/src/root/gauntlet_install.rs
pub fn install() {
    #[cfg(feature = "plane-mcp")]   flip_one_shot_to_kernel(busbar_mcp::PLANE_KEY);
    #[cfg(feature = "plane-a2a")]   flip_one_shot_to_kernel(busbar_a2a::PLANE_KEY);
    #[cfg(feature = "proto-llm")]   flip_one_shot_to_kernel(busbar_llm::PLANE_DECL.key);
    #[cfg(feature = "plane-voice")] flip_session_to_kernel(busbar_voice::PLANE_KEY);
}

$ sed -n '2352,2358p' crates/busbar-kernel/src/plane_host/mod.rs
pub async fn run_gauntlet(...) -> axum::response::Response {
    let selected = plane.capability_key().and_then(one_shot_runner);
    if let Some(runner) = selected { return runner(req, plane).await; }

$ sed -n '279,290p' crates/busbar/src/root/tests/gauntlet_kernel.rs
fn install_flips_mcp_onto_the_unified_kernel_loop() {
    crate::root::gauntlet_install::install();
    assert!(busbar_kernel::plane_host::gauntlet_runner_registered(busbar_mcp::PLANE_KEY), ...);
```
All four plane crates return a capability key (`receive.rs:859`, `method.rs:1242`,
`native_ingress.rs:559`, `topology/mod.rs:269`), all four are registered, and four sibling tests
assert exactly that. The stale text is at `gauntlet_install.rs:11-14`, `gauntlet_kernel.rs:19-22`,
the docs on `run_gauntlet_via_kernel` and `open_gauntlet_via_kernel`, and `main.rs:634-637`.
ACTION:    Replace the four "DORMANT / registers ZERO planes / not the shipped path" paragraphs
           with the shipped statement (registered for all four keys at boot; the money claim —
           `Admission::ZeroHold`, `Evidence::default`, no book bound — is unchanged and should be
           restated as a property of the SHIPPED exit rather than of a dormant one). `main.rs` is
           outside this slice; the two in-slice files are `root/gauntlet_install.rs` and
           `root/gauntlet_kernel.rs`.

### X-2001 · The A2A shadow-compare calls the unreachable fallback arm "the shipped authority"
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '7,10p' crates/busbar/src/root/tests/a2a_kernel_rider.rs
//! plane through BOTH loops — `leg_legacy` = `busbar_kernel::plane_host::run_gauntlet` (the
//! shipped authority), `leg_loop` = the dormant `run_a2a_via_kernel` ...

$ grep -n "impl GauntletPlane for A2aMeterStandin" -A6 crates/busbar/src/root/tests/a2a_kernel_rider.rs
  # no capability_key override

$ sed -n '2233,2235p' crates/busbar-kernel/src/plane_host/mod.rs
    fn capability_key(&self) -> Option<&str> { None }

$ sed -n '859,861p' crates/busbar-a2a/src/a2a/receive.rs
    fn capability_key(&self) -> Option<&str> { Some(crate::PLANE_KEY) }
```
The stand-in inherits `capability_key() == None`, so `leg_legacy` takes `run_gauntlet`'s inline
fallback. The real `A2aInvokePlane` returns `Some(PLANE_KEY)`, which `install()` registers — so the
shipped A2A request takes `leg_loop`. The test compares the kernel loop against an arm no request
reaches, while its header says it compares against the shipped one.
ACTION:    Give `A2aMeterStandin` a `capability_key` and drive the two legs explicitly (one with
           the runner registered, one with it absent), or restate the header to say the comparison
           is loop-vs-inline-fallback and that the fallback is not the shipped A2A path. Either way
           `run_a2a_via_kernel` is now a test-only delegate for a flip that already happened by
           another mechanism — say so or delete it. (`root/a2a_kernel_rider.rs` is out of slice.)

### X-2002 · `crates/busbar` has no library target, so the `test-harness` feature arm can never be reached
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "^\[lib\]" crates/busbar/Cargo.toml
  (no output)
$ ls crates/busbar/src/lib.rs
  ls: crates/busbar/src/lib.rs: No such file or directory
$ sed -n '74,75p' crates/busbar/src/root/mod.rs
#[cfg(any(test, feature = "test-harness"))]
pub mod harness;
$ git grep -n "root::harness\|harness::" -- crates/busbar
crates/busbar/src/root/mod.rs:75:pub mod harness;        # the declaration itself; nothing else
$ git grep -n "^use busbar::" -- crates/busbar/tests
  (no output; control: git grep -c "use busbar_kernel::" -- crates/busbar/tests → 3 files)
```
`root/harness.rs`'s own header states the feature exists because *"an integration test under
`tests/` … links the library as an ordinary DEPENDENCY"*. There is no library to link, and
`crates/busbar/benches/hook_path.rs:38-41` independently records the same fact
(*"`busbar` is a binary-only package (`[[bin]]`, no `[lib]`)"*). `harness::run` and
`RecordingLedger` have zero callers anywhere; `ci.yml:1961-1962` builds the `busbar/test-harness`
feature row, which can only prove it compiles.
ACTION:    Owner's call, one of: (a) give `crates/busbar` a `[lib]` target and land the cross-leg
           table the harness exists for; (b) delete `root/harness.rs`, the `test-harness` feature,
           the `feature-sets` row and the `construction.toml` known_site together. Do not leave a
           feature whose stated purpose the crate shape forbids.

### X-2003 · The C1 hook-path regression gate is run by nothing
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -in "bench" -- .github | wc -l
11                       # all prose; not one `cargo bench` invocation
$ git grep -n "cargo bench" -- .github scripts xtask
  (no output)
$ git grep -c "cargo test" -- .github/workflows/ci.yml
41                       # positive control
$ git grep -n "hook_path" -- .github scripts xtask
xtask/src/gates/hot_path_perf.rs:21:  # a comment explaining why that gate is NOT a bench runner
```
`benches/hook_path.rs:21` calls C1 *"the regression gate. A deployment that runs no content hook
must pay EXACTLY NOTHING. If C1 moves … stop and fix the seam."* Nothing in CI saves or compares a
criterion baseline, so C1 can never move anything red. `cargo test --all-targets` smoke-runs the
target once; it does not compare.
ACTION:    Either wire a `cargo bench -p busbar --bench hook_path -- --baseline <pinned>` step with
           a stored baseline artifact into the perf job, or demote the header's "regression gate"
           language to "manual instrument" and name who runs it and when.

### X-2004 · The field-coverage gate scans a deleted directory and not the one that replaced it
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '229,241p' crates/busbar/tests/field_coverage.rs
        repo_root().join("crates/busbar-core/src"),
        ...
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue; };

$ ls -d crates/busbar-core
ls: crates/busbar-core: No such file or directory
$ git ls-files | grep -c "^crates/busbar-core/"
0                        # control: ^crates/busbar-core-admin/ → 58

$ for d in <the 8 roots>; do ...; done
crates/busbar-core/src                   MISSING
crates/busbar/src … crates/busbar-voice-codec/src   EXISTS (7)

$ python3 (re-ran the gate's own logic)
carried test names: 114
ghosts under CURRENT roots: 0
of those, found in crates/busbar-kernel/src: 0
```
The comment at `:220-222` says *"the instruments live in busbar-core, and a scanner that read only
the thin bin would call every claim a ghost"* — busbar-core was absorbed into `busbar-kernel`
(`crates/busbar/Cargo.toml:20-24`), and `crates/busbar-kernel/src` is not in the stack. The dead
root is swallowed silently by the `continue`. It is green today only because 0 of 114 carried
claims happen to live in the kernel; the first field instrument written there fails the gate with
"your test does not exist".
ACTION:    Replace `crates/busbar-core/src` with `crates/busbar-kernel/src` in the stack at `:229`
           and update the comment; consider failing loudly on a root that does not exist rather
           than `continue`ing past it.

### X-2005 · The plane-isomorphism gate reflects 4 of the 5 planes the root installs
CLASS:     instrument-blind · drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -in "decision" -- crates/busbar/tests/plane_isomorphism.rs
  (rc=1, no output)
$ git grep -c "voice" -- crates/busbar/tests/plane_isomorphism.rs
crates/busbar/tests/plane_isomorphism.rs:8            # positive control

$ sed -n '101,112p' crates/busbar/tests/plane_isomorphism.rs
    #[cfg(feature = "proto-llm")]   v.push(("llm",   &busbar_llm::PLANE_DECL));
    #[cfg(feature = "plane-mcp")]   v.push(("mcp",   &busbar_mcp::PLANE_DECL));
    #[cfg(feature = "plane-a2a")]   v.push(("a2a",   &busbar_a2a::PLANE_DECL));
    #[cfg(feature = "plane-voice")] v.push(("voice", &busbar_voice::PLANE_DECL));

$ grep -n -A40 "fn register_planes" crates/busbar/src/main.rs | tail -6
    #[cfg(feature = "plane-decision")]
    installed.push(&root::plane_decision::PLANE_DECL);
    busbar_kernel::plane::registry::install_planes(installed.leak());
```
`plane-decision` is in `default`. The decision decl is the ALL-INERT one — `claims` empty,
`admission` `None`, `routes`/`admin_routes`/`hydrate`/`start` all `None`
(`crates/busbar/src/root/tests/plane_decision.rs:77-85` asserts exactly that) — which is the
maximally asymmetric case this gate exists to force a declaration for, and it is invisible to it.
Compounding drift in the same file's header: it calls itself "THE 4-PLANE … GATE", says the
installed set is `{llm, mcp, a2a}`, and says *"The VOICE plane is off-default, feature-gated, and
NOT linked into the binary or this test target"* — `crates/busbar/Cargo.toml`'s `default` list
contains `plane-voice`, and `installed_decls()` pushes it.
ACTION:    Add `("decision", &busbar::root::plane_decision::PLANE_DECL)` — or, since the decl lives
           in the bin crate and this is an integration test, re-source the reflection from
           `busbar_kernel::plane::registry`'s installed list so it can never again enumerate fewer
           planes than the root installs. Rewrite the header's plane count and the voice paragraph.

### X-2006 · The capability-equality oracle has no row for the fifth plane
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ git grep -cin "decision" -- crates/busbar/tests/capability_equality.rs
  (no output — 0)
$ git grep -cin "voice" -- crates/busbar/tests/capability_equality.rs
crates/busbar/tests/capability_equality.rs:18        # positive control
$ sed -n '115,118p' crates/busbar/tests/capability_equality.rs
    ("llm",   &["llm"]),
    ("mcp",   &["mcp-client", "mcp-server"]),
    ("a2a",   &["a2a-client", "a2a-server"]),
    ("voice", &["voice-client", "voice-server"]),
```
Four rows; the root installs five. Demoted to ADJUDICATE rather than VERIFIED because whether the
decision plane OWES ledger columns at all is an owner ruling — it claims no path, mounts no route
and reaches no request — and adding an empty column could be the wrong answer.
ACTION:    Owner: does `decision` owe a `capability-equality.json` column? If yes, add the row and
           the ledger columns. If no, add an explicit exemption naming the plane, so the absence is
           a decision rather than an omission.

### X-2007 · The two tests over the REAL published store — one of them the ledger's opening-figure migration — skip silently, and their remedy names a deleted script
CLASS:     money · instrument-blind · drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ awk '/fn cached_published_sqlite_tarball/,/^}/' crates/plugin-loader/src/tests/store_adapter_tests.rs
pub(super) fn cached_published_sqlite_tarball() -> Option<std::path::PathBuf> {
    ... std::fs::read_dir(root.join("plugins/store-sqlite")).ok()? ...
}
# no `var_os("CI")` anywhere in it

$ git grep -n 'var_os("CI")' -- crates/plugin-loader
crates/plugin-loader/src/tests/export_conformance_tests.rs:166
crates/plugin-loader/src/tests/export_tests.rs:83
crates/plugin-loader/src/tests/hook_tests.rs:40
crates/plugin-loader/src/tests/lib_tests.rs:34,1283,1358,1574
crates/plugin-loader/src/tests/plane_conformance_tests.rs:61,985
crates/plugin-loader/src/tests/registry_tests.rs:592
# eleven guards; cached_published_sqlite_tarball is the one locator with none

$ git ls-files | grep -i "fetch-plugin"
  (rc=1, no output)
$ git ls-files | grep shadow-oracle | head -3
testing/shadow-oracle/accepted-differences.json ...        # positive control
$ ls testing/shadow-oracle/ | grep -c "fetch-plugin"
0

$ grep -n "path: ~/.cache/busbar-oracle" .github/workflows/ci.yml
3266:          path: ~/.cache/busbar-oracle
3286:          path: ~/.cache/busbar-oracle
$ grep -n "^  [a-z0-9_-]*:" .github/workflows/ci.yml | awk -F: '$1<3270' | tail -1
3140:  shadow-oracle:
```
Both cache steps live inside the `shadow-oracle` job, which does not run `cargo test -p
busbar-plugin-loader`. The unit-test job never has `~/.cache/busbar-oracle/plugins/store-sqlite`,
so on every ordinary CI run:

* `store_adapter_tests::a_round_trip_through_the_published_sqlite_store` (`:722`), and
* `store_adapter_migration_tests::an_opening_sealed_off_the_published_sqlite_store` (`:773`) —
  **the only proof that the previous release's rows produce a correct opening figure on a handle
  that cannot be written to** —

both `eprintln!` and `return`, and libtest reports them green. The printed remedy,
`testing/shadow-oracle/fetch-plugin.sh`, was deleted (`sched-oracle-store-cells.yml:33-34` records
the deletion; the live command is `./bin/oracle fetch-plugin store-sqlite`). The repo already owns
the correct pattern in this slice — `crates/busbar/tests/mcp_stdio_serve.rs:72-97`'s `record_skip`
panics under CI and otherwise writes a durable skip ledger.
ACTION:    (1) Give `cached_published_sqlite_tarball` the same `if candidate.is_none() &&
           std::env::var_os("CI").is_some() { panic!(...) }` guard the other ten fixture locators
           carry — or, better, the `record_skip` ledger pattern. (2) Fix both skip messages to name
           `./bin/oracle fetch-plugin store-sqlite`. (3) Restore the oracle artifact cache to the
           job that runs these tests, or move the two tests into the job that has it. Do NOT close
           this by re-recording or waiving anything — the oracle is not waived.

### X-2008 · The method-coverage gate's pinned-red reason names three directories that do not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '552,555p' crates/busbar/tests/method_coverage.rs
#[ignore = "RED BY DESIGN until 1.6.0: cells are still MISSING because crates/busbar-core/src/{mcp,a2a}/ \
$ sed -n '44,46p' crates/busbar/tests/method_coverage.rs
//! `crates/busbar/src/mcp/` and `crates/busbar/src/a2a/` are deleted whole in step 15 ...

$ ls -d crates/busbar/src/mcp crates/busbar/src/a2a crates/busbar-core
ls: crates/busbar/src/a2a: No such file or directory
ls: crates/busbar/src/mcp: No such file or directory
ls: crates/busbar-core: No such file or directory
$ git ls-files | grep -c "^crates/busbar-plane-mcp/"   # the code that replaced them
(non-zero)
```
The gate's mechanism is fine (`pinned_missing_set_is_exact` runs on every `cargo test` and fails in
both directions). What is stale is the JUSTIFICATION for the pinned red: the deletion it says is
pending has happened, and the replacement crates (`busbar-plane-mcp`, `busbar-plane-a2a`,
`busbar-mcp`, `busbar-a2a`) exist. A reader cannot tell from the text whether the queue is still
owed or merely un-reclassified.
ACTION:    Rewrite the `#[ignore]` reason and `:44` to name the crates that exist now and to state
           the CURRENT reason every cell is unclaimed. Do not touch `qa/method-coverage.missing`.

### X-2009 · `plane_transport_neutrality.rs` names a script that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '5p' crates/busbar/tests/plane_transport_neutrality.rs
//! `scripts/plane-transport-neutrality.sh`).
$ ls scripts/ | grep -i "plane"
plane-config-noun-gate.sh  plane-delete-test.sh  plane-grep-gate.sh
plane-keys.sh              plane-noun-gate.sh    plane-roots.sh
$ git ls-files | grep -c "plane-transport-neutrality"
0
```
ACTION:    Point the reference at whichever of `plane-grep-gate.sh` / `plane-noun-gate.sh` now owns
           the shell half, or drop the parenthetical.

### X-2010 · `boot_lines_neutrality.rs` mirrors normalisation rules from two deleted files
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "capture-exec.py\|normalize.py" -- crates/busbar/tests/boot_lines_neutrality.rs
:15   "exactly as `testing/shadow-oracle/normalize.py`'s `boot.exhaustion-order` rule"
:106  "(`testing/shadow-oracle/capture-exec.py`'s"
:107  "`scrub`, `normalize.py`'s `ver.string`)"
:281  "`boot.exhaustion-order` precedent (testing/shadow-oracle/normalize.py)"
:387  "(`capture-exec.py`'s `exec.ansi` rule)"
$ git ls-files | grep -c "normalize.py\|capture-exec.py"
0
$ ls testing/shadow-oracle/
accepted-differences.json accepted-gaps.json cells.json ... scripts  # neither file present
```
The test's normalisation (sorting a consecutive run, scrubbing the version string, stripping ANSI)
is justified entirely by precedent in files that are gone, so the precedent cannot be checked and
the two sides can now drift without anything noticing.
ACTION:    Re-anchor each of the five citations on the rule's current home (the pinned Rust
           `busbar-oracle` engine, per `sched-oracle-store-cells.yml:33-34`) or on
           `testing/shadow-oracle/cells.json` if the rule is expressed there.

### X-2011 · Four references to `crates/busbar-core/…`, a crate that no longer exists
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "busbar-core" -- crates/busbar/tests/cli_validate.rs crates/busbar/tests/migration_corpus.rs
cli_validate.rs:225:   see `crates/busbar-core/src/config_validate/tests/tests.rs`'s
cli_validate.rs:1004:  `busbar-core` can pin it — core's test build resolves the dialects ...
migration_corpus.rs:408: fix the migrator (crates/busbar-core/src/config/migrate.rs), not the corpus.
$ git ls-files | grep -c "^crates/busbar-core/"
0                                   # control: ^crates/busbar-core-admin/ → 58
$ git grep -c "config/migrate.rs" -- crates/busbar-kernel/src | head -1
(the migrator's live home)
```
`migration_corpus.rs:408` is the worst of the three: it is the failure message an engineer reads
when the corpus goes red, and it sends them to a path that does not exist.
ACTION:    Repoint all four at `crates/busbar-kernel/src/…`. (`field_coverage.rs`'s and
           `method_coverage.rs`'s copies of the same drift are X-2004 and X-2008.)

### X-2012 · `--validate` after a `-c` flag boots and binds the gateway; `--safe-mode` as the first argument exits 2
CLASS:     customer-surface
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '47,50p' crates/busbar/src/root/cli.rs
pub(crate) fn handle_cli_flags() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {          # FIRST argument only

$ sed -n '203,215p' crates/busbar/src/root/cli.rs
        Some(a) if a == "-c" || a == "--config" || a == "--providers" || ... => { None }
        Some(other) => { eprintln!("busbar: unrecognized argument '{other}'..."); Some(2) }

$ sed -n '171p' crates/busbar/src/root/cli.rs
    --safe-mode         boot on base config.yaml alone (quarantine the persisted overlay)

$ grep -n '&\["' crates/busbar/tests/cli_validate.rs | grep -c '"--validate"'
(every case leads with --validate; none tests a flag BEFORE it)
```
`busbar -c ./config.yaml --validate` matches the `-c` arm, returns `None`, and proceeds to
`run()` — which binds listeners. `--validate`, `--list-plugins`, `--migrate-config`,
`--generate-signing-key`, `--print-metadata-blocklist` are all first-argument-only, while `-c`,
`--providers`, `--safe-mode` and `--mcp-stdio` are scanned across the whole arg list; the
asymmetry is undocumented. `--safe-mode` leading is the existing owner-OPEN item PB-23
(`docs/design/ARCHITECTURE.md:1735`, `docs/design/1.5.5-BEHAVIOUR.md:117`) — carried here because
its sibling half is new and the fix is the same line. ADJUDICATE, not VERIFIED: read from source,
not reproduced against a built binary (the build lock is contended).
ACTION:    Scan the full arg list for the exit-and-print commands the way `safe_mode_requested`
           already scans for `--safe-mode`, and add `Some("--safe-mode") => None` to the match.
           Add cli_validate cases with the flag BEFORE `--validate` — with a timeout, since the
           current behaviour is to serve forever.

### X-2013 · The owed rendered-exposition equivalence has not landed at the composition root, and its placeholder is an empty test
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ tail -5 crates/plugin-loader/src/tests/export_conformance_tests.rs
fn the_rendered_exposition_equivalence_is_owed_at_the_composition_root() {
    // Nothing to assert; this test is a landmark. It fails only if deleted, which is the point.
}

$ git grep -n "rendered_exposition\|run_dropped_in\|dispatch_compiled_in" -- crates/busbar crates/busbar-kernel
  (no output)
$ git grep -c "run_compiled_in" -- crates/plugin-loader
crates/plugin-loader/src/tests/export_conformance_tests.rs:4      # positive control
```
The file names the composition root — this slice — as the owed assertion's home
(*"Its home is the composition root, which is the one place entitled to name both"*). It is not
there. The landmark test is green on an empty body, so nothing in CI distinguishes "owed" from
"forgotten", and the #11 equivalence is proven only at the `(kind, metrics, diagnostics)` tuple,
one step short of the rendered `/metrics` text the acceptance clause asks for.
ACTION:    Land the sketched test in `crates/busbar/tests/` (install recorder → `run_compiled_in`
           → render → reset → `run_dropped_in` → render → `assert_eq!`), then delete the landmark.
           Until then, at minimum make the landmark a `#[ignore]`d full-strength assertion in the
           house style (`field_coverage`/`method_coverage`) rather than an empty green.

### X-2014 · The #11 RED arm is a two-`Cell` simulation that touches no product code
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '/fn the_pre_envelope_path_loses_a_dropped_in_plugins_counters/,/^}/p' \
    crates/plugin-loader/src/tests/export_conformance_tests.rs
    let host_registry = std::cell::Cell::new(0u64);
    let plugin_local_registry = std::cell::Cell::new(0u64);
    for _ in 0..2 { host_registry.set(host_registry.get() + 1); }
    ...
    assert_eq!(dropped_in_scrape, 0, "the defect: a dropped-in plugin's counters land where nothing scrapes");
```
No loader symbol, no plugin, no fold. The module header calls this the arm that "stays in the file"
so "a test that only ever passes" cannot hide what it is protecting against — but it is arithmetic
on two `Cell`s, and it will keep passing after any regression in the real envelope. ADJUDICATE
because the file is honest that it is a MODEL ("because that is the shape of the defect rather than
an analogy for it"), so whether a model counts as the kept red arm is an owner ruling.
ACTION:    Owner: either accept the model explicitly (and say in the doc that it is not a regression
           detector), or replace it with a real red arm — e.g. fold a dropped-in envelope under a
           name the compare filter excludes and assert the compare goes empty.

### X-2015 · Only 2 of 6 plugin kinds have a both-ways (compiled-in ≡ dropped-in) witness
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "pub const" -- crates/busbar-plugin/src/cold/mod.rs | sed -n '1,10p'
kind::{STORE, SECRET, AUTH, HOOK, EXPORT, PLANE}        # six kinds

$ git ls-files | grep -i conformance | grep plugin-loader
crates/plugin-loader/src/tests/export_conformance_tests.rs
crates/plugin-loader/src/tests/plane_conformance_tests.rs

$ sed -n '/^\[dev-dependencies\]/,$p' crates/plugin-loader/Cargo.toml | grep "^busbar-"
busbar-plugin-example-plane = { path = "../plane-example" }
busbar-export-example-plugin = { path = "../export-example-plugin" }

$ for d in auth-static-plugin hook-test-plugin store-example-plugin secret-example-plugin; do
    grep -n "crate-type" crates/$d/Cargo.toml; done
all four: crate-type = ["cdylib", "rlib"]

$ sed -n '12,24p' crates/auth-static-plugin/Cargo.toml
# ... The `plane` and `export` fixtures already carry both and already hold the only
# two both-ways witnesses in the tree ...
# ADDING THE ARTIFACT IS NOT THE WITNESS. `open` below is still private and there is no
# `dispatch_compiled_in` twin ... `busbar_plugin_sdk::dispatch_export_enveloped` is the ONLY
# enveloped dispatch the SDK has (#85 covered `export` and no other kind) ...
```
`store`, `secret`, `auth` and `hook` each ship an rlib whose stated reason for existing is this
proof, and each is linked by no conformance test. The blocker is named and upstream
(`dispatch_export_enveloped` is the SDK's only enveloped dispatch), so this is a tracked gap rather
than an oversight — but plugin-loader's manifest is the file that decides which fixtures are linked
and it links two.
ACTION:    Land `dispatch_*_enveloped` for the remaining four kinds in `busbar-plugin-sdk`, then
           add the four fixture dev-deps here and the four conformance modules beside the two that
           exist. Until then, record the four-kind gap where a reader of this manifest will see it.

### X-2016 · A secret-bearing hook re-opens the plugin per call, so `MAX_INFLIGHT_HOOK_CALLS`'s stated bound does not hold
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '/const MAX_INFLIGHT_HOOK_CALLS/,-14p' crates/plugin-loader/src/hook.rs
/// It is this many slots PER LOADED HOOK, not per process — one semaphore lives on each
/// [`DlopenPolicy`]. ... The pool-exhaustion bound the cap exists for is still bounded, at this
/// many threads per loaded hook, and a deployment loads a handful.
const MAX_INFLIGHT_HOOK_CALLS: usize = 64;

$ grep -n "slots: Arc::new(tokio::sync::Semaphore::new" crates/plugin-loader/src/hook.rs
(inside load_hook_from_bytes — one semaphore per OPEN, not per configured hook)

$ sed -n '750,756p' crates/busbar-kernel/src/hooks/mod.rs
    // A hook carrying a `SecretRef` is deliberately NOT eligible (`key` returns `None`) and
    // re-resolves on every call, exactly as before, because its resolved value can change ...
    let Some(key) = resolution::key(name, hook, env) else {
        return gate_transport_uncached(name, hook, env);
    };
```
`gate_transport_uncached` does the full `dlopen` + plugin `open`, so a hook whose `settings` carry
a `SecretRef` constructs a fresh `DlopenPolicy` — and a fresh 64-permit semaphore — on every
resolution, defeating the per-hook isolation the constant's doc argues for. Also stated in
`lib.rs:76-83`'s `intern_name` note: *"`open_hook`/`open_auth` run per config/plugin reload, per
`push_configure`, per `fetch_status` (every Prometheus `/metrics/hooks` scrape refresh) …"*
ADJUDICATE: the per-request-ness of `gate_transport_named` is in `busbar-kernel`, outside this
slice, and I did not trace the full request path to confirm the worst case.
ACTION:    Owner/kernel: either move the semaphore off `DlopenPolicy` onto the hook NAME (a
           process-wide map keyed by configured hook, so re-opens share one cap), or make the
           SecretRef path share a cap. Either way, correct the constant's doc in `hook.rs` so it
           states the bound that actually holds.

### X-2017 · `tarball::unpack` accepts a nested member, which its own doc says it refuses
CLASS:     drift
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ sed -n '/^\/\/\/ Unpack a plugin tarball FULLY IN MEMORY/,+4p' crates/plugin-loader/src/tarball.rs
/// ... the archive must contain EXACTLY one `manifest.json` and EXACTLY one other regular file
/// (the library), nothing else - no directories, links, absolute paths, or parent references.

$ sed -n '158,176p' crates/plugin-loader/src/tarball.rs
        if path.components().any(|c| !matches!(c,
            std::path::Component::Normal(_) | std::path::Component::CurDir)) { return Err(...) }
        let name = path.file_name()...
```
`a/manifest.json` has two `Normal` components, so it passes the guard and is then keyed on the
flattened basename `manifest.json`. Non-regular entries (including directory entries) ARE rejected
earlier, so a nested file can only appear in an archive built without directory headers — hence
ADJUDICATE rather than VERIFIED, and there is no security consequence (the manifest is signed and
pins the library by sha256).
ACTION:    Either tighten the guard to require exactly one component (matching
           `fetch::filename_is_single_component`, which the module already cites as the same rule),
           or soften the doc to say identity comes from the basename.

---

## OUT-OF-SLICE — proven by this slice, reported not acted on

1. **`crates/busbar/src/main.rs:634-637`** carries the fourth copy of the false DORMANT claim
   ("it registers ZERO planes, so every gauntlet/session path stays on the substrate loop").
   Same evidence as X-2000.
2. **`crates/busbar/src/root/a2a_kernel_rider.rs`** — its whole header ("DORMANT — DUAL-PATH, MONEY
   AUTHORITY NOT FLIPPED", "the one-line flip … waits on the fleet-box money oracle") is stale for
   the same reason, and `run_a2a_via_kernel` is now a test-only one-line delegate. Same evidence as
   X-2000/X-2001.
3. **`docs/design/1.6.0-THE-LIST.md:194` (X-167)** is stale. It states *"An operator still CANNOT
   WRITE a `decisions:` block … `LIFTED_TOP_LEVEL_KEYS` frozen at
   `["mcp","oauth_as","tools","agents","streams"]`"*. Measured:
   `crates/busbar-kernel/src/config/prepass.rs:130-131` is
   `&["mcp", "oauth_as", "tools", "agents", "streams", "decisions"]`, and
   `crates/busbar/src/root/tests/plane_decision.rs:160-181` proves a valid `decisions:` block lands
   as the plane's own typed section (and `:130`/`:145` prove a scalar and a typo'd member are
   refused). THE-LIST is not mine to edit.
4. **`docs/design/1.6.0-THE-LIST.md:193` (X-64 · X-136)** states *"`busbar-plane-decision` … is not
   a dependency of the `busbar` binary at all … Zero references in `crates/busbar/src/`"*.
   Measured: `crates/busbar/Cargo.toml`'s `default` contains `plane-decision`, which is
   `["dep:busbar-plane-decision"]`, and `crates/busbar/src/root/plane_decision.rs` + `main.rs:310`
   are the references. Also stale.
5. **`crates/busbar-kernel-ledger/src/cost/rate.rs`** — `RateCard::from_micro_rates_in` takes `f64`
   micro rates. Found because `units_admin/tests/units_admin.rs:3684` mirrors that signature.
   The only `f64` this slice touches originates there; the money slice owns it.
6. **`crates/busbar-kernel/src/hooks/mod.rs:750-756`** — the SecretRef re-resolution path behind
   X-2016.
7. **`qa/reachability-evidence.md:134` already records** `crates/busbar/src/root/money_book.rs`
   (239 lines, a MONEY seam) as an unreached module; R8 confirms it at HEAD
   (`git grep -n "money_book" -- crates` → the `pub mod` declaration, its own `#[path]`, and its own
   tests, nothing else). Not re-raised — it is ratcheted.
8. **`crates/plugin-loader/src/registry.rs`** `open_export` (0 callers of any kind) and `open_plane`
   (test-only callers) are already X-133/X-134 on THE-LIST and a live row at
   `qa/unconstructed.toml:262`. Confirmed still true at HEAD; not re-raised.

---

## TALLY
```
files in slice:  75
verdict lines:   75
CLEAN:           55
FINDING:         20      rows raised: 18   (X-2000 .. X-2017)
DELETABLE:        0
UNREADABLE:       0
```
Rows by class: drift 7 (X-2000, X-2008, X-2009, X-2010, X-2011, X-2017 + the drift half of X-2005) ·
instrument-blind 7 (X-2001, X-2003, X-2004, X-2005, X-2006, X-2013, X-2014) ·
missing-code 3 (X-2002, X-2015, X-2016) · money 1 (X-2007) · customer-surface 1 (X-2012).
Rows by certainty: VERIFIED 12 · ADJUDICATE 6 · PARK 0.
