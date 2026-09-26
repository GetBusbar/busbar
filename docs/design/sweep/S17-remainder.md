# S17-remainder — sweep verdicts

**Slice:** everything the other sixteen slices did not claim — the seven transports (grpc, http,
sse, stdio, tcp, tls, ws), the example/test plugin cdylibs, the store crates, the `testing/` rigs,
and the loose workspace manifests.
**Denominator:** the 102 files in `.sweep/S17-remainder.txt`. Every one has exactly one verdict line
below, in slice order. **X-id block:** X-2600 .. X-2699; used X-2600 .. X-2663.

Read-and-report only: no source was edited, no golden or ratchet touched, no `cargo` run (the build
lock is under ~20 agents). Every zero below carries a positive control — the same command, shaped to
return non-zero on something known to exist.

## THE TWO THINGS THIS SLICE WAS ASKED TO WEIGH

**(a) TRANSPORT is one kind, bidirectional, bound to the HOT/POD lane.** Three of the seven are
one-way, and the breaks are on three different axes. `ws` decodes both Text and Binary frames and
can emit only Binary, with no opcode anywhere in `FrameMeta` to carry the distinction (**X-2602**).
`grpc` enforces the operator's message ceiling on the read and leaves the write at tonic's
`usize::MAX` default (**X-2630**). `sse` is a full SSE re-segmenter inbound and a byte pass-through
to `http` outbound, so it accepts a connection, reads SSE off it, and cannot answer in the framing
it just read (**X-2635**). No forgery survives — `TransportKeyHandle::keyless()` is used correctly
at `testing/ws-conformance/subject/src/main.rs:52`, and #65 closed the seal. What replaced the
forgery is a larger absence: **`WRAPPABLE_BYTE_STREAM`, the transport half of the TLS fail-closed
seam, is declared on `TransportMeta`, defaulted `false`, overridden by none of the seven, and read
by nothing — while both `connsec::prepare` call sites pass a hard-coded `true` in its place**
(**X-2601**). Alongside it, `SELECTOR_FORMS` and `EGRESS_SELECTOR_FORMS` — the claim grammar all
seven `claims.rs` files exist to declare — have zero readers in the tree (**X-2600**).

**(b) The `testing/` rigs are DELETABLE candidates; verify invocation first.** I did, and the answer
is **no deletions**. `testing/ws-conformance/subject` is invoked by nothing (**X-2610**, confirming
LEDGER G45 from the subject's side) and sits outside every gate's source walk (**X-2609**,
confirming G23) — but it must NOT be deleted, because **if it ran it would find X-2602**: an Autobahn
echo peer that returns binary for every text case fails section 1.1 for a reason that is the
transport's, not the rig's (**X-2611**). Deleting the rig would delete the only instrument in the
tree that could have caught the transport defect. **DELETABLE: 0, argued rather than assumed.**

**Manifests.** Five dead dependency rows measured and controlled: four rustls-stack rows in
`busbar-transport-ws`, whose own `lib.rs:20` says "this crate encrypts nothing" (**X-2603**), and
`tokio-rustls` in `busbar-transport-http` (**X-2604**). One dev-only edge sitting in
`[dependencies]` where the crate already has the dev row (**X-2605**). Four manifest comments that
justify an artifact or an edge with a premise the tree contradicts (**X-2615**, **X-2648**,
**X-2646**, **X-2659**).

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `crates/api/src/durable.rs` | FINDING | `sed -n '68,92p'` -> the `///` block opened at :71 ("Atomically + durably publish...with `opts`") runs unbroken to :89 and attaches to PRIVATE `fn holding_dir` (:90); `sed -n '154,162p'` -> `pub fn write_with` at :160 has no doc. `git grep -n "exclusive: true" -- '*.rs'` -> 2 hits, both `src/tests/durable_tests.rs`; the two shipped `DurableOpts` sites (overlay.rs:1012, highwater.rs:229) leave it false. Module doc :7/:8/:33 name `admin::structure`, `plugin-loader::stage` and `main.rs` — none holds what is claimed. | X-2618, X-2619, X-2620 |
| `crates/api/src/lib.rs` | FINDING | `grep -n "no I/O" crates/api/src/lib.rs` -> :19; `grep -c "std::fs::" crates/api/src/durable.rs` -> 10, and `pub mod durable;` is declared at :24. The four-bullet list called "exactly the shared surface" omits `durable`, `operation`, `usage_migration`. All 7 `mod` declarations resolve to files on disk; no orphan. | X-2617 |
| `crates/api/src/operation.rs` | FINDING | `git grep -n "Operation::CATALOGUE\ | FETCH\ |
| `crates/api/src/store.rs` | CLEAN | Pure re-export shim: `sed -n '29,39p'` -> 20 `pub use busbar_contract::records::{...}` + 3 de-collided aliases; a moved name would not compile. `git grep -l "busbar_api::Store\ | busbar_api::VirtualKey" -- '*.rs'` -> live consumers, so the staged back-compat surface the header promises is still load-bearing. |
| `crates/api/src/tests/auth_tests.rs` | FINDING | Reachable: `grep -n '#\[path = "tests/auth_tests.rs"\]' crates/api/src/auth.rs` -> :278-279. Cells are sound (`AuthOutcome` equality, the `cacheable` default). But :26 pins `auth-admin-tokens/src/lib.rs:46,51` and `auth-static-plugin/src/lib.rs:90`; actual are 66,71 and 92. | X-2624 |
| `crates/api/src/tests/durable_tests.rs` | FINDING | Reachable via `durable.rs:358-359`. `grep -n "plant_decoy_arm" crates/api/src/tests/durable_tests.rs` -> one hit, :249, inside the NEXT test — so `exclusive_mode_publishes_0600_and_survives_stale_own_temp` (:212) plants no stale temp. The two `exclusive: true` cells (:218,:244) are the only constructors of that posture in the tree (X-2619). | X-2623 |
| `crates/api/tests/mutation_hardening_hooks_and_operation.rs` | FINDING | Auto-discovered under `tests/`. `assert!(dbg.contains('2'))` at :218-221 is satisfied by `system_chars: Some(27)` — the fixture's system at :202 is `"you are a helpful assistant"` (27 chars) and `hooks.rs:93-97` renders `system_chars` before `message_count`. Mutating `message_count` to a constant leaves the cell green. | X-2621 |
| `crates/api/tests/mutation_hardening_secret_contract.rs` | CLEAN | Auto-discovered. `grep -n "MAX_SECRET_FILE_BYTES" crates/api/src/secret.rs` -> :246 `= 1024 * 1024`, matching the test's literal. Every `for` iterates a non-empty array literal; every error-string assertion matches a live literal in `secret.rs:154-234,327`. Weakest cell (:205, `err.contains("cannot resolve")`) still reds on `unwrap_err()` if the cap is removed — weak, not blind. | - |
| `crates/auth-admin-tokens/Cargo.toml` | CLEAN | Workspace member (root `Cargo.toml` members). One dep row, `busbar-api`, used in `src/lib.rs` and `tests/mutation_hardening.rs`. No `[dev-dependencies]` and none needed — the integration test names only `busbar_api` and the crate itself. | - |
| `crates/auth-admin-tokens/tests/mutation_hardening.rs` | CLEAN | Auto-discovered (`tests/`, no `autotests = false`). `both_carriers_correct_still_identifies` is the only cell in the tree presenting both carriers correct, so it is the sole `\ | `->`^` killer for `src/lib.rs:74`. All three loops iterate non-empty literals. Timing posture holds: both `constant_time_eq(&sha256_hex(..), ..)` compares at lib.rs:66,71 run unconditionally. |
| `crates/auth-static-plugin/Cargo.toml` | FINDING | `git grep -rn "busbar-auth-static-plugin\ | busbar_auth_static_plugin" -- '*.toml' '*.rs' \ |
| `crates/auth-static-plugin/src/lib.rs` | CLEAN | `echo -n "sekret" \ |  shasum -a 256` matches the fixture digest its test asserts. Every symbol the header names resolves: `dispatch_export_enveloped` -> `plugin-sdk/src/lib.rs:962`; `plane_conformance_tests.rs`/`export_conformance_tests.rs` both exist under `crates/plugin-loader/src/tests/`. `constant_time_eq` (`busbar-contract/src/redacted.rs:124`) is a real XOR-accumulate with `black_box`. License validation refuses a present-but-bad key and accepts absence. |
| `crates/auth-static-plugin/src/tests/lib_tests.rs` | CLEAN | Reachable: `grep -n '#\[path = "tests/lib_tests.rs"\]' crates/auth-static-plugin/src/lib.rs` -> :125-127. Each cell asserts a concrete value (the sha256 literal at :66 is independently reproducible), and the free-tier/bad-license pair drives both arms of `validate_license`. | - |
| `crates/busbar-kernel-breaker/Cargo.toml` | FINDING | `ls crates \ |  grep "^busbar-unit"` -> `busbar-unit-transport-key` only, yet :1 names `busbar-unit-breaker`. `ls -d crates/busbar-caps` -> No such file or directory (control: `crates/busbar-contract` exists) while :10,:13 name `busbar-caps` as the only workspace crate this one may name; the real row at :31 is `busbar-contract`. |
| `crates/busbar-kernel-breaker/src/budget.rs` | FINDING | `git grep -nF ".set_budget(" -- crates/ xtask/ docs/ qa/` -> 3 hits: `src/tests/mod.rs:593`, `busbar-kernel-egress/tests/breaker_adapter.rs:404`, `qa/unconstructed.toml:152`. No shipped caller, so the map is always empty, `budget_remaining()` is always `None`, `LaneState::BudgetExhausted` is unreachable and `spend_budget` returns `true` forever. ALREADY TRACKED as `breaker-request-budget` in `qa/unconstructed.toml:149-157`. Money shape of the file itself is sound: `spend()` is a CAS loop with `if cur <= 0 { return false }`, no `f64`, and `refund()`'s pairing is upheld by its one caller's `BudgetGuard`. | X-2649 (context) |
| `crates/busbar-kernel-breaker/src/cfg.rs` | FINDING | `sed -n '20,24p'` -> `pub window_s: u64` while the config grammar it must bridge spells it `window_secs` and says so: `crates/busbar-kernel/src/config/pools.rs:359-362` "the pre-1.0 `window_s` alias is GONE - an unknown key fails boot". `:4` cites `crates/busbar-substrate/src/store.rs:205-259`; `ls` -> missing. Every field is dead today for the separately-tracked reason that `BreakerPolicy` is built empty (`qa/unconstructed.toml` `breaker-pool-observation`). | X-2652, X-2653 |
| `crates/busbar-kernel-breaker/src/journal.rs` | FINDING | `git grep -n "impl.*JournalSink" -- crates/` -> `journal.rs:72` (`NoopJournal`, empty body) and `src/tests/mod.rs:700` (test-only). `git grep -n "with_journal" -- crates/` -> callers only at `src/tests/mod.rs:777,852`. `crates/busbar/src/root/adapters.rs:119` pins `RootBreakerUnit = BreakerUnit<NoopJournal, DiagnosticsSink>`, so all four `ProbeEvent` variants are minted into a discard on every shipped node. `grep -n '^id  *=' qa/unconstructed.toml` -> no breaker-journal row, unlike its three sibling breaker gaps. | X-2649, X-2663 |
| `crates/busbar-kernel-breaker/src/port.rs` | FINDING | `:20-21` states "no `busbar-contract` (this crate's `Cargo.toml` is explicit that `busbar-caps` is the only workspace crate it may name)"; `:83` is `use busbar_contract::upstream::Disposition;` and `:84+` read its `.label()`s. `ls -d crates/busbar-caps` -> missing. Separately `git grep -n "acquire_for_kernel" -- crates/busbar-kernel-breaker/` -> 3 hits, all under `src/tests/`, yet `qa/construction.toml:1601` still lists this file as a reviewed seal site. | X-2650 |
| `crates/busbar-kernel-breaker/src/tests/mod.rs` | CLEAN | Reachable via `lib.rs:597`. 37 cells (`grep -cE '^\s*#\[test\]'`). The concurrency/jitter cells carry counted floors and their own positive controls (e.g. :1149 `seen.len() > 1` before the band assert), so they can produce a NO. Only defect is the header's :5 citation of the deleted `crates/busbar-substrate/src/tests/breaker_tests.rs` — recorded under X-2653. | - |
| `crates/busbar-kernel-breaker/src/tests/port.rs` | CLEAN | Reachable via `port.rs:172`. 23 cells. `the_grpc_table_names_every_code_exactly_once` (:391) cross-checks the hand-written `GRPC_DISPOSITIONS` against `GRPC_STATUS_TABLE.len()` — a real NO on a table edit. `noop_diagnostics_stays_silent...` (:283) asserts a disposition rather than silence, which is weak but honest in its own doc (:285-286). | - |
| `crates/busbar-timing/Cargo.toml` | FINDING | `sed -n '23p'` -> `package.description` ends "method timers nest inside busbar-core's stage profiler"; `ls -d crates/busbar-core` -> No such file or directory (control: `crates/busbar-core-admin` exists). This is a PUBLISHED metadata field, not a comment — it reaches `cargo metadata`, rustdoc and any SBOM. The live module is `crates/busbar-kernel/src/profile.rs`. Also: for s in dump reset record enabled set_enabled timer Timer; `git grep -cF "busbar_timing::$s" -- crates/  |  grep -v busbar-timing/` -> none, while the control `busbar_timing::timeit` -> 12 files; the per-request `reset()`...`dump_scoped()` bracket `lib.rs:42-44` documents has no caller anywhere. Feature wiring itself is sound: `timing = ["dep:libc"]`, default `[]`, and CI runs the on-leg. |
| `crates/busbar-timing/src/imp/tests/imp_tests.rs` | CLEAN | Compiled only under `feature="timing"` (`lib.rs:577-579`, inside `#[cfg(feature = "timing")] mod imp`) — and that leg IS run: `.github/workflows/ci.yml:1144` `cargo test -p busbar-timing --features timing`, in the always-on `check` job, with a `TIMING_MIN_TESTS: "5"` floor at :1158 that stops the binary silently collapsing to empty. 9 cells; `a_bucket_keeps_counting_past_the_32_bit_ceiling` (:60) asserts the bucket VALUE so it reds in release too. | - |
| `crates/busbar-timing/src/imp/tests/mutation_hardening_tests.rs` | CLEAN | Same gate and the same proven CI leg. 3 cells; `a_cached_disabled_gate_does_not_resample_the_environment` (:28) varies the environment while pinning `ENABLED=1`, so deleting the `1 => false` arm is RED. 9+3+1 = 13 tests under the on-leg, clearing the floor of 5. | - |
| `crates/busbar-timing/src/tests/zero_cost_when_off_tests.rs` | CLEAN | `lib.rs:594` gates it `#[cfg(all(test, not(feature = "timing")))]` — so it is compiled by the DEFAULT `cargo test --workspace` (ci.yml:935) and excluded from the on-leg. Both legs covered; not a dark file. `timer_off_is_zero_sized` reds if `Timer` gains a field; `off_entry_points_are_noops` reds if `enabled()` stops answering false. | - |
| `crates/busbar-timing/tests/smoke.rs` | CLEAN | Whole body is `#[cfg(feature = "timing")]` at :14, so the default build compiles an empty binary exactly as :11-12 claims — and the on-leg (ci.yml:1144) plus the 5-test floor is what keeps that from being vacuous. `set_enabled(true)` then `assert!(enabled())` is the only cross-boundary observation available and it is taken. | - |
| `crates/busbar-transport-grpc/Cargo.toml` | FINDING | Dep rows are all used (`/tmp/depcheck.sh` -> 12/12 in `[dependencies]`, 2/2 dev), but :17-23 gives a FALSE reason for the `busbar-transport-http` edge: `git grep -n "busbar_transport_http" -- crates/busbar-transport-grpc` -> Cargo.toml:18 (the comment), `src/mount.rs:15` (an intra-doc link, no `use`, no call) and `src/tests/battery.rs:21`. By the manifest's own stated rule — the rule it applied to demote `busbar-transport-tcp` — this row qualifies for `[dev-dependencies]`. The edge IS load-bearing, but only for rustdoc's `-D broken_intra_doc_links` on `mount.rs:15`, which is not what the comment says. | X-2659 |
| `crates/busbar-transport-grpc/src/claims.rs` | FINDING | `git grep -l "SELECTOR_FORMS" -- '*.rs' \ |  grep -v "^crates/busbar-transport-\ |
| `crates/busbar-transport-grpc/src/client.rs` | FINDING | `:125` `.max_decoding_message_size(state.max_message_bytes)`. `git grep -n "max_encoding_message_size" -- '*.rs'` -> rc=1, zero hits tree-wide; control, the decoding spelling -> 3 hits. tonic 0.14.6's `DEFAULT_MAX_SEND_MESSAGE_SIZE` is `usize::MAX`, so the operator's ceiling binds the read and not the write. | X-2630 |
| `crates/busbar-transport-grpc/src/codec.rs` | FINDING | The byte-blind `RawCodec` is sound and `MAX_MESSAGE_BYTES` is a real default. But `:21-23` states the send-side ceiling as a CALLER OBLIGATION ("the number must stay at or above the largest single message the relay path can emit") rather than enforcing it, and nothing enforces it — see X-2630. | X-2630 |
| `crates/busbar-transport-grpc/src/conn.rs` | CLEAN | `git grep -n "Call::new\ | arm_cut\ |
| `crates/busbar-transport-grpc/src/lib.rs` | FINDING | `git grep -n "busbar_transport_grpc::" -- '*.rs'` -> 2 hits, both `GrpcTransport` (`busbar/src/root/registry.rs:95`, `busbar/tests/transport_composed_over_consistency.rs:19`); control `busbar_transport_ws::` -> 6. So `pub mod mount` (:38) and the `MESSAGE_MAX_BYTES_KEY` re-export (:42) have no external consumer at all. | X-2631, X-2660 |
| `crates/busbar-transport-grpc/src/meta.rs` | FINDING | `git grep -n "WRAPPABLE_BYTE_STREAM" -- '*.rs'` -> 6 hits, none in any transport crate; the const defaults `false` and both `connsec::prepare` call sites (`busbar/src/main.rs:1692,1873`) pass a literal `true` in its place. Ten of this file's sixteen declared consts have zero external readers. | X-2600, X-2601 |
| `crates/busbar-transport-grpc/src/server.rs` | FINDING | `:132` `tonic::server::Grpc::new(RawCodec).max_decoding_message_size(state.max_message_bytes)` — the serve side sets the decode ceiling and no encode ceiling, and `OutStream::poll_next` (:378) emits every queued `Vec<u8>` unmeasured. Same break as client.rs. | X-2630 |
| `crates/busbar-transport-grpc/src/tests/battery.rs` | FINDING | Reachable via `lib.rs:44-46`. `grep -n "CapCfg" crates/busbar-transport-grpc/src/tests/battery.rs` -> :54,:55,:67 (definition) and :2008 (one use, inside a `listen`/`accept` cell). Every dialling instance comes from `client_transport()` (:26), which never calls `listen`, so the doc's claim that the cap rides "every connection this same instance goes on to accept OR dial" has no dial-side cell — and production never calls `listen` at all (X-2661). | X-2661 |
| `crates/busbar-transport-grpc/src/tests/mount.rs` | FINDING | Reachable via `mount.rs:179-181`. `an_unaddressed_call_is_unimplemented_either_way` (:180-186) asserts `UNADDRESSED_STATUS == 12` — a constant against itself — and that `resolve` errors. `git grep -n "UNADDRESSED_STATUS" -- '*.rs'` -> the grpc const (:177) and this one reader; nothing maps `Unaddressed` to it, so "unimplemented either way" is never observed on any answer. | X-2631 |
| `crates/busbar-transport-grpc/src/transport.rs` | FINDING | `:167` is the ONLY write to `max_message_bytes`, and it is inside `listen`. `git grep -n "listen_all" -- '*.rs'` -> `busbar/src/root/transports.rs:347` (the definition), `busbar/src/root/tests/transports.rs:276` (a test) and `busbar/src/main.rs:538`, which is a doc comment reading "This boot does not call `listen_all`". So the operator's cap never reaches a dialled gRPC connection. Second half: the root answers the key only under `#[cfg(feature = "plane-voice")]` while grpc ships unconditionally (`busbar/Cargo.toml:145`). | X-2608, X-2661 |
| `crates/busbar-transport-grpc/tests/no_plane_names.rs` | FINDING | Re-ran the scan by hand: `grep -rn -e 'busbar-plane-' -e 'busbar_kernel' -e 'busbar_contract::caps' -e 'run_unit' crates/busbar-transport-grpc/src/` -> rc=1; control, same command against `crates/busbar-transport-sse/src/` -> rc=0 with 5 hits. So the gate passes today and the zero is real. Two defects in the gate itself: :194's `\ | \ |
| `crates/busbar-transport-http/Cargo.toml` | FINDING | `grep -rn "tokio_rustls\ | tokio-rustls" crates/busbar-transport-http/src/` -> rc=1, no output; control `grep -rn "hyper_rustls" .../src/` -> lib.rs:155,356. Line 30 compiles nothing. (`rustls`, `rustls-pki-types` and `webpki-roots` ARE each named in lib.rs — only this one row is dead.) |
| `crates/busbar-transport-http/src/claims.rs` | FINDING | Eight ingress forms, empty egress list, zero readers (X-2600's measurement + control). | X-2600 |
| `crates/busbar-transport-http/src/meta.rs` | FINDING | No `WRAPPABLE_BYTE_STREAM` override on the transport that serves the deployment's TLS door — the const the connsec seam says it reconciles. Ten of sixteen consts have no external reader. | X-2600, X-2601 |
| `crates/busbar-transport-http/src/raw.rs` | FINDING | Reachable (`lib.rs:94`, tests via `raw.rs:345-347`). `git grep -n "RawStartLine::Status" -- '*.rs'` -> `raw.rs:93` (construct) and `src/tests/raw.rs:129` (the only place `code`/`reason` are read). `transport.rs:251` uses the variant only as a refutable-let else-branch. The fields are parsed and allocated on every header parse and never consumed. | X-2662 |
| `crates/busbar-transport-http/src/tests/mod.rs` | FINDING | Reachable via `lib.rs:1314`. `sed -n '2247,2254p'` -> `the_unset_seam_builds_the_same_posture_as_the_bare_entry_point` is two `let _ =` bindings and NO assertion, while its doc claims "both stand up the platform-roots posture". It is the only cell in the crate that builds a TLS client config, so a mutant returning a `.dangerous()` accept-anything verifier passes it. | X-2632, X-2633 |
| `crates/busbar-transport-http/src/tests/raw.rs` | CLEAN | Reachable via `raw.rs:345-347`. Every cell asserts a concrete value; the loop at :28 walks a 38-byte literal and is followed by `assert!(decoder.is_done())` at :32, which proves the collection was non-empty. | - |
| `crates/busbar-transport-http/src/transport.rs` | FINDING | `git grep -n "transport_chain" -- crates/busbar-transport-http` -> exactly one hit, `:52 transport_chain: vec!["tcp", "http"]` — a constant, with no test. Control: the fact IS asserted for siblings (`tls/src/tests/mod.rs:691` `["tcp","tls"]`, `ws/src/tests/battery.rs:495` `["tcp","tls","ws"]`) and `tls/src/transport.rs:44,298` carries a real per-connection chain. So an `https://` egress arrival reports `tcp -> http`, and `sse` pushes onto that same constant (`sse/src/transport.rs:28`). | X-2634 |
| `crates/busbar-transport-sse/Cargo.toml` | FINDING | `grep -n "tokio" crates/busbar-transport-sse/src/{transport,lib,proto,reframe,claims,meta}.rs` -> rc=1, no output; control `grep -n "futures" .../transport.rs` -> :21,:101. The `[dependencies] tokio` row at :18 serves only `src/tests/mod.rs`, and `[dev-dependencies] tokio` at :26 already carries a feature superset. Also the one transport manifest with no `features = ["test-seal"]` dev row: `git grep -n "test-seal" -- 'crates/busbar-transport-*/Cargo.toml'` -> 6 manifests, sse absent. | X-2605, X-2637 |
| `crates/busbar-transport-sse/src/claims.rs` | CLEAN | Both lists are honestly empty with the reason stated ("composed OVER `http` and adds no selection surface of its own"), so this file introduces no unread declaration of its own. It is a member of the dead trait pair only. | - |
| `crates/busbar-transport-sse/src/meta.rs` | FINDING | `git grep -n "WRAPPABLE_BYTE_STREAM" crates/busbar-transport-sse/` -> no output. `TRANSPORT_FACTS = &[]` and the inherited `STATUS_CLASS` are argued and right; the absent const is not. | X-2601 |
| `crates/busbar-transport-sse/src/tests/mod.rs` | FINDING | Reachable via `lib.rs:92-93`. Instruments are strong — `the_resegmentation_scan_costs_one_pass_over_the_frame_not_one_per_chunk` (:124-188) is a real complexity floor, not slack. But `fixture_seal()` at :21-25 calls `busbar_contract::caps::KernelSeal::acquire_for_kernel()` directly: `git grep -ln "TestKernelSeal" -- 'crates/busbar-transport-*'` -> 6 crates, sse absent. This is the one transport not migrated to the #65 blessed test seal. | X-2637 |
| `crates/busbar-transport-sse/src/tests/proto.rs` | CLEAN | Reachable via `proto.rs:164-166`. Every cell is a concrete `assert_eq!` against a hand-computed offset; an LF-only or CRLF mis-split mutation of `find_frame_terminator` reds a named line. | - |
| `crates/busbar-transport-sse/src/tests/reframe_tests.rs` | FINDING | Reachable via `reframe.rs:157-159`. `:52-82` asserts `reframer.prefers_event_stream(x) == prefers_event_stream(x)` where `PassThroughReframe::prefers_event_stream` IS `prefers_event_stream(accept)` (`reframe.rs:130-132`) — it can only red on a mutation of the two-line delegation, never on a defect in the function it is named for. `:90` is the only caller of `install_sse_reframe` in the tree. | X-2636 |
| `crates/busbar-transport-sse/src/transport.rs` | FINDING | `grep -n "write\ | encode_envelope" crates/busbar-transport-sse/src/transport.rs` -> `:269 self.http.write(...)`, `:279 self.http.encode_envelope(...)` — pure delegation. `git grep -n "reframe" -- crates/busbar-transport-sse/src/transport.rs` -> no output. The read side is a full SSE re-segmenter (:52-261: terminator carve, comment-frame drop, inherited status, `MAX_CURSOR_BYTES`); the write side emits an HTTP request line and no `event:`/`data:`/blank-line framing. `listen`/`accept` delegate to `http` (:32-42) and `src/tests/mod.rs:474-545` drives exactly that inbound path, so the transport accepts, reads SSE, and cannot answer in the framing it just read. |
| `crates/busbar-transport-stdio/Cargo.toml` | CLEAN | `/tmp/depcheck.sh crates/busbar-transport-stdio` -> busbar-contract (7 src files), tokio (4), futures (3); the dev rows are the `test-seal` feature and a macros-enabled tokio. No dead row, no dev-only row sitting in `[dependencies]`. | - |
| `crates/busbar-transport-stdio/src/claims.rs` | CLEAN | Both lists empty and argued ("stdio carries no header, path or handshake surface to select on: a claim on this transport can only ever be the whole channel. Empty rather than guessed"). The honest row of the seven. | - |
| `crates/busbar-transport-stdio/src/conn.rs` | FINDING | `git grep -n "busbar_transport_stdio::StaticConfig" -- '*.rs'` -> rc=1, no output; `grep -rn "StaticConfig" crates/busbar-transport-stdio/` -> definition (:113,115,127), the re-export, and five hits in `src/tests/mutation_hardening.rs`. A `pub struct` with two public trait impls whose only consumer is a `#[cfg(test)]` module. The rest of the file is sound — `begin_close` orders flag-then-notify and says why, and `ReaderSlot` carries the `partial` buffer across a cancelled `read_until`. | X-2607 |
| `crates/busbar-transport-stdio/src/lib.rs` | FINDING | `:45 pub use conn::StaticConfig;` is the export with no external consumer (command above). Everything else resolves: `mod claims/conn/meta/transport` all on disk; `#[cfg(test)] #[path="tests/battery.rs"] mod battery;` at :48-50 compiles the battery, which in turn declares `mutation_hardening` at `battery.rs:22-23`. | X-2607 |
| `crates/busbar-transport-stdio/src/meta.rs` | FINDING | `STATUS_CLASS`/`STATUS_NAMESPACE = None` and `TRANSPORT_FACTS = &[]` are argued and right for a pipe. `WRAPPABLE_BYTE_STREAM` is absent — and `busbar-contract/src/transport/mod.rs:152` names stdio as exactly the transport that should leave it `false` DELIBERATELY. Leaving it to the default is indistinguishable from never having considered it, which is the whole of X-2601. | X-2601 |
| `crates/busbar-transport-stdio/src/tests/mutation_hardening.rs` | CLEAN | Reachable via `src/tests/battery.rs:22-23`. Every cell names the mutant it kills and each can produce a NO: `plugin_key_is_stdio` dies on any `KEY` edit; `a_stream_that_ended_on_an_error_stays_ended` pins `done` with `is_poisoned()`/`is_closed()` both asserted false, so an `\ | \ |
| `crates/busbar-transport-tcp/Cargo.toml` | CLEAN | Four dep rows, all used (`/tmp/depcheck.sh` -> tokio-util 1, busbar-contract 5, futures 3, tokio 4). Dev rows are the `test-seal` feature and a `test-util`/`macros` tokio. | - |
| `crates/busbar-transport-tcp/src/claims.rs` | FINDING | `&[SelectorForm::Port]` plus an empty egress list; neither is read anywhere (X-2600's zero + control). | X-2600 |
| `crates/busbar-transport-tcp/src/meta.rs` | FINDING | `UPGRADES_TO = &["tls"]` and `UNIT0_TRIGGER = Some(FirstBytes)` are both in the ten consts with zero external readers, and `WRAPPABLE_BYTE_STREAM` is absent on the base byte stream every session transport composes over — the one where a `true` would be unambiguous. | X-2600, X-2601 |
| `crates/busbar-transport-tcp/src/tests/mutation_hardening.rs` | CLEAN | Reachable via `src/tests/mod.rs:17`. Every cell names the surviving mutant it kills and asserts a value rather than a shape. This file's sibling cell in `tests/mod.rs:791`, `a_write_blocked_on_a_nonreading_peer_is_interrupted_by_close`, is the one `tls` never got (X-2638). | - |
| `crates/busbar-transport-tcp/src/transport.rs` | CLEAN | `git grep -n "raced_write" -- '*.rs'` -> the definition (`lib.rs:287`) and BOTH call sites (`transport.rs:209` in `write`, `:286` in `unit0_refusal`). Read and write are both raced against `closing`; `dial` is bounded; `map_io_err` is total. This is the reference implementation `tls` did not follow. | - |
| `crates/busbar-transport-tls/Cargo.toml` | CLEAN | All nine dep rows used (`/tmp/depcheck.sh`), and the manifest's own drift-prone citation checks out: it states the single `busbar_transport_tcp` reference is `src/tests/mod.rs:651`, and `grep -n "busbar_transport_tcp" crates/busbar-transport-tls/src/tests/mod.rs` -> exactly `651`. A manifest comment that still lands on its line. | - |
| `crates/busbar-transport-tls/src/claims.rs` | FINDING | The `ClientCertSubject` omission is argued and correct — the fingerprint is real, the DN is not parsed, and advertising the form on a constant subject would collapse silently. But the list it produces is read by nothing (X-2600), so the careful reasoning has no consumer to be careful for. | X-2600 |
| `crates/busbar-transport-tls/src/meta.rs` | FINDING | `git grep -n "WRAPPABLE" crates/busbar-transport-tls/` -> no output. This is the transport that TERMINATES TLS and it does not declare the TLS-termination capability the connsec seam says it reconciles. | X-2600, X-2601 |
| `crates/busbar-transport-tls/src/tests/mod.rs` | FINDING | Reachable via `lib.rs:526`. Rich battery, but two gaps: (1) `grep -n "a_write_blocked" crates/busbar-transport-tls/src/tests/mod.rs` -> no match, while `crates/busbar-transport-tcp/src/tests/mod.rs:791` has `a_write_blocked_on_a_nonreading_peer_is_interrupted_by_close`; the nearest tls cell (`a_close_notify_self_bounds_on_a_held_writer_lock`, :481) holds the lock itself and so demonstrates the leak rather than refuting it. (2) four sites (:796,:801,:854,:1328,:1335) still call `busbar_contract::caps::KernelSeal::acquire_for_kernel()` directly although this crate's manifest DOES carry `features = ["test-seal"]` — a half-finished #65 migration. (3) `git grep -n "with_handshake_timeout" -- '*.rs'` -> the definition (`lib.rs:221`) and three callers, all in THIS file (:189,:1836,:1879) — the operator knob `limits.tls_handshake_timeout_secs` reaches no shipped transport. | X-2637, X-2638, X-2639 |
| `crates/busbar-transport-tls/src/tests/mutation_hardening.rs` | CLEAN | Reachable via `src/tests/mod.rs:22`. Both `detach` arms (`Server`, `Client`) are separately driven; `a_broken_close_does_not_hang_the_peers_read` wraps in a 3 s `timeout(...).expect(...)`, so a no-op `close` is a fast panic rather than a hang — it can produce a NO. | - |
| `crates/busbar-transport-ws/Cargo.toml` | FINDING | `grep -rn "rustls\ | webpki\ |
| `crates/busbar-transport-ws/src/claims.rs` | FINDING | Declares eleven ingress forms and, in its own words, "a genuine open question ... whether that reading is what the design intends, since `http`'s own row would otherwise carry the identical set unused". Both rows are unused, because nothing reads `SELECTOR_FORMS` at all. | X-2600 |
| `crates/busbar-transport-ws/src/lib.rs` | FINDING | `:36 pub use conn::StaticConfig;` — `git grep -n "busbar_transport_ws::StaticConfig" -- '*.rs'` -> rc=1, and `grep -rn StaticConfig crates/busbar-transport-ws/` -> 5 hits, all definition/re-export; not even this crate's own 1318-line battery constructs it (control: `busbar_transport_ws::` resolves 6 times elsewhere). The header's ":8 text/binary WS messages are the frame unit" is half-true — the crate reads both and can write only one. | X-2602, X-2606 |
| `crates/busbar-transport-ws/src/meta.rs` | FINDING | No `WRAPPABLE_BYTE_STREAM`, and `STATUS_CLASS`/`TRANSPORT_FACTS`/`UNIT0_TRIGGER` sit in the ten-const set with zero external readers. `COMPOSES_OVER` is the one const here that a consumer actually reads (`busbar/src/root/registry.rs`), which is the control that makes the other ten measurable. | X-2600, X-2601 |
| `crates/busbar-unit-transport-key/Cargo.toml` | FINDING | `:7` says this crate "depends on `busbar-caps` for the handle"; `ls -d crates/busbar-caps` -> No such file or directory (control: `crates/busbar-contract` exists), and the actual row at :23 is `busbar-contract`. `busbar-caps` was folded in under #37/#38 (`busbar-contract/src/caps/mod.rs:64`). Dep rows themselves are all used. Separately, this crate's `provision_server_named`/`NamedTlsLocations` have no shipping caller. | X-2646, X-2647 |
| `crates/export-example-plugin/Cargo.toml` | FINDING | `grep -rh "#\[test\]" crates/export-example-plugin/src \ |  wc -l` -> 7, while the `[lib]` comment at :12-15 justifies `rlib` with "when this crate has no in-crate `#[test]`s of its own". The DECISION is right — `plugin-loader/Cargo.toml` dev-deps really do link this rlib for the both-ways export conformance cell — but the stated REASON is false, which is the shape that gets an artifact deleted by the next reader who checks it. `serde_json` dep is live (lib.rs + tests.rs). |
| `crates/hook-test-plugin/Cargo.toml` | CLEAN | `grep -rn <dep> crates/hook-test-plugin/src` -> tracing 9, serde 66, serde_json 52, busbar_plugin_sdk 3. Every row live, none test-only. The `rlib` comment here gives the reason that IS true for this crate (a scoped `cargo test -p` emits no cdylib otherwise) and the crate genuinely has no external rlib linker. | - |
| `crates/hook-test-plugin/src/lib.rs` | CLEAN | All 13 `HookConfig` knobs are driven from outside the crate: `git grep -n <knob> -- '*.rs' \ |  grep -v '^crates/hook-test-plugin/'` -> every one has >=1 external hit (thinnest: `restrict_tags` -> `busbar-kernel/src/hooks/tests/tests.rs:2016`; `fail_decide` -> `plugin-loader/src/tests/hook_tests.rs:656`). The cdylib is loaded by four external crates. The two `as f64` at :233-234 are metric VALUES in a JSON describe payload, not money. |
| `crates/hook-test-plugin/src/tests.rs` | CLEAN | Reachable via `lib.rs:301`. 20 cells, every assert outside a loop, no empty-collection oracle; `#[should_panic(expected = ...)]` at :295 pins the panic arm by message rather than by shape. | - |
| `crates/hooks-ranking/Cargo.toml` | CLEAN | `grep -c tokio crates/hooks-ranking/src/lib.rs` -> 0; tokio appears only under tests and is correctly in `[dev-dependencies]`. `async-trait` is used three times in `src/lib.rs` (:45,:159,:179). `busbar-api` live. The crate is a default feature of both `busbar-kernel` (:173) and `busbar` (:192). | - |
| `crates/hooks-ranking/src/lib.rs` | FINDING | The ranking itself is CLEAN: `git grep -n "busbar_hooks_ranking::native_policy" -- '*.rs'` -> shipped callers at `busbar-kernel/src/hooks/mod.rs:291` and `:1427`; the `f64` at :78 is a ranking key, and `usable_key` (:123-128) filters a non-finite key to `None` BEFORE the comparator, so `partial_cmp` never sees a NaN and the documented non-transitivity panic is unreachable. Two doc defects: :20 cites `forward::decide_policy_order` and `git ls-files \ |  grep -E "forward\.rs\ |
| `crates/hooks-ranking/src/tests/lib_tests.rs` | CLEAN | Reachable via `lib.rs:258`. 18 cells. The NaN/INFINITY cases (:345,:370) and the empty-pool Abstain cell (:199) are real instruments — the registry loop iterates five literal names and `native_registry_names_round_trip` (:184) asserts the round-tripped `name()` rather than a bare `is_some()`. No empty-collection oracle. | - |
| `crates/hooks-ranking/tests/determinism.rs` | CLEAN | Auto-discovered. Every symbol its doc names exists: `grep -n "rank_ascending_by\ | rank_descending_by\ |
| `crates/plane-example/Cargo.toml` | CLEAN | `git grep -n "busbar-plugin-example-plane" -- '*.toml'` -> `crates/plugin-loader/Cargo.toml:63` (dev-dep), so the `rlib` half really is linked — the one example fixture whose `rlib` justification is true and verified. Both dep rows live (`busbar_plugin` 19 refs, `busbar_plugin_sdk` 4). The kind-naming rationale in the header is sound. | - |
| `crates/plane-example/src/lib.rs` | FINDING | `grep -n "\.load(" crates/plane-example/src/lib.rs` -> rc=1, no output; control `grep -c "\.store(\ | \.fetch_add("` -> 3. The module doc at :100-104 calls `dispatched`/`started_at_nanos`/`metered_units` "the counters that prove the crossings happened ... what makes 'did the vtable actually get crossed?' a question this fixture's return status can answer" — nothing ever reads them, `admin_routes`/`openapi` are `None` (:403-404), and `dispatch` returns only a `RawStatus`. Consequence: `dispatch` never checks `started_at_nanos`, so a plane dispatched WITHOUT `start` returns Ok. The ":56 no f32/f64 anywhere in this file" claim is true. |
| `crates/plugin-sdk/src/boundary.rs` | FINDING | `read_buf` (:128-136) returns `Err(())` on exactly one input, `len > 0 && ptr.is_null()`, and nothing in the tree constructs it. `git grep -n "null config pointer\ | config is not valid UTF-8" -- '*.rs'` -> exactly 2 hits, :207 and :211, the construction sites themselves — no test asserts either message. So `CtorFail::Protocol` and the `STATUS_PROTOCOL` returns at :178/:207/:211 are unreached. (The other two producers, :173 null-handle and :224 null-out_handle, ARE asserted, at `src/tests/lib_tests.rs:654` and `:678` — which is the control proving the assertion shape exists.) |
| `crates/plugin-sdk/src/tests/pack_tests.rs` | FINDING | Reachable via `pack.rs:622` — but only under the `pack` feature, which is NOT in `[features] default` (`crates/plugin-sdk/Cargo.toml`), and the only CI leg that enables it is `sdk pack` in the `feature-sets` job whose `if:` (`.github/workflows/ci.yml:1951`) skips pushes to non-promotion branches; on this branch these 22 cells are never compiled (they do run on PRs and on dev/qa/main). Content defect: `x_busbar_ref_passes_pack_time_validation_untouched` (:817-832) loops `BUSBAR_REF_VALUES` and asserts acceptance, while `validate_secret_fields` never inspects `x-busbar-ref` and pack.rs rejects no unknown `x-*` at all — mutating the constant to `&["garbage"]` leaves it green. | X-2656, X-2657 |
| `crates/plugin-sdk/tests/boundary_class.rs` | FINDING | Auto-discovered; the `#[global_allocator]` witness is sound and the panic/ctor-panic arms are genuinely driven. But `grep -n "STATUS_PROTOCOL" crates/plugin-sdk/tests/boundary_class.rs` -> :24 (the import) and :226, an `assert_ne!` — the file that declares itself the parameterized class harness "a new export inherits" asserts the protocol status is NOT produced and never that it IS. Also :145 allocates `MAX_PLUGIN_RESPONSE_LEN + 1` = 256 MiB + 1 on every run under a counting global allocator. | X-2622 |
| `crates/secret-example-plugin/Cargo.toml` | FINDING | `grep -rh "#\[test\]" crates/secret-example-plugin/src \ |  wc -l` -> 8, while the `[lib]` comment at :12-17 justifies `rlib` with "when this crate has no in-crate `#[test]`s of its own". Same false premise as the export and store fixtures. Dep rows all live. |
| `crates/secret-example-plugin/src/tests.rs` | CLEAN | Reachable via `lib.rs:71`. Seven cells, each asserting a distinct `SecretErrorKind` arm; `open`'s three config paths and `resolve`'s four are all driven. No secret value reaches an assertion message. | - |
| `crates/busbar-contract/src/tests/secret_ref_tests.rs` | CLEAN | Reachable via `src/lib.rs:429-431`. `the_schema_and_the_deserializer_agree_shape_for_shape` iterates a 22-row literal and cross-checks two INDEPENDENT oracles (the JSON schema and the serde deserializer) — the strongest instrument in this slice: a change to either side alone reds it. | - |
| `crates/busbar-contract/tests/secret_ref_mutation_hardening.rs` | CLEAN | Auto-discovered. Both named references resolve: `ls docs/code-layout.md` -> exists; `grep -n "an_unquoted_inline_secret_is_refused_without_echoing_it" crates/secret-ref/src/tests/lib_tests.rs` -> :242. The refusal cells assert the message does NOT contain the secret, which is a real NO. | - |
| `crates/store-example-plugin/Cargo.toml` | FINDING | `grep -rh "#\[test\]" crates/store-example-plugin/src \ |  wc -l` -> 34 against the `[lib]` comment's "no in-crate `#[test]`s of its own". `libc` is proven live (`grep -rn libc .../src` -> lib.rs:307,333). The "NO DEV-DEPENDENCIES" paragraph is accurate. Adjacent: `src/tests/mod.rs:748-750` asserts in prose that the manifest-allowlist gate "is report-only in CI today (`continue-on-error: true`)" and `.github/workflows/ci.yml:3574` now says that flag "IS GONE". |
| `crates/store-example-plugin/src/ram.rs` | FINDING | `awk '/^impl Store for FileStore/{f=1} f&&/^    fn /' crates/store-example-plugin/src/lib.rs \ |  grep -oE "fn [a-z_]+"` -> 17 verbs, and `add_usage` and `scrub_key` are NOT among them; control, `put_usage` IS. `RamStore` implements both (`ram.rs:198`, `:164`). So `FileStore` — the durable mode — inherits `RecordStore`'s defaults: `add_usage` becomes get/apply/put (`busbar-contract/src/records.rs:1157-1166`), a lost-update RMW; `scrub_key` becomes `Err("this Store does not support scrub_key")` (`records.rs:1102-1106`). `grep -rn "add_usage\ |
| `crates/store-example-plugin/src/tests/mutation_hardening.rs` | FINDING | Reachable via `src/tests/mod.rs:19`. `:65-68` asserts `err.contains(&path...) \ | \ |
| `crates/store-example-plugin/src/tests/store_conformance.rs` | FINDING | `grep -c "^pub fn " ...store_conformance.rs` -> 22; `grep -o "store_conformance::[a-z_]*" .../tests/mod.rs \ |  sort -u` -> 5 symbols. Seventeen declared oracles have no caller, masked by a FILE-level `#![allow(dead_code)]` at :4. Control: the near-identical twin at `crates/store-memory/tests/store_conformance.rs` uses a per-ITEM `#[allow(dead_code)]` at :23, and names the five plane oracles 10 times (definition + call) where this copy names each exactly once (definition only) and `mod.rs` zero times. |
| `crates/store-memory/Cargo.toml` | CLEAN | `grep -n serde crates/store-memory/src/lib.rs` -> no output; `serde`/`serde_json` are used only under `tests/` and are correctly in `[dev-dependencies]`. `busbar-api` and `busbar-contract` both live (`src/lib.rs:17-18`). The cleanest manifest in the slice. | - |
| `crates/store-memory/src/tests/lib_tests.rs` | FINDING | Reachable via `src/lib.rs:898`. Instruments are real (the `AKIA_OLD` sweep assertion at :614-619 catches the regression). Defect is a comment that states the opposite of its subject: `:585-587` says "`revoke_credential` stamps `revoked_at` from the real wall clock, not the pinned one", while `src/lib.rs:686-691` says "`self.now()` (pinned-clock-aware), not the bare free function" and does exactly that. The "verify the stamped value directly" the comment prescribes is never done — unlike the tombstone twin at :538-541, which does assert `deleted_at`. | X-2645 |
| `crates/store-memory/tests/mutation_hardening.rs` | CLEAN | Auto-discovered. Both body-roundtrip loops prove non-emptiness: `cases` is a six-entry literal, and the second asserts `got.len() == bodies.len()` at :112 BEFORE zipping. The `list_keys` ordering cell inserts out of order, so a mutant that returns insertion order reds it. | - |
| `crates/store-memory/tests/record_conformance.rs` | FINDING | Auto-discovered and internally sound. But the leg it is the oracle for has no shipping caller: `git grep -n "\.record_put(\ | \.record_get(\ |
| `examples/smart-router/rust-hook/Cargo.toml` | FINDING | Deliberately outside the repo workspace (`[workspace]` at the foot, and no `members`/`exclude` row for it) — that part is stated and true. But it has no `[lib]`, no `crate-type = ["cdylib"]` and no `busbar-plugin-sdk` row, so it cannot be the `module: smart-router-hook` in-process `kind:hook` plugin its own README (:25) now tells a customer to configure. `serde`/`serde_json` are the only rows and both are used. | X-2642 |
| `examples/smart-router/rust-hook/src/main.rs` | FINDING | `git grep -rn "UnixStream" -- '*.rs'` -> this file only, ZERO under `crates/`. The example is a `UnixListener` line-protocol daemon whose doc block (:1-12) tells the operator to wire `hooks: [{ module: socket, ... }]`; `crates/busbar-kernel/src/config/hooks.rs:383-387` states that transport was RETIRED ("This REPLACES the retired `socket`/`webhook` out-of-process transports"), and the only hook constructor is `env.registry.open_hook(&hook.plugin, ...)` (`hooks/mod.rs:795-798`) with no module-name arm. Following either the code or the older half of the README gets a fail-closed boot refusal. Two smaller drifts: `:161`'s `cost_per_mtok` member comment (removed per `config/pools.rs:251`) and `:172-175` ignoring the `op` field busbar now sends (`hooks/wire.rs:435-447`), which on a line-oriented socket desynchronises framing by answering a `notify`. | X-2642, X-2643 |
| `testing/ws-conformance/subject/Cargo.toml` | FINDING | A real member (`Cargo.toml:53`) that no gate reaches: `grep -n "ws-conformance" qa/kind-isolation.toml` -> rc=1, control `grep -n "busbar-transport-ws" qa/kind-isolation.toml` -> 1903,1908,1913,2270,2275; and every source walk in `xtask/src/gates/kind_isolation.rs` roots at `["crates"]` (1727, 2698, 2745, 3607, 4436, 7593, 7631). Dep rows themselves are all used (`/tmp/depcheck.sh` -> 5/5), and the `busbar-transport-tcp/src/tests/mod.rs` citation in its header resolves. | X-2609 |
| `testing/ws-conformance/subject/src/main.rs` | FINDING | `git grep -rn "ws-conformance" -- .github scripts xtask` -> rc=1, no output; control `git grep -rln "a2a-tck\ | llm-conformance" -- .github scripts xtask` -> 7 files. The binary compiles under `--workspace` and is executed by nothing, while `testing/ws-conformance/scripts/run.sh:142` says it "runs in CI". Its echo discards the arriving `_stream` and the opcode (:77-79) and its accept-error arm `continue`s with no bound (:66-71). `TransportKeyHandle::keyless()` at :52 IS the correct post-#65 spelling — no forgery here. |

The `crates/secret-ref` rows are re-pathed to where fold F1 (DECISIONS #83) put the files: the
crate merged into `busbar-contract`, whose `Cargo.toml` is S09's row. Its own manifest, verdicted
CLEAN here, is deleted; the two dev-deps it carried (`jsonschema`, `serde_yaml`) moved with the tests
that use them.

## ROWS RAISED

### X-2600 · `SELECTOR_FORMS` and `EGRESS_SELECTOR_FORMS` are declared by all seven transports and read by nothing
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Per-const count of files naming each `TransportMeta` associated const OUTSIDE
           `crates/busbar-transport-*` and `crates/busbar-contract`:
           `for k in SELECTOR_FORMS EGRESS_SELECTOR_FORMS COMPOSES_OVER HANDOFF ... ; do git grep -l "$k" -- '*.rs' | grep -v "^crates/busbar-transport-\|^crates/busbar-contract/" | wc -l; done`
             SELECTOR_FORMS         external-files=0
             EGRESS_SELECTOR_FORMS  external-files=0
             SESSION_BOUND          external-files=0
             UNIT0_TRIGGER          external-files=0
             UPGRADES_TO            external-files=0
             TRANSPORT_FACTS        external-files=0
             DECODES_PAYLOAD        external-files=0
             STATUS_CLASS           external-files=0
             STATUS_NAMESPACE       external-files=0
             HANDSHAKE_TRIGGER      external-files=0
           POSITIVE CONTROL, same command shape, same corpus:
             COMPOSES_OVER          external-files=3   (crates/busbar/src/root/registry.rs,
                                                        crates/busbar/tests/transport_composed_over_consistency.rs,
                                                        crates/busbar-contract/tests/transport_registry.rs)
             HANDOFF                external-files=2
           So the grep shape finds real external readers; these ten find none.
           The only consumer-shaped thing in the tree is the enum's own algebra, and it disclaims the
           per-transport lists in its own words:
           `head -25 crates/busbar-contract/tests/grammar_overlaps.rs` ->
             "nothing in the kernel, the units or the planes reads the list — they match on a form"
           `grep -n "SELECTOR_FORMS\|TransportMeta" crates/busbar-contract/tests/grammar_overlaps.rs` -> no output (rc=0, empty)
           `grep -n "SelectorForm" crates/busbar-kernel/src/grammar.rs` -> line 33 only, inside a
           `pub use busbar_contract::{...}` re-export block; no kernel code evaluates it.
           Meanwhile `crates/busbar-plane-streaming/src/claims.rs:150` writes
           `Selector::PathSuffix("/v1/realtime")` against the `ws` wire, and no code checks that
           `ws`'s declared `SELECTOR_FORMS` admits `PathSuffix`.
ACTION:    Either wire the boot-time claim check to reject a plane `Selector` whose form is absent
           from the serving transport's `SELECTOR_FORMS` (which is what the seven `claims.rs` headers
           say the constant is for), or delete `SELECTOR_FORMS`/`EGRESS_SELECTOR_FORMS` from
           `TransportMeta` and the seven `claims.rs` files. Do not leave a grammar declared on both
           sides with no evaluator between them.

### X-2601 · `WRAPPABLE_BYTE_STREAM` is the transport half of the TLS fail-closed seam, and no transport declares it and no code reads it
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "WRAPPABLE_BYTE_STREAM" -- '*.rs'` -> exactly 6 hits, NONE in any transport crate:
             crates/busbar-contract/src/transport/mod.rs:154   const WRAPPABLE_BYTE_STREAM: bool = false;   <- the declaration, default false
             crates/busbar-contract/src/transport/wire.rs:494  (doc reference)
             crates/busbar-core-connsec/src/lib.rs:24,241,264  (doc + the refusal's message)
             crates/busbar-core-connsec/src/tests.rs:144       (the only place the refusal is built)
           The contract states the seam (mod.rs:145-153):
             "`TLS`-configured binding + a transport that leaves this at the default `false` =>
              the binding fails closed at boot rather than being silently served in plaintext"
           The reconciler is `busbar_core_connsec::prepare(label, tls_cfg, resolver, transport_capable)`
           (crates/busbar-core-connsec/src/lib.rs:291-299), whose `Some(_) if !transport_capable`
           arm builds `FailClosed::IncapableTransport`.
           BOTH shipped call sites pass a HARD-CODED literal instead of the const:
             crates/busbar/src/main.rs:1692  busbar_core_connsec::prepare(&addr, tls_cfg.as_ref(), &secret_resolver, true)
             crates/busbar/src/main.rs:1873  busbar_core_connsec::prepare(label, Some(&tls), &secret_resolver, true)
           `git grep -n "IncapableTransport" -- '*.rs'` -> the only constructor outside the definition
           is `crates/busbar-core-connsec/src/tests.rs:158`. The variant is unreachable in the shipped
           binary: an error arm that cannot be emitted, guarding a property nothing measures.
           POSITIVE CONTROL for the "no transport declares it" half: the same grep shape over
           `SESSION_BOUND` returns a hit in every one of the seven `meta.rs` files; over
           `WRAPPABLE_BYTE_STREAM` it returns none.
ACTION:    Either have the seven `meta.rs` files declare `WRAPPABLE_BYTE_STREAM` honestly
           (`true` for tcp/tls/http/ws/grpc, left `false` for stdio, which is the case the contract
           doc names) and have the composition root pass
           `<T as TransportMeta>::WRAPPABLE_BYTE_STREAM` into `prepare` in place of the two `true`
           literals; or delete the const, the `IncapableTransport` variant and the prose that claims
           the reconciliation happens. Today the seam is named in three files and exists in none.

### X-2602 · `ws` decodes Text frames and can never write one: the transport is one-way on the opcode
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  Every data send in the crate:
           `grep -n "SinkExt::send(&mut \*w, Message::" crates/busbar-transport-ws/src/transport.rs`
             613:  Message::Pong(payload)          (control frame)
             681:  Message::Binary(payload.into()) <- Transport::write
             766:  Message::Close(Some(close_frame))
             809:  Message::Binary(payload.into()) <- unit0_refusal
           There is no `Message::Text` send anywhere in the crate.
           POSITIVE CONTROL, the read side of the same file:
           `grep -n "Some(Ok(Message::" crates/busbar-transport-ws/src/transport.rs`
             556: Message::Binary(b)   577: Message::Text(t)   596: Close   610: Ping   625: Pong|Frame
           The two inbound arms (556, 577) build a byte-identical `Frame`, and the frame carries no
           opcode to build it from: `awk '/pub struct FrameMeta/,/^}/' crates/busbar-contract/src/transport/wire.rs`
           shows `bytes`, `transport_units`, `status`, `status_code`, `retry_after_secs` and nothing else.
           So a peer's Text/Binary distinction is destroyed on the way in and unspellable on the way
           out. `crates/busbar-plane-streaming/src/claims.rs:6,35,150` claims the JSON duplex
           dialects `openai-realtime` and `gemini-live` over exactly this wire — both are text-framed
           JSON protocols upstream (interop consequence not run here: see CERTAINTY on the ACTION).
           The kind's own contract is bidirectional; this transport is not.
ACTION:    Add the opcode to the frame the transport hands up and takes back (a `FrameMeta` field,
           or a `Framing`-level text/binary tag), have `frames()` set it from the arm it matched, and
           have `write` emit `Message::Text` when the frame says text. Until then `busbar-transport-ws`
           cannot answer a text peer in kind and the Autobahn subject in this slice cannot pass
           Autobahn section 1.1. (The interop half is ADJUDICATE — the code asymmetry above is VERIFIED.)

### X-2603 · `busbar-transport-ws` carries the whole rustls stack as four dependency rows that compile nothing
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `grep -rn "rustls\|webpki\|Rustls\|RootCertStore\|ClientConfig\|ServerName" crates/busbar-transport-ws/src/` -> rc=1, no output.
           POSITIVE CONTROL, identical command against the sibling that really does use them:
           `grep -rln "rustls\|webpki" crates/busbar-transport-tls/src/` ->
             crates/busbar-transport-tls/src/tests/mod.rs
             crates/busbar-transport-tls/src/transport.rs
             crates/busbar-transport-tls/src/lib.rs
           The four dead rows are `crates/busbar-transport-ws/Cargo.toml`:
             tokio-rustls = { workspace = true }
             rustls = { workspace = true }
             rustls-pki-types = { workspace = true }
             webpki-roots = { workspace = true }
           All four are non-optional, so they are in this plugin crate's dependency CLOSURE, which is
           the unit DECISIONS #40's dep wall is drawn over — and `crates/busbar-transport-ws/src/lib.rs:20`
           states the opposite in prose: "this crate encrypts nothing". This is the same defect
           `crates/busbar-transport-http/Cargo.toml:15-23` documents having just fixed for the
           sibling-transport rows ("two lines that compiled nothing carried a capability crate into
           four plugin closures", commit 0357a842f) — the external half was not swept.
ACTION:    Delete the four rows from `crates/busbar-transport-ws/Cargo.toml`.

### X-2604 · `busbar-transport-http` declares `tokio-rustls` and names it nowhere
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `grep -rn "tokio_rustls\|tokio-rustls" crates/busbar-transport-http/src/` -> rc=1, no output.
           POSITIVE CONTROL, same corpus, the TLS crate this one really does use:
           `grep -rn "hyper_rustls" crates/busbar-transport-http/src/` ->
             crates/busbar-transport-http/src/lib.rs:155  type EgressClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;
             crates/busbar-transport-http/src/lib.rs:356  let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls);
           `rustls`, `rustls-pki-types` and `webpki-roots` ARE each named in `src/lib.rs`; only
           `tokio-rustls` (Cargo.toml:30) is dead.
ACTION:    Delete line 30 of `crates/busbar-transport-http/Cargo.toml`.

### X-2605 · `busbar-transport-sse` declares `tokio` as a shipped dependency for a `#[cfg(test)]` module, and already has the dev-dependency
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "tokio" crates/busbar-transport-sse/src/{transport,lib,proto,reframe,claims,meta}.rs` -> rc=1, no output.
           POSITIVE CONTROL, same files: `grep -n "futures" crates/busbar-transport-sse/src/transport.rs` ->
             21: use futures::{Stream, StreamExt};
             101: Box::pin(futures::stream::unfold(...))
           The only `tokio` in the crate is `crates/busbar-transport-sse/src/tests/mod.rs`, reached
           through `crates/busbar-transport-sse/src/lib.rs:92-93` `#[cfg(test)] mod tests;`.
           `crates/busbar-transport-sse/Cargo.toml` already carries
           `[dev-dependencies] tokio = { features = ["net","rt-multi-thread","sync","io-util","time","macros"] }`
           at line 26 — a strict superset of the `[dependencies]` row's `["sync"]` at line 18.
ACTION:    Delete `tokio = { workspace = true, features = ["sync"] }` from
           `crates/busbar-transport-sse/Cargo.toml` `[dependencies]`. The dev row already covers the battery.

### X-2606 · `busbar_transport_ws::StaticConfig` is a public config view with zero references anywhere, and its `get_int` would silently drop the message ceiling
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "busbar_transport_ws::StaticConfig" -- '*.rs'` -> rc=1, no output.
           `grep -rn "StaticConfig" crates/busbar-transport-ws/` -> 5 hits, ALL of them the definition
           and the re-export (conn.rs:122,126,136,148 and lib.rs:36). Not even this crate's own
           1318-line battery constructs it.
           POSITIVE CONTROL: `git grep -n "busbar_transport_ws::" -- '*.rs' | grep -v "^crates/busbar-transport-ws"`
           -> 6 hits (grpc/src/transport.rs:42,164; busbar/src/root/registry.rs:104;
           busbar/src/root/transports.rs:52; busbar/tests/transport_composed_over_consistency.rs:28;
           testing/ws-conformance/subject/src/main.rs:24), so the path spelling resolves.
           The hazard if it were used: `crates/busbar-transport-ws/src/conn.rs:136-145` answers `None`
           to EVERY `get_int` key, including `MESSAGE_MAX_BYTES_KEY`, which
           `crates/busbar-transport-ws/src/transport.rs:415` reads to install the operator's ceiling.
           A caller that listened through this view would get tungstenite's 64 MiB default — the exact
           defect commit a21a83209 closed.
ACTION:    Delete `StaticConfig` and the `pub use conn::StaticConfig;` at
           `crates/busbar-transport-ws/src/lib.rs:36`, or make `get_int` answer
           `MESSAGE_MAX_BYTES_KEY` and give it a caller.

### X-2607 · `busbar_transport_stdio::StaticConfig` is public API whose only consumer is its own `#[cfg(test)]` module
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "busbar_transport_stdio::StaticConfig" -- '*.rs'` -> rc=1, no output (same
           positive control as X-2606 establishes the spelling resolves for this crate family).
           `grep -rn "StaticConfig" crates/busbar-transport-stdio/` -> definition (conn.rs:113,115,127),
           re-export (lib.rs:45), and four hits in `src/tests/mutation_hardening.rs` (lines 4,64,66,69,100)
           which is reached only through `crates/busbar-transport-stdio/src/tests/battery.rs:22-23`
           under `#[cfg(test)]`. No shipped caller.
ACTION:    Make it `pub(crate)` (the tests are in-crate and reach it either way), or delete it
           together with `crates/busbar-transport-stdio/src/lib.rs:45`.

### X-2608 · The root answers the message-ceiling config key only under `plane-voice`, and `grpc` — which always ships — reads the same key
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  The key is one string with two readers:
             crates/busbar-transport-ws/src/transport.rs:107    pub const MESSAGE_MAX_BYTES_KEY: &str = "limits.request_body_max_bytes";
             crates/busbar-transport-grpc/src/transport.rs:47   pub const MESSAGE_MAX_BYTES_KEY: &str = "limits.request_body_max_bytes";
           and `GrpcTransport::listen` reads it at `crates/busbar-transport-grpc/src/transport.rs:167`.
           The only thing that ANSWERS it is `ListenerView::get_int`
           (`crates/busbar/src/root/transports.rs:310-327`), and the answer is feature-gated:
             #[cfg(feature = "plane-voice")]      { (key == MESSAGE_MAX_BYTES_KEY).then(...) }
             #[cfg(not(feature = "plane-voice"))] { let _ = key; None }
           with the comment "Without the voice plane there is no transport assembling messages, so no
           key is answered." That statement is false. `grep -n "busbar-transport-grpc\|busbar-transport-ws" crates/busbar/Cargo.toml`:
             144: busbar-transport-ws   = { path = "../busbar-transport-ws", optional = true }
             145: busbar-transport-grpc = { path = "../busbar-transport-grpc" }     <- NOT optional
           `listen_all` (`crates/busbar/src/root/transports.rs:346-357`) hands the same `ListenerView`
           to every `&dyn Transport`, grpc included.
           The broken configuration is a CI gate, not a hypothetical:
           `grep -n "no-default-features" .github/workflows/ci.yml` -> job `no-default-features` at
           lines 1740-1770 builds/clippies/tests exactly that shape.
           Blast radius is bounded rather than open: `GrpcTransport::message_cap`
           (`src/transport.rs:108-114`) falls back to `codec::MAX_MESSAGE_BYTES` when the field is 0 —
           so the failure is the operator's configured ceiling being silently replaced by the crate
           default, not an unbounded decode.
ACTION:    Remove the `plane-voice` gate from `ListenerView::get_int` — the key is answered for any
           transport that asks — and correct the comment. Add a cell that asserts a grpc listener
           built with `--no-default-features` decodes under the deployment's cap, since today nothing
           would go red.

### X-2609 · `testing/ws-conformance/subject` is a workspace member that no gate's source walk reaches and no `kind-isolation` row names
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  It is a real member: `Cargo.toml:53  "testing/ws-conformance/subject",`.
           `grep -n "ws-conformance\|ws_conformance" qa/kind-isolation.toml` -> rc=1, no output.
           POSITIVE CONTROL, same file: `grep -n "busbar-transport-ws" qa/kind-isolation.toml` ->
             1903, 1908, 1913 (`crate = "busbar-transport-ws"`), 2270, 2275 — so the ratchet does
             carry per-crate rows, and this member has none.
           Every source walk in the gate roots at `crates`:
           `git grep -n "WalkSpec::new(\[\"crates\"\])\|parts\[0\] == \"crates\"" xtask/src/gates/kind_isolation.rs`
             1727, 2698  (`parts[0] == "crates"`)
             2745, 3607, 4436, 7593, 7631  (`WalkSpec::new(["crates"])`)
           So both of this slice's subject files sit outside every scan. The crate MINTS a capability
           (`TransportKeyHandle::keyless()`, `subject/src/main.rs:52`) and BINDS a listener
           (`subject/src/main.rs:54-58`) with no gate looking at it. This confirms 1.6.0-LEDGER G23 is
           still open from the subject's own side.
ACTION:    Add `testing` to the gate's walk roots (or move the subject under `crates/`), and add the
           `[[cell]]`/`[[dep]]`/registry rows for `ws-conformance-subject` that every other member has.

### X-2610 · The Autobahn subject binary is executed by nothing, while its rig's `run.sh` says it "runs in CI"
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -rn "ws-conformance" -- .github scripts xtask` -> rc=1, no output.
           POSITIVE CONTROL, same corpus, a rig that IS wired:
           `git grep -rln "a2a-tck\|llm-conformance" -- .github scripts xtask` ->
             .github/workflows/ci.yml, .github/workflows/oracle-proof.yml,
             .github/workflows/qa-conformance-a2a.yml, scripts/a2a-subject/boot.sh,
             scripts/method-inventory.py, xtask/fixtures/full-gate/continuation-ci.yml,
             xtask/src/gates/conformance_sync/render.rs
           `git ls-files .github/workflows | grep ws` -> no output; there is no `ws-conformance.yml`,
           although `docs/design/1.6.0-local-only-audit.md:344` still lists one.
           The rig's own source asserts the opposite:
           `testing/ws-conformance/scripts/run.sh:142` -> "Docker-live mode; runs in CI
           (crossbario/autobahn-testsuite vs busbar's ws-conformance-subject)."
           The subject compiles under `cargo build --workspace` and is never RUN. Confirms
           1.6.0-LEDGER G45 from the subject's side.
ACTION:    Either add the workflow that invokes `testing/ws-conformance/scripts/run.sh --subject`,
           or delete the `runs in CI` sentence at `run.sh:142` and mark `ws` `not-run` consistently.
           Do not leave a rig whose own source claims a wiring it does not have. NOTE: the subject
           is NOT deletable — X-2602 shows Autobahn would find a real defect if it ran.

### X-2611 · The Autobahn subject echoes every frame as `StreamId(0)` and as binary, so it cannot answer Autobahn's text cases correctly
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '74,85p' testing/ws-conformance/subject/src/main.rs`:
             while let Some(item) = frames.next().await {
                 match item {
                     Ok((_stream, frame)) => {                       <- the arriving stream id is discarded
                         let bytes = ScratchBytes::new(frame.bytes.as_slice());
                         if ws.write(&conn, StreamId(0), bytes).await.is_err() {
           and the write it calls can only emit `Message::Binary` (see X-2602 evidence,
           `crates/busbar-transport-ws/src/transport.rs:681`).
           Autobahn's case suite grades an ECHO: section 1.1 sends text payloads and requires text
           back. This subject returns binary for every one of them. So the rig, if it were ever run
           (X-2610), would be red on a whole section for a reason that is the transport's (X-2602),
           not the subject's — which is why X-2610 must not be closed by deleting the rig.
ACTION:    Close X-2602 first; then have the subject echo `frame`'s opcode and its `_stream` rather
           than hard-coding `StreamId(0)` and binary.

### X-2612 · The subject's accept-error arm spins without bound
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '64,71p' testing/ws-conformance/subject/src/main.rs`:
             loop {
                 let conn = match ws.accept(&listener).await {
                     Ok(conn) => conn,
                     Err(e) => {
                         eprintln!("ws-conformance-subject: accept error: {e:?}");
                         continue;
                     }
           A permanently-failing listener (a closed or unbound fd) makes `accept` return `Err`
           immediately and forever; the arm `continue`s with no backoff, no error budget and no exit,
           so the process burns a core and floods stderr instead of dying. Every sibling in this
           slice that pumps a loop bounds it — cf. `crates/busbar-transport-ws/src/transport.rs:610-624`,
           where the Ping answer carries `PONG_BUDGET` and a failure ends the pump.
ACTION:    Count consecutive accept errors and exit non-zero past a small bound (the rig reads the
           process's exit status), or at minimum back off before the `continue`.

### X-2613 · The `no_plane_names` gate states its allowed set in terms of `busbar-contract-transport`, a crate that no longer exists
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-grpc/tests/no_plane_names.rs:163-165`:
             "The allowed set of busbar names in a transport's manifest is exactly two:
              `busbar-contract` and `busbar-contract-transport`, plus the sibling transports it composes over."
           `ls -d crates/busbar-contract-transport` -> "No such file or directory".
           `grep -n "busbar-contract-transport" Cargo.toml` -> rc=1, no output (no member row).
           POSITIVE CONTROL: `ls -d crates/busbar-contract` -> exists;
           `grep -c "busbar-contract" Cargo.toml` -> 3.
           The crate was folded into `busbar-contract` in b65fbfb83. The gate's assertion still
           PASSES — it is the stated rule that drifted, and a rule that names a crate nobody can
           declare is a rule a reader will apply wrongly.
ACTION:    Rewrite the doc sentence to "exactly one: `busbar-contract`, plus the sibling transports
           it composes over."

### X-2614 · The `no_plane_names` anti-vacuity cell has a `||` arm that is a literal containing itself, so that assertion cannot go red
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-grpc/tests/no_plane_names.rs:194`:
             assert!(contains_word("let x = A2A_MOUNT;", "a2a") || "A2A_MOUNT".contains("A2A"));
           The right operand is `"A2A_MOUNT".contains("A2A")` — a string literal tested against its
           own substring. It is `true` for every possible implementation of `contains_word`,
           including one that always returns `false`, so this line cannot detect the mutation the
           cell exists to detect. It is the first line of the file's own anti-vacuity guard, whose
           doc says "Each assertion below plants exactly what the test above is looking for and
           requires the matcher to fire on it" — this one requires nothing.
           The seven assertions below it (lines 195-200) are sound and do constrain `contains_word`,
           so the cell as a whole is not blind; this one line is.
ACTION:    Drop the `|| "A2A_MOUNT".contains("A2A")` disjunct and leave
           `assert!(contains_word("let x = A2A_MOUNT;", "a2a"));`.

### X-2615 · `busbar-auth-static-plugin` carries an `rlib` crate-type for a compiled-in witness that its own manifest says does not exist
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `crates/auth-static-plugin/Cargo.toml` declares `crate-type = ["cdylib", "rlib"]` and then
           says, in the same comment block (lines 18-25):
             "ADDING THE ARTIFACT IS NOT THE WITNESS. `open` below is still private and there is no
              `dispatch_compiled_in` twin of the `busbar_call` symbol `export_auth_plugin!` emits, so
              nothing can yet drive the compiled-in door."
           Nothing links the rlib:
           `git grep -rn "busbar-auth-static-plugin\|busbar_auth_static_plugin" -- '*.toml' '*.rs' | grep -v "^crates/auth-static-plugin/"`
           -> one hit only, `crates/busbar-kernel/src/auth/tests/plugin_chain_tests.rs:43`, which
           LOCATES THE CDYLIB ON DISK (`busbar_plugin_loader::plugin_library_filename(...)`), never
           links the crate.
           POSITIVE CONTROL, the two fixtures whose rlib IS linked:
           `sed -n '/dev-dependencies/,$p' crates/plugin-loader/Cargo.toml` ->
             busbar-plugin-example-plane  = { path = "../plane-example" }
             busbar-export-example-plugin = { path = "../export-example-plugin" }
           so a linked-rlib fixture looks different in the tree, and this one is not one.
           (The sibling cdylib-only fixtures — hook-test, secret-example, store-example — each carry
           `rlib` for the DIFFERENT and real reason that `cargo test -p <crate>` will not emit the
           cdylib without it. That reason does not apply here, because this manifest gives a
           different one and then withdraws it.)
ACTION:    Either write the `dispatch_compiled_in` twin and the both-ways cell the comment promises,
           or drop `"rlib"` and the paragraph, leaving the reason the siblings give if it applies.

### X-2616 · Four `Operation` constants are constructed by nothing but the `ALL` table and tests, under a `dead_code` allow that cannot fire
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:  `git grep -n "Operation::CATALOGUE" -- '*.rs'` (same for FETCH, TASK, CONTROL) -> every hit
           is either `crates/api/src/operation.rs:242-246` (the `ALL` table listing them) or a file
           under a `tests/` path (`crates/api/tests/mutation_hardening_hooks_and_operation.rs`,
           `crates/busbar-kernel/src/handlers/tests/dispatch_tests.rs`,
           `crates/busbar-kernel/src/tests/operation_tests.rs`,
           `crates/busbar-mcp/src/codec/tests/mcp_tests.rs`).
           POSITIVE CONTROL, same command shape: `Operation::SUBSCRIBE` and `Operation::INVOKE` each
           return a SHIPPED hit (`crates/busbar-kernel/src/plane_host/dispatch.rs:359`,
           `crates/busbar-kernel/src/ir/invoke.rs:4` / `ir/subscribe.rs:4`), so the grep finds
           shipped constructors when they exist.
           Separately, the guard written over them is inert: `#[cfg_attr(not(test), allow(dead_code))]`
           at operation.rs:220,222,224,227,239 and 130 sits on `pub` items of a `pub` type in
           `pub mod operation` (declared at `crates/api/src/lib.rs:26`) of a library crate. `dead_code`
           never fires on an item reachable from the crate root, so the attribute suppresses a lint
           that could not have fired and reads as a claim about shipping that the compiler never made.
           ADJUDICATE rather than VERIFIED: the module header (operation.rs:63-69) states this posture
           deliberately ("declared AHEAD of the cells that will construct them"), so whether it is a
           defect is an owner call, not a measurement. The inert attribute is a measurement.
ACTION:    Owner call on the four unconstructed constants. Independently, delete the six
           `#[cfg_attr(not(test), allow(dead_code))]` attributes — they cannot fire, and a reader
           takes them as evidence of a test-only boundary the compiler is not enforcing.

### X-2617 · `busbar-api`'s crate header says "no I/O" and lists four of its seven modules as "exactly the shared surface"
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "no I/O" crates/api/src/lib.rs` ->
             19://! Everything here is a CONTRACT, not machinery: no I/O, no engine state, no transport.
           `grep -c "std::fs::" crates/api/src/durable.rs` -> 10
           `pub mod durable;` is declared at `crates/api/src/lib.rs:24` and does `File::open`,
           `rename`, `sync_all`, `remove_file` and `create_dir` — it IS the crate's I/O.
           The bullet list at lines 9-17 that the header calls "exactly the shared surface"
           enumerates auth, hooks, store, secret and omits all three `pub mod`s: `durable` (:24),
           `operation` (:26), `usage_migration` (:29).
           This is the crate a third-party plugin author links and this header is the first thing
           they read about it.
ACTION:    Add a `- **durable** — the one atomic/durable file-publish primitive (the ONE I/O
           exception)` bullet plus bullets for `operation` and `usage_migration`, and amend line 19
           to "no engine state, no transport, and no I/O beyond `durable`".

### X-2618 · `durable::write_with`'s entire public contract is attached to a private helper, and `write_with` itself carries no doc
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '68,92p' crates/api/src/durable.rs` — one contiguous `///` block runs from line 71
           ("Atomically + durably publish `bytes` to `path` with `opts`.") through line 89 and
           terminates at `fn holding_dir(path: &Path) -> &Path {` on line 90, which is PRIVATE.
           `sed -n '154,162p' crates/api/src/durable.rs`:
             158  }
             159  (blank)
             160  pub fn write_with(path: &Path, bytes: &[u8], opts: DurableOpts) -> io::Result<()> {
           — no doc comment on the public item.
           And `pub fn write` (durable.rs:~56) sends the reader there: "See [`write_with`] for the
           full contract." The intra-doc link resolves to an undocumented item, and the contract
           prose (temp naming, the `Ok(())` post-condition, the `Err` post-condition) renders under
           a private fn rustdoc never emits. `busbar-api` is the crate every third-party plugin
           builds against and `pub mod durable` is on its public surface (`crates/api/src/lib.rs:24`).
ACTION:    Move lines 71-84 above `pub fn write_with` at line 160; leave 85-89 as `holding_dir`'s doc.

### X-2619 · `DurableOpts::exclusive` and its `O_EXCL` branch have no shipped constructor
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "exclusive: true" -- '*.rs'` -> 2 hits, both tests:
             crates/api/src/tests/durable_tests.rs:218
             crates/api/src/tests/durable_tests.rs:244
           `git grep -n "DurableOpts" -- '*.rs' | grep -v "crates/api/src/durable.rs\|durable_tests.rs"`
           -> the only two shipped constructors, and neither sets it:
             crates/busbar-kernel/src/config/overlay.rs:1012  DurableOpts { mode: Some(0o600), ..Default::default() }   (Default => exclusive: false)
             crates/plugin-loader/src/highwater.rs:229        DurableOpts { mode: Some(0o600), exclusive: false }
           POSITIVE CONTROL: the same grep shape finds `exclusive: false` at highwater.rs:231, so it
           does match shipped construction when it exists.
           The field's own doc (durable.rs:47-52) and the module header (durable.rs:20) justify it as
           "the signing-key anti-pre-plant posture", and the signing-key write it was built for is
           gone — `crates/busbar/tests/cli_validate.rs:653` now asserts "busbar must NOT write a
           signing key". So the `O_EXCL` path and its stale-temp pre-removal exist for the two test
           cells alone.
ACTION:    Owner call: delete the field, the `O_EXCL` branch and the two cells; or land the
           signing-key mint that constructs `exclusive: true` in the same change. Do not leave a
           security posture whose only caller is its own test.

### X-2620 · `durable.rs`'s module header names three things that moved or never existed, one of them the gate exemption a reader would audit
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Three claims in `sed -n '1,36p' crates/api/src/durable.rs`:
           (a) line 7 names "`admin::structure` / the `structure-lint` gate".
               `git grep -rn "mod structure" -- '*.rs'` -> `xtask/src/gates/mod.rs:65: pub mod structure_lint;`
               and `xtask/src/yaml_lite.rs:902` (an unrelated test mod). There is no `admin::structure`.
           (b) line 8 names "the ephemeral `plugin-loader::stage`" as the one exempt hand-rolled rename.
               `grep -c "rename\|sync_all" crates/plugin-loader/src/stage.rs` -> 0
               POSITIVE CONTROL, same file: `grep -c "fs::" crates/plugin-loader/src/stage.rs` -> 10
               The gate's actual allowlist is in `xtask/src/gates/structure_lint/choke_points.rs`:
                 BanRule::new(r"fs::rename\(", "hand-rolled rename-to-publish",
                              &["crates/api/src/durable.rs".into(), format!("{core}/export/file.rs")])
               — so the file that IS exempt (`export/file.rs`) is never named here, and the file
               that IS named is not exempt and has nothing to exempt.
           (c) line 33 names "(main.rs, config/overlay.rs)" as the `DurableOpts` call sites.
               `grep -n "DurableOpts" crates/busbar/src/main.rs` -> rc=1, no output.
               POSITIVE CONTROL, same file: `grep -c "fn main" crates/busbar/src/main.rs` -> 1.
               The second real site is `crates/plugin-loader/src/highwater.rs:229`.
ACTION:    (a) -> `xtask/src/gates/structure_lint/choke_points.rs`; (b) -> `crates/busbar-kernel/src/export/file.rs`;
           (c) -> `(config/overlay.rs, plugin-loader/src/highwater.rs)`.

### X-2621 · The `message_count` guard is satisfied by `system_chars: Some(27)` and cannot go red
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/api/tests/mutation_hardening_hooks_and_operation.rs:218-221`:
             assert!(dbg.contains('2'), "message_count must reflect the real count: {dbg}");
           The subject, `crates/api/src/hooks.rs:90-99`, renders:
             f.debug_struct("PromptProjection")
              .field("system_chars", &self.system.as_deref().map(|s| s.chars().count()))
              .field("message_count", &self.messages.len())
           and the fixture's system is `"you are a helpful assistant"`
           (`mutation_hardening_hooks_and_operation.rs:202`) — 27 characters. The Debug string is
           therefore `PromptProjection { system_chars: Some(27), message_count: 2, .. }` and the
           `'2'` the assertion looks for is the one in `27`.
           Mutate `hooks.rs:97` to `.field("message_count", &0)` and every assertion in the cell
           still passes: `contains("system_chars")` ok, `contains("message_count")` ok,
           `contains('2')` ok via `Some(27)`, and the redaction asserts are unaffected. The only
           cell in the tree claiming to guard the count cannot produce a NO for it.
ACTION:    `assert!(dbg.contains("message_count: 2"), "message_count must reflect the real count: {dbg}");`

### X-2622 · `CtorFail::Protocol`'s two arms and `read_buf`'s `Err(())` arm are reached by nothing, and the class harness only ever asserts the status is NOT produced
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `read_buf` (`crates/plugin-sdk/src/boundary.rs:128-136`) returns `Err(())` on exactly one
           input: `len > 0 && ptr.is_null()`. Its two consumers turn that into `STATUS_PROTOCOL`:
             boundary.rs:178  call_boundary: `Err(()) => return STATUS_PROTOCOL`
             boundary.rs:207  open_boundary: `Err(()) => Err(CtorFail::Protocol("null config pointer"))`
           and a third protocol arm sits beside it:
             boundary.rs:211  `Err(_) => Err(CtorFail::Protocol("config is not valid UTF-8"))`
           `git grep -n "null config pointer\|config is not valid UTF-8" -- '*.rs'` -> exactly 2 hits,
           boundary.rs:207 and :211, i.e. the construction sites themselves. No test in the tree
           asserts either message. (The grep returning those two hits is its own positive control:
           the literal-string search works.)
           STATUS_PROTOCOL *is* asserted twice, but for OTHER producers:
             crates/plugin-sdk/src/tests/lib_tests.rs:654  null HANDLE into call_impl  (boundary.rs:173)
             crates/plugin-sdk/src/tests/lib_tests.rs:678  null out_handle on open     (boundary.rs:224)
           so `boundary.rs:178`, `:207` and `:211` — the three arms that depend on `read_buf`/UTF-8 —
           are the ones nothing drives.
           `crates/plugin-sdk/tests/boundary_class.rs` is the file that declares itself the
           parameterized class harness "a new export inherits", and its only mention of the status
           is `assert_ne!(st, STATUS_PROTOCOL, ...)` at line 226 — it asserts the status is not
           produced and never that it is.
ACTION:    Add to `boundary_class.rs`: `assert_eq!(open_boundary::<TestHandle>(ptr::null(), 4, ...), STATUS_PROTOCOL)`
           and one with a `[0xFFu8]` config (bad UTF-8), plus
           `assert_eq!(call_boundary(handle, ptr::null(), 4, ...), STATUS_PROTOCOL)`. Three cells
           close all three arms and the `read_buf` guard under them.

### X-2623 · `exclusive_mode_publishes_0600_and_survives_stale_own_temp` never plants a stale own temp
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "plant_decoy_arm" crates/api/src/tests/durable_tests.rs` -> one hit, line 249,
           inside `exclusive_pre_removal_clears_a_temp_left_by_a_crashed_run` (declared at :239).
           The body of `exclusive_mode_publishes_0600_and_survives_stale_own_temp` (:212-228) writes
           twice and asserts mode and contents; nothing plants a decoy, so the
           `_and_survives_stale_own_temp` half of the name is carried entirely by the NEXT test.
           A reviewer greps the name, finds this cell, and believes the pre-removal is covered here.
ACTION:    Rename to `exclusive_mode_publishes_0600_and_rewrites`. (Coverage itself is fine — the
           next cell really does plant the decoy.)

### X-2624 · `auth_tests.rs` pins three line numbers into two other crates and all three have moved
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/api/src/tests/auth_tests.rs:26` reads
             "(`crates/auth-admin-tokens/src/lib.rs:46,51`, `crates/auth-static-plugin/src/lib.rs:90`)"
           `grep -n "sha256_hex" crates/auth-admin-tokens/src/lib.rs` -> 14 (the `use`), 66, 71 —
           the two compare sites are at 66 and 71, not 46 and 51.
           `grep -n "sha256_hex\|fn authenticate" crates/auth-static-plugin/src/lib.rs` -> 27 (`use`),
           90 (`fn authenticate`), 92 (the compare), 117. The cited `:90` is the signature line; the
           behaviour it points at is 92.
           This is the cell that documents WHERE the constant-time compare of a credential hash
           happens; a reader auditing the timing posture is sent to the wrong lines in both crates.
ACTION:    Replace the pinned numbers with symbol names (`AdminTokens::authenticate`'s two
           `constant_time_eq(&sha256_hex(..), ..)` compares; `StaticAuth::authenticate`'s), which
           cannot drift. If numbers stay, correct them to 66,71 and 92.

### X-2625 · THE DURABLE STORE TEMPLATE NEVER GOT `add_usage`, so the ledger accumulate silently degrades to a lost-update read-modify-write
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:  `awk '/^impl Store for FileStore/{f=1} f&&/^    fn /' crates/store-example-plugin/src/lib.rs | grep -oE "fn [a-z_]+" | sort`
           -> 17 verbs: add_metering, append_plane_record, delete_key, delete_plane_record, get_key,
              get_plane_record, get_usage, list_keys, list_metering, list_plane_record_parents,
              list_plane_records, plane_token_live, purge_plane_records_before, put_key, put_usage,
              redeem_plane_token, upsert_plane_record.
           `add_usage` is NOT among them. POSITIVE CONTROL: `put_usage` IS, so the awk finds the
           verbs FileStore does delegate.
           `grep -oE "^    fn [a-z_]+" crates/store-example-plugin/src/ram.rs | sort` -> `RamStore`
           DOES implement `add_usage` (ram.rs:198), as an atomic additive accumulate:
           `entry(..).or_default().apply_delta(delta)` under ONE write guard.
           So `FileStore` — the `durable_path` mode — inherits the trait default,
           `crates/busbar-contract/src/records.rs:1157-1166`:
             fn add_usage(&self, bucket_id, window_start, delta) -> RecordStoreResult<()> {
                 let mut cur = self.get_usage(bucket_id, window_start)?;   // read guard, clone, DROP
                 cur.apply_delta(delta);
                 self.put_usage(bucket_id, window_start, &cur)             // write guard, ABSOLUTE SET
             }
           Two concurrent `add_usage` calls on one durable handle interleave between the two guards
           and one increment is lost. This is exactly the failure the crate's own
           `two_handles_do_not_lose_updates_under_contention` (`src/tests/mod.rs:450`) exists to
           refuse — and that cell drives `append_plane_record`, never the ledger:
           `grep -rn "add_usage\|scrub_key" crates/store-example-plugin/src/tests/ | wc -l` -> 0
           POSITIVE CONTROL: `grep -rn "add_metering" crates/store-example-plugin/src/tests/ | wc -l` -> 4
           `add_usage` is the hot path (`flush_budgets` per tick), and this crate is the COPY-ME
           TEMPLATE for `kind: store`, so the shape is what a third-party durable backend inherits.
ACTION:    Add to the delegation block in `crates/store-example-plugin/src/lib.rs` (beside `put_usage`):
             fn add_usage(&self, b: &str, w: u64, d: &busbar_api::UsageDelta) -> StoreResult<()> { self.inner.add_usage(b, w, d) }
           and extend `two_handles_do_not_lose_updates_under_contention` to drive `add_usage` so the
           regression has an instrument.

### X-2626 · `scrub_key` is implemented in RAM mode and REFUSED in durable mode
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  Same `awk` as X-2625: `scrub_key` is not in `FileStore`'s 17 delegated verbs, while
           `RamStore::scrub_key` is at `crates/store-example-plugin/src/ram.rs:164`.
           The inherited default, `crates/busbar-contract/src/records.rs:1102-1106`:
             fn scrub_key(&self, _id: &str) -> RecordStoreResult<()> {
                 Err(RecordStoreError("this Store does not support scrub_key".to_string()))
             }
           `ram.rs:19` states why the verb exists at all: "plus `Store::scrub_key`, whose trait
           default is a loud error and would turn a compliance-relevant request into a FAILURE
           rather than an erasure."
           So a right-to-erasure request is refused EXACTLY in the mode where the key row is on
           disk. No test touches it (`grep -rn "scrub_key" crates/store-example-plugin/src/tests/`
           -> 0 hits, control `add_metering` -> 4), and the conformance oracle that would have
           caught it is one of the seventeen never invoked (X-2629).
ACTION:    `fn scrub_key(&self, id: &str) -> StoreResult<()> { self.inner.scrub_key(id) }` in the
           same delegation block, plus a cell that asserts the durable mode erases rather than errors.

### X-2627 · The template's RAM backend auto-sweeps the billing ledger the contract says must NEVER be auto-swept
CLASS:     money
CERTAINTY: PARK
EVIDENCE:  `crates/store-example-plugin/src/ram.rs:246-249`, on the `add_metering` write path:
             if Self::tick(&self.metering_sweep_ticker) {
                 let n = now();
                 m.retain(|(_, bucket, _, _, _), _| bucket.saturating_add(MAX_RETENTION_SECS) > n);
             }
           `crates/busbar-contract/src/records.rs`, on `purge_metering_before`: "Retention purge for
           the DURABLE billing ledger (`MeteringRow`/`MeteringDelta`) ... Unlike
           `purge_windows_before`, this must NEVER be wired to an automatic sweeper — billing
           evidence is opt-in-purge-only ... The engine's admin surface is the only intended caller,
           and only behind an explicit, audit-logged operator action."
           The carve-out for a self-sweeping in-memory store is attached to `purge_windows_before`
           (the token ledger, legitimately swept at ram.rs:206-210), not to the metering ledger.
           PARK, not VERIFIED-as-defect: for a RAM fixture whose map dies with the process this
           destroys nothing an operator can bill from. But this is the template a durable backend is
           COPIED from, and the copied `retain` deletes unsettled billing rows with no operator
           action and no audit record. That is a billed byte and an owner ruling, not mine.
ACTION:    Owner ruling. Either delete ram.rs:246-249 and bound the map another way, or add an
           explicit RAM-ONLY exemption comment stating that the contract does not grant it and that
           a durable copy must strike these four lines.

### X-2628 · "the error must name the failing path" is satisfied by a constant
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/store-example-plugin/src/tests/mutation_hardening.rs:65-68`:
             assert!(
                 err.contains(&path.display().to_string()) || err.contains("durable_path"),
                 "error must name the failing path: {err}"
             );
           `sed -n '196,212p' crates/store-example-plugin/src/lib.rs` — EVERY error `load_from` can
           produce already begins with the literal `durable_path`:
             "durable_path '{}' is not readable state: {e}"   and   "durable_path '{}': {e}"
           so the second disjunct is constant-true and the first can never be the deciding oracle.
           MUTATION THAT PROVES IT: change lib.rs:208-210 to `StoreError(format!("durable_path: {e}"))`
           — the path is gone from the message and the cell stays green.
           Separately `:4` cites `src/tests.rs`; `ls crates/store-example-plugin/src/tests.rs` ->
           No such file or directory (it is `src/tests/mod.rs`). Every SYMBOL the header names does
           still resolve; only the file path drifted.
ACTION:    Drop `|| err.contains("durable_path")` at line 67; fix the path at line 4.

### X-2629 · Seventeen of twenty-two conformance oracles in the store template are declared and never invoked, and a file-level `allow(dead_code)` is what keeps it silent
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `grep -c "^pub fn " crates/store-example-plugin/src/tests/store_conformance.rs` -> 22
           `grep -o "store_conformance::[a-z_]*" crates/store-example-plugin/src/tests/mod.rs | sort -u`
           -> 5 symbols only: assert_delete_key_unknown_id_is_an_error,
              assert_plane_purge_honours_the_cutoff, assert_plane_purge_task_keeps_active_rows,
              assert_put_key_does_not_resurrect_a_tombstone, live_key.
           Never called include `assert_plane_task_upsert_get_list`,
           `assert_plane_event_chain_is_ordered_by_seq`, `assert_plane_call_parents_enumerated`,
           `assert_plane_demotion_upsert_list_delete`, `assert_plane_token_is_single_use` — all five
           exercise verbs `FileStore` DOES implement (lib.rs:620-660).
           POSITIVE CONTROL, the near-identical twin:
           `grep -c "assert_plane_task_upsert_get_list\|assert_plane_event_chain_is_ordered_by_seq\|assert_plane_call_parents_enumerated\|assert_plane_demotion_upsert_list_delete\|assert_plane_token_is_single_use" crates/store-memory/tests/store_conformance.rs`
           -> 10 (five definitions + five calls), versus 5 in the store-example copy (definitions
           only) and 0 in its `mod.rs`. So they are runnable oracles, not skips.
           What makes it silent: `#![allow(dead_code)]` at LINE 4 of the store-example copy —
           file-level. The store-memory twin uses a per-ITEM `#[allow(dead_code)]` at line 23, so an
           uninvoked oracle there would still warn.
ACTION:    Replace the file-level `#![allow(dead_code)]` with per-item allows on only the
           credential/audit helpers that genuinely cannot run against `RamStore`, and add the five
           plane-verb calls against `&store()` in `src/tests/mod.rs` beside line 372.

### X-2630 · The gRPC message ceiling binds the READ and is `usize::MAX` on the WRITE
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "max_encoding_message_size" -- '*.rs'` -> rc=1, ZERO hits in the repository.
           POSITIVE CONTROL, the sibling spelling: `git grep -n "max_decoding_message_size" -- '*.rs'` ->
             crates/busbar-transport-grpc/src/client.rs:125
             crates/busbar-transport-grpc/src/codec.rs:16   (a doc reference)
             crates/busbar-transport-grpc/src/server.rs:132
           tonic 0.14.6's own defaults (`tonic/src/codec/mod.rs:101-102`):
             DEFAULT_MAX_RECV_MESSAGE_SIZE = 4 * 1024 * 1024
             DEFAULT_MAX_SEND_MESSAGE_SIZE = usize::MAX
           This is X-2602's shape on the other axis: the transport refuses to READ a message over
           the operator's ceiling and will happily WRITE one the same ceiling would refuse.
           `codec.rs:21-23` states the send-side bound as a CALLER OBLIGATION ("the number must stay
           at or above the largest single message the relay path can emit") rather than enforcing
           it, and `transport.rs:286-358 write()` measures nothing — `let n = payload.len();` is
           reported as delivered whatever its size. An operator who caps at 64 KiB gets a node that
           refuses 64 KiB + 1 inbound and emits multi-MiB outbound at a peer whose own default recv
           limit is 4 MiB.
ACTION:    Add `.max_encoding_message_size(state.max_message_bytes)` to both builders —
           `crates/busbar-transport-grpc/src/client.rs:124-125` and `.../server.rs:131-132`.

### X-2631 · `busbar_transport_grpc::mount` is a public module with no consumer, and `UNADDRESSED_STATUS` is mapped by nothing
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "busbar_transport_grpc::" -- '*.rs'` -> 2 hits, BOTH `GrpcTransport`:
             crates/busbar/src/root/registry.rs:95
             crates/busbar/tests/transport_composed_over_consistency.rs:19
           POSITIVE CONTROL: `git grep -n "busbar_transport_ws::" -- '*.rs'` -> 6 hits.
           So `pub mod mount` (`lib.rs:38`) — `split_call`, `call_path`, `resolve`, `declared_calls`,
           `status_of`, `UNADDRESSED_STATUS`, `CallName`, `Addressed`, `Unaddressed` — has no caller
           outside its own `src/tests/mount.rs`. (`busbar_transport_http::mount` is the same: its
           only reference in the tree is the doc link at `grpc/src/mount.rs:15`.)
           The instrument consequence is exact. `crates/busbar-transport-grpc/src/tests/mount.rs:180-186`:
             fn an_unaddressed_call_is_unimplemented_either_way() {
                 assert_eq!(UNADDRESSED_STATUS, 12);
                 for target in ["/not-a-call", "/pkg.v1.Thing/Nope"] { assert!(resolve(&SURFACE, target).is_err()); }
             }
           `git grep -n "UNADDRESSED_STATUS" -- '*.rs'` -> the grpc const (mount.rs:177) and this one
           reader. Nothing maps `Unaddressed` onto it, so "unimplemented either way" is asserted of
           a constant against itself and never of an answer anything produces.
ACTION:    Either wire the mount (a `serve`-shaped entry the composition root calls, consuming
           `resolve` + `status_of` + `UNADDRESSED_STATUS`), or gate the module
           `#[cfg(any(test, feature = "mount"))]` so an unshipped API stops counting as shipped surface.

### X-2632 · The whole `EgressTrust` branch of the http egress client — SPKI pinning, extra anchors, mutual-TLS client identity — is never instantiated
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "build_egress_client_with_trust" -- '*.rs'` -> the definition
           (`crates/busbar-transport-http/src/lib.rs:344`), one doc line (:329), ONE production
           caller (`lib.rs:333`) which passes `&EgressTrust::default()`, and one test
           (`src/tests/mod.rs:2253`) which passes the same default.
           `git grep -n "SpkiPinVerifier" -- '*.rs'` -> `lib.rs:434` (the only construction, inside
           the branch that requires a NON-default trust), plus its own struct/impl at :446,:451,:463.
           `git grep -n "EgressTrust" -- '*.rs'` -> nothing anywhere populates `extra_anchors`,
           `pinned_public_keys` or `client_identity` for this transport; the only non-default
           `EgressTrust` literals in the tree are in `busbar-contract`'s redaction test (:27) and
           this crate's own `build_egress_trust_all_none` helper (`src/tests/mod.rs:2256`).
           POSITIVE CONTROL that the same shape IS wired for the sibling knob:
           `ClientSettings` really does travel root -> transport (`busbar/src/root/policy.rs:188` ->
           `HttpTransport::new`, `lib.rs:277-279`).
           Consequence: `wants_client_cert`'s pin branch, `SpkiPinVerifier` (a `.dangerous()` custom
           `ServerCertVerifier`) and the entire mutual-TLS client-identity path are unreachable in
           every shipped build — a security capability declared, implemented, leaf-tested and never
           constructed.
ACTION:    Give the composition root a way to build `EgressTrust` from the deployment, exactly as
           `root/policy.rs:188` builds `ClientSettings`, and pass it at
           `crates/busbar-transport-http/src/lib.rs:277`. Until then, say in the doc that the branch
           is staged ahead of its caller.

### X-2633 · The egress-trust seam's only "posture" cell asserts nothing at all
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '2247,2254p' crates/busbar-transport-http/src/tests/mod.rs`:
             /// Building with a default trust takes the unset branch and produces a client, the same as the bare
             /// entry point does — neither panics and both stand up the platform-roots posture.
             #[test]
             fn the_unset_seam_builds_the_same_posture_as_the_bare_entry_point() {
                 let settings = ClientSettings::default();
                 let _bare = build_egress_client(&settings);
                 let _seam = build_egress_client_with_trust(&settings, &EgressTrust::default());
             }
           There is no `assert`. The doc's claim ("both stand up the platform-roots posture") is
           checked by nothing, and this is the ONLY cell in the crate that builds a TLS client
           config. A mutant that makes `client_tls_config` (`lib.rs:390`) return a config built with
           `.dangerous().with_custom_certificate_verifier(<accept-anything>)` passes it green.
ACTION:    Assert the branch actually taken — e.g. compare `client_tls_config(&EgressTrust::default())`'s
           root-store length against `webpki_roots::TLS_SERVER_ROOTS.len()`, and assert the pinned
           branch produces a DIFFERENT verifier.

### X-2634 · `http::arrival` hardcodes the transport chain, so an egress arrival over TLS reports a stack it is not standing on
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "transport_chain" -- crates/busbar-transport-http` -> exactly ONE hit:
             crates/busbar-transport-http/src/transport.rs:52:  transport_chain: vec!["tcp", "http"],
           — a constant, and no test in the crate touches it.
           POSITIVE CONTROL, the siblings all carry a real per-connection chain and assert it:
             crates/busbar-transport-tls/src/transport.rs:44,298  (built from `Inner::chain`)
             crates/busbar-transport-tls/src/tests/mod.rs:691     assert_eq!(record.transport_chain, vec!["tcp","tls"])
             crates/busbar-transport-ws/src/tests/battery.rs:495  assert_eq!(record.transport_chain, vec!["tcp","tls","ws"])
             crates/busbar-transport-grpc/src/conn.rs             (`ConnState::chain`, appended)
           `http` is the one that asserts a constant — and it does so for EGRESS connections dialled
           through the pooled `hyper_rustls` client (`lib.rs:277`), which for an `https://` upstream
           really is `tcp -> tls -> http`. `sse::arrival` then pushes `"sse"` onto that same constant
           (`crates/busbar-transport-sse/src/transport.rs:28`), so an SSE stream over TLS reports
           `["tcp","http","sse"]`. The chain is what an auditor reads to know whether bytes crossed
           a wire in the clear.
ACTION:    Carry the chain on `Inner` (`Ingress` = `["tcp","http"]`, `Egress` = per the dialled
           scheme) and read it at `transport.rs:52`, mirroring `tls`. Add the assertion the two
           siblings already have.

### X-2635 · `sse` reads SSE frames and cannot write one
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "write\|encode_envelope" crates/busbar-transport-sse/src/transport.rs` ->
             :269   self.http.write(conn, stream, bytes)
             :279   self.http.encode_envelope(fields, body, arena)
           — pure delegation, and `git grep -n "reframe" -- crates/busbar-transport-sse/src/transport.rs`
           -> no output, so the module that DOES produce SSE bytes (`reframe.rs:78 push_event`) is
           not reachable from `write` at all.
           The read side is a full SSE re-segmenter (`transport.rs:52-261`): blank-line terminator
           carve, comment-frame drop via `proto::frame_carries_a_field`, inherited status leg,
           `MAX_CURSOR_BYTES` budget. The write side emits an HTTP REQUEST line
           (`http/src/transport.rs:404-407 "method path HTTP/1.1"`) and never a
           `200 ... text/event-stream` head nor an `event:`/`data:`/blank-line frame.
           The inbound lifecycle makes it concrete: `sse::listen`/`accept` delegate to `http`
           (`transport.rs:32-42`), and `src/tests/mod.rs:474-545` drives exactly that path — a body
           carved into SSE events by `sse::frames`. So the transport accepts a connection, reads SSE
           off it, and has no way to answer in the framing it just read. Same class as X-2602.
ACTION:    Either frame `sse::write`'s payload through `reframe::push_event` before delegating, or
           declare the crate egress-only and refuse `accept` with `TransportError::HandoffMismatch`
           so the two lifecycles match the one direction it implements.

### X-2636 · `install_sse_reframe` is called by nothing, the file says the composition root installs it, and a second, DISAGREEING copy of the same negotiation ships
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "install_sse_reframe" -- '*.rs'` -> the definition (`reframe.rs:147`), two
           doc mentions (:109, :140) and ONE caller, `src/tests/reframe_tests.rs:90`.
           POSITIVE CONTROL, the seam it claims to mirror:
           `git grep -n "install_hostless_egress" -- '*.rs'` -> `busbar-kernel/src/egress/seam.rs:466`
           plus a real composition-root call at `crates/busbar/src/main.rs:665`.
           The file contradicts itself:
             reframe.rs:107-109  "ADDITIVE AND DORMANT: ... NOTHING on the shipped path consults the seam yet"
             reframe.rs:124-125  "The composition root installs this today, so a mount that opts onto the seam ..."
           Worse, the shipped implementation of the same negotiation lives elsewhere and ANSWERS
           DIFFERENTLY: `crates/busbar-mcp/src/mcp/sse.rs:161 prefers_event_stream` compares the SSE
           q-value only against `application/json` and breaks ties by source position, while
           `crates/busbar-transport-sse/src/reframe.rs:37` compares against any concrete media range
           and breaks ties in SSE's favour (`q >= body_q`, :64). For
           `Accept: application/json, text/event-stream` the mcp copy answers false and this one true.
ACTION:    Delete the false sentence at reframe.rs:124-125. Then either install the seam beside
           `main.rs:665` and retire `mcp/sse.rs:161`, or gate the module
           `#[cfg(any(test, feature = "reframe"))]`. Two answers to one content negotiation is the
           defect underneath the doc.

### X-2637 · The #65 test-seal migration stopped at five of six transports; `sse` has no `test-seal` dev-dep and `tls` is half-converted
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -ln "TestKernelSeal" -- 'crates/busbar-transport-*'` -> grpc, http, stdio, tcp,
           tls, ws (manifest + battery each). `sse` ABSENT.
           `git grep -n "test-seal" -- 'crates/busbar-transport-*/Cargo.toml'` -> grpc:47, http:46,
           stdio:27, tcp:24, tls:38, ws:29. `sse` ABSENT — so sse's manifest cannot even name the
           blessed seal.
           `git grep -n "acquire_for_kernel" -- 'crates/busbar-transport-*'` ->
             crates/busbar-transport-sse/src/tests/mod.rs:22-23
             crates/busbar-transport-tls/src/tests/mod.rs:796, 801, 854, 1328, 1335
           `crates/busbar-transport-grpc/Cargo.toml:44-46` records the intended end state:
           "`busbar_contract::plugin::TestKernelSeal` is the one blessed fixture implementor of the
           SEALED `KernelSeal` trait; this crate's test harnesses used to forge their own."
           HONEST SCOPE: this does NOT red `cargo xtask gate seal-witness`, which excludes `/tests/`
           (`xtask/src/gates/seal_witness.rs:58 EXCLUDE`). It is a migration finished on five crates
           and left half-done on two — the shape that later reads as "this is the ordinary way to
           obtain a seal".
ACTION:    Add `busbar-contract = { path = "../busbar-contract", features = ["test-seal"] }` to
           `crates/busbar-transport-sse/Cargo.toml` `[dev-dependencies]` and replace `fixture_seal()`
           (`src/tests/mod.rs:21-25`) with `TestKernelSeal`; convert the five remaining
           `acquire_for_kernel` sites in `crates/busbar-transport-tls/src/tests/mod.rs`.

### X-2638 · `tls::write` is not raced against close, and both the fix and its test exist one crate over
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "raced_write" -- '*.rs'` -> three hits, ALL in tcp:
             crates/busbar-transport-tcp/src/lib.rs:287        (the helper)
             crates/busbar-transport-tcp/src/transport.rs:209  (in `write`)
             crates/busbar-transport-tcp/src/transport.rs:286  (in `unit0_refusal`)
           Zero in `busbar-transport-tls`. `grep -n "closing" crates/busbar-transport-tls/src/transport.rs`
           -> :189, :190, :200 — all three inside `frames()`. `tls::write` (transport.rs:236-261) and
           `tls::unit0_refusal` (:370-406) take `inner.write.lock()` and `write_all` unguarded.
           `crates/busbar-transport-tcp/src/lib.rs:273-284` states the reasoning the tls crate did
           not take: "a `write_all` into a full send buffer blocks until the peer drains it, and a
           peer that never reads never does ... `close` could not interrupt such a write." A tls
           write into a full send buffer pins the writer lock, the rustls session and the socket for
           the life of the process, and `close` (transport.rs:359-368) cannot reach it — it spawns
           `send_close_notify`, which self-bounds at `CLOSE_NOTIFY_BUDGET` and gives up
           (`lib.rs:474-492`), leaving the original writer parked.
           The instrument is missing on the same line:
           `grep -n "a_write_blocked" crates/busbar-transport-tcp/src/tests/mod.rs` -> :791
             a_write_blocked_on_a_nonreading_peer_is_interrupted_by_close
           `grep -n "a_write_blocked" crates/busbar-transport-tls/src/tests/mod.rs` -> no match.
           The nearest tls cell (`a_close_notify_self_bounds_on_a_held_writer_lock`, :481-512) holds
           the writer lock itself and never releases it before the assertion, so it DEMONSTRATES the
           leak rather than refuting it.
ACTION:    Lift `raced_write` into `crates/busbar-transport-tls/src/lib.rs` — `Inner` there already
           carries the `closed`/`closing` pair (lib.rs:108-119) — wrap the two write bodies at
           `transport.rs:245-258` and `:380-386`, and port
           `a_write_blocked_on_a_nonreading_peer_is_interrupted_by_close` into the tls battery.

### X-2639 · `limits.tls_handshake_timeout_secs` and the tcp dial budget never reach the transports that implement them
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "with_handshake_timeout\|with_dial_timeout" -- '*.rs'`:
             crates/busbar-transport-tcp/src/lib.rs:177           (definition)
             crates/busbar-transport-tcp/src/tests/mod.rs:358     (the only caller — a test)
             crates/busbar-transport-tls/src/lib.rs:221           (definition)
             crates/busbar-transport-tls/src/tests/mod.rs:189, 1836, 1879  (the only callers — tests)
           `grep -n "TlsTransport::new\|TcpTransport::new" crates/busbar/src/root/registry.rs`
           -> :274 `TcpTransport::new()`, :275 `TlsTransport::new()` — the bare constructors, so both
           run on the compiled-in defaults.
           The operator knob exists, is validated and is admin-surfaced:
             crates/busbar-kernel/src/config/limits.rs:121  DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS = 10
             crates/busbar-kernel/src/config/limits.rs:281  pub tls_handshake_timeout_secs: u64
             crates/busbar-kernel/src/config_validate/mod.rs:1258  refuses < 1
             crates/busbar-core-admin/src/v1/json/handlers.rs:2769  surfaced
           The two numbers coincide today (both 10), which is exactly why the break is invisible:
           the day an operator moves the knob, `busbar-kernel/src/tls.rs` honours it and
           `busbar-transport-tls` does not.
ACTION:    Thread the resolved limit through `compose_transports` the way `ClientSettings` already
           is: `TlsTransport::new().with_handshake_timeout(Duration::from_secs(limits.tls_handshake_timeout_secs))`
           at `crates/busbar/src/root/registry.rs:275`, and the tcp dial budget at :274.

### X-2640 · The "a transport is a wire, never a plane" gate exists for two of the seven transports, and two of the five without it would fail it today
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `git ls-files | grep no_plane_names` ->
             crates/busbar-transport-grpc/tests/no_plane_names.rs
             crates/busbar-transport-http/tests/no_plane_names.rs
           and `diff` of the two produces no output — byte identical. `sse`, `tcp`, `tls`, `ws` and
           `stdio` have none.
           The gate scans every `.rs` under `src/` with a bare `text.contains(core)` and no comment
           stripping, and `CORE_NAMES` includes `busbar_kernel` and `busbar_contract::caps`:
           `grep -rn "busbar_contract::caps\|busbar_kernel" crates/busbar-transport-sse/src/ crates/busbar-transport-tls/src/` ->
             crates/busbar-transport-sse/src/lib.rs:11    "ported from `busbar_kernel::proto`"
             crates/busbar-transport-sse/src/proto.rs:4   "ported from `busbar_kernel::proto`"
             crates/busbar-transport-sse/src/tests/mod.rs:21   busbar_contract::caps::Grant<...>
             crates/busbar-transport-tls/src/tests/mod.rs:796,801,854,1328,1335  busbar_contract::caps::...
           POSITIVE CONTROL that the grpc crate really is clean: the same grep against
           `crates/busbar-transport-grpc/src/` -> rc=1, no output.
ACTION:    Copy `tests/no_plane_names.rs` into the five crates that lack it and fix what it finds
           (X-2637 is the sse/tls half of that fix). Close X-2613 and X-2614 in the copy, not after it.

### X-2641 · The plane fixture's "counters that prove the crossings happened" are write-only, and `dispatch` never checks that `start` ran
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `grep -n "\.load(" crates/plane-example/src/lib.rs` -> rc=1, NO OUTPUT.
           POSITIVE CONTROL, same file: `grep -c "\.store(\|\.fetch_add("` -> 3.
           `git grep -n "metered_units\|started_at_nanos" -- '*.rs' | grep -v "^crates/plane-example/"`
           -> no output either.
           The module doc at :100-104 calls `dispatched` / `started_at_nanos` / `metered_units` "the
           counters that prove the crossings happened ... what makes 'did the vtable actually get
           crossed?' a question this fixture's return status can answer." Every mention in the file
           is a declaration (:116,:118,:121), an initializer (:217-219) or a write (:268,:373-374).
           `admin_routes`/`openapi` are `None` (:403-404) and `dispatch` returns only a `RawStatus`,
           so nothing can observe them — delete :373-374 outright and every test stays green.
           The consequence that bites: `dispatch` (:282) never reads `started_at_nanos`, so a plane
           DISPATCHED WITHOUT `start` returns `Ok`. The lifecycle obligation the doc leans on is
           unenforced, in the fixture whose whole job is to be the reference for plane authors.
           (The file's own claim at :56 — "There is no `f32`/`f64` anywhere in this file" — is true.)
ACTION:    At `crates/plane-example/src/lib.rs:290`, right after `let st = ...`:
             if st.started_at_nanos.load(Ordering::Relaxed) == 0 { return StatusClass::Refused; }
           which makes the `start` crossing load-bearing and observable through the status the
           fixture's tests already read.

### X-2642 · The flagship smart-router example implements a hook transport busbar retired, and its own README has already moved on without it
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -rn "UnixStream" -- '*.rs'` -> `examples/smart-router/rust-hook/src/main.rs`
           ONLY. ZERO hits under `crates/`.
           The example's doc block (main.rs:1-12) instructs:
             //! Run it:            cargo run --release -- /run/busbar/router.sock
             //! Point busbar at it:  hooks: [ { module: socket, settings: { path: ... }, kind: gate } ]
           busbar no longer speaks it. `crates/busbar-kernel/src/config/hooks.rs:383-387`:
             "The `kind: hook` PLUGIN backing this hook, by signed-manifest name or alias ... This
              REPLACES the retired `socket`/`webhook` out-of-process transports: a hook now runs
              in-process behind the frozen plugin ABI."
           `git grep -n "\"socket\"" -- '*.rs'` -> a doc example (`api/src/hooks.rs:347`) and the
           v0->v1 MIGRATOR only (`busbar-kernel/src/config/migrate.rs:1459,1460,1530`). The only
           hook constructor is `env.registry.open_hook(&hook.plugin, ...)`
           (`busbar-kernel/src/hooks/mod.rs:795-798`) — there is no module-name match arm.
           The README WAS migrated (`examples/smart-router/README.md:15-25` says the transports were
           retired in 1.5.0 and now shows `module: smart-router-hook  # your signed kind:hook
           plugin`) — but it now names a plugin this crate CANNOT be:
           `examples/smart-router/rust-hook/Cargo.toml` has no `[lib]`, no `crate-type = ["cdylib"]`
           and no `busbar-plugin-sdk`, and its entry point is `fn main()`. README lines 9, 11 and 49
           still describe running it as a socket daemon. A customer following either half gets the
           fail-closed boot refusal `hooks.rs:386` promises.
ACTION:    Port `rust-hook` to `crate-type = ["cdylib","rlib"]` + `busbar_plugin_sdk::export_hook_plugin!(open)`
           — the shape `crates/hook-test-plugin/src/lib.rs:252-298` already demonstrates — and delete
           README lines 9-13 and 47-51. Minimum if the port is deferred: replace main.rs:7-9 with a
           note that the socket transport was retired in 1.5.0.

### X-2643 · Two further drifts in the same example: a removed config field and an ignored wire field
CLASS:     customer-surface
CERTAINTY: ADJUDICATE
EVIDENCE:  (a) `examples/smart-router/rust-hook/src/main.rs:161`:
               cost_per_mtok: Option<f64>, // YOUR declared cost on the pool member
             `crates/busbar-kernel/src/config/pools.rs:251`: "the 1.4.x `cost_per_mtok:` member field
             is REMOVED: `rate_card` is the ONLY cost source", and `config/migrate.rs:1829` retires
             it. The README already says so (line 34); this comment did not follow. The FIELD is
             still on the hook wire (`busbar-kernel/src/hooks/wire.rs:577`, populated at :725), so
             this is comment-only. (`:159`'s `tier` example `"large"` also contradicts the
             fable/opus/sonnet/haiku ladder the same file's `weights()` uses at :123-133.)
           (b) `main.rs:172-175` deserialises `Payload { request, candidates }` and ignores the
             top-level `op` field busbar now sends (`busbar-kernel/src/hooks/wire.rs:435-447`:
             `OP_DECIDE`/`OP_TRANSFORM`/`OP_NOTIFY`, "a fire-and-forget tap — never answer it"). On a
             line-oriented socket, replying to a `notify` desynchronises the one-line-in/one-line-out
             framing for every subsequent decide. `policy_server.go` has the same gap (no `Op` field,
             :28-50) but over HTTP the stray reply is harmlessly discarded.
           ADJUDICATE: both are moot while X-2642 stands, and (b) becomes live the moment the
           example is ported. I did not run the wire to confirm the desync.
ACTION:    Fold into the X-2642 port: read `op`, answer only `decide`/`transform`, and fix the two
           comments at :159 and :161.

### X-2644 · The record leg of the store contract: three `pub fn`s with no shipping caller, over a trait with no implementor
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "\.record_put(\|\.record_get(\|\.record_scan(" -- '*.rs' | sed 's/:.*//' | sort | uniq -c`
             14 crates/store-memory/src/tests/lib_tests.rs
             31 crates/store-memory/tests/record_conformance.rs
           — no shipping caller anywhere.
           POSITIVE CONTROL: `git grep -n "\.put_key(" -- '*.rs' | sed 's/:.*//' | sort -u | wc -l` -> 35.
           `git grep -nE "impl( <[^>]*>)? (busbar_contract::)?kinds::Store for" -- '*.rs'` -> no output:
           `crates/busbar-contract/src/kinds.rs:300` declares `pub trait Store` with
           `record_put`/`record_get`/`record_scan` plus eighteen more verbs, and NOTHING in the
           workspace implements it. `MemoryStore`'s three (`src/lib.rs:156,194,216`) are INHERENT
           `pub fn`s that copy the trait's spelling without being it.
           `crates/store-memory/tests/record_conformance.rs`'s header admits the first half ("nothing
           in the workspace implemented them — the contract declared three signatures and every
           caller went round them") and does not state the second: the implementation added in reply
           is still reachable only from its own tests. Two doc references
           (`busbar/src/root/durability.rs:53`, `plugin-loader/src/store_adapter.rs:18-19`) name the
           verbs; neither calls them. A green conformance suite over an unreached leg reads as
           coverage of a live path.
ACTION:    Either `impl busbar_contract::kinds::Store for MemoryStore` and route `store_adapter`
           through it, or mark the three inherent fns `#[doc(hidden)]` and state in
           `record_conformance.rs`'s header that the leg is on no caller's path yet.

### X-2645 · A test comment that states the opposite of the code it describes, and skips the check it prescribes
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/store-memory/src/tests/lib_tests.rs:585-587`:
             // Revoke it far in the past (pin the clock at revoke time so `revoked_at` lands well past
             // the retention ceiling) — `revoke_credential` stamps `revoked_at` from the real wall clock,
             // not the pinned one, so pin first, revoke, then verify the stamped value directly.
           `sed -n '680,695p' crates/store-memory/src/lib.rs` says the opposite in as many words:
             // `self.now()` (pinned-clock-aware), not the bare free function — the `creds` sweep
             // added for the retention fix ages rows off `revoked_at` against `self.now()` ...
             c.meta.revoked_at = Some(self.now());
           The comment is internally contradictory (its own first clause relies on the pinned clock)
           and the "verify the stamped value directly" it prescribes is never done — unlike the
           tombstone twin at :538-541, which does `assert_eq!(...deleted_at, Some(old_deleted_at))`.
           The cell still catches a regression through the `AKIA_OLD` sweep assertion at :614-619, so
           this is a stale comment plus a missing failure-localising anchor, not a hole.
ACTION:    Replace :586-587 with "`revoke_credential` stamps `revoked_at` from `self.now()`, so the
           pin governs it", and add after :589:
             assert_eq!(s.list_credentials("k-old").unwrap()[0].revoked_at, Some(old_revoked_at));

### X-2646 · `busbar-unit-transport-key`'s manifest header names `busbar-caps`, a crate deleted in the #37/#38 fold
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-unit-transport-key/Cargo.toml:7`: "so it depends on `busbar-caps` for the
           handle and on `rustls` for the one thing this crate actually builds". The `[dependencies]`
           row at :23 is `busbar-contract`.
           `ls -d crates/busbar-caps` -> No such file or directory.
           POSITIVE CONTROL: `ls -d crates/busbar-contract` -> exists.
           `git grep -n "busbar-caps" -- crates/busbar-contract/src/caps/mod.rs` -> ":64 Folded from
           the former `busbar-caps` crate (#37/#38)".
           TREE-WIDE, NOT LOCAL: `git grep -n "busbar-caps" -- '*.rs' '*.toml'` returns 20+ hits
           across `busbar-kernel-breaker`, `busbar-kernel-egress`, `busbar-kernel-audit`,
           `busbar-kernel-identity` and `busbar-core-admin`, and
           `crates/busbar-kernel-egress/tests/prose.rs:70` uses the string as TEST DATA — so a blind
           sed would change a fixture. Flagging the scope; I did not adjudicate prose.rs:70.
ACTION:    `busbar-caps` -> `busbar-contract` at `crates/busbar-unit-transport-key/Cargo.toml:7`, and
           a separate reviewed sweep for the other 20+ sites that checks `prose.rs:70` by hand first.

### X-2647 · The per-name (SNI) certificate capability is implemented, tested, and instantiated by no shipping caller
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "provision_server_named" -- '*.rs' | grep -v "^crates/busbar-unit-transport-key/"`
             crates/busbar-transport-tls/src/tests/mod.rs:1169  (doc)
             crates/busbar-transport-tls/src/tests/mod.rs:1331  (the only call — a test)
           `git grep -n "NamedTlsLocations" -- '*.rs' | grep -v "^crates/busbar-unit-transport-key/"`
             crates/busbar-transport-tls/src/tests/mod.rs:1177, 1341, 1346
           POSITIVE CONTROL, the sibling that IS wired:
           `git grep -n "provision_server\b" -- '*.rs' | grep -v "^crates/busbar-unit-transport-key/" | grep -v "/tests/"`
             crates/busbar/src/root/transports.rs:60   (imported)
             crates/busbar/src/root/transports.rs:178  (called)
           `crates/busbar-unit-transport-key/src/lib.rs:458` (`provision_server_named`) and `:345`
           (`NamedTlsLocations`) implement per-name certificate resolution behind a
           `ResolvesServerCert`. `crates/busbar/src/root/transports.rs:60` imports
           `provision_client, provision_server, AccessJournal, SecretSource, Slot, TlsConfigSink,
           TlsLocations` — not the named pair. No listener in any shipped build can serve more than
           one certificate.
ACTION:    Wire `provision_server_named` into `crates/busbar/src/root/transports.rs` behind the
           multi-name listener config, or mark the pair `#[doc(hidden)]` and state in its doc that it
           is staged ahead of its caller.

### X-2648 · Three `[lib]` manifest comments justify `rlib` with a premise the tree contradicts
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  All three say "rlib is REQUIRED for `cargo test` to actually emit the cdylib artifact at
           all WHEN THIS CRATE HAS NO IN-CRATE `#[test]`s OF ITS OWN":
             crates/export-example-plugin/Cargo.toml:12-15
             crates/secret-example-plugin/Cargo.toml:12-17
             crates/store-example-plugin/Cargo.toml:12-14
           `for c in export-example-plugin secret-example-plugin store-example-plugin; do grep -rh "#\[test\]" crates/$c/src | wc -l; done`
             7
             8
             34
           and each declares its test module (`export .../src/lib.rs:97`, `secret .../src/lib.rs:72`,
           `store .../src/lib.rs:721`).
           The DECISION is right — `plugin-loader`'s dev-deps really do link two of these rlibs, and
           `plane-example` needs its rlib to link `PLANE_DECL` as the compiled-in reference — so only
           the REASON is stale. That is the dangerous shape: the next reader who checks the premise,
           finds it false, and drops the `rlib` silently breaks the dlopen fixtures.
           (DISTINCT from X-2615: `auth-static-plugin`'s comment gives a DIFFERENT reason and then
           withdraws it, and nothing links its rlib at all.)
ACTION:    In all three, replace the trailing clause with "...because a scoped `cargo test -p <dependent>`
           otherwise builds no cdylib for this package".

### X-2649 · The breaker's probe journal has no shipped implementor, all four `ProbeEvent` variants are minted into a discard, and unlike its three sibling gaps it has no `unconstructed.toml` row
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "impl.*JournalSink" -- crates/` ->
             crates/busbar-kernel-breaker/src/journal.rs:72   impl JournalSink for NoopJournal   (empty body)
             crates/busbar-kernel-breaker/src/tests/mod.rs:700  (test-only Arc<RecordingJournal>)
           `git grep -n "with_journal" -- crates/` -> callers only at `src/tests/mod.rs:777,852`.
           `grep -n "RootBreakerUnit" crates/busbar/src/root/adapters.rs` ->
             :119 pub type RootBreakerUnit = BreakerUnit<NoopJournal, DiagnosticsSink>;
           So `ProbeEvent::{Won, Succeeded, Failed, Released}` — constructed at lib.rs:471, 496, 549,
           570 — go straight into `NoopJournal::record`'s empty body on every shipped node.
           The module header (journal.rs:1-6) says "the architecture's ledger requires one" and names
           `busbar-unit-wal` as the intended implementor: `ls crates | grep "^busbar-unit"` ->
           `busbar-unit-transport-key` only (X-2651).
           THE ASYMMETRY THAT MAKES THIS A FINDING RATHER THAN A KNOWN GAP:
           `grep -n "^id  *=" qa/unconstructed.toml` carries `breaker-request-budget` (:149),
           `breaker-error-map` (:160), `breaker-with-limits` (:171) and `breaker-pool-observation`
           (:293) — four rows for this one crate — and NO row for the journal. It appears only as a
           bare line in `docs/design/1.6.0-unconstructed-sweep.md:317`. The ratchet that tracks this
           crate's unconstructed capabilities does not track this one.
ACTION:    Add a `[[capability]] id = "breaker-probe-journal"` row to `qa/unconstructed.toml`
           (`symbol = "with_journal"`, `construct = ["::with_journal(", "impl JournalSink"]`), or bind
           `busbar-kernel-wal`/`busbar-kernel-audit` as the sink at
           `crates/busbar/src/root/adapters.rs:119`.

### X-2650 · `port.rs` asserts it takes no `busbar-contract` dependency on the line above the one that takes it, and cites a crate that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '19,25p;80,86p' crates/busbar-kernel-breaker/src/port.rs`:
             :20  //! This module takes no dependency beyond [`crate::classify`] and [`crate::Outcome`] — in
             :21  //! particular, no `busbar-contract` (this crate's `Cargo.toml` is explicit that `busbar-caps` is the
             :22  //! only workspace crate it may name).
             ...
             :83      use busbar_contract::upstream::Disposition;
             :84+     pub const TRANSIENT_UPSTREAM: &str = Disposition::TransientUpstream.label();
           `pub mod label` reads all four metric literals straight off
           `crates/busbar-contract/src/upstream.rs:48`'s `Disposition::label()`.
           `ls -d crates/busbar-caps` -> No such file or directory. POSITIVE CONTROL:
           `ls -d crates/busbar-contract` -> exists.
           The same `busbar-caps` claim is restated in `Cargo.toml:10,13`, where the real row at :31
           is `busbar-contract`.
ACTION:    Rewrite port.rs:20-22 to say the module names `busbar_contract::upstream::Disposition`
           for the label bank — which is the good reason it does — and replace `busbar-caps` with
           `busbar-contract` there and at `Cargo.toml:10,13`.

### X-2651 · Four `busbar-unit-*` crate names in the breaker crate name nothing
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -nE "busbar-unit-(breaker|wal|egress|audit)" -- crates/busbar-kernel-breaker/`
             crates/busbar-kernel-breaker/Cargo.toml:1   "# busbar-unit-breaker — the breaker unit: ..."
             crates/busbar-kernel-breaker/src/journal.rs:5  "owns the real journal (`busbar-unit-wal` / the audit unit)"
             crates/busbar-kernel-breaker/src/lib.rs:6   "# busbar-unit-breaker — the breaker unit"
             crates/busbar-kernel-breaker/src/port.rs:56  "per `// contract:` in `busbar-unit-egress`'s `ports.rs`"
           `ls crates | grep "^busbar-unit"` -> `busbar-unit-transport-key` — the only one.
           The live names are `busbar-kernel-breaker`, `busbar-kernel-wal`, `busbar-kernel-egress`.
           (The ARCHITECTURE.md citation at Cargo.toml:3 / lib.rs:8 DOES resolve —
           `grep -n "Breaker::observe" docs/design/ARCHITECTURE.md` -> :580 — so only the crate names
           rotted.) journal.rs:5 is the one that matters: it names the crate that was supposed to
           implement the sink in X-2649.
ACTION:    Replace `busbar-unit-X` with `busbar-kernel-X` in those four lines.

### X-2652 · `cfg.rs` keeps the window field name the config grammar deleted
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '20,24p' crates/busbar-kernel-breaker/src/cfg.rs` -> `pub window_s: u64,`
           `grep -n "window_secs\|window_s\b" crates/busbar-kernel/src/config/pools.rs`:
             :359  /// Sliding-window length in seconds (one canonical name; the pre-1.0 `window_s` alias is
             :360  /// GONE - an unknown key fails boot).
             :362  pub window_secs: u64,
           Not a wire bug today — `cfg.rs` carries no serde and there is no lowering at all (the
           separately-tracked `breaker-pool-observation` gap) — but it is the rename applied on ONE
           side, and this is precisely the field a future lowering has to bridge. Values agree
           (30 / 0.5 / 5 / 3 against `DEFAULT_BREAKER_*` at pools.rs:378-384), so nothing surfaces
           the mismatch until someone writes the bridge and picks the wrong name.
ACTION:    Rename `window_s` -> `window_secs` at `cfg.rs:22,35` and the three reads at `cell.rs:304`
           and `src/tests/mod.rs:1206,1220`.

### X-2653 · Two 1.5.5 provenance paths in the breaker crate no longer resolve
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Extracted every `crates/...` path literal from the breaker files and tested each with
           `[ -e "$p" ]`:
             MISSING crates/busbar-substrate/src/store.rs              (cited at cfg.rs:4)
             MISSING crates/busbar-substrate/src/tests/breaker_tests.rs (cited at src/tests/mod.rs:5)
           `grep -n "busbar-substrate/src" crates/busbar-kernel-breaker/src/cfg.rs crates/busbar-kernel-breaker/src/tests/mod.rs`
           confirms both citation sites. Both are explicitly labelled 1.5.5 provenance, so this is a
           reader-cost drift rather than a correctness one; the live descendant is
           `crates/busbar-kernel/src/store/in_memory/breaker.rs`.
ACTION:    Repoint both to `crates/busbar-kernel/src/store/in_memory/breaker.rs`, or say "1.5.5, path
           since deleted" so the reader stops looking.

### X-2654 · `busbar-timing`'s PUBLISHED `package.description` names a crate that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '23p' crates/busbar-timing/Cargo.toml`:
             description = "Debug-only, feature-gated per-method micro-timing (...). Default OFF and
                            zero-cost; method timers nest inside busbar-core's stage profiler."
           `ls -d crates/busbar-core` -> No such file or directory.
           POSITIVE CONTROL: `ls -d crates/busbar-core-admin` -> exists (so the name is a near-miss,
           not a typo for something absent entirely).
           `git ls-files | grep -E "profile\.rs$"` -> `crates/busbar-kernel/src/profile.rs` — the
           module it means.
           This one is NOT a comment. `package.description` lands in `cargo metadata`, in generated
           documentation and in any SBOM built from the manifest, so the stale name is emitted rather
           than merely read. The same stale row is at `crates/busbar-timing/Cargo.toml:3` and
           `docs/ci/feature-sets.md:43`.
ACTION:    Replace `busbar-core` with `busbar-kernel` at `crates/busbar-timing/Cargo.toml:3,23` and
           `docs/ci/feature-sets.md:43`.

### X-2655 · `busbar-timing`'s documented per-request bracket has no caller anywhere in the tree
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  For each exported symbol,
           `git grep -cF "busbar_timing::<sym>" -- crates/ | grep -v busbar-timing/`:
             dump (none)  dump_scoped (none)  reset (none)  record (none)
             enabled (none)  set_enabled (none)  timer (none)  Timer (none)
           POSITIVE CONTROL, same command shape:
           `git grep -cF "busbar_timing::timeit" -- crates/ | grep -v busbar-timing/` -> 12 files.
           So the macro IS used twelve times and NONE of the crate's other public surface is used at
           all. `lib.rs:42-44` documents a `reset()` ... `dump_scoped()` per-request bracket as one of
           the crate's TWO operating modes; nothing in the tree brackets anything. `set_enabled` is
           reached only by `tests/smoke.rs:20`. In a real binary the only path to output is
           `libc::atexit` (lib.rs:395) driven by `BUSBAR_TIMING` — the per-request mode is a
           declaration with no construction.
ACTION:    Either add the bracket at the one request boundary it was written for, or delete the
           "Per-request" paragraph at lib.rs:42-44 and the `dump_scoped`/`reset` exports at lib.rs:118.

### X-2656 · `BUSBAR_REF_VALUES` has no reader but its own test, and that test cannot fail
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "BUSBAR_REF_VALUES" -- .` -> three hits, and only one is code that runs:
             crates/plugin-sdk/src/pack.rs:67            const BUSBAR_REF_VALUES: &[&str] = &["pool","group","model","provider"];
             crates/plugin-sdk/src/tests/pack_tests.rs:819   for value in BUSBAR_REF_VALUES {
             docs/design/inventory/1.5.5-plugins-stores.md:2363  (prose)
           POSITIVE CONTROL, a const in the same file that IS read:
           `git grep -n "SECRET_NAME_HINTS" -- crates/plugin-sdk/` ->
             pack.rs:45 (definition), pack.rs:317 (doc), pack.rs:375 (`.iter().any(|hint| lower.contains(hint))`).
           `validate_secret_fields` never inspects `x-busbar-ref`, and `pack.rs` rejects no unknown
           `x-*` extension at all. So the cell's stated claim — "it is not rejected as an
           unrecognized `x-*` extension" — is vacuous: any string whatsoever passes, and
           `jsonschema::validator_for` accepts unknown keywords by spec. Mutate the constant to
           `&["garbage"]` and the test stays green. The constant is kept out of `dead_code` solely by
           the loop that cannot fail.
ACTION:    Add a negative arm asserting `validate_secret_fields` REJECTS
           `"x-busbar-ref": "not_a_vocabulary_entry"`, and the corresponding
           `BUSBAR_REF_VALUES.contains(...)` check in `validate_secret_fields` — or delete the
           constant and the cell together.

### X-2657 · `pack_tests.rs` compiles only under a non-default feature whose one CI leg is skipped on this branch
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `sed -n '/^\[features\]/,/^\[/p' crates/plugin-sdk/Cargo.toml`:
             pack = ["dep:busbar-plugin-loader", "dep:busbar-secret-ref", "dep:jsonschema", "dep:getrandom", "dep:hex"]
           — there is NO `default` key, so `pack` is off unless asked for. `src/pack.rs` (and with it
           `src/tests/pack_tests.rs`, declared at pack.rs:622) compiles only under it.
           The only leg that enables it, `.github/workflows/ci.yml:2001-2003`:
             - name: sdk pack
               features: busbar-plugin-sdk/pack
               tests: -p busbar-plugin-sdk
           sits in the `feature-sets` job whose gate is `.github/workflows/ci.yml:1951`:
             if: github.event_name != 'push' || contains(fromJSON('["refs/heads/main","refs/heads/dev","refs/heads/qa"]'), github.ref)
           So on a push to `consolidated/1.6.0` these 22 cells are never compiled. They DO run on
           every pull request and on dev/qa/main, so this is a tier property rather than a dark file
           — but the 22 cells that guard the plugin PACK path (signing, schema, secret-field refusal)
           give no signal on the branch the work happens on.
           Recorded also because the same row was struck by accident once before, and the ci.yml
           comment above it says so: "STRUCK BY MISTAKE ONCE (afe12ec00) ... the only thing that
           changed was that nothing compiled `src/pack.rs` any more."
ACTION:    Owner call: either move the `sdk pack` leg into the always-on `check` job, or record in
           the file's own header that it is a promotion-tier instrument so a reader on a feature
           branch does not read its silence as green.

### X-2658 · `hooks-ranking`'s module header names a module that does not exist and contradicts its own test
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/hooks-ranking/src/lib.rs:20`: "`forward::decide_policy_order` invokes the resolved
           policy per request."
           `git ls-files | grep -E "forward\.rs|/forward/"` -> rc=1, no output.
           POSITIVE CONTROL, the function really does exist under another name:
           `git grep -n "fn decide_policy_order" -- crates/` ->
             crates/busbar-llm/src/engine/hooks.rs:507
           and every other citation in the tree spells it `proxy::decide_policy_order`
           (`git grep -c "proxy::decide_policy_order" -- crates/` -> 3 files).
           Second half, in the same file: :196-197 says `least_busy` "Always has data
           (available_concurrency is always known), so never Abstains", while `rank_descending_by`'s
           guard at :140 is `keyed.iter().all(|(_, k)| k.is_none())`, which is TRUE on an empty
           vector — and the crate's own `tests/lib_tests.rs:199-213` asserts exactly that
           `least_busy` DOES abstain on an empty pool. The doc and the test disagree, and the test is
           right.
           (`resolve_policy` at :19 is fine: `crates/busbar-kernel/src/hooks/mod.rs:281`. And
           `hooks-ranking` is a default feature of both `busbar-kernel` (:173) and `busbar` (:192),
           so `native_policy` is genuinely shipped-live.)
ACTION:    `forward::decide_policy_order` -> `busbar_llm::engine::hooks::decide_policy_order` at :20,
           and qualify :197 as "never Abstains on a non-empty pool".

### X-2659 · The grpc manifest's stated reason for depending on `busbar-transport-http` is false, and the real reason is a different one
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-grpc/Cargo.toml:17-23` keeps the row in `[dependencies]` with:
             "`src/mount.rs` is written against `busbar_transport_http::mount` and says so, so this
              edge is real and shipped ... `busbar-transport-tcp` is NOT here: its only mention in the
              crate is `src/tests/battery.rs`, and it has moved to `[dev-dependencies]` accordingly."
           `git grep -n "busbar_transport_http" -- crates/busbar-transport-grpc` -> 3 hits:
             Cargo.toml:18              (the comment itself)
             src/mount.rs:15            (an intra-doc link in a `//!` header — no `use`, no call)
             src/tests/battery.rs:21    (a test)
           `src/mount.rs`'s only imports are `busbar_contract::transport::{driver::Outcome, surface::*}`.
           By the manifest's OWN stated rule — the rule it applied to demote `busbar-transport-tcp` —
           this row qualifies for `[dev-dependencies]` too.
           CAVEAT THAT MAKES THE FIX NON-OBVIOUS, and it is why this is a drift row rather than a
           deletion row: the `[`busbar_transport_http::mount`]` link on mount.rs:15 IS load-bearing
           under the `doc-links` CI job (`-D broken_intra_doc_links`), and dev-dependencies are not
           on rustdoc's path for the lib target. So the edge is real for exactly one reason and it is
           not the reason given.
ACTION:    Rewrite Cargo.toml:17-23 to say the edge exists for the intra-doc link at `src/mount.rs:15`,
           or demote that link to plain backticks and move the row to `[dev-dependencies]`.

### X-2660 · `MESSAGE_MAX_BYTES_KEY` is spelled in three places and the root binds two of them
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `git grep -n "MESSAGE_MAX_BYTES_KEY" -- '*.rs'`:
             crates/busbar-transport-grpc/src/transport.rs:47  pub const MESSAGE_MAX_BYTES_KEY: &str = "limits.request_body_max_bytes";
             crates/busbar-transport-grpc/src/lib.rs:42        pub use transport::{GrpcTransport, MESSAGE_MAX_BYTES_KEY};
             crates/busbar-transport-ws/src/transport.rs:107   pub const MESSAGE_MAX_BYTES_KEY: &str = "limits.request_body_max_bytes";
             crates/busbar/src/root/transports.rs:52           use busbar_transport_ws::MESSAGE_MAX_BYTES_KEY;
           `crates/busbar/src/root/transports.rs:284-287` states the reason the constant is imported
           rather than re-spelled: "That key is the transport crate's own constant rather than a
           second spelling of the same string here, because the two sides of a key are exactly where
           a literal drifts: the crate that asks and the root that answers."
           There are THREE sides and the root binds two. `busbar_transport_grpc::MESSAGE_MAX_BYTES_KEY`
           has no reader outside its own crate (X-2631's `busbar_transport_grpc::` -> 2 hits, both
           `GrpcTransport`), and no test compares the grpc copy to the ws copy — so if either moves,
           the protection this doc describes does not fire.
ACTION:    Add `assert_eq!(busbar_transport_grpc::MESSAGE_MAX_BYTES_KEY, busbar_transport_ws::MESSAGE_MAX_BYTES_KEY);`
           to `crates/busbar/src/root/tests/transports.rs` beside the existing cell at :307.

### X-2661 · The gRPC message cap is installed at `listen`, and production never calls `listen`
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-grpc/src/transport.rs:167` is the ONLY write to
           `max_message_bytes` (`grep -n "max_message_bytes" crates/busbar-transport-grpc/src/*.rs`
           -> :67 field, :86/:97 both constructors initialise it to 0, :110 read, :167 the one store),
           and it is inside `listen`. `dial` (:200-268) reads it back through `message_cap()` and
           never sets it. The doc at :64-66 asserts the cap is "carried on every connection this same
           instance goes on to accept OR dial" — true only if `listen` ran first on the same instance.
           `git grep -n "listen_all" -- '*.rs'`:
             crates/busbar/src/main.rs:538            "WHY NOTHING IS BOUND HERE ... This boot does not call `listen_all`"
             crates/busbar/src/root/transports.rs:347 (the definition)
             crates/busbar/src/root/tests/transports.rs:276  (a test)
           So no shipped path calls `GrpcTransport::listen` at all, and the cap stays 0 ->
           `message_cap()` falls back to `codec::MAX_MESSAGE_BYTES` (4 MiB, transport.rs:108-114).
           Blast radius is bounded rather than open — a safe default, not an unbounded decode — but
           the operator's `limits.request_body_max_bytes` reaches gRPC in no configuration at all,
           which is a strictly worse position than X-2608 (where it reaches in default builds only).
           TEST HALF: `grep -n "CapCfg" crates/busbar-transport-grpc/src/tests/battery.rs` -> the
           definition at :54-67 and ONE use at :2008, inside a `listen`/`accept` cell. Every dialling
           instance comes from `client_transport()` (:26), which never calls `listen`, so the dial
           side of the doc's claim has no cell.
ACTION:    Give `GrpcTransport` a constructor-carried cap the way `ws` has
           (`WsTransport::over_with_max_message_bytes`, used at `busbar/src/root/registry.rs:279`) —
           add `pub fn over_with_max_message_bytes(lower, cap)` and call it at `registry.rs:293` —
           so the cap does not depend on a `listen` that never happens. Add the dial-side cell.

### X-2662 · `RawStartLine::Status`'s fields are parsed and allocated on every header parse and read only by a test
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:  `git grep -n "RawStartLine::Status" -- '*.rs'`:
             crates/busbar-transport-http/src/raw.rs:93        (the construction)
             crates/busbar-transport-http/src/tests/raw.rs:129 (the only place `code`/`reason` are read)
           `crates/busbar-transport-http/src/transport.rs:251` uses the variant only as a
           refutable-let ELSE branch
           (`let RawStartLine::Request { .. } = &raw.start else { return Err(Framing) }`), so nothing
           in the crate consumes `code` or `reason`.
           The VARIANT must exist — it is what makes `parse_message` refuse a status line on the
           ingress path — so this is dead DATA rather than a wrong answer: two fields allocated per
           parse and discarded.
           ADJUDICATE on whether it is worth changing; the measurement is not in doubt.
ACTION:    Either make `RawStartLine::Status` payload-free at `raw.rs:20-26`, or give `code`/`reason`
           a consumer on the egress path where they were presumably intended.

### X-2663 · `ProbeEvent::Failed.cooldown_until` re-reads the cell state outside the lock that armed it, and can journal a deadline already in the past
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:  `sed -n '563,575p' crates/busbar-kernel-breaker/src/lib.rs`:
             563  let effect = cell.record_failure(now, cfg, retry_after, self.max_honored_retry_after_secs);
             566  if effect.reopened() { let cooldown_until = match cell.state() {   // SECOND, UNLOCKED read
             567      CellState::Open { until } => until,
             568      _ => now,                                                      // silent wrong value
           `record_failure` arms the cooldown UNDER `transition_lock`
           (`crates/busbar-kernel-breaker/src/cell.rs:552 let _tx = lock_recover(&self.transition_lock)`),
           but `observe` re-reads `cell.state()` outside it. A concurrent `record_success` that closes
           the cell in the gap makes the match fall to `_ => now`, and the journal line then carries
           `cooldown_until == now` — a deadline that has already passed.
           `sed -n '215,221p' crates/busbar-kernel-breaker/src/cell.rs` shows the fix was never
           applied: `FailureEffect::Reopened` at :220 is still BARE, with no `(u64)` payload to carry
           the deadline `record_failure` just stored.
           `docs/design/1.6.0-local-only-audit.md:1360` names this exact defect as open.
           NOTHING CAN PRODUCE A NO: the three journal race cells in
           `crates/busbar-kernel-breaker/src/tests/mod.rs`
           (`a_fresh_trip_is_never_journaled_as_a_failed_probe`,
            `a_probe_that_closed_the_cell_is_always_journaled_as_succeeded`) assert WHICH event is
           emitted and never the `cooldown_until` value.
           ADJUDICATE: the race is argued from the code path, not reproduced — and it is moot today
           because the only sink is `NoopJournal` (X-2649), which is precisely why it has survived.
ACTION:    Change `FailureEffect::Reopened` to `Reopened(u64)` at `cell.rs:220`, have
           `record_failure`'s `ST_HALF_OPEN` arm (cell.rs:588-592) return the deadline it just stored,
           and use it at `lib.rs:566` instead of the second `cell.state()`. Add a cell asserting the
           journaled `cooldown_until`, which today nothing does.

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT (stated, not acted on)

- `crates/busbar-contract/src/transport/mod.rs:101-154` — the `TransportMeta` trait is where the
  dead half of X-2600 and X-2601 lives. Ten of its sixteen associated consts have zero readers
  outside the transport crates (`SELECTOR_FORMS`, `EGRESS_SELECTOR_FORMS`, `SESSION_BOUND`,
  `UNIT0_TRIGGER`, `UPGRADES_TO`, `TRANSPORT_FACTS`, `DECODES_PAYLOAD`, `STATUS_CLASS`,
  `STATUS_NAMESPACE`, `HANDSHAKE_TRIGGER`); `COMPOSES_OVER` (3) and `HANDOFF` (2) are the control
  that the measurement works.
- `crates/busbar/src/main.rs:1692` and `:1873` — both `busbar_core_connsec::prepare` call sites pass
  a literal `true` where `<T as TransportMeta>::WRAPPABLE_BYTE_STREAM` belongs. This is the half of
  X-2601 that is not in my slice, and it is the half that makes `FailClosed::IncapableTransport`
  unreachable in the shipped binary.
- `crates/busbar/src/root/transports.rs:310-327` — `ListenerView::get_int` answers the message
  ceiling only under `#[cfg(feature = "plane-voice")]`, with the comment "Without the voice plane
  there is no transport assembling messages, so no key is answered." `grpc` is a non-optional
  dependency (`crates/busbar/Cargo.toml:145`) and reads that exact key. X-2608.
- `crates/busbar/src/root/registry.rs:274-275, 293` — builds `TcpTransport::new()`,
  `TlsTransport::new()` and `GrpcTransport::over(..)`, none of which can carry the operator's
  handshake/dial/message budgets. X-2639, X-2661.
- `crates/busbar-transport-http/src/lib.rs:277, 333, 390-463` — the `EgressTrust` / `SpkiPinVerifier`
  / client-identity branch. X-2632.
- `crates/busbar-transport-tls/src/lib.rs` and `src/transport.rs:236-261, 370-406` — the unraced
  writes X-2638 describes; the fix already exists at `crates/busbar-transport-tcp/src/lib.rs:287`.
- `crates/busbar-transport-sse/src/reframe.rs:124-125` and `crates/busbar-mcp/src/mcp/sse.rs:161` —
  two implementations of one content negotiation that answer differently for
  `Accept: application/json, text/event-stream`. X-2636.
- `crates/store-example-plugin/src/lib.rs` (the `impl Store for FileStore` block) — the missing
  `add_usage` and `scrub_key` delegations. X-2625, X-2626.
- `crates/busbar-kernel-breaker/src/lib.rs:563-576` and `src/cell.rs:215-221` — the unlocked
  re-read behind X-2663.
- `crates/secret-ref/src/lib.rs:5` names `crates/busbar-core/src/config/secret.rs` as its extraction
  origin; `ls -d crates/busbar-core` -> No such file or directory (control: `crates/busbar-core-admin`
  exists). Same dead crate name as X-2654. Not in my slice; not acted on.
- `git grep -ln "busbar-contract-transport" -- '*.rs' '*.toml'` returns nine more files outside this
  slice that still name the crate folded away in b65fbfb83 (X-2613 is this slice's one).
- `git grep -n "busbar-caps" -- '*.rs' '*.toml'` returns 20+ sites outside this slice, and
  `crates/busbar-kernel-egress/tests/prose.rs:70` uses the string as TEST DATA — a blind sed would
  break a fixture. X-2646 flags the scope; I did not adjudicate prose.rs:70.
- `crates/store-example-plugin/src/tests/mod.rs:748-750` asserts in prose that the
  `manifest-allowlist` gate is "report-only in CI today (`continue-on-error: true`)";
  `.github/workflows/ci.yml:3574` now reads "`continue-on-error: true` IS GONE, AND SO IS THE REASON
  FOR IT." A check whose subject moved. Its own rule also only inspects the left-hand side of a dep
  `=`, so `foo = { package = "busbar-store-memory" }` would pass.
- `crates/plugin-sdk/Cargo.toml` — not in my slice, but it is what makes X-2657 true: `pack` has no
  `default` and the one CI leg that enables it is promotion-tier.
- `crates/busbar-timing/src/lib.rs:42-44, 118` and `docs/ci/feature-sets.md:43` — the per-request
  bracket with no caller and the third stale `busbar-core` row. X-2654, X-2655.
- `crates/api/src/hooks.rs:90-99` is the subject of X-2621; `crates/api/src/durable.rs` is in slice
  but `crates/busbar-kernel/src/config/overlay.rs:1012` and
  `crates/plugin-loader/src/highwater.rs:229` — the two shipped `DurableOpts` sites — are not.

## TALLY

```
files in slice:  102     (equals the line count of .sweep/S17-remainder.txt)
verdict lines:   102     (diff of the table's FILE column against the slice file: empty, in order)
CLEAN:            37
FINDING:          65     rows raised: 64  (X-2600 .. X-2663, contiguous, all inside X-2600..X-2699)
DELETABLE:         0     argued: see "(b)" above — the one rig that looked deletable is the only
                         instrument that could have caught X-2602
UNREADABLE:        0
```

Rows by class: missing-code 15 · instrument-blind 14 · drift 13 · config 8 · customer-surface 7 ·
auth 4 · money 2 · abi 1.

Rows by certainty: VERIFIED 59 · ADJUDICATE 4 (X-2616, X-2643, X-2662, X-2663) · PARK 1 (X-2627,
a billed byte — the template's RAM backend auto-sweeps the metering ledger the contract says must
never be auto-swept; owner ruling, not mine).
