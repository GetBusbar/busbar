# S10-admin-auth — sweep verdicts

Slice: `busbar-core-admin`, `busbar-oauth2`, `busbar-core-connsec`. 62 files.
X-id block X-1900..X-1999.

Read-and-report only. No source edited. No golden, `openapi.json`, `accepted-differences.json`
or `qa/*.toml` ratchet touched.

## The architecture this slice was judged against
admin and oauth2 are NOT plugins — they are **cleanliness crates**: always compiled in, one-way
dep on core, off the hot path. Both MINT busbar tokens, but **CORE owns the badge press** — the
token stamp and the per-office ceiling (oauth <= the user's scopes, admin <= its configured
ceiling). A mint path that does not pass through core's ceiling is a serious auth finding.

**That rule HOLDS on every path that ships, and I checked it directly.**

* **Admin mint** (`keys.rs:774`) stamps through core: `app.mint_policy.check_mint(&mint_req)` —
  the block-level TTL ceiling AND the caller's per-role `mint_ceilings` (pools/TTL/binding mode).
  An explicit TTL over-ask is REFUSED, a default is clamped. The anti-sprawl ceiling
  (`check_key_cap`) counts the UNBOUND bucket too, so the cap is not evadable by omitting `group`,
  and it fails closed on a store error.
* **OAuth mint** ceiling is `policy::default_grant_scopes`, and it is the **same value** on both
  arrival mechanisms — registration (`policy::registration_config`) and CIMD
  (`cimd::CimdStore::new(.., default_grant_scopes(&identity), ..)`, `plane.rs:156`). The
  subset check `cimd.rs:310` refuses rather than narrows. `client_credentials` and `device_code`
  are absent from `allowed_grant_types` by construction.
* **`busbar-oauth2/src/cimd.rs:121-170` reaches `busbar_kernel::egress` — VERIFIED SAFE.** The
  flagged control surface goes through the shared guard, not around it: `net_guard::split_url` →
  `judge_scheme` → `resolve_and_pin` (exactly one resolution, every answered address judged,
  cloud-metadata arm first) → `EngineSpec::pinned` (the pin IS the resolver) → `send_bounded`
  under one hop deadline → `refuse_redirect` → a capped streaming body read. `fetch_policy()` sets
  `allow_private: false, allow_plaintext: false, max_redirects: 0`. This is the SAME guard the rest
  of busbar's egress uses, not a second copy. No row.

The one serious finding below is not a missing ceiling. It is an entire **second** mint pipeline,
fully built and fully tested, that **no shipping path can reach**.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `crates/busbar-core-admin/src/admin_codec/claims.rs` | CLEAN | `git grep -n "AdminPlane" crates/busbar/src/root/registry.rs` → `:88` imported, sealed via `seal_claims`. `SCHEME`/`SCHEME_ALTS` ARE read in production: `crates/busbar-kernel/src/registry.rs:389-393 schemes_compatible`. `const _: () = assert!(matches!(ADMIN_PREFIX.as_bytes(), b"/api/v1/admin"))` is a real compile-time pin. | - |
| `crates/busbar-core-admin/src/admin_codec/generated/mod.rs` | CLEAN | `git grep -n verb_table_1_5_5` → declared here, consumed `admin_codec/verbs.rs:20`. | - |
| `crates/busbar-core-admin/src/admin_codec/generated/verb_table_1_5_5.rs` | CLEAN | 66 rows. Scope column pinned to the artifact by `admin_codec/tests/verbs.rs:139` reading `x-busbar-required-scope` (NOT re-derived). | - |
| `crates/busbar-core-admin/src/admin_codec/meta.rs` | CLEAN | `impl PlaneMeta for AdminPlane` consumed by `root/registry.rs` `seal_claims`. `METER_CLASSES = &[]` is correct (`count` is kernel-reserved; declaring it would be a boot refusal). | - |
| `crates/busbar-core-admin/src/admin_codec/mod.rs` | CLEAN | `pub mod` tree all declared; `AdminPlane` constructed at `root/registry.rs:88`. | - |
| `crates/busbar-core-admin/src/admin_codec/refusal.rs` | CLEAN | `git grep -n envelope_of` → production caller `root/units_admin/admin_mount.rs:359`. Hand-formatted JSON is safe: traced BOTH call sites — `error_answer(status, code)` passes `code` as the message, and the only other is `DOOR_MESSAGE` (a const). No caller-controlled text reaches it. | - |
| `crates/busbar-core-admin/src/admin_codec/tests/mod.rs` | CLEAN | Carries the no-plane-face canary AND its own filter-not-a-wall control (`the_entry_face_scan_sees_the_impl_it_forbids_and_not_the_declaration`). Can produce a NO. | - |
| `crates/busbar-core-admin/src/admin_codec/tests/refusal.rs` | CLEAN | 3 tests / 11 assertions over `envelope_of`, the function the live listener builds every error with. | - |
| `crates/busbar-core-admin/src/admin_codec/tests/verbs.rs` | CLEAN | The strongest instrument in the slice: reads scope from the artifact's own column, asserts `checked == 66` and `read_only_rows == 34` so the walk cannot go vacuous. | - |
| `crates/busbar-core-admin/src/admin_codec/verbs.rs` | CLEAN | `grep -n "const _: () = assert!"` → 4 compile-time cross-checks. `rows_and_names_agree` (`:297`) checks `rows.len() != verbs.len()` AND bidirectional membership; `VERB_COUNT: usize = 66 + 18 + 5 + 3` (`:237`) is a LITERAL, so the const-assert at `:343` is a real floor, not a tautology. | - |
| `crates/busbar-core-admin/src/governance.rs` | FINDING | `git grep -n "impl .*Governance for"` → 5 fakes in `verbs_tests.rs`; ONE shipping impl at `crates/busbar/src/root/units_admin/mod.rs:911`, whose `mint_key` (`:941`) and `rotate_key` (`:949`) both `return Err(GovernanceError::Validation)`, `group_exists` returns `true` unconditionally, `actual_parent` returns `None` unconditionally. | X-1900 |
| `crates/busbar-core-admin/src/idempotency.rs` | FINDING | `git grep -n "IdempotencyCache"` → constructed only from `verbs.rs`, reachable only through `Verbs::create_key`/`rotate_key`. The LIVE replay cache is a different one: `app.idempotency_cache` (`keys.rs:620`, `busbar-kernel/src/state.rs:351`). Two cache implementations; one never runs. | X-1900 |
| `crates/busbar-core-admin/src/keys.rs` | CLEAN | The LIVE admin surface. Core ceiling confirmed at `:774` `app.mint_policy.check_mint(&mint_req)`; parse failures map to a GENERIC 400 logging only byte length (`:648`); `check_key_cap` fails closed and counts the unbound bucket; `EXISTENCE_GATE` held inside `spawn_blocking` (cancellation-safe). `rotate_replay_key` is length-prefixed and IS used here (`:1498`). | - |
| `crates/busbar-core-admin/src/lib.rs` | CLEAN | `install()` called unconditionally by the composition root, `crates/busbar/src/main.rs:343`. Every `pub mod` resolves to a file on disk. | - |
| `crates/busbar-core-admin/src/mint.rs` | FINDING | `git grep -n plan_mint_group` → `crate::mint::plan_mint_group` has exactly ONE non-test caller, `verbs.rs:334`, inside `Verbs::create_key`. The production mint calls a DIFFERENT function of the same name with a different signature (`busbar_kernel::governance::group_provision::plan_mint_group`, re-exported at `v1/json/handlers.rs:1017`, called `keys.rs:880`). | X-1900 |
| `crates/busbar-core-admin/src/refusal.rs` | CLEAN | `ReasonCode` mapped to the kernel's vocabulary at `root/units_admin/mod.rs` `verbs_reason`; `store_error_into_refusal` used at `verbs.rs:613`. No variant unreachable. | - |
| `crates/busbar-core-admin/src/restart.rs` | CLEAN | `UnitDrain::of_unit` / `release` / `drain_released_at_exit` all called from `root/units_admin/admin_mount.rs:174,414,589`; `publish_shutdown` from `main.rs:1481`. | - |
| `crates/busbar-core-admin/src/tests/core_moved_tests.rs` | CLEAN | Wired `lib.rs:177` under `cfg(all(test, feature="auth-admin-tokens"))` (a DEFAULT feature). 6 named auth-behaviour tests / 27 assertions, incl. blank-header rejection and split-listener double-exposure. | - |
| `crates/busbar-core-admin/src/tests/idempotency_tests.rs` | FINDING | Wired `idempotency.rs:176`. Tests the dead cache (X-1900). Separately, `create_and_rotate_scoped_keys_never_replay_each_other` (`:113`) hand-writes `"rotate:key-42:shared-header"` and never calls `verbs::rotate_replay_key`, which actually returns `format!("rotate:{}:{}:{}:{}", id.len(), id, header.len(), header)`. | X-1900, X-1907 |
| `crates/busbar-core-admin/src/tests/internal_error_tests.rs` | FINDING | Real instrument (500 + non-empty envelope, guards against `Response::default()`'s bare 200). Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/key_cap_tests.rs` | FINDING | Real instrument: 4 tests proving cap counts LIVE keys only, the unbound bucket is capped, and rebind excludes the mover. Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/key_revoke_tombstone_tests.rs` | CLEAN | Wired `lib.rs:172`. Drives the real router end-to-end (mint → DELETE → revoke), asserting 200 + `key.revoke`/`applied` audit row. | - |
| `crates/busbar-core-admin/src/tests/mint_tests.rs` | FINDING | Wired `mint.rs:91`. 9 tests / 17 assertions — good instruments, but the subject (`crate::mint::plan_mint_group`) never runs in the shipped binary. | X-1900 |
| `crates/busbar-core-admin/src/tests/mint_wiring_tests.rs` | FINDING | Wired `verbs_tests.rs:2064`. Its own header says these go through `Verbs::create_key` to reach "the shipped path" — that premise is false. Worse, the defect it exists to catch ("an adapter answering `None`, or the empty string") is EXACTLY what the shipping `CoreGovernance::actual_parent` does, harmlessly, because the path is dead. | X-1900 |
| `crates/busbar-core-admin/src/tests/parse_duration_secs_tests.rs` | FINDING | Real instrument (exact 10-year boundary, `3650d` ok / `3651d` err). Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/posture_tests.rs` | CLEAN | Wired `posture.rs:190`. 13 tests / 30 assertions. The `for verb in NEW_VERBS` loops (`:18,:51`) are NOT vacuous: `NEW_VERBS.len()` is pinned at 18 by the compiler via `rows_and_names_agree` + the `VERB_COUNT = 66+18+5+3` literal. Checked, and it holds. | - |
| `crates/busbar-core-admin/src/tests/provision_tests.rs` | CLEAN | Wired `keys.rs:1978`. 2 tests / 17 assertions over the LIVE auto-provision path, incl. "mint failure after the provision commit still records the committed group" and the group ceiling. | - |
| `crates/busbar-core-admin/src/tests/rate_window_tests.rs` | CLEAN | Wired `rate_tests.rs:352`. Exemplary: pins `now - (now % 60)` from a NON-epoch minute, both directions (same minute still exhausted / next minute fresh), with the per-slot-age and leaked-sentinel halves. Plainly able to produce a NO. | - |
| `crates/busbar-core-admin/src/tests/reject_overlong_id_tests.rs` | FINDING | Real instrument (exact `>` vs `>=` boundary). Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/restart.rs` | CLEAN | Wired `restart.rs:243`. 5 named tests incl. "a drain is released only by the unit that asked for it" — the keyed-ask property the module exists for. | - |
| `crates/busbar-core-admin/src/tests/sentinel_tests.rs` | FINDING | Wired `idempotency_tests.rs:135`. Excellent instruments (leaked sentinel outlives the window; committed value IS swept; per-slot age; clear never removes a committed value) — pointed at the dead cache. | X-1900 |
| `crates/busbar-core-admin/src/tests/table_matches_openapi.rs` | CLEAN | Wired `lib.rs:70`. Reads scope from the artifact, not a rule-copy; checks BOTH set differences; `assert_eq!(ops.len(), 66, "the loop has to have something to check")` is an explicit anti-vacuity floor. | - |
| `crates/busbar-core-admin/src/tests/tests.rs` | FINDING | Wired `keys.rs:1971-1973` under `cfg(all(test, feature="auth-admin-tokens"))` — a DEFAULT feature; `cargo test -p busbar-core-admin --lib -- --list` registers 156 `keys::tests::*`. Much of it is excellent (the rotate cache-key collision regression at `:2583`; anti-vacuity floors `seen.len() >= 60`, `ops.len() >= 40`; the bidirectionally-ratcheted `COND_WITNESS_DEBT`). Two tests nonetheless report PASS having asserted nothing, and one comment cites a test that does not exist. | X-1909, X-1910 |
| `crates/busbar-core-admin/src/tests/transport_tests.rs` | FINDING | Real instrument (computed mount prefix must equal `contract::ADMIN_PREFIX`). Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/txn_tests.rs` | FINDING | Wired `lib.rs:166`. `concurrent_mints_never_bind_a_deleted_group` (`:328`) has ONE assertion, doubly guarded by `for key in g.all_keys()` + `if let Some(bound)`. The 8 mint tasks' results are discarded: `m.await.expect("mint task joins")` (`:356`) asserts only that the task joined. `async fn mint(..) -> StatusCode` (`:139`) RETURNS the status precisely so a caller can assert it; this caller does not. | X-1908 |
| `crates/busbar-core-admin/src/tests/validate_mint_labels_tests.rs` | FINDING | Real instrument (exact label-count boundary). Header cites a dead path. | X-1903 |
| `crates/busbar-core-admin/src/tests/verbs_tests.rs` | FINDING | Wired `verbs.rs:631`. 15 of 34 tests drive `Verbs::create_key`/`rotate_key`; ALL 15 run against fakes and none exercises `CoreGovernance` (`grep -c CoreGovernance` → 0, control `FakeGovernance` → 34). The other 16 (`execute`/recovery verbs) DO cover live code. No blindness, no drift. | X-1900 |
| `crates/busbar-core-admin/src/transport.rs` | CLEAN | `mount` called from `lib.rs:89` `seam_mount`, which the composition root installs. Prefix derived, never hand-written. | - |
| `crates/busbar-core-admin/src/v1/json/mod.rs` | CLEAN | `JsonV1` mounted via `lib.rs:89`. `RESPONSES_KEY` heavily consumed under `openapi-schema`, which has its own CI job (`ci.yml:1233`). `record_declared_error` (`:196`) is a genuine under-claim guard that fails the build, correctly gated to test/test-support. | - |
| `crates/busbar-core-admin/src/v1/json/tests/patch_tests.rs` | FINDING | Wired `v1/json/handlers.rs:5215`, runs by default (3 tests). Assertions are concrete money figures read back off the merge output and `empty_patch_is_identity` is a full structural `assert_eq!`. But all 3 call sites pass `None` for `parent` and `child_default`, so 2 of `merge_group_patch`'s 4 arms are never set. Header cites a dead path. | X-1903, X-1913 |
| `crates/busbar-core-admin/src/v1/json/tests/tests.rs` | FINDING | Wired `v1/json/mod.rs:510` under `cfg(test)`. Two of its tests (`:410`, `:546`) carry `#[cfg(feature = "openapi-schema")]`, a NON-default feature, and the single CI job that enables it filters on the substring `openapi` — which neither test's name nor module path contains. No CI invocation runs them — proven by differencing the listed test sets three ways. A third test (`:704`) is unfloored and can pass having examined nothing. | X-1911, X-1912 |
| `crates/busbar-core-admin/src/v1/mod.rs` | CLEAN | Three `pub mod` + one `#[path]` test module, all resolving to files on disk. | - |
| `crates/busbar-core-admin/src/v1/named_def_views.rs` | FINDING | The module doc states the secret rule as exactly two closed paths ("a secret REFERENCE collapses to a boolean and a `settings:` bag collapses to its KEY NAMES"). There is a THIRD field carrying operator-document text: `unparseable: Some(entry.error.clone())` (`:92`), a raw `serde_json` error, served on a `Scope::ReadOnly` surface (`busbar-kernel-scope/src/lib.rs:300`). | X-1906 |
| `crates/busbar-core-admin/src/v1/tests/hook_stage_projection.rs` | CLEAN | Wired `v1/mod.rs:19`; all 5 confirmed in `--list` under default features, no feature gate. Loops are over `const` arrays pinned by `assert_eq!(ALL_HOOK_STAGES.len(), 4)` (`:154`), and `:104 assert!(!view.fires_at.is_empty())` sits OUTSIDE the inner loop, so it cannot go vacuous. The exhaustive `match` at `:139-144` with no `_` arm is a real compile-time guard. | - |
| `crates/busbar-core-admin/src/v1/tests/service_tests.rs` | FINDING | Wired `v1/service.rs:1244` under `cfg(test)` only; `--list` shows 75 `v1::service::tests::*` under default features. Money assertions are strong (literal expecteds, and `every_money_read_in_this_crate_is_registered` carries an explicit anti-vacuity floor). But `:951` skips with NO CI guard, `:1386` under-claims against its own docstring, and the header cites a dead path. | X-1903, X-1909, X-1914 |
| `crates/busbar-core-admin/src/verb.rs` | CLEAN | `LEGACY_VERBS` IS production-consumed (`rate.rs:85,160`; `verbs.rs:169 required_scope`; `root/units_admin/mod.rs:2051`). Its scope is COMPUTED by `scope_for` and compared against the artifact's column — a rule-vs-artifact check, not a self-comparison. `ADMITTED_UNDER_UNSET` consumed `posture.rs:97`. | - |
| `crates/busbar-oauth2/Cargo.toml` | FINDING | Workspace member (root `Cargo.toml:5`), depended on by `crates/busbar`. Dependency prose names a crate that does not exist: `git grep -n 'name = "busbar_core"' '*/Cargo.toml'` → rc=1 (control: `busbar-oauth2` → rc=0). | X-1904 |
| `crates/busbar-oauth2/src/consent.rs` | CLEAN | Approval is SPENT (`spend`, not `contains`); `ApproveAndRemember` never returned so no stored grant exists; session bounded at `MAX_SESSIONS`; the unencodable-`Location` path fails closed with a 502 rather than answering `access_denied` on the operator's behalf. | - |
| `crates/busbar-oauth2/src/lib.rs` | CLEAN | `install()` called unconditionally by `crates/busbar/src/main.rs`. Every `pub mod` resolves; `testkit` correctly gated on `any(test, feature="test-support")`. | - |
| `crates/busbar-oauth2/src/plane.rs` | FINDING | Logic is sound (`allowed_resources` set so an RFC 8707 `resource` cannot name a foreign audience; CIMD ceiling is the SAME `default_grant_scopes` as registration). But `:55` carries a broken intra-doc link. | X-1901 |
| `crates/busbar-oauth2/src/policy.rs` | CLEAN | The ceiling is config, not request content; `allowed_grant_types` pinned to the two the auth-code flow needs; `management_enabled = false`; `expect` on `ScopeSet::from_tokens` is sound because `AsIdentity::from_cfg` already refused non-tokens at boot. | - |
| `crates/busbar-oauth2/src/routes.rs` | FINDING | Logic is sound (`is_local_path` refuses `//` and `\`; session read from cookie never the form; two `Set-Cookie`s at two disjoint paths so the token endpoint never receives one). But `:6` carries a broken intra-doc link. | X-1902 |
| `crates/busbar-oauth2/src/signer.rs` | CLEAN | `ECDSA_P256_SHA256_FIXED_SIGNING` (not `..._ASN1`) on both sign and verify; explicit 64-byte length refusal; coordinates rebuilt into a 65-byte SEC1 point so a short decode cannot shift the other half. | - |
| `crates/busbar-oauth2/src/testkit.rs` | CLEAN | Runs the REAL `AsIdentity::from_cfg` + `AsPlane::build`, so a fixture cannot mount a deployment boot would refuse. `install_test_seam` is `Once`-guarded. | - |
| `crates/busbar-oauth2/src/tests/cimd_tests.rs` | CLEAN | Wired `cimd.rs:615`. Holds the scope ceiling and it is RED-ABLE: `a_document_asking_past_the_default_grant_is_refused` (`:84`) dies if `cimd.rs:310`'s `is_subset` is deleted, with `a_well_formed_document_materialises_a_public_client_under_the_ceiling` (`:53`) as the positive control. Observed green: `12 passed; 0 failed; 0 ignored`. | - |
| `crates/busbar-oauth2/src/tests/flow_tests.rs` | CLEAN | Wired `lib.rs:59`. 8 tests, no blindness (the `for c in &cookies` loops have a liveness floor OUTSIDE the loop), no drift. Note: it does not exercise the scope ceiling — every scope is the single `const SCOPE = "read"` which IS the whole `default_grant`, and clients are injected via `register_client` bypassing the policy. Not a row: the ceiling is properly covered by `cimd_tests.rs:84` and `policy_tests.rs:61`. | - |
| `crates/busbar-oauth2/src/tests/mount_tests.rs` | CLEAN | Wired `lib.rs:62`. `inventory()` is an EXHAUSTIVE destructure with no `..`, and `the_inventory_is_exactly_what_the_mount_registers` asserts set EQUALITY — so a surplus route and a missing mount are both caught. Explicitly anti-vacuous. | - |
| `crates/busbar-oauth2/src/tests/percent_decode_tests.rs` | CLEAN | Wired `routes.rs:545`. Pins the real historical panic (a `%` before a multibyte char), plus a well-formed control so the refusal is not a blanket one. | - |
| `crates/busbar-oauth2/src/tests/policy_tests.rs` | CLEAN | Wired `policy.rs:123`. Drives the REAL `AsPlane::build`, not a hand-made `ServerConfig`. Three of five were watched RED before green, and the one that could not be driven red says so at the test rather than glossing it. Model instrument. | - |
| `crates/busbar-oauth2/src/tests/signer_tests.rs` | CLEAN | Wired `signer.rs:230`. Carries the RFC 7515 A.3 known-answer vector via the upstream harness, PLUS `the_harness_fails_a_signer_that_does_not_actually_sign` — a meta-control proving the harness itself can go red. | - |
| `crates/busbar-core-connsec/Cargo.toml` | FINDING | Workspace member (root `Cargo.toml:6`); depended on by `crates/busbar/Cargo.toml:51`. Comment names a crate that does not exist. | X-1905 |
| `crates/busbar-core-connsec/src/lib.rs` | FINDING | `prepare` IS constructed and fails closed at BOTH production call sites — `main.rs:1692` and `main.rs:1873`, each `.unwrap_or_else(|e| die(...))`. (The `let _ =` at `:1692` discards the successfully-built wrap of a pre-flight validation, not an error — `die` already ran on `Err`.) Logic clean; comment names a crate that does not exist. | X-1905 |

## ROWS RAISED

### X-1900 · An entire second key-mint pipeline ships, fully tested, and no shipping path can reach it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  Three independent locks, each watched:

1. The root routes the two minting verbs AROUND the unit, before it is even built:
```
$ sed -n '2516,2518p' crates/busbar/src/root/units_admin/mod.rs
fn mints_its_own_identity(verb: KernelVerb) -> bool {
    matches!(verb, KernelVerb::PostKeys | KernelVerb::PostKeysIdRotate)
}
$ sed -n '2318,2323p' crates/busbar/src/root/units_admin/mod.rs
    if mints_its_own_identity(verb) {
        let answer = binding.dispatch.execute(verb, &request);
        binding.units.set_answer(ctx.key, answer);
        return Decision::proceed(token, busbar_contract::RoutePlan::default());
    }
#  ... `busbar_core_admin::Verbs::new(...)` is line 2324 — AFTER this return.
```

2. `Verbs::execute` hard-refuses the same two verbs in EVERY build, so there is no back door:
```
$ sed -n '461,463p' crates/busbar-core-admin/src/verbs.rs
        if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {
            return Err(Refusal::new(RefusalStep::Admit, ReasonCode::Internal));
        }
```

3. No caller anywhere invokes the entry points directly, and the crate is unpublished:
```
$ git grep -n "\.create_key(\|\.rotate_key(" -- '*.rs' | grep "^crates/busbar/src/"
#  (no output; rc=1)
$ git grep -n "\.create_key(" -- '*.rs' | grep -c "busbar-core-admin/src/tests/"   # control
28
$ grep -n "publish" crates/busbar-core-admin/Cargo.toml
17:publish = false
```

The ONLY shipping `impl Governance` is a set of stubs, consistent with never being called:
```
$ sed -n '941p;949p' crates/busbar/src/root/units_admin/mod.rs
        Err(busbar_core_admin::GovernanceError::Validation)   # mint_key
        Err(busbar_core_admin::GovernanceError::Validation)   # rotate_key
#  group_exists() -> true unconditionally (:913); actual_parent() -> None unconditionally (:919)
```

**What is dead:** `mint.rs` in full (`plan_mint_group`, `GroupLookup`, `MintPlan`);
`Governance::{mint_key, rotate_key, provision_group, group_exists, actual_parent}`;
`idempotency.rs` in full (`IdempotencyCache`, `Reservation`, `Probe`, `ReplayEncoder`);
`Verbs::create_key`/`rotate_key` (~160 lines of real orchestration) and `GovernanceGroupLookup`.
Roughly **1,050 lines of test** guard it: `mint_tests.rs` (9), `mint_wiring_tests.rs` (6),
`idempotency_tests.rs` (6), `sentinel_tests.rs` (6), and 15 of 34 in `verbs_tests.rs`.

**Why this is not merely tidy-up.** The live surface does all of this a SECOND time, elsewhere:
`keys.rs:609` runs its own idempotency against `app.idempotency_cache`, and `keys.rs:880` calls a
DIFFERENT `plan_mint_group` — same name, different crate, different signature, different return
type:
```
$ sed -n '53,58p' crates/busbar-core-admin/src/mint.rs          # the dead one
pub fn plan_mint_group(lookup: &impl GroupLookup, group: Option<&str>,
                       parent: Option<&str>, max_group_name_len: usize)
    -> Result<MintPlan, Refusal>
$ sed -n '97,102p' crates/busbar-kernel/src/governance/group_provision.rs   # the live one
pub fn plan_mint_group(current: &Arc<App>, group: &str,
                       parent: Option<&str>, actor: &str)
    -> Result<Option<Arc<App>>, TxnError>
```
Two mint-group policies, two idempotency caches, one of each running. `mint_wiring_tests.rs`'s own
header calls the dead adapter "the shipped path" and warns that "an adapter that dropped the
group's actual parent on the floor" would be a defect — which is precisely what the shipping
`CoreGovernance::actual_parent` does. The test suite is green, the warning is correct, and neither
touches the binary. That gap is the finding: the tests report a safety property about a path the
product does not take.

ACTION:    Owner ruling on direction, then one of two edits. EITHER delete the dead half —
`mint.rs`, `idempotency.rs`, `Verbs::create_key`/`rotate_key`, `GovernanceGroupLookup`, the five
`Governance` methods no shipping impl implements, and the ~1,050 lines of test that guard them —
keeping `rotate_replay_key` (live, `keys.rs:1498`); OR route `POST /keys` and
`POST /keys/{id}/rotate` through the unit by deleting `mints_its_own_identity` and the `verbs.rs:461`
refusal, and implement `CoreGovernance::{mint_key, rotate_key, group_exists, actual_parent}` for
real. Do NOT leave both. Whichever is chosen, `mint_wiring_tests.rs`'s "the shipped path" header
must be corrected — it is the sentence that would have caught this.

### X-1901 · `plane.rs` intra-doc link names a module this crate does not have
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "super::config" -- crates/busbar-oauth2/
crates/busbar-oauth2/src/plane.rs:55:/// Why the plane could not be built. Distinct from [`super::config::AsCfgError`] because these are
$ git grep -n "^pub mod" crates/busbar-oauth2/src/lib.rs
cimd, consent, plane, policy, routes, signer, testkit      # no `config`
$ git grep -n "pub enum AsCfgError" -- '*.rs'
crates/busbar-kernel/src/oauth_as/config.rs:66:pub enum AsCfgError
```
`super::config` resolves to `busbar_oauth2::config`, which does not exist — the config carrier
deliberately STAYED in core (this crate's own `lib.rs:22-26` says so). Uncaught because there is
no rustdoc gate in this repo: `git grep -rn "broken_intra_doc_links|rustdoc|cargo doc" -- .github/
xtask/ scripts/` → rc=1, and `grep -nE "^  [a-z0-9_-]+:" .github/workflows/ci.yml` lists no
`doc-links` job (control: the same grep lists 30 jobs that do exist).
ACTION:    Rewrite as `[`busbar_kernel::oauth_as::config::AsCfgError`]`. Comment-only.

### X-1902 · `routes.rs` module doc links a `crate::` path that belongs to core
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  Scanned every `[`crate::…`]` link in all 62 slice files against each crate's real
module set; exactly one does not resolve, and the positive control resolves as expected:
```
BROKEN-CRATE-LINK crates/busbar-oauth2/src/routes.rs:6  crate::core_routes::CoreRouter
                  (no `core_routes` module in crates/busbar-oauth2)
--- positive control: a link that DOES resolve ---
crates/busbar-core-admin/src/governance.rs:59: [`crate::verbs::Verbs::create_key`]
```
The file's own `use` statement three lines later is `use busbar_kernel::core_routes::CoreRouter;`
(`:31`), so the prose and the import disagree. Same root cause as X-1901: this file compiled inside
busbar-core before the 1.6.0 extraction, where `crate::core_routes` resolved.
ACTION:    Rewrite as `[`busbar_kernel::core_routes::CoreRouter`]`. Comment-only.

### X-1903 · Eight test files are headed "Tests for `crates/busbar-core/…`", a directory that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls -d crates/busbar-core
ls: crates/busbar-core: No such file or directory        (rc=1)
$ ls -d crates/busbar-core-admin                          # control
crates/busbar-core-admin                                  (rc=0)
$ for f in $(cat .sweep/S10-admin-auth.txt); do grep -Hn "crates/busbar-core/" "$f"; done
crates/busbar-core-admin/src/tests/internal_error_tests.rs:4://! Tests for `crates/busbar-core/src/admin/mod.rs`.
crates/busbar-core-admin/src/tests/key_cap_tests.rs:4://! Tests for `crates/busbar-core/src/admin/mod.rs`.
crates/busbar-core-admin/src/tests/parse_duration_secs_tests.rs:4://! Tests for `crates/busbar-core/src/admin/mod.rs`.
crates/busbar-core-admin/src/tests/reject_overlong_id_tests.rs:4://! Tests for `crates/busbar-core/src/admin/mod.rs`.
crates/busbar-core-admin/src/tests/transport_tests.rs:4://! Tests for `crates/busbar-core/src/admin/transport.rs`.
crates/busbar-core-admin/src/tests/validate_mint_labels_tests.rs:4://! Tests for `crates/busbar-core/src/admin/v1/…`.
crates/busbar-core-admin/src/v1/json/tests/patch_tests.rs:4://! Tests for `crates/busbar-core/src/admin/v1/json/handlers.rs`.
crates/busbar-core-admin/src/v1/tests/service_tests.rs:4://! Tests for `crates/busbar-core/src/admin/v1/service.rs`.
```
Every one is the 1.6.0 extraction's leftover: the subject moved to `crates/busbar-core-admin/src/`
and the header did not follow. A reader sent to the named path finds nothing.
ACTION:    Repoint all eight headers at the real subject file. Comment-only, no code moves.

### X-1904 · `busbar-oauth2/Cargo.toml` prose names `busbar_core` / `busbar-core` throughout
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'name = "busbar_core"' -- '*/Cargo.toml'
                                                          (rc=1 — no such lib)
$ git grep -n 'name = "busbar-oauth2"' -- '*/Cargo.toml'  # control
crates/busbar-oauth2/Cargo.toml:18                        (rc=0)
$ git grep -n "busbar_core::\|busbar-core\b" -- crates/busbar-oauth2/Cargo.toml
:8   # plane's runtime object only through the small seam in `busbar_core::oauth_as::seam`
:16  # which is the forbidden cycle. See `busbar_core::oauth_as` for the full rationale.
:54  # `busbar_core::test_support::TestApp`) resolves for a dependent crate's fixtures, as
```
The manifest's actual dependency edge is `busbar-kernel = { path = "../busbar-kernel" }` (`:33`),
so the prose describes an edge the same file contradicts three lines down. The header comment's
whole subject is the one-way dependency rule, which makes the wrong crate name here more than
cosmetic: it is the rule stated against a crate that does not exist.
ACTION:    Rename to `busbar_kernel::` / `busbar-kernel` in the four comment sites. Comment-only.

### X-1905 · connsec describes itself as a sibling of `busbar-core-oauth2`, a crate that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'name = "busbar-core-oauth2"' -- '*/Cargo.toml'
                                                          (rc=1 — does not exist)
$ git grep -n 'name = "busbar-oauth2"' -- '*/Cargo.toml'  # control
crates/busbar-oauth2/Cargo.toml:18                        (rc=0)
$ for f in $(cat .sweep/S10-admin-auth.txt); do grep -Hn "busbar-core-oauth2" "$f"; done
crates/busbar-core-connsec/Cargo.toml:4:# `busbar-core-oauth2` (DECISIONS #37's core tier):
crates/busbar-core-connsec/src/lib.rs:7://! `busbar-core-admin` / `busbar-core-oauth2`): never a plugin, always linked, off the hot path.
```
Both sites cite the crate as the exemplar of the "core tier" the manifest's own naming ruling (R2,
2026-09-22) is about — and the OAuth crate is precisely the one that did NOT take a
`busbar-core-` prefix. The paragraph arguing the naming rule cites a name the rule produced nowhere.
ACTION:    Rename both to `busbar-oauth2`. Comment-only.

### X-1906 · A read-only admin surface serves a raw serde error over the operator's stored overlay
CLASS:     auth
CERTAINTY: ADJUDICATE
EVIDENCE:  `named_def_views.rs:4-10` states the secret rule as exactly two closed paths. There is
a third field, and it is not collapsed:
```
$ sed -n '92p' crates/busbar-core-admin/src/v1/named_def_views.rs
        unparseable: Some(entry.error.clone()),
```
`entry.error` is `validate_def` → `parse_def`'s message, which interpolates serde's own `Display`:
```
$ sed -n '294,296p' crates/busbar-kernel/src/config/named_map.rs
NamedMapSection::IdentityProviders => serde_json::from_value(def.clone())
    .map_err(|e| format!("invalid `identity-providers.{name}` definition: {e}"))
```
It reaches an unauthenticated-by-scope read:
```
$ sed -n '261,266p' crates/busbar-core-admin/src/v1/service_operations.rs   # the list read
$ grep -n '"/api/v1/admin/identity-providers"' crates/busbar-kernel-scope/src/lib.rs
300:    op("GET", "/api/v1/admin/identity-providers", Scope::ReadOnly),
```
This repo has already ruled that serde's default error is a leak path, in its own words:
```
$ sed -n '216,219p' crates/secret-ref/src/lib.rs
// perfectly ordinary YAML, and each one landed on serde's default `invalid type`
// error — which prints the value it received. The one path this type exists to keep a
// secret off (the boot log) is exactly where it went, and unquoted is the spelling
// nobody thinks to check.
```
**I chased this to ground and NO leak is demonstrable today** — which is why this is ADJUDICATE and
not VERIFIED. Every secret-bearing field on the reachable config types is already protected, by a
property of a DIFFERENT crate:
```
$ # IdentityProviderCfg.token          -> Option<SecretRef>   (non-echoing Deserialize, secret-ref)
$ # BrowserLoginCfg.client_secret      -> Option<SecretRef>   (same)
$ # IdentityProviderCfg.settings       -> serde_json::Map<String, Value>  (accepts anything;
$ #                                       no type error can be raised over its contents)
```
So the finding is the SHAPE, not a present leak: the safety of a read-only admin response rests on
`secret-ref`'s non-echoing deserializer holding for every future secret-bearing field, the module
doc does not mention that dependency, and no test pins it. A future field typed `String` rather
than `SecretRef` reopens it silently, and this is the one surface where that would be served to a
read-only caller rather than written to a log.
ACTION:    Owner ruling. Minimum: amend the `named_def_views.rs` module doc so the rule names THREE
paths and states that the third is safe only because secret-bearing fields are `SecretRef`.
Stronger, and my recommendation: bound `entry.error` to a fixed, non-echoing refusal (the shape
`secret-ref` already uses) and add the test that pins it, so the guarantee stops depending on a
neighbouring crate's deserializer.

### X-1907 · The test that proves create and rotate cannot replay each other never calls the function that makes it true
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The test hand-writes its rotate key as a colon join:
```
$ sed -n '117,119p' crates/busbar-core-admin/src/tests/idempotency_tests.rs
    let cache: IdempotencyCache<String> = IdempotencyCache::new();
    let create_key = key("alice", "shared-header");
    let rotate_key = key("alice", "rotate:key-42:shared-header");
```
The shipped function produces a different string entirely — LENGTH-PREFIXED, which is the whole
point:
```
$ sed -n '94,96p' crates/busbar-core-admin/src/verbs.rs
pub(crate) fn rotate_replay_key(id: &str, header: &str) -> String {
    format!("rotate:{}:{}:{}:{}", id.len(), id, header.len(), header)
}
$ git grep -n "rotate_replay_key" -- '*.rs' | grep "/tests/"
#  (no output; rc=1 — no test anywhere calls it)
$ git grep -c "rotate_replay_key" -- crates/busbar-core-admin/src/verbs.rs   # control
4
```
So the test asserts only that two different `String`s are different `HashMap` keys — true of any
two distinct strings, and not a fact about the code under test. It would stay green if
`rotate_replay_key` were changed to return the bare header, which is exactly the collision its own
comment says "must never" happen because "a rotate's response carries secret material".
NOT AN UNCOVERED PROPERTY: the real thing IS proven, adversarially and end-to-end, at
`crates/busbar-core-admin/src/tests/tests.rs:2583`
(`test_admin_v1_rotate_idempotency_cache_key_does_not_collide_across_colon_joined_ids`), which
crafts the colliding `(id, header)` pair through the live HTTP surface. That is why this is a blind
instrument rather than a hole.
ACTION:    Either build the key through `crate::verbs::rotate_replay_key("key-42", "shared-header")`
so the test acquires a subject, or delete it as redundant against `tests.rs:2583` and say in its
place where the property is actually proven.

### X-1908 · `concurrent_mints_never_bind_a_deleted_group` has a liveness floor of zero
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  One assertion, behind two guards that can both be empty, and the mint results discarded:
```
$ sed -n '355,357p' crates/busbar-core-admin/src/tests/txn_tests.rs
        for m in minting {
            m.await.expect("mint task joins");
        }
$ sed -n '359,364p' crates/busbar-core-admin/src/tests/txn_tests.rs
        for key in g.all_keys().expect("keys readable") {
            if let Some(bound) = key.group.as_deref() {
                assert!(
                    live.groups_registry.contains_key(bound)
                        && live.cost.group_named(bound).is_some(),
$ awk 'NR>=328 && NR<=376 && /assert/' crates/busbar-core-admin/src/tests/txn_tests.rs | wc -l
1
```
`m.await.expect("mint task joins")` asserts that the TASK joined, never that the mint succeeded —
and the helper returns the status precisely so a caller can check it:
```
$ sed -n '139p' crates/busbar-core-admin/src/tests/txn_tests.rs
async fn mint(handle: &Arc<AppHandle>, name: &str, group: Option<&str>) -> StatusCode {
$ grep -n "StatusCode::CREATED" crates/busbar-core-admin/src/tests/txn_tests.rs   # control:
275:        StatusCode::CREATED                       # sibling tests in this file DO assert it
```
If all 8 mints 500'd, `all_keys()` yields nothing group-bound, the loop body never runs, zero
assertions execute and the test is GREEN — reporting "no dangling bind" because nothing was bound.
The sibling `concurrent_rebinds_never_bind_a_deleted_group` (`:378`) has the same shape and is
weaker still: its loop IS non-empty (6 pre-seeded keys on group `"other"`), but `"other"` is never
deleted, and it drops the `cost.group_named(bound).is_some()` half its twin checks.
ADJUDICATE rather than VERIFIED: this is established by source inspection: I did not force the
mints to fail and watch the test stay green, which needs a writable tree this read-only sweep did
not have.
ACTION:    Assert the status of every mint (`assert_eq!(m.await.expect("joins"), StatusCode::CREATED)`)
so the test has a liveness floor, and add the missing `cost.group_named` half to the rebind twin.
Re-run both against deliberately failing mints to confirm they go red before trusting the green.

### X-1909 · One skip-and-return arm reports PASS with no CI guard; twelve others are guarded and are not the finding
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  This slice has 13 `eprintln!("skip: …"); return;` arms. libtest scores a test that
RETURNS as `ok`, so each is a candidate blind spot. **Twelve of them are already guarded upstream,
and I checked that before writing this row rather than after:**
```
$ sed -n '2082,2089p' crates/busbar-kernel/src/test_support/mod.rs
            if std::env::var_os("CI").is_some() {
                panic!(
                    "the hook-test plugin cdylib is not built under CI (checked both the uplifted \
                     target dir and target/deps); refusing to silently skip the hook-plugin \
                     admin/resolution coverage"
                );
            }
            return None;
$ grep -n 'var_os("CI")' crates/busbar-kernel/src/test_support/mod.rs
2083:   2169:
```
So every arm fed by `test_hook_env` / `test_hook_env_with_schema` — `tests/tests.rs:740` and `:853`,
and the ten in `v1/tests/service_tests.rs` (`:36,69,110,1962,2009,2039,2070,2119,2148,2204`) —
PANICS under CI and can only go silently green on a developer's laptop running
`cargo test -p busbar-core-admin` without `--workspace`. Real, but bounded, and the design is
deliberate.

**The thirteenth has no guard of any kind**, and it is the finding:
```
$ sed -n '949,955p' crates/busbar-core-admin/src/v1/tests/service_tests.rs
    // Some environments (containers running as root) ignore permission bits entirely — skip
    // rather than false-fail if `read_dir` still succeeds. `_restore` drops (restoring
    // permissions) when this early return unwinds the scope.
    if std::fs::read_dir(&dir).is_ok() {
        eprintln!("skip: running with privileges that bypass directory permission bits");
        return;
    }
$ grep -n 'var_os("CI")\|var("CI")' crates/busbar-core-admin/src/v1/tests/service_tests.rs \
      crates/busbar-core-admin/src/tests/tests.rs
                                                        (rc=1 — no guard in either file)
$ grep -n 'var_os("CI")' crates/busbar-kernel/src/test_support/mod.rs    # control
2083:  2169:                                            (rc=0 — the pattern does exist)
```
`catalog_unreadable_dir_does_not_serve_stale_cache` chmods a directory to `0o000` and proves the
plugin catalogue does not serve a stale cache when the directory becomes unreadable. Its own comment
names the condition that defeats it — "containers running as root" — and CI jobs here run on
container runners, which is exactly where permission bits are commonly ignored. On such a runner the
test returns at line 954 having asserted nothing and scores `ok`. Unlike the twelve above, nothing
turns that into a failure anywhere.

The file states the correct rule itself, 1,300 lines below, and applies it in exactly one place:
```
$ sed -n '2248p' crates/busbar-core-admin/src/v1/tests/service_tests.rs
    // PANIC, never skip: a rig that skips when the cdylib is absent reports green over the code
    // it was written to cover.
```
ACTION:    Give the privilege skip the same CI guard the cdylib helper already has — `panic!` when
`CI` is set, naming the runner's privilege as the reason the coverage was lost. Whether the twelve
laptop-only arms should also become hard panics is a separate, lower-priority call for the owner;
they are already safe where it counts.

### X-1910 · `tests.rs` cites a test that does not exist, and carries an orphaned doc block
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "fn declared_error_set_has_no_over_claim" -- '*.rs'
                                                              (rc=1 — no such test)
$ git grep -n "fn declared_error_set_is_exactly_what_the_handlers_emit" -- '*.rs'   # control
crates/busbar-core-admin/src/tests/tests.rs:12855                 (rc=0)
$ sed -n '11670,11671p' crates/busbar-core-admin/src/tests/tests.rs
// `declared_error_set_has_no_over_claim` (in the json tests) can assert that every documented error
// is a real one. A declared 409 nobody can trigger is a lie in the contract; this is how it stays
```
The comment is the load-bearing justification for the whole witness-driver block — it explains WHY
the driver exists — and it sends the reader to a name that appears nowhere, and to the wrong file:
the real assertion is 1,185 lines below it in this same file, not "in the json tests".
Separately, `tests.rs:722-734` has two `///` doc blocks on one item with `#[cfg(unix)]` wedged
between them; the first describes hook registration / GET-sees-it / invalid-definitions-reject and
belongs to a test that is gone, leaving it glued to its neighbour.
ACTION:    Repoint the citation at `declared_error_set_is_exactly_what_the_handlers_emit` and say
"below in this file". Delete the orphaned doc block at `:722-727`. Comment-only.

### X-1911 · Two contract tests are compiled out by default and filtered out by the one job that would compile them
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  Both are gated on a NON-default feature:
```
$ sed -n '408,411p' crates/busbar-core-admin/src/v1/json/tests/tests.rs
#[cfg(feature = "openapi-schema")]
#[test]
fn restart_request_body_is_documented_optional() {
$ sed -n '544,546p' crates/busbar-core-admin/src/v1/json/tests/tests.rs
#[cfg(feature = "openapi-schema")]
#[test]
fn declared_errors_is_total_and_well_formed() {
$ grep -n "^default = " crates/busbar-core-admin/Cargo.toml
64:default = ["auth-admin-tokens", "hooks-ranking", "plane-mcp", "plane-a2a"]
```
So `cargo test --workspace` (`ci.yml:935`) compiles them out entirely. The ONLY job that enables the
feature then filters by test-name substring, and neither name — nor their module path
`v1::json::tests::` — contains it:
```
$ sed -n '1270p' .github/workflows/ci.yml
          out="$(cargo test -p busbar -p busbar-kernel -p busbar-core-admin --features openapi-schema --locked openapi -- --nocapture …)"
$ git grep -n 'restart_request_body_is_documented_optional\|declared_errors_is_total_and_well_formed' -- .github xtask scripts qa
                                                              (rc=1 — named nowhere in CI)
$ git grep -n 'openapi_json_matches_committed_file' -- .github   # control: a name that IS matched
3 hits                                                        (rc=0)
```
Proven EMPIRICALLY, not just by reading, by listing the test binary three ways and differencing the
sets (`cargo test … -- --list` under default features, under `--features openapi-schema`, and under
the CI filter):
```
### SET ARITHMETIC — v1::json::tests ###
exists with openapi-schema ON  : 18
runs in default workspace run  :  4
selected by CI 'openapi' filter: 12

### THE ORPHANS: exist under the feature, absent from BOTH runs ###
v1::json::tests::declared_errors_is_total_and_well_formed: test
v1::json::tests::restart_request_body_is_documented_optional: test
### control: the same comm leaves no residue for `emit_openapi_artifact`, which IS covered ###
```
`grep -rn -- '--all-features' .github/workflows/ xtask/src/ scripts/` finds only prose explaining
why `--all-features` is NOT used, so there is no unfiltered feature-on run anywhere to catch them.

The job's own `n < 8` floor cannot notice, because it counts tests that ran, not tests that exist —
and its comment says the floor is there so "a filter that quietly collapsed to a single surviving
test would still be a coverage hole". The filter has not collapsed: 12 tests in this file alone
still match, so the floor passes comfortably while these two have never executed.

A second, compounding fault: the doc comment immediately above `declared_errors_is_total_and_well_formed`
(`:542-545`) ends "Cheap, **always-on**, and it makes a typo'd table entry impossible rather than
merely unlikely." It is neither always-on nor ever run. This is the 4xx refusal-taxonomy totality
check claiming coverage it does not have.

What is lost is not cosmetic. `restart_request_body_is_documented_optional` is the only check that
`POST /api/v1/admin/restart` is not documented `"required": true` — the comment above it states that
a generated client honouring that would refuse to emit the call the server supports.
`declared_errors_is_total_and_well_formed` is the totality check on the error taxonomy.
ACTION:    Add both names to the `openapi-schema` job's filter (or rename them to contain `openapi`,
which the job's filter convention already implies), and raise the `n` floor in the same commit so
the two newly-running tests are pinned. Do not simply lower the floor.

### X-1912 · A hardened-surface test in `v1/json/tests/tests.rs` can check nothing and still pass
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `openapi_summaries_do_not_advertise_forbidden_body_fields` (`:704`) puts EVERY assertion
inside `for name in &known` (`:744`), where `known` is built by a scan (`:712-721`) that `continue`s
on any schema whose `additionalProperties` is not `false`, and the outer loop additionally
`continue`s on any operation with no `$ref` request body (`:729-733`). Nothing asserts `known` is
non-empty, and nothing counts the operations examined. If schemars stopped emitting
`additionalProperties: false`, `known` empties, the loop body never runs, and the test reports
that no summary advertises a forbidden body field — because it looked at none.

This is an outlier in its own file, not house style. Every sibling carries a floor:
```
$ grep -nE 'assert!\(!paths\.is_empty|op_count >= 30|with_body >= 28|assert_eq!\(declared, 27' \
      crates/busbar-core-admin/src/v1/json/tests/tests.rs
142:    assert!(!paths.is_empty(  …
480:    …op_count >= 30…
482:    …with_body >= 28…
694:    assert_eq!(declared, 27…
$ sed -n '744p' crates/busbar-core-admin/src/v1/json/tests/tests.rs   # the unfloored one
        for name in &known {
```
`declared_errors_is_total_and_well_formed` (`:552-590`) has the same unfloored nested-loop shape on
top of never running at all (X-1911). A lesser instance: `openapi_doc_is_31_and_v1_prefixed` (`:74`)
iterates `doc["paths"].as_object().unwrap().keys()` with no `!is_empty()` guard, while its sibling
at `:142` has exactly that guard.
ACTION:    Add a liveness floor to `:704` — `assert!(!known.is_empty(), …)` plus a count of
operations examined, matching the `op_count >= 30` shape its neighbours already use. Same for
`:552` and `:74`.

### X-1913 · Two of `merge_group_patch`'s four branches are never exercised as `Some`
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The function has four independent arms:
```
$ sed -n '1685,1696p' crates/busbar-core-admin/src/v1/json/handlers.rs
    if let Some(p) = parent {            base.parent = Some(p); }
    if let Some(en) = enabled {          base.enabled = en; }
    if let Some(l) = limits {            base.limits = l; }
    if let Some(cd) = child_default {    base.child_default = Some(cd); }
```
All three call sites in the whole repo pass `None` for `parent` (arg 2) and `child_default` (arg 5):
```
$ grep -n "merge_group_patch" crates/busbar-core-admin/src/v1/json/tests/patch_tests.rs
30:    let out = merge_group_patch(base,         None, None,        Some(vec![budget(5_000)]), None);
49:    let out = merge_group_patch(base,         None, Some(false), None,                      None);
66:    let out = merge_group_patch(base.clone(), None, None,        None,                      None);
```
Deleting `base.parent = Some(p);` or `base.child_default = Some(cd);` leaves all three tests green.
`patch_enabled_only_freezes_without_touching_limits` does assert `child_default` is PRESERVED when
the argument is `None` (`:54`), which is the other half — but the SET path is unproven on both arms.
On a group PATCH, `parent` is a re-homing and `child_default` is the template new leaves inherit
their limits from, so these are not incidental fields.
ACTION:    Add two cases passing `Some(..)` for `parent` and for `child_default`, asserting the
field is written. Six lines; the fixtures already exist in the file.

### X-1914 · A money test asserts the half of its claim that costs nothing and skips the half that matters
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The doc claims the limits go LIVE; the body never reads a limit back:
```
$ sed -n '1383,1385p' crates/busbar-core-admin/src/v1/tests/service_tests.rs
/// `build_with_group` creates a valid leaf, bumps the version, and rebuilds the cost model so the
/// new group's limits are live in the enforcement projection (the "raise a user's budget" path).
$ sed -n '1390,1404p' crates/busbar-core-admin/src/v1/tests/service_tests.rs
        limits: vec![budget(3_000, LimitWindow::Month)],
        …
    assert!(leaf.parent.is_some(), "leaf's parent chain resolved");
    assert!(next.cost.group_named("team").is_some());
```
`3_000` is written and never read. The test proves the leaf EXISTS in the cost model and that its
parent chain resolved; it does not prove the budget reached the enforcement projection, which is
the sentence its own doc leads with and the reason an operator runs the "raise a user's budget"
path. A leaf that materialised with a zero or defaulted cap would pass.
The stronger assertion is available and a sibling in this same file already makes it:
```
$ sed -n '1680p' crates/busbar-core-admin/src/v1/tests/service_tests.rs
    assert_eq!(month.budget_cap, Some(1_000));
```
NOT a money-correctness row and NOT a billed byte: the arithmetic under test is elsewhere and is
covered (this file's money assertions are otherwise strong — `39_000`, `24_000`, `19_000`,
`750_090_000`, `spend_cents == 2`, all literal expecteds, and `every_money_read_in_this_crate_is_registered`
carries an explicit `assert!(!found.is_empty(), "the scan is broken, not the crate")` floor). This
row is only that one instrument under-claims against its own docstring.
ACTION:    Read the cap back: `assert_eq!(leaf.buckets[..].budget_cap, Some(3_000))` in the shape
`:1680` already uses. Two lines.

## OUTSIDE MY SLICE — reported, not acted on
* **There is no rustdoc / `doc-links` gate in this repo at all.**
  `git grep -rn "broken_intra_doc_links|rustdoc|cargo doc" -- .github/ xtask/ scripts/` → rc=1
  (control: the same command finds 30 named jobs in `ci.yml`). This is what let X-1901 and X-1902
  ship. A `cargo doc -D broken_intra_doc_links` job would have caught both at zero cost. Worth a
  row in whichever slice owns `.github/workflows/ci.yml`.
* **`busbar-contract/src/grammar.rs:366 Claim::is_anonymous()` has zero callers.**
  `git grep -n "is_anonymous" -- '*.rs'` returns only the definition. Production asks the same
  question inline instead (`crates/busbar/src/root/units_mcp.rs:1812 claim.scheme.is_none()`,
  `busbar-plane-a2a/src/tests/surface.rs:196`). A `pub fn` on the ABI crate duplicating an
  expression nothing routes through. Belongs to the `busbar-contract` slice.
* **`crates/busbar/src/root/units_admin/mod.rs:911-949`** is the other half of X-1900. The stub
  `Governance` impl is correct GIVEN the routing, so the fix belongs with whichever direction the
  owner picks for X-1900 — but that file must change either way.
* `crates/busbar-core-admin/src/tests/rate_tests.rs`, `src/posture.rs`, `src/rate.rs`,
  `src/verbs.rs`, `src/v1/service.rs`, `src/v1/service_operations.rs`, `src/v1/json/handlers.rs`
  and `src/v1/json/named_map.rs` are in this crate but NOT in my file list. I read into several of
  them as evidence and raised nothing against them; they still need their own slice's verdict.

## TALLY
```
files in slice:  62
verdict lines:   62
CLEAN:           37
FINDING:         25     rows raised: 15  (X-1900 .. X-1914)
DELETABLE:        0
UNREADABLE:       0
```
By class: missing-code 1 · drift 6 · auth 1 · instrument-blind 7 · (X-1900 also carries auth weight).
By certainty: VERIFIED 13 · ADJUDICATE 2 · PARK 0.
No money row: this slice holds no `nanos`/`cents`/`micros` arithmetic. The one money edge
(`busbar-kernel-ledger`, named by `busbar-core-admin/Cargo.toml:41` for the usage read) is
`busbar-kernel-ledger`'s own, and belongs to S12-MONEY. **No billed byte was self-approved.**
