# S06-scripts — sweep verdicts

Slice: `scripts/` (100 tracked files, the denominator of this report — every one gets exactly one
verdict line below, in slice order). Repo `/Users/matthew/Developer/GetBusbar/busbar`, branch
`consolidated/1.6.0`, swept 2026-09-23.

Two questions dominated this slice, and both are answered per file with a command:

1. **Is it invoked by ANYTHING?** Every reachability claim here is a `git grep` over
   `.github qa xtask crates scripts Makefile testing` — the places that can actually run a script —
   and every zero carries a positive control (the same grep shape on `release-check.sh`, which is
   invoked from `ci.yml:515` and `qa/full-gate.toml`, returning 122 hits). A mention in `docs/` is
   not an invocation and is not counted as one.
2. **Can it produce a NO?** Where a script ships a `--selftest`, I ran it; where it does not, I
   found the input that makes it red, or recorded that I could not. Eighteen offline selftests were
   executed for this report. Two of them came back RED on the tree as it stands.

X-id block: **X-1500 .. X-1599**. Thirty-two raised, none outside the block.

| FILE | VERDICT | EVIDENCE | ROWS |
|------|---------|----------|------|
| `scripts/a2a-subject/binding-shim.mjs` | CLEAN | `git grep -n -F 'binding-shim.mjs' -- .github qa xtask crates scripts testing` -> real invocation `scripts/a2a-subject/boot.sh:713 node scripts/a2a-subject/binding-shim.mjs`; `git grep -nE 'run:.*boot\.sh' -- .github` -> qa-conformance-a2a.yml:701/716/730. Attaches `Authorization: Bearer` ONLY when the request carries none (`:79`,`:156`); no verifier, no token in any log line. | - |
| `scripts/a2a-subject/h2-admit-refusal.sh` | FINDING | read: asserts 429 + body contains 'budget is spent' + `egress_delta_on_refusal -eq 0` + `req_mid -eq req_after`. Exact codes, exact deltas -> red-capable. BUT `grep -c 'egress' scripts/a2a-subject/h2-admit-refusal.sh` -> 6, `grep -c 'egress.*-gt 0'` -> 0: the only egress assertion is delta==0, which is also what a dead capture instrument prints. | X-1506 |
| `scripts/a2a-subject/h2-audit-record.sh` | CLEAN | read: `exactly one new admin audit entry, action agent.call, outcome applied, resource agent:probe`; the python filters on seq>since AND action AND outcome AND resource. `git grep -n -F 'h2-audit-record.sh' -- .github qa crates` -> ci.yml, qa/teller-steps.json, crates/busbar/src/root/tests/units_a2a.rs. | - |
| `scripts/a2a-subject/h2-card-epoch.sh` | CLEAN | read: asserts total==8 and NAMES the two wrong answers it is distinguishing (14 = newest-card reprice, 2 = opening-forever). Verified the cited field exists: `git grep -n 'spend_micros' -- crates` -> crates/busbar-core-admin/src/v1/json/openapi.json:1504 + tests/tests.rs:686. | - |
| `scripts/a2a-subject/h2-class-price.sh` | FINDING | read `sed -n '45,115p'`: leg (3) reads `spend_micros` then uses it ONLY inside `if [ "$failures" -ne 0 ]`. There is no code path that compares it to count x rate. With (1) and (2) green the script prints PASS claiming `the row charged count x rate + fee` having computed nothing. | X-1507 |
| `scripts/a2a-subject/h2-exit-terminal.sh` | CLEAN | read: `req_delta -eq 2` and `audit_rows -eq 2` for two served units -- exact, so both a drop and a double-post are red. | - |
| `scripts/a2a-subject/h2-ledger-unconditional.sh` | CLEAN | read: the CONTROL arm is read FIRST and, when red, the script says in its own failure text that `the claim arm below is NOT evidence of anything`. Both arms drive the same binary; `H2_RATE_CARD_YAML=' '` is a real card-absent config (`git grep -n H2_RATE_CARD_YAML -- scripts` -> set at :75, consumed at h2-lib.sh:115). | - |
| `scripts/a2a-subject/h2-lib.sh` | FINDING | `ls scripts/a2a-subject/h2-mock-agent.py` -> No such file or directory, yet `:7` and `:62` name it; `:63` says `pin: unpinned` while `:115`-`:122` writes `pin: { mechanism: jws_issuer_key }` and the file's own header (`:11`-`:17`) explains at length why unpinned CANNOT be used. Positive control: the sibling `scripts/mcp-subject/h2-lib.sh:7` names `h2-mock-upstream.mjs`, which exists. | X-1505 X-1530 |
| `scripts/a2a-subject/h2-meter-row.sh` | CLEAN | read: `req_delta -eq 1`, `spend_delta -eq 1`, `row_requests = 1` -- three exact assertions on two different write paths (admission counter and metering series), and the failure text names `'-' means the meter wrote no row at all`. | - |
| `scripts/a2a-subject/h2-mock-agent.mjs` | FINDING | `:103`-`:105` ends captureEgress with a bare `} catch { /* best-effort */ }`; the consumer `h2-lib.sh:335 h2_egress_count()` reads the capture as a file count, so a silently failed capture returns 0 -- the PASS value. Separately `:14`-`:16` claims it `borrows that EXACT canonicalization (jcs) and signing shape (signCard) rather than re-deriving it`, but `grep -n '^import' scripts/a2a-subject/h2-mock-agent.mjs` -> 4 node builtins only, and `grep -n export scripts/a2a-subject/signing-vendor.mjs` -> only a key `.export()`, no module export: jcs/signCard are a verbatim copy. | X-1505 X-1506 |
| `scripts/a2a-subject/h2-route-failover.sh` | CLEAN | read `sed -n '25,75p'`: 8 down-agent calls, requires a 503 carrying UNSUPPORTED_OPERATION, zero further egress after the trip, AND -- the part the four sibling refusal legs lack -- an explicit positive control on the same instrument, `[ "$(h2_egress_count)" -gt 0 ]` for before the trip. This leg would notice the swallowed capture X-1506 names. | - |
| `scripts/a2a-subject/h2-unpriced-refuses.sh` | FINDING | read `cat`: ARM 1 requires exactly 200 and exactly spend_cents=1. ARM 2's `*)` arm fails ONLY `if [ "$on_status" = "200" ]` -- every other value passes, including curl's `000` for a call that never completed. `diff scripts/a2a-subject/h2-unpriced-refuses.sh scripts/mcp-subject/h2-unpriced-refuses.sh` -> prose only; the logic is identical in both. | X-1508 |
| `scripts/a2a-subject/h2-verify-refusal.sh` | FINDING | read: 403 + body contains 'not granted' + zero usage delta -- exact. `grep -c 'egress.*-gt 0' scripts/a2a-subject/h2-verify-refusal.sh` -> 0: the egress assertion is `egress_after -eq egress_before` only. | X-1506 |
| `scripts/a2a-subject/signing-vendor.mjs` | CLEAN | read: generates a real ed25519 pair, writes only the SPKI public half to `keyOut`, signs the card with RFC-8785 JCS over `b64url(protected).b64url(payload)` -- the shape `a2a/jws.rs` verifies. `git grep -l -F A2A_VENDOR_RECORD -- scripts` -> boot.sh + this file, so the optional recorder is wired and off by default. | - |
| `scripts/bare-bones-build.sh` | DELETABLE | `git grep -n -F 'bare-bones-build' -- .github qa xtask crates scripts Makefile testing` -> 1 hit, its own line 5. Repo-wide -> 3, the other two in docs/. Positive control, same grep shape on `release-check.sh` -> 122 hits incl. `ci.yml:515 run:`. Coverage is not lost: `xtask/src/full_gate.rs:99` still runs `cargo build --no-default-features --locked` workspace-wide. | X-1531 |
| `scripts/bolt-pass.sh` | CLEAN | `bash scripts/bolt-pass.sh --selftest` -> rc=0 `bolt-pass self-test: PASS.`; `bash scripts/bolt-pass.sh` with no args -> rc!=0, `FAILED (FAIL-CLOSED): --binary is required`. Invoked at `.github/workflows/manual-bolt-pass.yml`. Minor: `:15` names `.github/workflows/bolt-pass.yml`; `ls .github/workflows/bolt-pass.yml` -> No such file (the file is `manual-bolt-pass.yml`). | - |
| `scripts/build-provenance-gate.sh` | CLEAN | `bash scripts/build-provenance-gate.sh --selftest` -> rc=0 `[selftest] PASS`; bare invocation -> rc=2 with `the old --line <stamp> mode was REMOVED. A stamp handed in on the command line is not evidence about any binary` -- it refuses the vacuous input by name. Live at `ci.yml`, `docker.yml`, `qa/full-gate.toml`, `xtask/src/full_gate.rs`. | - |
| `scripts/capability-equality-summary.py` | FINDING | `python3 scripts/capability-equality-summary.py` -> rc=0 and prints `EQUALITY: 0 of 91 cells missing (65 proven, 26 n/a) -- LLM == MCP == A2A is not yet true, and this line names where:` followed by nothing. The clause is hardcoded into the f-string at `:149`, outside the `if missing:` at `:151`. `xtask/src/full_gate.rs:779` prints this verbatim. | X-1529 |
| `scripts/check-proof-manifest-public.mjs` | CLEAN | `node scripts/check-proof-manifest-public.mjs --selftest` -> rc=0, 10 cases including `REFUSED: an empty manifest set` and `REFUSED: a leaked bearer token`. Live at `ci.yml` and `qa/full-gate.toml`. | - |
| `scripts/ci-images.py` | FINDING | `python3 scripts/ci-images.py --selftest` -> **rc=1** `SELFTEST FAILED: the repository is already RED, so a mutation proves nothing. mysql:8 is pinned in one workflow but reached by neither pin nor mirror in release-stage.yml`; `--list` -> rc=1 and NO JSON on stdout. `git grep -ni mysql -- .github/workflows/release-stage.yml` -> empty. Live at `.github/workflows/sched-ci-images-mirror.yml`, which triggers on push to dev/main touching ci.yml. | X-1514 |
| `scripts/ci-runner-bootstrap.sh` | FINDING | `grep -n '^set ' scripts/ci-runner-bootstrap.sh` -> `17:set -uxo pipefail` (no -e); the last two statements (`:298`-`:299`) are an unconditional `touch /var/run/busbar-runner-ready` + `echo BOOTSTRAP COMPLETE`, and the pre-warm above them carries `\|\| true`. The marker HAS a consumer: `scripts/ci-runners-reconcile.sh:258` prints `ready=yes/NO` from it. | X-1523 |
| `scripts/ci-runners-down.sh` | FINDING | ran the `--all` ghost-sweep shape: `gh api ... 2>/dev/null \| while read` under `set -uo pipefail` with no `set -e` -> loop body ran 0 times, nothing printed, script exit status 0. Positive control: the non---all path reports `$SWEPT_GHOSTS` (lib.sh:326), so the more thorough path is the blinder one. `git grep -n -F 'ci-runners-down' -- .github qa xtask` -> no `run:` anywhere (operator tool). | X-1522 |
| `scripts/ci-runners-lib.sh` | CLEAN | `git grep -n -F 'ci-runners-lib.sh' -- scripts` -> sourced by down/register/ssh/up/reconcile/selftest/cost-watch. Uncalled-function scan over every `^[a-z_]*()` definition -> zero uncalled. `n_of()` at `:106` explicitly handles the `grep -c`-exits-1-on-empty trap with `\|\| true`; `sweep_ghost_runners` feeds its loop from a heredoc so the counter survives; `register_agents` never prints the token. | - |
| `scripts/ci-runners-lint.sh` | CLEAN | `git grep -n -F 'ci-runners-lint' -- .github qa xtask crates scripts` -> no caller (documented manual tool at `docs/ci/self-hosted-runners.md:112`). All nine lint targets exist (`ls` each -> present); both checks set `rc=1`; a missing shellcheck is `exit 2`, not a skip -- so it cannot pass by not running. | - |
| `scripts/ci-runners-register.sh` | CLEAN | `git grep -n -F 'ci-runners-register' -- .github` -> only `.github/actionlint.yaml`. `register_agents $ONLINE \|\| die` is a real red path; the registration token is never echoed (verified by running the live path against a `gh` stub: the token value does not appear in stdout). | - |
| `scripts/ci-runners-selftest.sh` | FINDING | ran case D with a `gh` stub whose token is `SELFTESTTOKENVALUE`: the dry-run path prints `[dry-run] gh api -X POST ...` and `register_agents` returns at `lib.sh:380` BEFORE gh runs, so the token can never appear. Positive control, same stub with `CI_RUNNER_DRY_RUN=0` -> `minted a registration token (not printed, expires in ~60 min)`, i.e. gh IS called on the live path case D never reaches. | X-1520 |
| `scripts/ci-runners-ssh.sh` | FINDING | `sed -n '95,105p'`: `aws ec2 revoke-security-group-ingress ... >/dev/null 2>&1 \|\| log "  (revoke reported nothing to do)"` -- `\|\| log` on the command whose failure IS the signal, with the reason discarded, and the message asserts the opposite of what happened. The header calls this load-bearing (`an open port on a box that executes arbitrary branch code`). Positive control: `lib.sh:403` tests the identical `ssm_wait` result with `case ... *Failed*\|*TimedOut*) return 1`. | X-1521 |
| `scripts/ci-service-endpoints.sh` | CLEAN | `git grep -n -F 'ci-service-endpoints.sh' -- .github` -> 6 real `run:` lines (ci.yml:843/2746/3212, manual-keep-proof.yml:229/670, oracle-proof.yml:116). `set -euo pipefail`; the one `2>/dev/null` (on `addr_of`) is immediately followed by the emptiness test that IS the verdict. | - |
| `scripts/deferral-words.py` | DELETABLE | `git grep -n -F 'deferral-words' -- .github qa xtask crates scripts Makefile` -> 0 invocations (only its own docstring at `:2`,`:36`-`:41`). Positive control, same grep on `release-check.sh` -> 111 hits. Its default mode also cannot red (`for ...: print(...)` then `return 0`; measured 1434 hits, rc=0). `docs/design/1.6.0-TRACKER.md:198` already records `it is invoked by NOTHING`, and LEDGER G56 rules the metric cannot be a gate. | X-1531 |
| `scripts/documented-claims-check.py` | CLEAN | `python3 scripts/documented-claims-check.py` -> rc=0, `GREEN -- 56 claims ... 33 pinned by a recorded cell`. Its arm 4 (`:121`-`:127`) genuinely discriminates: I measured 1402 ids present in cells.json and absent from the golden PASS set, any one of which makes it red. | - |
| `scripts/documented-claims-check.sh` | FINDING | `bash scripts/documented-claims-check.sh --selftest` -> **rc=1**, `FAIL  a cited cell the golden never recorded is caught (rc=0, expected a red naming 'never recorded')`. `qa/segments.toml:418` runs `--selftest && --check`, so this segment is RED today. | X-1502 |
| `scripts/executable-config-lint.py` | CLEAN | `python3 scripts/executable-config-lint.py --selftest` -> rc=0, 3/3 fixture groups, 8 RED fixtures flagged by the real binary and the waiver-expiry cases red. Real run `--root . --min-docs 90` -> rc=0, 105 judged / 0 failed -- the `--min-docs` floor means `scanned nothing` cannot read as clean. Live at `ci.yml:1704,1718` and `plugin-ci.yml`. | - |
| `scripts/extract-inline-tests.py` | DELETABLE | `git grep -n -F 'extract-inline-tests' -- .` -> 2 hits, both filename listings in `docs/design/sweep/DENOMINATOR.md`. Its only caller is its own sibling `.sh`, which is itself uncalled. Positive control: same grep on `qa-segments.sh` -> `ci.yml:654 run:` + `qa/full-gate.toml:65 script=`. | X-1531 |
| `scripts/extract-inline-tests.sh` | DELETABLE | same grep as above -> zero callers outside `scripts/extract-inline-tests.py`. `bash scripts/extract-inline-tests.sh --selftest` -> rc=0 `GREEN (10 cases)` -- a working instrument that nothing runs. | X-1531 |
| `scripts/fixtures/auth-github-wiremock/token.json` | CLEAN | `git grep -n -F 'fixtures/auth-github-wiremock' -- . ':!docs'` -> 1 hit, `scripts/release-check-1.5.2.sh:965 -v ${REPO_ROOT}/scripts/fixtures/auth-github-wiremock:/home/wiremock/mappings:ro`, and that script is invoked from `scripts/release-check.sh:1728`. Stub token `gho_test` is a fixture value, not a credential. NOT used by plugin-ci.yml -- that workflow boots its own wiremock and the plugin's `tests/e2e.rs` arms it. | - |
| `scripts/fixtures/auth-github-wiremock/user-orgs.json` | CLEAN | same mount as above (one `-v` covers the whole directory as WireMock's `mappings`). Shape is a valid WireMock stub mapping (priority/request.urlPath/response.jsonBody); `/user/orgs` is the path `auth-github` reads for group membership. | - |
| `scripts/fixtures/auth-github-wiremock/user.json` | CLEAN | same mount. `/user` -> `{login: octotest, id: 12345}` is the identity the token-exchange flow asserts on. | - |
| `scripts/fixtures/auth-ldap/seed.ldif` | CLEAN | `git grep -n -F 'fixtures/auth-ldap' -- . ':!docs'` -> `scripts/release-check-1.5.2.sh:200` (comment) and `:1118` (`-v .../scripts/fixtures/auth-ldap:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro`). `userPassword: alicepassword` is a throwaway fixture credential in a hermetic container. The `seeAlso`-as-group_attr choice is stated and reasoned in the file. | - |
| `scripts/gate-mutants.sh` | CLEAN | `bash scripts/gate-mutants.sh --selftest` -> rc=0 `all cases green`, and the case list names the red directions explicitly (`one surviving mutant is red`, `a timed-out mutant is red, not forgiven`, `a red baseline is red`, `a shard that produced no output at all is red`). `grep -n '^set '` -> `45:set -uo pipefail` (no -e), so the `grep -c . "$caught"` at `:217`-`:220` cannot abort the script when a file is empty, and 0 is the correct reading there. Live at `.github/workflows/gate-mutants.yml` and `xtask/tests/gate_mutation_proof.rs`. | - |
| `scripts/history-rewrite-empty-bodies.sh` | FINDING | `PATH=/bin:/usr/bin /bin/bash scripts/history-rewrite-empty-bodies.sh --selftest` -> rc=2, dying silently at the dry-run case; isolated cause `/bin/bash -c 'f(){ local -A m=(); }; f'` -> `local: -A: invalid option`, rc=2 (macOS /bin/bash is 3.2.57). `local -A` at `:189`,`:210` and `${MAP_NEW[-1]}` at `:286` are bash-4-only; the shebang is `#!/usr/bin/env bash` with no version guard. Positive control: the same file under bash 5.3 reaches `SELFTEST: ALL GREEN`. The three refusal cases PASS under 3.2 because they abort before the first associative array, so the failure reads as partially green. | X-1528 |
| `scripts/loom.sh` | CLEAN | `bash scripts/loom.sh --selftest` -> rc=0 `loom gate selftest: GREEN (4 cases)`. `:81` uses `out=$(cargo test ... 2>&1) && status=0 \|\| status=$?`, which is the correct form (not `RC=$?` after a pipe). Live at `ci.yml`, `qa/full-gate.toml`, and cited from `crates/busbar-kernel/src/config/transaction.rs`. | - |
| `scripts/mcp-conformance.sh` | CLEAN | `bash scripts/mcp-conformance.sh --selftest` -> rc=0 `self-test: 14 fixture(s) passed`. Read `sed -n '355,400p'`: `assert_covered "$out"` runs BEFORE the exit code is honoured (`An armed run that executed nothing is the state the skip above would otherwise rot into`), the battery leg is `NO LONGER SKIPPABLE`, and the stale-report fallback was removed by name. `[ -f qa/mcp-conformance-baseline.yml ] && baseline=(...)` is safe under `set -e` -- measured: `bash -c 'set -euo pipefail; b=(); [ -f /no/such ] && b=(--x); echo REACHED'` -> REACHED, rc=0. | - |
| `scripts/mcp-fixture-absence-gate.sh` | CLEAN | `bash scripts/mcp-fixture-absence-gate.sh --selftest` -> rc=0 `self-test: 9 fixture(s) passed`, and the cases are floors, not smoke: `a collapsed forbidden set was accepted` is a MISS, `discovery finds N forbidden identifier(s) in this tree` is a GREEN floor, and RED 5 re-runs the OLD process-substitution shape so the floor-reaches-the-caller property cannot pass by accident. | - |
| `scripts/mcp-subject/boot.sh` | FINDING | `grep -n '^set ' scripts/mcp-conformance.sh scripts/mcp-subject/boot.sh scripts/a2a-subject/boot.sh` -> mcp-conformance.sh:78 and a2a-subject/boot.sh:149 set `-euo pipefail`; mcp-subject/boot.sh (1186 lines) sets nothing. It relies on inherited `pipefail` at e.g. `:135`-`:138`, where `node tool-digest.mjs \| sed >> file \|\| die` makes `die` unreachable without it. | X-1527 |
| `scripts/mcp-subject/client-arm.sh` | CLEAN | `git grep -n -F 'client-arm.sh' -- scripts` -> `mcp-conformance.sh:523 MCP_SUBJECT_CLIENT_CMD="bash $(pwd)/scripts/mcp-subject/client-arm.sh ..."`. It is a DRIVER, not an asserter -- the conformance suite judges the peer's transcript -- so its `curl ... \|\| true` is correct rather than a swallowed verdict. | - |
| `scripts/mcp-subject/credential-shim.mjs` | CLEAN | `git grep -n -F 'credential-shim.mjs' -- scripts` -> `mcp-subject/boot.sh:1155 node scripts/mcp-subject/credential-shim.mjs`. Attaches the bearer only when absent (`:51`-`:52`); contains no verifier, so there is no unreachable-failure path; the error path logs the upstream host and the exception, never the token. | - |
| `scripts/mcp-subject/diagnostic-upstream.mjs` | FINDING | `:495`-`:497` accumulates the body as `let raw = ""; req.on("data", c => (raw += c))`, which decodes each Buffer independently. Measured: a two-byte UTF-8 char split across chunks -> `\ufffd\ufffd` (efbfbdefbfbd) under string concat vs `e9` correct under `Buffer.concat`. Positive control: the sibling `scripts/mcp-subject/h2-mock-upstream.mjs:71` does `Buffer.concat(chunks).toString('utf8')`. | X-1526 |
| `scripts/mcp-subject/h2-admit-refusal.sh` | FINDING | `diff scripts/a2a-subject/h2-admit-refusal.sh scripts/mcp-subject/h2-admit-refusal.sh` -> 25 prose lines, identical logic. `grep -c 'egress.*-gt 0' scripts/mcp-subject/h2-admit-refusal.sh` -> 0. | X-1506 |
| `scripts/mcp-subject/h2-audit-record.sh` | CLEAN | `diff` against the a2a twin -> 22 prose lines. Same exact-row assertion (one new entry, action/outcome/resource all pinned). | - |
| `scripts/mcp-subject/h2-authenticate-refusal.sh` | CLEAN | read `sed -n '30,85p'`: the strongest leg in the family. Three refusals (no credential, garbage bearer, wrong audience) each require exactly 401, an EXPLICIT positive control requires the right-audience bind to be 200 (`otherwise the three refusals above are equally consistent with a busbar that refuses everything`), and `egress_delta -eq 1` pins that only the admitted control reached the upstream -- which is also a live positive control for the capture instrument X-1506 names. | - |
| `scripts/mcp-subject/h2-card-epoch.sh` | CLEAN | `diff` against the a2a twin -> 55 lines, prose + plane nouns. Same 1+7=8 arithmetic and the same two named wrong answers. | - |
| `scripts/mcp-subject/h2-class-price.sh` | FINDING | `grep -n 'spend_micros\\|failures -ne 0' scripts/mcp-subject/h2-class-price.sh` -> `:100` reads it, `:102` uses it only inside the `-ne 0` branch, `:105` prints PASS. Identical structure to the a2a twin. | X-1507 |
| `scripts/mcp-subject/h2-exit-terminal.sh` | CLEAN | `diff` against the a2a twin -> 14 prose lines. Exactly-2 deltas on both surfaces. | - |
| `scripts/mcp-subject/h2-ledger-unconditional.sh` | CLEAN | `diff` -> 18 prose lines. Control-first structure preserved. | - |
| `scripts/mcp-subject/h2-lib.sh` | FINDING | `sed -n '1,30p'` -> header names `h2-mock-upstream.mjs`, which exists; no `.py` citation (`grep -rn '\.py\b' scripts/mcp-subject/*.sh` -> no hits). `h2_validate_card` uses `res=$(...); rc=$?` on a command substitution assignment (correct) and refuses the substring match `config valid` by name because it is contained in `config validation failed`. Flagged only for reachability: `git grep -nE 'run:.*(verify-1\.6\.0-done\|rigs-ledger)' -- .github` -> rc=1, no hits, so nothing in CI ever sources this file (positive control: the same regex on `release-check\|qa-segments` -> 2 hits). | X-1530 |
| `scripts/mcp-subject/h2-meter-row.sh` | CLEAN | `diff` -> 50 lines, prose + `(probe_ping, mcp)` vs `(agent:probe, a2a)`. Same three exact assertions. | - |
| `scripts/mcp-subject/h2-mock-upstream.mjs` | FINDING | `:44`-`:46` ends captureEgress with a bare `} catch { }`; a silently failed capture makes `h2_egress_count` return 0, which is the PASS value for four legs. Also `:11` cites `testing/shadow-oracle/mock-upstream.py` as the on-disk contract; `ls` -> No such file, and `git log --diff-filter=D -- testing/shadow-oracle/mock-upstream.py` -> `c73ae4f66 the oracle tool leaves this tree`. | X-1505 X-1506 |
| `scripts/mcp-subject/h2-unpriced-refuses.sh` | FINDING | `diff scripts/a2a-subject/h2-unpriced-refuses.sh scripts/mcp-subject/h2-unpriced-refuses.sh` -> prose and class names only; the `case $arm_on in ... *) if [ "$on_status" = "200" ]` arm is byte-identical. | X-1508 |
| `scripts/mcp-subject/h2-verify-refusal.sh` | FINDING | `diff` -> 35 prose lines. `grep -c 'egress.*-gt 0'` -> 0; the only egress assertion is delta==0. | X-1506 |
| `scripts/mcp-subject/mint-audience-token.mjs` | CLEAN | auth verified against the Rust both ways: it signs `Buffer.from(JSON.stringify({sub,exp,kid,a[,g]}),'utf8')` with raw Ed25519 (`:92`-`:93`) and emits `bbk_<b64url(body)>.<b64url(sig)>`; `crates/busbar-kernel/src/governance/signing.rs:318-349` b64url-DECODES segment 1 and verifies over the decoded bytes -- same bytes, not the base64 text. `exp` is copied from a token busbar minted and re-enforced at `:351`; audience at `:357`-`:365` is a four-arm match with no fall-through. No key material in any log. | - |
| `scripts/mcp-subject/seam-arm.sh` | CLEAN | `git grep -n -F 'seam-arm.sh' -- scripts` -> `mcp-conformance.sh:499 MCP_SUBJECT_UPSTREAM_CONFIG_CMD="bash $(pwd)/scripts/mcp-subject/seam-arm.sh ..."`, and `MCP_SUBJECT_UPSTREAM_CONFIG_CMD` is read by `testing/mcp-conformance/src/core/target.mjs`. `set -euo pipefail`, mandatory positional args via `${1:?...}`, atomic tmp+`mv -f` write. | - |
| `scripts/mcp-subject/tool-digest.mjs` | CLEAN | digest verified byte-for-byte: it hashes, per part of `[name, description, canonical(inputSchema)]`, an 8-byte big-endian length then the UTF-8 bytes (`:41`-`:51`); `crates/busbar-mcp/src/mcp/client/catalogue.rs:88-101` does `h.update((part.len() as u64).to_be_bytes()); h.update(part.as_bytes())`. Mutation-proved: one byte changed in the fixture -> `node --selftest` rc=1 `DISAGREES with busbar's digest layout`; unmutated -> rc=0. `boot.sh:129` runs the selftest before trusting any digest. | - |
| `scripts/method-inventory.py` | CLEAN | `python3 scripts/method-inventory.py --selftest` -> rc=0, 8 refusal cases including `only 0 method constants found ... refusing to generate a vacuous inventory` -- the scanned-nothing floor is explicit. `--check` -> rc=0. Live at `ci.yml:1492,1494` and consumed by `crates/busbar/tests/method_coverage.rs`. | - |
| `scripts/no-plugins-gate.sh` | FINDING | demonstrated accidentally and then confirmed: with `CARGO_TARGET_DIR=/Users/matthew/Developer/GetBusbar/.sweep/target-S06` the selftest built the featureless binary to `.sweep/target-S06/debug/busbar` (110 MB, 12:21) and then `cp "${REPO_ROOT}/target/debug/busbar"` (`:526`,`:529`,`:540`) staged the STALE 159 MB default-features binary from 11:12 -- and the run still printed `SELF-TEST PASSED`. Positive control inside the same repo: `scripts/proto-deletion-gate.sh:82`-`:87` diagnoses this exact bug by name and fixes it with `GATE_TARGET_ROOT="${CARGO_TARGET_DIR:-target}"`. | X-1509 |
| `scripts/pgo-build.sh` | CLEAN | `grep -n 'pgo_fail' scripts/pgo-build.sh` -> 20+ call sites; every phase (instrumented build, --validate of the training config, health, key mint, token shape, each training shape, merge, final link) routes failure through `pgo_fail`, which removes the marker and `exit 1`. `:67 scripts/release-key-guard.sh require \|\| exit 1` asserts the key before compiling. Running it with no key -> rc=1 with the release-key-guard refusal banner. | - |
| `scripts/pgo-drift-check.sh` | CLEAN | `bash scripts/pgo-drift-check.sh --selftest` -> rc=2 `ERROR: --selftest needs llvm-profdata ... Skipping the self-test is not an option` -- it REFUSES rather than skipping, which is the right shape; `ci.yml:2841` installs `components: clippy, llvm-tools` for exactly this reason and `:2880` runs it. The full drift gate is deliberately NOT wired (ci.yml:2870-2878 states why: it needs a `--folded` production capture that does not exist), so only the selftest half can go red today -- declared, not hidden. | - |
| `scripts/pin-missing-cells.py` | DELETABLE | `git grep -n -F 'pin-missing-cells' -- .github qa xtask crates scripts Makefile` -> Rust COMMENTS only, no invocation. Run -> rc=0 `already exact: 0 cells`. `docs/design/xtask-gates.md:156` already records it as callerless. | X-1531 |
| `scripts/plane-config-noun-gate.sh` | CLEAN | `bash scripts/plane-config-noun-gate.sh --selftest` -> rc=0 `ALL GREEN (counts parse targets, ignores homonyms/seam)`; `--check` on the real tree -> 17 parse targets named with file:line, so the scanner is not blind. `qa/segments.toml:533` runs `--selftest && GREP_GATE_REPORT_ONLY=1 ... --check` -- the selftest arm is the red-capable half and the meter is declared report-only in the same file. | - |
| `scripts/plane-grep-gate.sh` | CLEAN | `bash scripts/plane-grep-gate.sh --selftest` -> rc=0 `ALL GREEN (substring RED/GREEN discipline proven)`; `--report` on the real tree -> 271 substring hits with file:line, so it is measuring. `qa/segments.toml:354` runs `--selftest && GREP_GATE_REPORT_ONLY=1 ... --report`; report-only is declared at `:348`-`:351`. | - |
| `scripts/plane-noun-gate.sh` | DELETABLE | `git grep -n 'plane-noun-gate' -- scripts qa .github xtask \| grep -v '^scripts/plane-noun-gate.sh:'` -> 6 hits, every one a COMMENT in another script or a doc; zero invocations. Positive control, same grep for `plane-config-noun-gate` -> `qa/segments.toml:533 run = "scripts/plane-config-noun-gate.sh --selftest && ..."`. Both siblings are wired; this one is not. `--selftest` -> rc=0 ALL GREEN and `--report` -> 159 real leak lines: a working, measuring, unarmed gate. | X-1500 |
| `scripts/plane-roots.sh` | DELETABLE | `git grep -n 'plane_roots_selftest\\|plane_roots_resolve' -- . ':!docs' ':!scripts/plane-roots.sh'` -> **zero hits**; `git grep -n 'plane-roots\.sh' -- . ':!docs' ':!scripts/plane-roots.sh'` -> 5 hits, all comments. Positive control: `git grep -n 'plane-keys\.sh' -- scripts` -> `plane-config-noun-gate.sh:65 . "$(dirname "$0")/plane-keys.sh"`, a real dot-source. `xtask/src/planes.rs:2` says the Rust module consolidated it; `scripts/release-script-lint.sh:154` still calls it `dot-sourced by three lints`, which is no longer true. | X-1503 |
| `scripts/plugin-ci-refs.sh` | CLEAN | `bash scripts/plugin-ci-refs.sh --selftest` -> rc=0 `plugin-ci-refs.sh selftest passed`. Read `sed -n '70,115p'`: a non-40-hex `.busbar-ref` is `return 1` (with the reason: a moving ref collapses the pinned leg into the moving one), an unresolvable pin is `return 1`, an unresolvable moving ref after the dev fallback is `return 1`. The one warning path (no `.busbar-ref` at all) is deliberate and states why. Live at `.github/workflows/plugin-ci.yml`. | - |
| `scripts/plugin-registry-check.sh` | CLEAN | `bash scripts/plugin-registry-check.sh --selftest` -> rc=0 `the org sweep fails loud and still finds strays`; `--list` -> the full TSV registry. Live at `ci.yml`, `qa/full-gate.toml`, `qa/segments.toml`, and consumed by `qa-gate-run.sh`/`release-check.sh`. | - |
| `scripts/pr-land-selftest.sh` | CLEAN | `bash scripts/pr-land-selftest.sh` -> rc=0 `GREEN -- 5 cases, conflict/body/red/green/dry-run all discriminate`. Each case drives the real `scripts/pr-land.sh` against a real git remote; only `gh` is shimmed. `git grep -n -F 'pr-land.sh' -- .github qa xtask crates Makefile testing` -> 0 (not CI-gated; positive control `release-check.sh` -> 122). | - |
| `scripts/pr-queue-selftest.sh` | FINDING | `bash scripts/pr-queue-selftest.sh` -> rc=0 GREEN, 7 cases, and it does drive the real `pr-queue.sh`. But `grep -n -- '--dry-run' scripts/pr-queue-selftest.sh` -> rc=1, no hits; positive control `grep -n -- '--dry-run' scripts/pr-land-selftest.sh` -> 3 hits (case E). The one mode with a swallowed verdict is the one mode the selftest never drives. | X-1510 |
| `scripts/pr-queue.sh` | FINDING | `sed -n '183,187p'`: `bash "$PR_LAND" $hashes --base "$base" $waitflag --dry-run \|\| true` then an UNCONDITIONAL `opened=$((opened + 1))`. Measured with a lander stub that prints pr-land's own dry-run-RED line and exits 1: `1 PR(s) opened, 0 red`, exit 0. Positive control, the SAME refusing lander without `--dry-run`: `STOPPING -- ... did not go green`, `0 opened, 1 red`, exit 1. | X-1510 |
| `scripts/preflight.sh` | DELETABLE | `git grep -n -F 'preflight.sh' -- .github qa xtask crates scripts Makefile testing` -> 2 hits, both its own lines 7-8. Repo-wide -> 6, the other 4 in docs/. The `preflight` JOB at `ci.yml:211` is a `needs:` barrier with no `run:` and never names this file. Positive control: `release-check.sh` -> 122. `docs/design/xtask-gates.md:154` already lists it under Retire (`'mirrors ci.yml EXACTLY' by hand ... Nothing calls it`). | X-1531 |
| `scripts/profile-lock.sh` | CLEAN | `bash scripts/profile-lock.sh --selftest` -> rc=0 `[selftest] PASS`; bare run on the tree -> `PASS -- the release profile is the locked optimized posture`. Live at `ci.yml:2857,2885` and read by `crates/busbar/build.rs`. | - |
| `scripts/promote-selftest.sh` | CLEAN | `bash scripts/promote-selftest.sh` -> rc=0 `GREEN -- 8 cases; exact-sha ff, red/missing/blind/non-ff/local-drift/pairs all refused`. Invoked via `scripts/promote.sh:61 exec bash .../promote-selftest.sh` on `--selftest`. | - |
| `scripts/proof-manifest.py` | FINDING | three, all VERIFIED by running or by AST: (1) `python3 scripts/proof-manifest.py --version audit-probe --out /tmp/x.json` -> `NameError: name 'shutil' is not defined` at `:840`; `grep -n '^import' ` -> shutil is not in the block at `:41`-`:51` while it is used at `:692`,`:707`,`:840`. (2) `tail -5` -> `main()`, not `sys.exit(main())`, while `main` has `return 1` at `:775`,`:905`,`:947` -- `:905`'s own comment says `Non-zero so CI cannot publish an index that says nothing and call the step green`. Positive control: `tail -3 scripts/verify-artifact.py` -> `sys.exit(main())`. (3) `grep -n 'def selftest\\|selftest(' ` -> defined at `:653`, never called, and no `--selftest` in the `add_argument` list. Plus the stale `evidence:` paths -- see X-1504. | X-1504 X-1511 X-1512 |
| `scripts/proto-deletion-gate.sh` | CLEAN | `bash scripts/proto-deletion-gate.sh --selftest` -> rc=0 `static legs GREEN (RED on a real reference, silent on prose and tests)`. It is the repo's positive control for X-1509: `:82`-`:87` names the hard-coded-`target/` bug and fixes it with `GATE_TARGET_ROOT="${CARGO_TARGET_DIR:-target}"`, and every build below passes an explicit `CARGO_TARGET_DIR=`. `:574` asserts the ABSENCE of `crates/busbar-kernel/src/handlers/mcp.rs`, which is the intended direction (`ls` -> absent). | - |
| `scripts/prove-remote.sh` | CLEAN | read `sed -n '1,164p'`: `RC=$?` at `:159` follows `rsh_script ... <<'PROVE'`, a simple command with a heredoc, not a pipe -- correct. Every remote leg is `\|\| exit 1`. The oracle leg's `else` branch (no `./bin/oracle`) would be a green-by-absence, but `git ls-files bin/` -> `bin/oracle` is TRACKED, and `git check-ignore -v bin/oracle` -> not ignored, so the `git clean -qffdx -e target` at `:104` cannot remove it. Live at `manual-keep-proof.yml`. | - |
| `scripts/public-hygiene-lint.py` | CLEAN | `python3 scripts/public-hygiene-lint.py --selftest` -> rc=0, 11/11 rules red-proven with 11 green twins, and a zero-file scan exits 2 (the strongest scanned-nothing floor in the slice). Live at `ci.yml:1561`, `plugin-ci.yml`, `qa/full-gate.toml`, `xtask/src/gates/map_proof.rs`. NOTE (not a defect in this file): on this branch it measures rc=1, 118 hits / 20 allowed. | - |
| `scripts/qa-gate-run.sh` | CLEAN | `grep -c 'die ' scripts/qa-gate-run.sh` -> 15, and `die()` at `:66` is `exit 1`. `grep -n '\|\| true'` -> 1 hit, on `du -sh target` (a log line, not a verdict). The one `grep -c` at `:337` is guarded by an `if ... grep -q` immediately above it, so it can never be the zero-and-exit-1 case. Live at `ci.yml`, `qa-gate.yml`, `qa/full-gate.toml`, and dispatched by `xtask/src/gates/qa_gate_dispatch.rs`. | - |
| `scripts/qa-segments.sh` | CLEAN | `bash scripts/qa-segments.sh --selftest` -> rc=0 `ALL GREEN (shape + preserved coverage + inert reserved + registry-exact ...)`. Live at `ci.yml:654`, `qa-gate.yml`, `qa/full-gate.toml:65`. | - |
| `scripts/release-build.sh` | FINDING | `bash scripts/release-build.sh x86_64-nonesuch` -> the python's `sys.exit("release-build.sh: target ... is not declared")` message prints, then `scripts/release-build.sh: line 89: SPEC_ARCHIVE: unbound variable`. `eval "$(...)"` does not propagate the substitution's exit status (the substitution is an ARGUMENT, not the whole command), so under `set -euo pipefail` the designed refusal does not stop the script -- only the accidental `set -u` two lines later does. | X-1513 |
| `scripts/release-check-1.5.2.sh` | CLEAN | `bash scripts/release-check-1.5.2.sh --selftest` -> rc=2 `unknown argument` (it has no such flag; its `selftest` hits are the internal `oidc_selftest`, which is a real assertion: `:654` `minted JWT did NOT verify against the published JWKS key` -> exit 1). `trap on_err ERR` + `set -euo pipefail` means any phase failure prints `DO NOT TAG THIS RELEASE` and exits non-zero. Invoked from `scripts/release-check.sh:1728` under `phase_selected phase-152-feature-gate`. | - |
| `scripts/release-check.sh` | CLEAN | `bash scripts/release-check.sh --selftest` -> rc=0, 9 cases, all of them about the defect this file exists for (`a missing sibling does NOT read as a clean pass`, `the gap banner names the phase that did not run`, `a missing sibling is fatal under --require-siblings`, `skip-docker counts as a coverage gap`). `--check-coverage` -> rc=0 `every partition tiles the full phase set exactly once`. The verdict is COMPUTED from `record_phase_skip` bookkeeping, not asserted. `ci.yml:515` runs the selftest. | - |
| `scripts/release-gate/binfmt.py` | CLEAN | `git grep -n -F 'binfmt.py' -- scripts` -> `release-gate/platform-checks.sh:181 "$PY" scripts/release-gate/binfmt.py` (the interpreter is a variable, which is why a naive basename grep under-counts it). Fail-closed both ways: `binfmt.py target/debug/busbar` -> `macho aarch64`; on a TOML -> `unknown unknown` (platform-checks records FAIL); on a truncated `MZ` -> rc=1 traceback, captured by the caller's `2>&1` -> FAIL. | - |
| `scripts/release-gate/channel-checks.sh` | FINDING | three unanchored/empty-set comparisons, each measured. `install:e2e` (`:718`) uses a bare `grep -q "$NEWEST"`: with NEWEST=1.5.2 and a binary reporting `busbar 1.5.20` -> MATCH -> records PASS, while the anchored form used 30 lines later by `site:download-page` (`:748`) correctly does NOT match. `helm:render` (`:552`) matches `getbusbar/busbar:1.5.20` and even `busbar:1X5Y2` for NEWEST=1.5.2 -- `lib.sh:204`-`:211` provides `version_re_after` for exactly this and this row does not use it. `contract:drift`'s second assertion computes `wf_named` with `grep -cE '^ *- target: ...' .github/workflows/release-stage.yml` -> 0, and `git grep -lE '^ *- target: ' -- .github/workflows/` -> no files at all, so the `undeclared` set difference is always empty. Also `:566`'s remediation names `.github/workflows/release-gate.yml`; `ls` -> No such file (it is `fleet-autoscaler.yml`). | X-1515 X-1516 X-1517 X-1518 |
| `scripts/release-gate/docker-checks.sh` | CLEAN | `git grep -n 'docker-checks' -- .github` -> `fleet-autoscaler.yml:242 run: scripts/release-gate/docker-checks.sh "$VERSION"`. Its label row makes the assertion `fleet-checks.sh` omits: `:258 [ "$label" = "$V" ]`. Every function it defines is called. It reads `STAGED_RECORD` as JSON CONTENT with its own inline jq, which matches what the workflow actually sets. | - |
| `scripts/release-gate/expected-ids.sh` | CLEAN | read `cat -n`: the per-target ids are DERIVED from `.github/release-targets.json` and `:49`-`:52` makes a failed `published_targets` FATAL rather than letting a process substitution yield a short list -- and `gate.sh --selftest` CASE 1 proves that by staging an unparseable contract. `set -euo pipefail`; `[ -z "$STAGED_RECORD" ] \|\| emit ...` lines are never the final command. | - |
| `scripts/release-gate/fleet-checks.sh` | FINDING | `grep -nE 'digest_matches\|version_re\|\[ "\$' scripts/release-gate/fleet-checks.sh` -> three hits, none involving `$V`; `$V` appears only inside message strings (`:37`,`:64`,`:69`). `bundle:headroom-latest` records PASS on pullability alone, and `bundle:headroom-boot` records PASS with the text `(rebuilt on busbar ${V})` having checked nothing about the version. `expected-ids.sh:123` says the row asserts the bundle `was (re)pushed`. Positive control: `docker-checks.sh:258` makes exactly this assertion for the engine image. | X-1519 |
| `scripts/release-gate/gate.sh` | FINDING | `:285` filters `ALL` to rows where `$5 == VERSION` into `MINE`, `:291` does `ALL="$MINE"`, and `:317` then calls `ledger_foreign_rows "$ALL"` -- whose awk body is `$5 != want`. Reproduced on a synthetic ledger: against `mine.tsv` the function prints nothing (branch unreachable); against the UNFILTERED `all.tsv` it prints `asset:y=1.5.4 asset:z=<no version>` (positive control). So the `WRONG RELEASE ... RED by construction` `exit 1` at `:318`-`:326` cannot fire, and the surviving live path (`:286`-`:290`) emits a `::error::` annotation with no exit. `git log --format='%h %ad %s' -- scripts/release-gate/gate.sh` shows the refusal (47a4bffb5, 09-06) predates the filter (a79d6e32f, 09-07). | X-1501 |
| `scripts/release-gate/platform-checks.sh` | FINDING | `git grep -n 'platform-checks' -- .github` -> `fleet-autoscaler.yml:218`. Its own version comparison is correctly anchored (`:166`). It carries the shared qa-sha defect: `fleet-autoscaler.yml:186` sets `STAGED_RECORD` to jq-compacted CONTENT while `lib.sh:86 [ -f "$rec" ]` requires a PATH, so `staged_qa_sha` returns empty and every ledger row's column 6 is blank. | X-1515 |
| `scripts/release-key-guard.sh` | CLEAN | `bash scripts/release-key-guard.sh --selftest` -> rc=0 `both halves discriminate`, and the cases are the right ones: unset/empty/short/long/padded/nonhex all refused, a keyless archive refused (`the 1.5.3 aarch64 shape`), a DIFFERENT key refused, a missing archive refused, and -- the one that matters -- `assert-embedded ran with NO key to look for` is a MISS because `an empty needle is found in every binary`. Live at `docker.yml`, and called by `release-build.sh:104` and `pgo-build.sh:67`. | - |
| `scripts/run-mutants-ec2.sh` | DELETABLE | `git grep -n -F 'run-mutants-ec2' -- .github qa xtask crates` -> zero invocations (gate-mutants.yml runs `gate-mutants.sh`). `docs/design/xtask-gates.md:157` already says `no caller ... Move to docs/ as a recipe or delete`. Its `is it pushed` preflight also cannot fail -- measured: `git branch -r --contains $(git rev-parse HEAD) >/dev/null 2>&1; echo $?` -> **0** while the same command's stdout is EMPTY; positive control on `origin/main` -> stdout `origin/HEAD -> origin/main origin/main ...`. The discriminator is stdout and `:44` discards it. | X-1524 X-1531 |
| `scripts/signing-gate.sh` | CLEAN | read `cat -n`: five assertions, each with an exit-code AND a specific needle, and the needles were deliberately narrowed after the gate twice `still printing PASS while testing nothing about signing` (`:196`-`:199`). The positive case requires `1 validated, 0 skipped`. The second keygen is length-checked at `:80` for a stated reason (an unparseable key would pack the wrong-key tarball UNSIGNED). Live at `plugin-ci.yml:451`. | - |
| `scripts/snapshot-refs.sh` | DELETABLE | `git grep -n -F 'snapshot-refs' -- .` -> 1 hit, a filename listing in `docs/design/sweep/DENOMINATOR.md:872`. Positive control, same grep on `release-check.sh` -> 122 hits incl. `ci.yml:515 run:`. It also hard-codes `/Users/matthew/...` paths and writes to `$HOME/Downloads`. Its free-space floor is defeated by the input it guards: with `OUT` pointing at a missing dir, `FREE_MB=$(df -m ...)` is empty and `[ "" -lt 300 ]` is a shell ERROR (rc=2), so the `if` is NOT taken and it proceeds to write bundles; positive control `FREE_MB=10` -> refusal fires. | X-1525 X-1531 |
| `scripts/verify-artifact.py` | CLEAN | `python3 scripts/verify-artifact.py --selftest` -> rc=0, 16 checks including an explicit `a floor of zero is not a floor` case and `a target no row applies to is refused`; `--coverage` -> rc=0, every declared row executed. `row_release_pubkey` makes a POSITIVE assertion (the 64 hex bytes must be present) and refuses an unset/malformed key rather than skipping, because `an empty needle is found in every binary`. The key is public and only ever echoed as `key[:12]`. Live at `.github/artifact-contract.json`, `build-artifact.yml`, `ci.yml`, `release-stage.yml`, `qa/full-gate.toml`. | - |

## ROWS RAISED

### X-1500 · `plane-noun-gate.sh` is a 329-line gate with a working self-test that nothing invokes
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'plane-noun-gate' -- scripts qa .github xtask | grep -v '^scripts/plane-noun-gate.sh:'
scripts/plane-config-noun-gate.sh:18:# THIS IS A METER, NOT A HARD GATE — YET (exactly the posture of scripts/plane-noun-gate.sh)...
scripts/plane-config-noun-gate.sh:44:# MODES / ENV (mirrors scripts/plane-noun-gate.sh):
scripts/plane-config-noun-gate.sh:225:# ... Same stripping shape as scripts/plane-noun-gate.sh's build_code_stream.
scripts/plane-delete-test.sh:170:# plane-noun-gate.sh/plane-grep-gate.sh) — this one is PACKAGE names ...
scripts/plane-grep-gate.sh:108:# plane-purity-lint.sh / ... / plane-noun-gate.sh, and a drained crate leaves
scripts/plane-keys.sh:124:# The consumers (scripts/plane-noun-gate.sh, scripts/plane-grep-gate.sh) therefore treat a
scripts/verify-1.6.0-done.sh:64:# require scripts/plane-noun-gate.sh / scripts/plane-grep-gate.sh == 0. Those meter ...
                                   ^ all seven are COMMENTS. Zero invocations.

POSITIVE CONTROL — the same grep for its wired sibling:
$ git grep -n 'plane-config-noun-gate' -- qa
qa/segments.toml:533:run    = "scripts/plane-config-noun-gate.sh --selftest && GREP_GATE_REPORT_ONLY=1 scripts/plane-config-noun-gate.sh --check"

The gate is not broken — it works:
$ bash scripts/plane-noun-gate.sh --selftest   -> rc=0  "ALL GREEN (meter RED/GREEN discipline proven)"
$ bash scripts/plane-noun-gate.sh --report     -> "plane-noun gate: 159 LLM-noun leak line(s)"
```
Three sibling meters were written to the same design (`plane-grep-gate.sh`, `plane-config-noun-gate.sh`,
`plane-noun-gate.sh`). Two are in `qa/segments.toml`. This one was never added, so its self-test has
never run in CI and its 159 measured leak lines have never been reported by any job.
ACTION:    add to `qa/segments.toml` beside the other two —
           `run = "scripts/plane-noun-gate.sh --selftest && GREP_GATE_REPORT_ONLY=1 scripts/plane-noun-gate.sh --report"` —
           or delete the file and the six comments that name it.

### X-1501 · the release gate's "WRONG RELEASE" refusal reads a ledger it has already filtered clean
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/release-gate/gate.sh:285   awk -F'\t' -v v="$VERSION" 'NF && $5 == v' "$ALL" > "$MINE"
scripts/release-gate/gate.sh:291   ALL="$MINE"
scripts/release-gate/gate.sh:317   foreign="$(ledger_foreign_rows "$ALL" "${VERSION:-}")"
scripts/release-gate/lib.sh:380      $5 != want { printf "%s=%s ", $1, ... }

$ printf 'asset:x\tPASS\td\tu\t1.6.0\tsha1\n'  > all.tsv
$ printf 'asset:y\tPASS\td\tu\t1.5.4\tsha1\n' >> all.tsv
$ printf 'asset:z\tPASS\td\tu\t\tsha1\n'      >> all.tsv
$ awk -F'\t' -v v=1.6.0 'NF && $5 == v' all.tsv > mine.tsv
$ awk -F'\t' -v want=1.6.0 'NF==0{next} $5 != want {printf "%s=%s ", $1, ($5==""?"<no version>":$5)}' mine.tsv
                                              # -> EMPTY. The exit-1 branch is unreachable.
POSITIVE CONTROL, same function against the UNFILTERED input:
$ awk -F'\t' -v want=1.6.0 '...' all.tsv
asset:y=1.5.4 asset:z=<no version>            # -> the function works; only its input was emptied.
```
So `gate.sh:318-326` — whose own text reads *"a full set of stale green rows reads exactly like a
verified release. RED by construction."* — cannot fire. The only surviving defence is `:286-290`,
which emits a `::error::` ANNOTATION and never changes the exit code, so a run whose ledger dir
carries this release's rows plus a previous release's rows exits 0. (The all-stale case is still
caught, by the vacuous-run guard at `:295`.) The refusal landed in `47a4bffb5` (2026-09-06); the
filter that emptied its input landed in `a79d6e32f` (2026-09-07) — a fix applied on one side only.
ACTION:    move the filter after the refusal: call `ledger_foreign_rows "$MINE_SOURCE"` on the
           pre-filter file, or delete `:285`/`:291` and let the refusal at `:317` do the job it
           was written for.

### X-1502 · the documented-claims gate's self-test is RED today — its planted defect is no longer a defect
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ bash scripts/documented-claims-check.sh --selftest
PASS  the committed register is green
... (8 more PASS)
FAIL  a cited cell the golden never recorded is caught (rc=0, expected a red naming 'never recorded')
documented claims selftest: RED (1/10 cases failed)
rc=1

$ grep -n -B3 'never recorded' scripts/documented-claims-check.sh
101:  # (f) a cited cell that EXISTS but the pinned golden never recorded ...
102:  #     The mysql store cell is exactly that shape in this tree.
103:  plant "$tmp/f.json" 'claim("README:1057")["cell"] = ["plugins.store-persist|store-mysql"]'

$ grep -n 'store-mysql' testing/shadow-oracle/golden/1.5.5/ledger.tsv
2285:plugins.load|store-mysql           PASS    script plugin-list.sh: status 0
2290:plugins.store-persist|store-mysql  PASS    script store-persist.sh: status 0
```
The subject moved: the golden now records the mysql cell, so planting it no longer plants a defect.
The checker itself is fine — measured, 1402 ids are in `cells.json` and absent from the golden's PASS
set, any one of which would red it.

This is LIVE: `qa/segments.toml:418` reads
`run = "scripts/documented-claims-check.sh --selftest && scripts/documented-claims-check.sh --check"`,
and the segment is `status = "active"`, `tier = "fast"`. The `--check` half never runs.
ACTION:    repoint `scripts/documented-claims-check.sh:103` at a cell that is genuinely unrecorded,
           e.g. `["a2a|grpc|client|client|CancelTask|ok"]` (present in `cells.json`, SKIP not PASS on
           the golden). Do NOT re-record the golden.

### X-1503 · `plane-roots.sh` is a sourced library that nothing sources, superseded by `xtask/src/planes.rs`
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n 'plane_roots_selftest\|plane_roots_resolve' -- . ':!docs' ':!scripts/plane-roots.sh'
                                   # -> ZERO hits. Nothing calls either exported function.
$ git grep -n 'plane-roots\.sh' -- . ':!docs' ':!scripts/plane-roots.sh'
scripts/plane-keys.sh:15            # comment
scripts/release-script-lint.sh:48   # comment
scripts/release-script-lint.sh:154  # comment
xtask/src/gates/structure_lint/roots.rs:20  //! comment
xtask/src/planes.rs:2               //! comment
                                   # -> five COMMENTS, no `.` and no `source`.

POSITIVE CONTROL — the sibling library that IS dot-sourced:
$ git grep -n 'plane-keys\.sh' -- scripts
scripts/plane-config-noun-gate.sh:65:. "$(dirname "$0")/plane-keys.sh"
scripts/plane-grep-gate.sh:107:. "$(dirname "$0")/plane-keys.sh"
```
`xtask/src/planes.rs:2` states the consolidation: *"`scripts/plane-roots.sh` (WHERE a plane lives) as
one Rust module, so no gate restates the plane…"*. The shell half was left behind. Its own
self-test (`plane_roots_selftest`) has four cases, including `PLANE-ROOTS-EMPTY`, and none has ever run.
DRIFT, same row: `scripts/release-script-lint.sh:154` still calls it *"dot-sourced by three lints and
intentionally 100644"*, which is no longer true of any lint. (`release-script-lint.sh` is outside this
slice — reported, not acted on.)
ACTION:    delete `scripts/plane-roots.sh` and correct `scripts/release-script-lint.sh:48,154` to name
           a library that is still sourced (`scripts/plane-keys.sh`).

### X-1504 · `proof-manifest.py` publishes money-path rows whose evidence files do not exist, and `--mark` deletes the note that says so
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ for p in crates/busbar-llm/src/engine/tests/crossproto_delivery_billing_tests.rs \
           crates/busbar-core/src/ingress/tests/tests.rs \
           scripts/plane-purity-lint.sh scripts/g6-freeze-witness.sh scripts/plane-abi-neutrality.sh; do
    [ -e "$p" ] || echo "MISSING $p"; done
MISSING crates/busbar-llm/src/engine/tests/crossproto_delivery_billing_tests.rs   # :173
MISSING crates/busbar-core/src/ingress/tests/tests.rs                             # :176  (crate is gone entirely)
MISSING scripts/plane-purity-lint.sh                                              # :225
MISSING scripts/g6-freeze-witness.sh                                              # :241
MISSING scripts/plane-abi-neutrality.sh                                           # :277
$ ls -d crates/busbar-core  -> No such file or directory
POSITIVE CONTROL: scripts/plane-grep-gate.sh (also an `evidence:` value, :263) -> present.
```
Driving the real function: before `--mark`, `crossproto-billing` and `usage-decode-tap` carry
`status=unknown note="test file not found"`. After `--mark crossproto-billing=success` (which is what
`ci.yml:3042` does from `needs.check.result`), the loop at `:869-872` REPLACES `note` with
*"captured from the sibling ci.yml job result"* and sets `status=pass`. The published dashboard then
shows a money-path oracle green with a drilldown to a file that is not there. The three gate rows
run a real `cargo xtask gate ...` but name the RETIRED shell script as their evidence, so
`evidence_present` is permanently false beside `status: pass`.
ACTION:    repoint `:173` to `crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs`,
           `:176` to the absorbed ingress test under `crates/busbar-kernel/`, and `:225`/`:241`/`:277`
           to the xtask gates that actually run (`xtask/src/gates/plane_purity/mod.rs` etc.); and make
           the `--mark` loop refuse to overwrite a note when `evidence_present` is false.

### X-1505 · the H2 rig headers cite three deleted `.py` mocks, one wrong pin mechanism, and a shared implementation that is a copy
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls scripts/a2a-subject/h2-mock-agent.py       -> No such file or directory
$ grep -n 'h2-mock-agent\.py' scripts/a2a-subject/h2-lib.sh
7:# throwaway busbar + its own instance of h2-mock-agent.py on its own ports ...
62:# Boots busbar with one registered A2A agent "probe" (scripts/a2a-subject/h2-mock-agent.py,
63:# `pin: unpinned`), and the group(s) named in <group-yaml-block>.

  but the same file WRITES, at :121-:122:
    pin: { mechanism: jws_issuer_key, key: "${H2_ISSUER_KEY}" }
  and its own header at :11-:17 explains why `unpinned` CANNOT be used
  ("`a2a/pin.rs` caps `unpinned` on purpose ... can never be approved").

$ ls testing/shadow-oracle/mock-upstream.py     -> No such file or directory
$ grep -n 'mock-upstream\.py' scripts/*/h2-mock-*.mjs
scripts/a2a-subject/h2-mock-agent.mjs:18:// ... the same on-disk contract testing/shadow-oracle/mock-upstream.py and
scripts/mcp-subject/h2-mock-upstream.mjs:11:// testing/shadow-oracle/mock-upstream.py does for the llm plane.
$ git log --oneline --diff-filter=D -1 -- testing/shadow-oracle/mock-upstream.py
c73ae4f66 the oracle tool leaves this tree, and what stays is busbar's own evidence

$ grep -n '^import' scripts/a2a-subject/h2-mock-agent.mjs
29,30,31,32: four node builtins only
$ grep -n 'export' scripts/a2a-subject/signing-vendor.mjs
32:  publicKey.export({...})      # a key export, not a module export
```
`h2-mock-agent.mjs:14-16` claims it *"borrows that EXACT canonicalization (`jcs`) and signing shape
(`signCard`) rather than re-deriving it, so there is one implementation … not two that can drift."*
There are two: `jcs()`/`signCard()` at `:51-75` are a verbatim copy of `signing-vendor.mjs:38-62`
with only `kid` changed, and nothing pins them to each other.
POSITIVE CONTROL: the sibling `scripts/mcp-subject/h2-lib.sh:7` names `h2-mock-upstream.mjs`, which
exists — the drift is one-sided.
ACTION:    `.py` -> `.mjs` and `pin: unpinned` -> `pin: jws_issuer_key` in
           `scripts/a2a-subject/h2-lib.sh:7,62,63`; repoint the `mock-upstream.py` citations at the
           surviving llm-plane mock; and either `export { jcs, signCard }` from `signing-vendor.mjs`
           and import them, or correct the header to say the code is duplicated and unpinned.

### X-1506 · the H2 egress instrument fails silently, and four refusal legs assert only the value a dead instrument returns
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/a2a-subject/h2-mock-agent.mjs:103-105    } catch {
scripts/mcp-subject/h2-mock-upstream.mjs:44-46     // best-effort: a capture failure must never
                                                   // change the response busbar gets
                                                 }
scripts/a2a-subject/h2-lib.sh:335   h2_egress_count() { find "$H2_EGRESS_DIR" -type f 2>/dev/null | wc -l | tr -d ' '; }
```
The consumer reads the instrument as a FILE COUNT, so a capture that silently fails returns 0 — which
is exactly the PASS value for every leg whose only egress assertion is `delta == 0`:
```
$ for f in scripts/{mcp,a2a}-subject/h2-{admit,verify}-refusal.sh; do
    echo "$f  egress=$(grep -c egress $f)  positive_control=$(grep -c 'egress.*-gt 0\|egress_delta.*-eq 1' $f)"; done
scripts/mcp-subject/h2-admit-refusal.sh   egress=6  positive_control=0
scripts/mcp-subject/h2-verify-refusal.sh  egress=5  positive_control=0
scripts/a2a-subject/h2-admit-refusal.sh   egress=6  positive_control=0
scripts/a2a-subject/h2-verify-refusal.sh  egress=5  positive_control=0

POSITIVE CONTROL — two legs in the same family that WOULD notice a dead instrument:
scripts/mcp-subject/h2-authenticate-refusal.sh:77   [ "$egress_delta" -eq 1 ]
scripts/a2a-subject/h2-route-failover.sh:65         [ "$(h2_egress_count)" -gt 0 ]
```
"Zero egress on the refusal" is the whole claim of those four legs — that the node turned the caller
away *before* dialling. A mock that cannot write its capture file proves that claim for free.
ACTION:    make the capture fatal in both mocks —
           `} catch (e) { console.error(\`FATAL: egress capture failed, the instrument is blind: ${e}\`); process.exit(70); }`
           — so a blind instrument kills the rig instead of passing it.

### X-1507 · `h2-class-price.sh` prints a PASS asserting a product it never computes
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/a2a-subject/h2-class-price.sh  (and the byte-identical structure in the mcp twin, :100-:105)

  # ── (3) THE PRICE MUST BE THE PRODUCT ──
  spend_micros="$(h2_meter_row_field "agent:probe" "a2a" spend_micros)"
  if [ "$failures" -ne 0 ]; then
    detail="${detail}(3) price = Σ count × rate is BLOCKED BY the above; ..."
  fi

  if [ "$failures" -eq 0 ]; then
    h2_verdict PASS "one served message/send reported a non-zero count under the declared class
                     'bytes', a card can price it, and the row charged count × rate + fee"
```
`spend_micros` is read and then used ONLY inside the `-ne 0` branch. There is no code path anywhere
in the file that compares it to `count × rate + fee`. The header (`:35-:39`) reasons carefully that
(3) *"is reported as BLOCKED BY the ones that fell, never as passed"* — and that is true only while
(1) or (2) is red. When both go green, (3) is silently skipped and the PASS string asserts it anyway.
There is no input to this script that makes leg (3) produce a NO.
ACTION:    after the `-ne 0` block, add the missing assertion, e.g.
           `[ "$spend_micros" -eq $(( quantity * rate + 10000 )) ] || { failures=$((failures+1)); ... }`
           under the card the leg validated in (1); until that is possible, drop the
           `and the row charged count × rate + fee` clause from the PASS text so the verdict states
           only what was measured.

### X-1508 · `h2-unpriced-refuses.sh` ARM 2 accepts any non-200, including a call that never completed
CLASS:     money
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/{a2a,mcp}-subject/h2-unpriced-refuses.sh   (diff -> prose and class names only)

  case "$arm_on" in
    boot-refused-unpriced) : ;;
    boot-failed|mint-failed) failures=$((failures+1)); ... ;;
    *)
      if [ "$on_status" = "200" ]; then
        failures=$((failures+1)); detail="... was SERVED 200 and billed spend_cents=${on_spend} ..."
      fi
      ;;
  esac
```
Every status other than `200` passes. `h2_call` builds its status from
`curl -sS -m 20 -o "$out" -w '%{http_code}'`, which prints `000` when the request does not complete
(timeout, connection refused, a busbar that died after booting). So a harness failure on the money-
sacred arm is indistinguishable from the refusal the arm exists to prove. The same file takes care
to distinguish `boot-failed` from `boot-refused-unpriced` by grepping the log — the call arm applies
no such discrimination. ARM 1 by contrast requires exactly `200` and exactly `spend_cents=1`.
ACTION:    require a refusal, not merely a non-200 —
           `case "$on_status" in 200) <the existing red> ;; 000) failures=$((failures+1)); detail="...arm 2 never completed the call (curl 000); this is a harness failure, not a refusal" ;; esac`
           and assert the refusal body names the unpriced class.

### X-1509 · `no-plugins-gate.sh` builds with `cargo build` but stages a hard-coded `target/debug/busbar`, and its self-test still says PASS
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/no-plugins-gate.sh:525  cargo build -p busbar --no-default-features --features proto-llm --locked
scripts/no-plugins-gate.sh:526  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-no-default-features"
                          :529  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-default-features"
                          :540  cp "${REPO_ROOT}/target/debug/busbar" "${stage}/busbar-no-default-features"

$ CARGO_TARGET_DIR=/Users/matthew/Developer/GetBusbar/.sweep/target-S06 bash scripts/no-plugins-gate.sh --selftest
  ...
  SELF-TEST PASSED — every RED fixture was caught and the GREEN fixture was not.

$ ls -la /Users/matthew/Developer/GetBusbar/.sweep/target-S06/debug/busbar
-rwxr-xr-x  110094072  Sep 23 12:21     <- what `cargo build` actually produced (featureless)
$ ls -la target/debug/busbar
-rwxr-xr-x  159414152  Sep 23 11:12     <- what `cp` staged and the fixtures judged (stale, full-features)
```
`cargo build` honours `CARGO_TARGET_DIR`; the `cp` does not. Under that variable the gate stages and
judges a binary it did not build, and both the RED-A/RED-B fixtures and the final banner still report
PASS. CI does not set the variable today (`git grep -n CARGO_TARGET_DIR -- .github` -> no hits), so
this is an operator/local hazard rather than a live CI hole — but the sweep contract itself instructs
agents to set it.
POSITIVE CONTROL — the same bug, already diagnosed and fixed in a sibling gate in this repo:
```
scripts/proto-deletion-gate.sh:82-87
  # spelled as the literal `target/…`, which silently ignored a caller's `CARGO_TARGET_DIR` ...
  GATE_TARGET_ROOT="${CARGO_TARGET_DIR:-target}"
```
ACTION:    add `GATE_TARGET_ROOT="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"` beside `REPO_ROOT` and
           replace the three `"${REPO_ROOT}/target/debug/busbar"` literals with
           `"${GATE_TARGET_ROOT}/debug/busbar"` — the same one-line shape `proto-deletion-gate.sh`
           already uses.

### X-1510 · `pr-queue.sh --dry-run` swallows the lander's refusal and counts the line as opened
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/pr-queue.sh:183-186
  if [ "$dry" = 1 ]; then
    echo "+ $PR_LAND $hashes --base $base $waitflag --dry-run"
    bash "$PR_LAND" $hashes --base "$base" $waitflag --dry-run || true
    opened=$((opened + 1))
scripts/pr-land.sh:186-187   exits 1 under --dry-run precisely to say "a real run would have REFUSED"

$ # temp repo, lander stub printing pr-land's own dry-run-RED line and exiting 1
$ bash scripts/pr-queue.sh --dry-run ...
pr-land.sh: dry-run RED — a real run would have REFUSED at the preflight above.
pr-queue.sh: 1 PR(s) opened, 0 red
exit 0
$ # POSITIVE CONTROL: the SAME refusing lander, no --dry-run
pr-queue.sh: STOPPING — 7312e9ab… did not go green; its PR is left open.
pr-queue.sh: 0 PR(s) opened, 1 red
exit 1
```
The self-test never drives that mode:
```
$ grep -n -- '--dry-run' scripts/pr-queue-selftest.sh   -> rc=1, no hits
$ grep -n -- '--dry-run' scripts/pr-land-selftest.sh    -> 3 hits (case E)   [positive control]
```
ACTION:    `scripts/pr-queue.sh:185` —
           `if bash "$PR_LAND" $hashes --base "$base" $waitflag --dry-run; then opened=$((opened+1)); else failed=$((failed+1)); rc=1; fi`
           and drop the now-duplicate `opened=$((opened+1))` on `:186`; add a `--dry-run` case to
           `scripts/pr-queue-selftest.sh`.

### X-1511 · `proof-manifest.py` uses `shutil` without importing it; every run that omits `--hits-dir` dies
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 scripts/proof-manifest.py --version audit-probe --out /tmp/proofprobe/x.json
NameError: name 'shutil' is not defined. Did you forget to import 'shutil'?     (line 840)

$ grep -n 'shutil' scripts/proof-manifest.py
692:        shutil.rmtree(empty_root, ignore_errors=True)
707:        shutil.rmtree(empty_root, ignore_errors=True)
840:        atexit.register(shutil.rmtree, hits_dir, True)
$ sed -n '41,51p' scripts/proof-manifest.py
argparse atexit hashlib json os re subprocess sys tempfile datetime pathlib     # no shutil
```
Line 840 is the `else:` branch taken whenever `--hits-dir` is omitted. `ci.yml:3042` does pass it, so
CI is shielded — but every local/manual run crashes, and the "we made it, we remove it" cleanup for
the hit-list TSVs (which the file itself says *"carry SOURCE lines … must not escape the build"*) can
never execute.
ACTION:    add `import shutil` to the import block at `scripts/proof-manifest.py:41`.

### X-1512 · `proof-manifest.py` discards `main()`'s return value, and its 120-line self-test is unreachable
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ tail -5 scripts/proof-manifest.py
if __name__ == "__main__":
    main()
$ grep -n 'return 1' scripts/proof-manifest.py | tail -3
775:        return 1
905:        return 1          # its own comment: "Non-zero so CI cannot publish an index that
947:        return 1          #  says nothing and call the step green."
POSITIVE CONTROL:
$ tail -3 scripts/verify-artifact.py
if __name__ == "__main__":
    sys.exit(main())

$ grep -n 'def selftest\|selftest(' scripts/proof-manifest.py
653:def selftest(root):          <- defined, never called
$ grep -n 'add_argument' scripts/proof-manifest.py
782..793: --version --out --repo-root --sha --run-id --run-url --staged-json --reports-dir --hits-dir --run-cargo
                               <- no --selftest
```
`--index` is passed by `ci.yml:3042`. `write_index` returning 1 over zero readable manifests
propagates to `main` -> `return 1` -> discarded -> exit 0 -> the step is green. The unreachable
`selftest()` contains the two floors that would catch exactly X-1504's shape: *"a corpus of zero
byte-pairs is FAIL, not pass/unknown"* and *"an absent field-coverage ledger is UNKNOWN, not a pass
over zero fields"*. It is also the only consumer of the missing `shutil` at `:692`/`:707`.
ACTION:    change `scripts/proof-manifest.py:955` to `sys.exit(main())`, add
           `ap.add_argument("--selftest", action="store_true")` with a dispatch, and run it as a CI
           step beside the collate step.

### X-1513 · `release-build.sh`'s undeclared-target refusal is swallowed by `eval "$( … )"`
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n '^set ' scripts/release-build.sh   -> 40:set -euo pipefail
$ bash scripts/release-build.sh x86_64-nonesuch
release-build.sh: target 'x86_64-nonesuch' is not declared in .github/release-targets.json. Add it
there -- that file is what the build matrix, the verify matrix and the asset list are all derived
from, so a target added anywhere else is built and never verified.
scripts/release-build.sh: line 89: SPEC_ARCHIVE: unbound variable
```
The python's `sys.exit("…")` at `:83-:86` is a designed refusal, but it sits inside
`eval "$("$PY" - "$TARGET" <<'PY' … )"` at `:67-:87`. A command substitution propagates its exit
status only when it IS the whole command (`x=$(cmd)`); as an ARGUMENT to `eval` it does not, so
`set -e` never sees it. The run is fail-closed today only by accident — `set -u` catches the unset
`SPEC_ARCHIVE` two lines later. Give `:89` a `${SPEC_ARCHIVE:-}` default at any point in the future
and the refusal becomes silent.
ACTION:    `scripts/release-build.sh:67` —
           `spec="$("$PY" - "$TARGET" <<'PY' … PY )" || exit 1` then `eval "$spec"`, so the
           substitution's status is the assignment's and `set -e` fires on the refusal itself.

### X-1514 · `ci-images.py` is RED on this branch and will break the GHCR mirror on merge to `dev`
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 scripts/ci-images.py --selftest ; echo rc=$?
SELFTEST FAILED: the repository is already RED, so a mutation proves nothing.
  `mysql:8` is pinned in one workflow but reached by neither pin nor mirror in release-stage.yml.
  ci.yml's `check` and release-stage.yml's `gate` run the identical test command and must run it
  against the identical services.
rc=1
$ python3 scripts/ci-images.py --list ; echo rc=$?
::error::ci-images: `mysql:8` is pinned in one workflow but reached by neither pin nor mirror …
rc=1        <- and NO JSON on stdout, which is what the mirror workflow consumes

$ git grep -ni mysql -- .github/workflows/release-stage.yml                  -> empty
$ git log -S mysql -- .github/workflows/release-stage.yml                    -> empty (never had one)
$ git show origin/dev:.github/workflows/ci.yml  | grep -c 'mysql:8'          -> 0
$ git show origin/main:.github/workflows/ci.yml | grep -c 'mysql:8'          -> 0
$ git log --oneline -1 -S'mysql:8' -- .github/workflows/ci.yml
f7e0bb5c8 shadow oracle: both sides record against the same three real backends
```
The pin is new on this branch. `sched-ci-images-mirror.yml` triggers on push to `main`/`dev` touching
`.github/workflows/ci.yml` or `scripts/ci-images.py`, so merging fires it and it dies at step 1.
Root cause: the script's own comment at `:44` promises job scoping — *"the workflows whose service
containers are mirrored, **and the job each pin must live in**"* — but `SOURCES = ("ci.yml",
"release-stage.yml")` carries no job and `collect()` regexes the whole file. The `mysql:8` pin lives
in ci.yml's `shadow-oracle:` job, not `check:`, so the check/gate parity rule is firing on a job
neither of them is.
ACTION:    scope the parity comparison to the jobs it claims to cover —
           `SOURCES = (("ci.yml", "check"), ("release-stage.yml", "gate"))` — and slice each file to
           that job block before `PINNED.finditer`.

### X-1515 · every release-gate ledger row's qa-sha column is blank, so the "two stagings, one name" guard cannot fire
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
.github/workflows/fleet-autoscaler.yml:186   rec="$(jq -c . staged/staged.json)"   # STAGED_RECORD = CONTENT
scripts/release-gate/lib.sh:86               [ -f "$rec" ] || return 0             # expects a PATH

--- PRODUCTION shape (STAGED_RECORD = jq -c content) ---
staged_qa_sha        -> []
staged_image_digest  -> [] rc=1
col5(version)=[1.6.0]   col6(qa_sha)=[]
--- POSITIVE CONTROL (STAGED_RECORD = a file path) ---
staged_qa_sha        -> [deadbeef…]
col5(version)=[1.6.0]   col6(qa_sha)=[deadbeef…]

ledger_sha_disagreements(production-shaped ledger) = []      # no disagreement is representable
$ git grep -n STAGED_SHA -- .github    -> no hits (the only other source, lib.sh:84, is never set)
```
The per-check inline `jq` reads `STAGED_RECORD` as content and works; only `lib.sh`'s helpers, which
fill column 6, do not. `gate.sh:324`'s "TWO STAGINGS, ONE NAME" refusal therefore reads an
all-blank column, and `lib.sh:69-72` calls that pairing load-bearing (*"The two together, not just
the version"*).
ACTION:    `scripts/release-gate/lib.sh:86` — accept both shapes:
           `[ -n "$rec" ] || return 0; { [ -f "$rec" ] && jq -r '.qa_sha // empty' "$rec" || printf '%s' "$rec" | jq -r '.qa_sha // empty'; } 2>/dev/null`

### X-1516 · `install:e2e` uses the unanchored version grep that the same file fixes thirty lines later
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/release-gate/channel-checks.sh:718   grep -q "$NEWEST"
scripts/release-gate/channel-checks.sh:748   (site:download-page, anchored)
scripts/release-gate/platform-checks.sh:166  (anchored)

NEWEST=1.5.2 ; installed binary reports 'busbar 1.5.20'
  install:e2e       grep -q "$NEWEST"   -> MATCH    => records PASS   (WRONG)
  anchored form                         -> NO MATCH => would record FAIL (CORRECT)
  anchored form vs 'busbar 1.5.2'       -> MATCH                       [positive control, no false red]
```
The comment at `:745` names this exact defect for the neighbouring row (*"passed v1.5.2 against a
page advertising v1.5.20"*). `install:e2e` is the one row that did not get the fix.
ACTION:    `scripts/release-gate/channel-checks.sh:718` —
           `if printf '%s' "$got" | grep -qE "(^|[^0-9.])v?${NEWEST//./\\.}([^0-9.]|$)"; then`

### X-1517 · `helm:render`'s image assertion is unanchored and its dots are unescaped
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/release-gate/channel-checks.sh:552   (NEWEST=1.5.2)
  image: "getbusbar/busbar:1.5.20"  -> MATCH => helm:render records PASS
  image: "getbusbar/busbar:1X5Y2"   -> MATCH => helm:render records PASS
POSITIVE CONTROL: scripts/release-gate/lib.sh:204-211 exists solely to prevent this and exports
`version_re_after`; this row does not call it.
```
ACTION:    `scripts/release-gate/channel-checks.sh:552` —
           `if grep -qE "image: *\"?[^\"]*busbar:$(version_re_after "$NEWEST")" "${WORK}/rendered.yaml"; then`

### X-1518 · `contract:drift`'s second assertion compares against a set that is always empty
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
The header states assertion #2: "Every literally-named target must be DECLARED in the contract."
$ grep -cE '^ *- target: [A-Za-z0-9_.-]+' .github/workflows/release-stage.yml   -> 0
$ git grep -lE '^ *- target: [A-Za-z0-9_.-]+' -- .github/workflows/             -> (no files)
  => wf_named = []  => the `undeclared` set difference is empty on every run.
Symptom, visible in the PASS detail the row already prints:
  "named by hand in the workflow: "        <- empty, every time
```
`image-linux-amd64`/`image-linux-arm64` now appear only in comments (`:885`, `:934`), which `wf_body`
strips. The row has silently degraded to assertion #1 alone (a substring check for
`release-targets.json`).
ACTION:    widen the extractor to the shape the workflow actually uses, or — simpler and
           self-proving — make an empty `wf_named` itself a drift reason:
           `[ -n "$wf_named" ] || record "contract:drift" FAIL "the target extractor matched NOTHING in release-stage.yml; assertion 2 is vacuous"`

### X-1519 · `bundle:headroom-latest` records PASS on pullability alone and never checks the version it names
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -nE 'digest_matches|version_re|\[ "\$' scripts/release-gate/fleet-checks.sh
58:    { [ "$st" = "exited" ] || [ "$st" = "missing" ]; } && break
60:    [ "$body" = "ok" ] && break
63:  if [ "$body" = "ok" ]; then
  -> zero comparisons involve $V.  $V appears only inside message strings (:37, :64, :69).

scripts/release-gate/expected-ids.sh:123
  emit "bundle:headroom-latest" "the getbusbar/busbar-headroom bundle :latest was (re)pushed and pulls"
                                                                      ^^^^^^^^^^^^^^ untested half
scripts/release-gate/fleet-checks.sh:66
  record "bundle:headroom-boot" PASS "the headroom bundle boots and serves ok on /healthz (rebuilt on busbar ${V})"
                                                                                            ^ asserted in prose only
POSITIVE CONTROL: scripts/release-gate/docker-checks.sh:258 makes exactly this assertion for the
engine image — `[ "$label" = "$V" ]`.
```
A bundle last pushed for busbar 1.4.0 pulls fine, boots fine, and records two green rows claiming it
was rebuilt on this release.
ACTION:    after `scripts/release-gate/fleet-checks.sh:33`, read the bundle's busbar version label
           (`docker inspect --format '{{index .Config.Labels "…busbar.version"}}'`) and record FAIL
           unless it equals `$V`.

### X-1520 · `ci-runners-selftest.sh` case D asserts the absence of a token on a path that never mints one
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ # gh stub whose registration token is SELFTESTTOKENVALUE
$ PATH="$D_BIN:$PATH" bash -c '. scripts/ci-runners-lib.sh; register_agents i-0selftest'   # dry-run default
[dry-run] gh api -X POST /orgs/GetBusbar/actions/runners/registration-token
[dry-run] aws ssm send-command ...
  => gh was NEVER called; the stub's token value cannot appear, so case D passes by construction.
$ # POSITIVE CONTROL: same stub, CI_RUNNER_DRY_RUN=0
minted a registration token (not printed, expires in ~60 min)
  => gh IS called on the live path — the path case D never reaches (register_agents returns at lib.sh:380).
```
`scripts/ci-runners-selftest.sh:85-86` — *"D. the registration never prints the token"* — cannot fail
regardless of what the live path does. (The live path is clean today, so this is a dead guard, not a
live leak.)
ACTION:    add a live-path assertion beside `:86` —
           `out_live="$(PATH="$D_BIN:$PATH" CI_RUNNER_DRY_RUN=0 bash -c ". '$HERE/ci-runners-lib.sh'; register_agents i-0selftest" 2>&1)"`
           — and grep THAT for the stub's token, keeping `:87`'s box-naming assertion on the dry run.

### X-1521 · `ci-runners-ssh.sh` reports a failed ingress revoke as a no-op and never fails
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/ci-runners-ssh.sh:100-101
  aws ec2 revoke-security-group-ingress --group-id "$SG_ID" \
    --ip-permissions "$perms" >/dev/null 2>&1 || log "  (revoke reported nothing to do)"
```
`|| log` on the command whose failure IS the signal, `2>/dev/null` discarding the reason, and a
message that asserts the opposite of what happened. The file's own header calls this load-bearing:
*"Leaving them would be an open port on a box that executes arbitrary branch code."*
Same file, `:87`: `log "ssm: $(ssm_wait "$CMD_ID" 30 6)"` logs the key-install status without testing it.
POSITIVE CONTROL: `scripts/ci-runners-lib.sh:403-406` tests the identical `ssm_wait` result —
`case "$st" in *Failed*|*TimedOut*|…) return 1`.
ACTION:    `scripts/ci-runners-ssh.sh:101` —
           `--ip-permissions "$perms" >/dev/null || die "FAILED to revoke ingress on $SG_ID — the fleet still has an open port"`

### X-1522 · `ci-runners-down.sh --all`'s ghost sweep silently does nothing and the script still exits 0
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/ci-runners-down.sh:86-96   gh api … 2>/dev/null | while read …    (set -uo pipefail, no set -e)
$ (ran the shape with a failing gh)
sweeping every offline org runner
pipeline status was: 1     <- loop body ran 0 times; nothing said so
done.
  script exit status: 0
POSITIVE CONTROL: the non---all path reports a count — `down.sh:99` prints `$SWEPT_GHOSTS`
from `lib.sh:326` — so the more thorough path is the blinder one.
```
`:70`'s `aws_w ec2 terminate-instances … >/dev/null` is likewise unchecked, so a failed terminate
still prints "done."
ACTION:    `scripts/ci-runners-down.sh:86` — capture first and refuse an empty read:
           `offline="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" --jq '…')" || die "could not enumerate org runners; ghosts NOT swept"`
           then iterate via a heredoc, exactly as `sweep_ghost_runners` already does.

### X-1523 · `ci-runner-bootstrap.sh` writes its readiness marker unconditionally
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n '^set ' scripts/ci-runner-bootstrap.sh
17:set -uxo pipefail                                   <- no -e
$ tail -4 scripts/ci-runner-bootstrap.sh
su - ubuntu -c "... cargo build --workspace --locked" || true      # :296
touch /var/run/busbar-runner-ready                                 # :298
echo "BOOTSTRAP COMPLETE"                                          # :299
```
Nothing between `:17` and the end can stop the script, and the last two statements are
unconditional — the always-PASS report row. The pre-warm's stated purpose (*"proves the toolchain and
native deps are actually complete"*) is negated by `|| true`; the gh install has the same shape
(`gh --version || true`, `:55`). The marker HAS a consumer: `scripts/ci-runners-reconcile.sh:258`
probes each box and prints `ready=yes/NO`, so a box whose apt, gh, sccache and pre-warm all failed
reports `ready=yes`.
ACTION:    `scripts/ci-runner-bootstrap.sh:298` —
           `[ -x /usr/local/bin/gh ] && [ -x /usr/local/bin/sccache ] && [ -d /home/ubuntu/prewarm/target ] && touch /var/run/busbar-runner-ready || echo "BOOTSTRAP INCOMPLETE"`

### X-1524 · `run-mutants-ec2.sh`'s "is it pushed" preflight cannot fail
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/run-mutants-ec2.sh:43-45
  SHA="$(git -C "$HERE" rev-parse HEAD)"
  if ! git -C "$HERE" branch -r --contains "$SHA" >/dev/null 2>&1; then
    echo "PREFLIGHT: $SHA is not pushed; the box fetches by SHA and would fail." >&2; exit 1

$ SHA=$(git rev-parse HEAD); echo "$SHA"
f35541827bdc32fdde78f15ba0365d90bee8f989
$ git branch -r --contains "$SHA" >/dev/null 2>&1 ; echo $?
0                                            <- the preflight PASSES
$ echo "[$(git branch -r --contains "$SHA" 2>/dev/null)]"
[]                                           <- and no remote branch contains it
$ echo "[$(git branch -r --contains "$(git rev-parse origin/main)" 2>/dev/null | head -3 | tr '\n' ' ')]"
[  origin/HEAD -> origin/main   origin/badge/openssf-solo-fixes   origin/main ]   [positive control]
```
`git branch -r --contains` exits 0 whether or not any remote branch contains the commit; the
discriminator is stdout, which `:44` discards. The box would then fetch a SHA that does not exist
remotely — precisely what `:45`'s message claims to prevent.
ACTION:    `scripts/run-mutants-ec2.sh:44` —
           `if [ -z "$(git -C "$HERE" branch -r --contains "$SHA" 2>/dev/null)" ]; then`
           (or delete the script, see X-1531).

### X-1525 · `snapshot-refs.sh`'s free-space floor is defeated by the one input it guards against
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/snapshot-refs.sh:26-31
  FREE_MB=$(df -m "$OUT" | awk 'NR==2 {print $4}')
  if [ "$FREE_MB" -lt 300 ]; then … exit 1 ; fi

$ # OUT points somewhere that does not exist (the case the floor exists for)
df: /no/such/dir: No such file or directory
FREE_MB=[]
/bin/bash: [: : integer expression expected
FLOOR NOT TAKEN -> proceeds to write bundles
test exit status: 2          (2 = shell ERROR, which is not false, so the `if` is not taken)
$ # POSITIVE CONTROL
FREE_MB=10    -> REFUSAL FIRED
FREE_MB=99999 -> not taken (correct)
```
This is the exact case `scripts/ci-runners-lib.sh:410-414` guards by name
(`case "$n" in ''|*[!0-9]*) n=0 ;;`). Note the shebang is bash: zsh returns 0 here, bash returns 2.
ACTION:    `scripts/snapshot-refs.sh:27` — insert `case "$FREE_MB" in ''|*[!0-9]*) FREE_MB=0 ;; esac`
           (or delete the script, see X-1531).

### X-1526 · `diagnostic-upstream.mjs` corrupts multi-byte UTF-8 split across TCP chunks
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
scripts/mcp-subject/diagnostic-upstream.mjs:495-497
  let raw = "";
  req.on("data", (c) => (raw += c));        <- decodes each Buffer independently

$ node -e '<two-byte char split across two chunks>'
string-concat  -> "��"  bytes efbfbdefbfbd
Buffer.concat  -> "é"             bytes c3a9
POSITIVE CONTROL: scripts/mcp-subject/h2-mock-upstream.mjs:71 does
  Buffer.concat(chunks).toString('utf8')
```
This is a FALSE-RED risk on the busbar under test: the fixture answers `-32700 "not valid JSON"` for
a payload busbar sent correctly, and the scenario scores that against busbar.
ACTION:    `scripts/mcp-subject/diagnostic-upstream.mjs:495-497` —
           `const chunks = []; req.on("data", (c) => chunks.push(c));` and, in the `end` handler,
           `const raw = Buffer.concat(chunks).toString("utf8");`

### X-1527 · `mcp-subject/boot.sh` declares no shell options of its own
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n '^set ' scripts/mcp-conformance.sh scripts/mcp-subject/boot.sh scripts/a2a-subject/boot.sh
scripts/mcp-conformance.sh:78:set -euo pipefail
scripts/a2a-subject/boot.sh:149:set -euo pipefail
                                  <- no line for scripts/mcp-subject/boot.sh (1186 lines)
```
Its correctness depends on inherited `pipefail`, e.g. `:135-138`
`node … tool-digest.mjs | sed … >> "$SUBJECT_DIGESTS" || die "could not digest …"` — without
`pipefail` the pipeline's status is `sed`'s and `die` is unreachable. Today a second guard
(`schema_hash: ""` at `:1074`) catches it, so this is defence-in-depth rather than a live hole — but
the sibling sets its own options and this one does not.
ACTION:    add `set -euo pipefail` after the header of `scripts/mcp-subject/boot.sh`.

### X-1528 · `history-rewrite-empty-bodies.sh` needs bash 4 and has no version guard, so on stock macOS its self-test dies half-green
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ PATH=/bin:/usr/bin /bin/bash scripts/history-rewrite-empty-bodies.sh --selftest ; echo $?
  PASS: dirty tree refused
  PASS: wrong tip refused
  PASS: non-empty body refused
=== selftest: dry run ===
2                                     <- dies here, silently
$ /bin/bash -c 'set -euo pipefail; f(){ local -A m=(); }; f'
/bin/bash: local: -A: invalid option     rc=2       (/bin/bash on macOS is 3.2.57)
$ grep -n 'local -A\|\[-1\]' scripts/history-rewrite-empty-bodies.sh
189:  local -A IN_SET=()
210:  local -A REMAP=()
286:  ${MAP_NEW[-1]}
POSITIVE CONTROL: the same file under Homebrew bash 5.3 reaches "SELFTEST: ALL GREEN".
```
The three refusal cases pass under 3.2 because they abort in `run_rewrite` steps 1-3, before the
first associative array — so a reader who skims sees a partially green self-test for a script that
cannot complete a rewrite on that shell. This is the documented `docs/security/HISTORY-REWRITE.md`
procedure, run by hand on exactly such machines.
ACTION:    `scripts/history-rewrite-empty-bodies.sh:60` (right after `set -euo pipefail`) —
           `[ "${BASH_VERSINFO[0]:-0}" -ge 4 ] || { echo "REFUSED: needs bash >= 4 (associative arrays); this is bash ${BASH_VERSION}" >&2; exit 1; }`

### X-1529 · `capability-equality-summary.py` prints a verdict that contradicts what it just measured
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 scripts/capability-equality-summary.py
EQUALITY: 0 of 91 cells missing (65 proven, 26 n/a) -- LLM == MCP == A2A is not yet true, and this line names where:
  per plane: llm 0, mcp-client 0, mcp-server 0, a2a-client 0, a2a-server 0, voice-client 0, voice-server 0
                                                  ^ names nothing, because there is nothing to name
```
`:149` hardcodes the clause into the f-string, outside any conditional, while `if missing:` at `:151`
correctly suppresses the (empty) list. With `missing == 0` the header asserts the negation of the
measurement. `xtask/src/full_gate.rs:779` prints this verbatim under `== equality ledger ==`, so the
full gate's own summary currently tells a reader the opposite of what the ledger says.
ACTION:    `scripts/capability-equality-summary.py:149` — make the clause conditional on `missing`.

### X-1530 · the whole H2 gating family is reachable but fires in no workflow
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
chain: h2-mock-{agent,upstream}.mjs <- h2-lib.sh <- h2-*.sh
       <- testing/shadow-oracle/rigs-ledger.sh::run_h2_{mcp,a2a} (:472, :558; floors of 6 per plane at :724, :726)
       <- scripts/verify-1.6.0-done.sh:1216-1228
$ git grep -nE 'run:.*(verify-1\.6\.0-done|rigs-ledger)' -- .github ; echo rc=$?
rc=1                                          <- neither terminus is executed by CI
$ git grep -nE 'run:.*(release-check|qa-segments)' -- .github | head -2      [positive control]
.github/workflows/ci.yml:515:        run: scripts/release-check.sh --selftest
.github/workflows/ci.yml:654:        run: scripts/qa-segments.sh --selftest
```
`docs/design/xtask-gates.md:154` already flags this family as UNRESOLVED (*"has never executed"*); the
chain has since been built but still has no trigger. Combined with X-1506, X-1507 and X-1508 this
means none of those three defects would have been caught by a run, because there are no runs.
ACTION:    add a `workflow_dispatch` (or a `qa`-tier) job that runs `scripts/verify-1.6.0-done.sh`'s
           H2 section, or wire `testing/shadow-oracle/rigs-ledger.sh`'s `run_h2_*` into
           `qa-conformance-{mcp,a2a}.yml` beside the conformance legs those rigs already share ports with.

### X-1531 · eight scripts in `scripts/` are invoked by nothing
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
Reachability command, run per basename over the places that can actually run a script:
`git grep -n -F '<basename>' -- .github qa xtask crates scripts Makefile testing`
```
scripts/preflight.sh                  -> 2 hits, both its own lines 7-8
scripts/bare-bones-build.sh           -> 1 hit, its own line 5
scripts/snapshot-refs.sh              -> 0 hits (repo-wide: 1, a filename listing in DENOMINATOR.md)
scripts/run-mutants-ec2.sh            -> comments only; gate-mutants.yml runs gate-mutants.sh
scripts/extract-inline-tests.sh       -> only its own .py sibling
scripts/extract-inline-tests.py       -> only its own .sh sibling
scripts/deferral-words.py             -> 0 invocations (only its own docstring)
scripts/pin-missing-cells.py          -> Rust COMMENTS only

POSITIVE CONTROL, same grep shape on a script that IS invoked:
$ git grep -n -F 'release-check.sh' -- .github qa xtask crates scripts Makefile testing | wc -l
122            (incl. .github/workflows/ci.yml:515 `run:` and qa/full-gate.toml)
```
Three of them work: `extract-inline-tests.sh --selftest` -> GREEN (10 cases); `deferral-words.py` has
a two-layer detector with a documented miss rate; `pin-missing-cells.py` runs clean. They are
capabilities that do not ship. The repo already agrees in writing for four:
`docs/design/xtask-gates.md:154` (preflight, *"Nothing calls it"*), `:156` (pin-missing-cells),
`:157` (run-mutants-ec2, *"Move to docs/ as a recipe or delete"*), and
`docs/design/1.6.0-TRACKER.md:198` (deferral-words, *"it is invoked by NOTHING"*).
Deleting `bare-bones-build.sh` loses no coverage: `xtask/src/full_gate.rs:99` still runs
`cargo build --no-default-features --locked` workspace-wide.
`snapshot-refs.sh` additionally hard-codes `/Users/matthew/…` paths and writes to `$HOME/Downloads`.
ACTION:    delete all eight, or wire each one to the job named in its own header. Two carry
           separate defects that make deletion the better answer (X-1524, X-1525).

## TALLY
```
files in slice:  100
verdict lines:   100
CLEAN:            59
FINDING:          31      rows raised: 32  (X-1500 .. X-1531 contiguous, none outside the block)
DELETABLE:        10
UNREADABLE:        0
```

### Rows by class
| class | rows |
|---|---|
| instrument-blind | X-1500, X-1501, X-1502, X-1509, X-1510, X-1512, X-1513, X-1515, X-1516, X-1517, X-1518, X-1519, X-1522, X-1523, X-1524, X-1525, X-1529, X-1506 |
| money | X-1507, X-1508 |
| auth | X-1520, X-1521 |
| drift | X-1504, X-1505 |
| missing-code | X-1503, X-1511, X-1526, X-1531 |
| config | X-1514, X-1527, X-1528, X-1530 |

All 32 rows are **VERIFIED** — each was produced by running a command and watching it, with a
positive control on every zero. None is ADJUDICATE; none is PARK. No golden, `openapi.json`,
`accepted-differences.json` or `qa/*.toml` ratchet was blessed, re-recorded or regenerated, and no
source file outside this report was edited.

### What this slice proves about files OUTSIDE it (reported, not acted on)
- **`scripts/release-gate/lib.sh`** — `:86`'s `[ -f "$rec" ]` is where X-1515 actually lives; the four
  `release-gate/*.sh` files in this slice are its victims, not its cause.
- **`scripts/release-script-lint.sh`** — `:48` and `:154` describe `scripts/plane-roots.sh` as
  *"dot-sourced by three lints"*. Measured: zero lints source it (X-1503).
- **`.github/workflows/fleet-autoscaler.yml:186`** — sets `STAGED_RECORD` to jq-compacted JSON
  content; `lib.sh` expects a path. One of the two must move (X-1515).
- **`.github/workflows/ci.yml`** — `:3184` pins `mysql:8` in the `shadow-oracle` job while
  `release-stage.yml` has no mysql at all, which is what makes `ci-images.py` red (X-1514).
- **`scripts/pr-land.sh`** — is the refusing side of X-1510 and is correct; `pr-queue.sh` is the side
  that discards its answer.
- **`scripts/verify-1.6.0-done.sh` / `testing/shadow-oracle/rigs-ledger.sh`** — the only callers of
  the H2 family, and neither is run by any workflow (X-1530).
- **`xtask/src/planes.rs`** — the Rust that superseded `plane-roots.sh`; the shell half was never
  removed (X-1503).
- **Branch state, not a slice defect:** `python3 scripts/public-hygiene-lint.py --root . --quiet` ->
  **rc=1**, 118 hits / 20 allowed over 3478 files (heaviest: `qa/construction.toml`,
  `scripts/plane-*.sh`, `xtask/src/gates/construction/rules.rs`). That is `ci.yml:1561`. The
  instrument is the strongest in this slice — 11 rules, each with a RED fixture and a GREEN twin, and
  a zero-file scan exits 2 — so the red is about the tree, not about the lint.
