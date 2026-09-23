# S16-ci-qa — `.github/workflows/` + `qa/`

Slice list: `.sweep/S16-ci-qa.txt` — **38 files**, 38 verdict lines below, in slice order.
X-id block: **X-2500 .. X-2599**. No id outside it.

**Content read at HEAD (`f90bd1ee0`) via `git show HEAD:<path>`, not from the working tree.**
Two files in `.github/workflows/`+`qa/` carry uncommitted in-flight edits from other agents
(`.github/workflows/ci.yml`, `qa/construction.toml`) and **neither is in this slice**
(`git status --porcelain -- .github/workflows/ qa/` → exactly those two `M` lines). Every one of my
38 files is identical in HEAD and the working tree.

No `qa/*.toml` ratchet was edited. Nothing was blessed, regenerated or re-recorded.

## The measurement that organises this report

`workflow_run` loads the workflow file from the **default branch**, always. Measured:

```
$ git ls-tree --name-only origin/main .github/workflows/ | wc -l     # 10
$ git ls-tree --name-only HEAD        .github/workflows/ | wc -l     # 29
$ for f in qa-codeql qa-security qa-conformance-a2a qa-conformance-mcp qa-conformance-voice; do
    git cat-file -e origin/main:.github/workflows/$f.yml 2>/dev/null || echo "ABSENT ON origin/main: $f.yml"; done
ABSENT ON origin/main: qa-codeql.yml
ABSENT ON origin/main: qa-security.yml
ABSENT ON origin/main: qa-conformance-a2a.yml
ABSENT ON origin/main: qa-conformance-mcp.yml
ABSENT ON origin/main: qa-conformance-voice.yml
$ git show origin/main:.github/workflows/qa-gate.yml | wc -l   # 338
$ git show HEAD:.github/workflows/qa-gate.yml        | wc -l   # 408   (identical=NO)
```

Six workflows in this slice are `workflow_run`-triggered. Five of them do not exist on the ref
GitHub reads them from. The sixth exists there in a 70-line-shorter form. The one instrument built
for exactly this failure — `cargo xtask gate qa-gate-dispatch`, whose own header says *"the
auto-fired gate ran ONE job while the whole segmentation umbrella sat unused on `qa` … the run went
green, it had simply done far less than anyone believed"* — is scoped to one file:

```
$ grep -n 'pub const WORKFLOW' xtask/src/gates/qa_gate_dispatch.rs
81:pub const WORKFLOW: &str = ".github/workflows/qa-gate.yml";
```

That is X-2500 and it is the most serious finding in the slice.

---

| FILE | VERDICT | EVIDENCE | ROWS |
| --- | --- | --- | --- |
| `.github/workflows/build-artifact.yml` | FINDING | `git show HEAD:… \| grep -n "five targets"` → `:111 "one env block, five targets"`; `python3 -c` over `.github/release-targets.json` → `published count: 6` and `release-stage.yml`'s own floor is `if len(inc) < 6`. Build path itself is sound: one step, no per-step `if:`, `BUSBAR_RELEASE_PUBKEY` on the single build step, `if-no-files-found: error` on the receipt, `[ -s "$archive" ]` before upload. All referenced paths exist (`scripts/release-build.sh`, `.github/actions/cargo-home`, `.github/release-targets.json`). | X-2515 |
| `.github/workflows/manual-bolt-pass.yml` | FINDING | `git grep -n "busbar-bolt-" -- .github/ scripts/` → only this file's own `upload-artifact`. `scripts/bolt-pass.sh` exists and is self-tested first (`--selftest`), the `--fdata` count guard refuses 0 or ≥2, the staging-tag shape is validated. The whole pipeline terminates in an artifact nothing downstream reads; the header says so. | X-2516 |
| `.github/workflows/manual-keep-proof.yml` | FINDING | Statuses are POSTed to `repos/…/statuses/${GITHUB_SHA}` (`:862`, `:975`) while every job checks out `${{ inputs.ref \|\| github.ref }}` (`:104`, `:499`, `:661`, `:901`). Oracle replay **does** pass `--strict` (`:790`) — verified live, unlike ci.yml:3342/oracle-proof.yml:234. Floors are real: `[ "$count" -lt 40 ]`, `[ "$ran" -eq 0 ]`, `files -ne 5`, `KEEP_MIN_TESTS=9700`, `owed -eq 0`. `steps.replay.outputs.rc` (`:791`) is read by nothing. | X-2510, X-2520 |
| `.github/workflows/plugin-ci.yml` | FINDING | Python/yaml walk over all 29 workflows: 41 uses of `uses: ./.github/actions/cargo-home`; exactly 3 sit in a job with no workspace-root checkout — `plugin-ci:build-test-signoff`, `plugin-ci:coverage`, `qa-gate:build`. Both plugin-ci jobs check out to `path: plugin` and `path: busbarAI` only. `scripts/plugin-ci-refs.sh` exists and is `--selftest`ed; service images are digest-pinned; the coverage job is explicitly non-gating. | X-2509 |
| `.github/workflows/plugin-consumer-verify.yml` | FINDING | `git grep -n "plugin-consumer-verify.yml" -- .github/workflows/ scripts/ qa/` → 0 `uses:` callers (2 prose mentions in `scripts/release-gate/fleet-checks.sh`). Its own header tells plugin repos to call `…@main`; `git cat-file -e origin/main:.github/workflows/plugin-consumer-verify.yml` → absent. The file itself is the one place in the slice that gets errexit right: `:173-178` documents `bash -e {0}` and issues `set +e` first. | X-2504 |
| `.github/workflows/plugin-functional.yml` | FINDING | 0 callers (`git grep` as above, excluding self). `grep -n "functional" plugins.yaml` → rc=1, no output; `grep -nE "^\s*gate:" plugins.yaml` → `suite`×7, `binary`×1, `smoke`×2 — no repo declares `functional`. Absent on `origin/main`, the ref its own header (`:45`) names. All five probe scripts and `verdict.sh` exist under `testing/fleet-fixtures/`; `verdict.sh` refuses empty `EXPECTED_IDS` and zero rows. | X-2503 |
| `.github/workflows/prepare-release.yml` | FINDING | `ls .github/workflows/tag-on-main.yml` → `No such file or directory`; `git log --oneline --all -- .github/workflows/tag-on-main.yml` → last touched by `a1879f190`. The file names it at `:22` and `:112`. The OpenAPI step's zero-match floor (`grep -qE 'test result: ok\. [1-9][0-9]* passed'`) is real and correct. `.github/scripts/bump_cargo.py` and `roll_changelog.py` both exist. | X-2508 |
| `.github/workflows/qa-codeql.yml` | FINDING | Absent on `origin/main` (see header measurement) while `on:` is `workflow_run: workflows:["CI"]`. Its header `:16-18` claims *"CodeQL has no such constraint, so it does not pay that cost"* — it is `workflow_run`-triggered, so it pays it in full. It also names `qa-gate-dispatch-lint.py` (`:15`); `git ls-files \| grep -i qa-gate-dispatch` → rc=1, empty (the rule is now `cargo xtask gate qa-gate-dispatch`). | X-2500, X-2501, X-2517 |
| `.github/workflows/qa-conformance-a2a.yml` | FINDING | Absent on `origin/main`; `on: [workflow_dispatch, workflow_run]` (yaml-parsed). Internals are strong and were checked: `harness-selftest.py`, `check-baseline-selftest.py`, `scripts/a2a-subject/boot.sh --selftest` all exist and run BEFORE any verdict; `testing/verdict-covers-every-leg.py` holds `verdict`'s `needs:` to set-equality with the job set and is itself `--selftest`ed. Every `run:`-invoked repo file in this workflow exists (positive control: `scripts/zzz-nope.sh` → absent). | X-2500 |
| `.github/workflows/qa-conformance-mcp.yml` | FINDING | Absent on `origin/main`. `./scripts/negative-control.sh` at `:386` resolves under `working-directory: testing/mcp-conformance` (`git ls-files \| grep negative-control` → `testing/mcp-conformance/scripts/negative-control.sh`) — not drift. `battery-subject` records an explicit `armed` output and the verdict treats `false` as RED; `official-subject` holds scenario coverage to set-equality, never a count. | X-2500 |
| `.github/workflows/qa-conformance-voice.yml` | FINDING | Absent on `origin/main`. Its terminal status is `name: Voice conformance verdict` (`:462`). `grep -n "Voice conformance" .github/required-status-checks.md` → rc=1; `sed -n '110,120p' scripts/ci-branch-protection.sh` → `REQUIRED_CONTEXTS_JSON` holds 4 strings, all from `ci.yml`. Its two siblings ARE listed in the doc (`:54`,`:55`); voice is in neither. | X-2500, X-2502 |
| `.github/workflows/qa-gate.yml` | FINDING | `origin/main` copy is 338 lines vs 408 at HEAD, `identical=NO`; `ROW_DEFAULT_BRANCH` is only asked on `qa`/`main` (`PROMOTION_BRANCHES`). `build` job: checkout `path: busbarAI` then `uses: ./.github/actions/cargo-home` (blamed to `7003b443fd`, 2026-09-16 — added six weeks after the `path:` structure, `133fd6ae8e`). Header `:47-52` still argues `fast` is a **sibling** of `build` while `:154` reads `needs: [build]` (the `:147-153` note records the correction; the header was not updated). Umbrella logic is correct: every tier's `result` read explicitly, `skipped` treated as red. | X-2500, X-2509 |
| `.github/workflows/qa-security.yml` | FINDING | Absent on `origin/main` while `on:` is `workflow_run` + `schedule` — scheduled workflows also only run from the default branch, so **both** of its triggers are inert until it lands on `main`. Its context `cargo-deny (advisories · licenses · sources · bans) + cargo-audit` is declared required-on-`qa` at `.github/required-status-checks.md:53` and is absent from `ci-branch-protection.sh`'s `REQUIRED_CONTEXTS_JSON`. The `issues: write` withholding and the `head_sha` checkout pin are both correct. | X-2500 |
| `.github/workflows/release-stage.yml` | FINDING | `git grep -n "release-order-lint.py"` → `:48` (and `release.yml:64`, `docker.yml:65,840`); `git ls-files \| grep release-order` → rc=1. The rule lives at `xtask/src/gates/release_order.rs` (`cargo xtask gate release-order`), and `full_gate.rs:534` already records the old spelling as "dead code for a year of commits". Prose says "FIVE TARGETS" at `:969`,`:1155`,`:1161` against 6 published. Verification graph is genuinely sound: `targets` floors at `len(inc) < 6` and `len(images) != 2`, `verify-assets`/`verify-artifact`/`verify-image` all run on `!cancelled()`, `verify-set-equality` floors at `len(declared) < 6` and compares receipts not job results, `verify-staged` deliberately uses default `needs` semantics, `record-staged` re-derives both digests from the registry and refuses an empty one. | X-2515, X-2517 |
| `.github/workflows/release.yml` | FINDING | Same `release-order-lint.py` citation (`:64`). `branch-green`'s `api()` retry: proved locally that under `bash -e` (GitHub's default `run:` shell) the loop runs but `if [ $? -ne 0 ]`'s `::error::REFUSING TO RELEASE … after 5 attempts` is unreachable — the shell exits at the `runs="$(api …)"` assignment. Fail-closed, diagnostic dead. The `no unique_by` fix, the `REQUIRED_WORKFLOWS` presence+branch+conclusion assertions, and `promote-release`'s "red RIGHT NOW" re-check (which correctly treats `conclusion: null` as red) are all live and correct. | X-2517, X-2518 |
| `.github/workflows/sched-ci-images-mirror.yml` | FINDING | Ran the exact line: `git log --diff-filter=A --format=%aI --follow -- <two pathspecs>` → `fatal: --follow requires exactly one pathspec`, rc=128. Under `bash -e` + the step's `set -uo pipefail` the assignment kills the step (measured: `step rc=128`, the anonymous-pullability loop never starts). With `set +e` it would instead yield `added=[]` → `age_days=0` → the grace window never expires. Controls: single-pathspec `--follow` → `2026-08-31T10:13:04-07:00`; two pathspecs without `--follow` → same. | X-2505 |
| `.github/workflows/sched-cost-watch.yml` | FINDING | Reproduced the step under all three shells. `bash -e` (GitHub's default for a `run:` with no `shell:`) and `bash --noprofile --norc -eo pipefail` both exit at the pipeline with `rc=2`, before the `case`; without `-e` the `::warning::SOFT-ALARM` arm is reached and the step exits 0. `scripts/cost-watch.py:99-108` confirms the 0/2/3/1/4 band contract is real. | X-2506 |
| `.github/workflows/sched-monthly-refresh.yml` | FINDING | Ran the bump line against the tree: `cur=$(grep -m1 '^version = ' Cargo.toml \| sed …)` → `cur=[]`. Root `Cargo.toml` is a virtual manifest (`grep -n "^version = \|^\[workspace" Cargo.toml` → only `1:[workspace]`, `84:[workspace.dependencies]`); the version lives at `crates/busbar/Cargo.toml:3` — which is exactly what `prepare-release.yml` bumps. `sed` then matches nothing, `$((PA+1))` yields `1`, and the job opens a green PR titled `… -> v..1` against `--base main`. | X-2507 |
| `.github/workflows/sched-oracle-store-cells.yml` | CLEAN | `--filter` regex is `re.escape`d and anchored per id; the ledger check demands exactly 3 rows, all PASS, named from the same `STORE_CELL_IDS` the filter is built from, and zero rows is explicitly red; the merge re-asserts `recorded == 3`; `testing/shadow-oracle/golden` exists so `git status --porcelain -- <that path>` has a real subject; `bin/oracle` carries every subcommand used (`record/merge/fetch-golden/fetch-plugin/cells`); `cargo xtask gate service-images --selftest` runs first; `contents: read` only. Every `run:`-invoked repo file exists (control: `scripts/zzz-nope.sh` → absent). | - |
| `.github/workflows/turnstile-dispatch.yml` | CLEAN | Dispatch-only by design and the header argues the removal of the `push` trigger. The token guard is a real refusal (`[ -z "${GH_TOKEN:-}" ] … exit 1`) under `shell: bash` + `set -euo pipefail`. `.github/workflows/turnstile.yml` is deliberately cross-repo (`GetBusbar/busbar-release`), not local drift. `secrets.TURNSTILE_DISPATCH_TOKEN` is the only use in the tree and the header documents its provisioning. | - |
| `qa/DESIGN-BINDINGS.md` | CLEAN | Generated by `cargo xtask gate design-bindings --write` (`xtask/src/gates/design_bindings/build.rs:25` `OUT_MD_REL`), regen-clean is a gate row. Extracted all 12 `gate:`/`lint:` path citations and all 19 path-qualified `test:` citations → **0 missing on disk** (control: 3 present samples printed). Summary is internally exact: 104 bindings = 104 mapped, 0 unproven, 0 unmapped. | - |
| `qa/documented-claims.json` | FINDING | Normalised-substring search of all 56 claim quotes against `docs/design/inventory/1.5.5-ops-observability.md`: **55 locatable, delta = +1 for every one of them**; 1 unmatched (`README:1055`). The register's own ids are "line addresses" into that document. `scripts/documented-claims-check.py:41` holds `RUNS = (("README", 1047, 1073), ("CHANGELOG", 1087, 1115))` as a literal and the script never opens the inventory document at all (`CLAIMS`/`CELLS`/`LEDGER` are its only three paths). Register is otherwise exact: counts block matches (56/27/29/33/23/2), all 28 cited cell ids present in `cells.json`. | X-2513 |
| `qa/field-coverage.missing` | FINDING | `grep -v '^#'` over the file → **0 data rows**. `crates/busbar/tests/field_coverage.rs:305-308` still `#[ignore]`s `every_field_is_carried_or_waived` on the stated grounds that "the field work queue in qa/field-coverage.missing is the deliverable … a visible red queue is the honest shape". Re-derived the ignored test in Python: `inventory=412 status=412 computed-MISSING=0` → it would **PASS**. | X-2512 |
| `qa/field-coverage.status` | CLEAN | 412 rows = 404 `carried` + 8 `waived`, 0 duplicates, 0 wildcards, 0 ids outside `qa/field-inventory.json` (412 fields). Re-ran the `every_carried_claim_names_a_real_test` scan: 114 distinct carried test names, **0 ghosts** (control: a bogus name is reported as a ghost). Note for elsewhere: that scanner's root list still names the retired `crates/busbar-core/src`; it fails SAFE (a missing root produces more ghosts, not fewer) and 0 carried tests live only under the unscanned `crates/busbar-kernel/src`. | - |
| `qa/field-schemas/anthropic.json` | CLEAN | Read by `xtask/src/gates/field_inventory.rs:78` (`SCHEMA_DIR = "qa/field-schemas"`, directory-enumerated, not a hardcoded dialect list) and is the provenance for `qa/field-inventory.json`. Carries `dialect`/`surface`/`source`/`retrieved`/`note` + request/response field lists; dialect `anthropic` has a live codec at `crates/busbar-llm-codec/src/anthropic/`. | - |
| `qa/field-schemas/bedrock.json` | CLEAN | Same reader and same provenance shape; `surface` = `POST /model/{modelId}/converse`; codec present at `crates/busbar-llm-codec/src/bedrock/` with a `field_carry_tests.rs` naming `qa/field-coverage.status`. | - |
| `qa/field-schemas/cohere.json` | CLEAN | Same reader; `surface` = `POST /v2/chat`; codec present at `crates/busbar-llm-codec/src/cohere/`. | - |
| `qa/field-schemas/gemini.json` | CLEAN | Same reader; `surface` = `POST /v1beta/models/{model}:generateContent`; codec present at `crates/busbar-llm-codec/src/gemini/`. | - |
| `qa/field-schemas/openai.json` | CLEAN | Same reader; `surface` = `POST /v1/chat/completions`; codec present at `crates/busbar-llm-codec/src/openai_chat/`. | - |
| `qa/field-schemas/responses.json` | CLEAN | Same reader; `surface` = `POST /v1/responses`; codec present at `crates/busbar-llm-codec/src/openai_responses/`. Six schema files ↔ six dialect codecs, and the 412-field inventory derived from them matches `qa/field-coverage.status` row-for-row. | - |
| `qa/inventory-gaps.json` | FINDING | Machine-checked every row: 266 gaps, 2 distinct inventory files, **0 missing on disk**, and **0 rows whose cited `file:line` no longer contains the id** (control: `CONF-001` at `1.5.5-config.md:72` resolves). The instrument is live (`xtask/src/gates/inventory_coverage.rs`, `--check` + artifact-drift row). What is PARKed is the magnitude: 266 named gaps against `qa/inventory-coverage.json`'s 552 ids — 48% of documented inventory rows have no PASSing oracle cell, and `generated_at` is `2026-09-10`. | X-2519 |
| `qa/loc.toml` | CLEAN | Read by `xtask/src/loc/config.rs:30` (`CONFIG_PATH`). All 8 crates in `[groups.new-planes]` exist as directories under `crates/` (control: `crates/busbar-nonexistent` → MISSING). `crate_roots = ["crates"]` is a real directory; `extra_crates = []` is documented as deliberate. The file's own note that a missing name is REPORTED rather than treated as zero is the right shape. | - |
| `qa/method-coverage.missing` | FINDING | `grep -v '^#'` → **0 data rows**. `crates/busbar/tests/method_coverage.rs:552-555` still `#[ignore]`s `every_cell_is_implemented_or_waived` with the reason *"RED BY DESIGN until 1.6.0: cells are still MISSING because `crates/busbar-core/src/{mcp,a2a}/` are being deleted and rebuilt cell by cell. The current list is pinned in qa/method-coverage.missing"* — `crates/busbar-core/` does not exist (`ls crates/` → `busbar-kernel`, no `busbar-core`) and the pinned list is empty. Re-derived the ignored test: `cells=230, na_reason=10, status=197, WAIVERS=23, computed-MISSING=0` → it would **PASS**. | X-2512 |
| `qa/method-coverage.status` | CLEAN | 197 rows, all `implemented`, 0 ids outside `qa/method-inventory.json` (230 cells), no duplicates. 230 = 197 implemented + 23 `qa/WAIVERS.md` impossibilities + 10 `na_reason` cells + 0 missing — exact, in both directions, and the `no-bypass` test (`NO_BYPASS_TOKENS`, `method_coverage.rs:489`) refuses any env read or filesystem write in the gate's own source. | - |
| `qa/plane-hook-isomorphism.allow` | FINDING | 27 asymmetry rows, 16 distinct `PlaneDecl` hooks, 4 capabilities — all 4 present in `qa/capability-equality.json`. But the `_doc` block asserts *"Voice is NOT installed in the binary/this test target (off-default, feature-gated)"* while `crates/busbar/Cargo.toml:192` reads `default = [… "plane-voice" …]` and the file itself carries **11 rows with `planes_none: ["voice"]`**. Those 11 can only be non-stale if voice IS reflected — `plane_isomorphism.rs`'s exactness arm (`:100-112`) makes a declared-but-absent pair a hard `STALE allowlist row(s)` failure. | X-2514 |
| `qa/plane-purity-strict.toml` | FINDING | The needle behind every number in this file is `busbar_core` (`xtask/src/gates/plane_purity/scanner.rs:223-225`). Measured: `git grep -c "busbar_core::" -- 'crates/**/*.rs'` → **one line in the whole tree**, and it is the comment at `crates/busbar-kernel/src/lib.rs:26` explaining that *"every internal `busbar_core::` spelling was rewritten to `busbar_kernel::`"* (`:29` `extern crate self as busbar_kernel;`). Against a measured 0, this file's `BACKWARDS = 33` and `[test-reach] llm=24 mcp=1 a2a=3` are ceilings over an empty population. The real reach is `busbar_kernel::`: llm 1327, mcp 607, a2a 482, voice 145 lines (415 of the mcp figure are production, outside `/tests/` and `*_tests.rs`), and `crates/busbar-mcp/Cargo.toml:41` declares `busbar-kernel` as an unconditional path dependency. The file's own header claim that it agrees with `qa/construction.toml`'s `ports-only-tests` "to within a single line" is also false: that table reads `busbar-llm = 0, busbar-mcp = 0, busbar-a2a = 0, busbar-voice = 0`. | X-2511 |
| `qa/reachability-evidence.md` | CLEAN | Read in both directions by `reachability:evidence` (`xtask/src/gates/reachability.rs:1023-1100`): FORWARD, every module the run reports dormant is written up; BACKWARD, every module written up is still in the tree, and a path that is not turns the row red. Checked the backward direction by hand: all 6 `crates/busbar/src/root/*.rs` modules the document writes up exist. (First pass reported 5 — the regex `[a-z_]+` silently dropped `units_a2a.rs`; re-run with `[A-Za-z0-9_]+` gave 6/6.) | - |
| `qa/WAIVERS.md` | CLEAN | 23 recorded impossibilities, each a backticked exact cell id with a one-paragraph argument; **0 ids absent from `qa/method-inventory.json`**. Both tests the header names exist: `recorded_impossibilities_are_exact_and_argued` and `no_status_entry_is_stale`, in `crates/busbar/tests/method_coverage.rs`. The three-way split the 2026-08-14 ruling describes reconciles exactly against the inventory (197 + 23 + 10 na = 230). | - |

---

## ROWS RAISED

### X-2500 · five of six `workflow_run` workflows are absent from the branch GitHub loads them from, and the gate built for that failure guards one file
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ for f in qa-codeql qa-security qa-conformance-a2a qa-conformance-mcp qa-conformance-voice qa-gate; do
    if git cat-file -e origin/main:.github/workflows/$f.yml 2>/dev/null; then
      echo "$f  main=$(git show origin/main:.github/workflows/$f.yml|wc -l)  head=$(git show HEAD:.github/workflows/$f.yml|wc -l)"
    else echo "$f  ABSENT ON origin/main"; fi; done
qa-codeql            ABSENT ON origin/main
qa-security          ABSENT ON origin/main
qa-conformance-a2a   ABSENT ON origin/main
qa-conformance-mcp   ABSENT ON origin/main
qa-conformance-voice ABSENT ON origin/main
qa-gate              main=338  head=408          # identical=NO

$ grep -n 'pub const WORKFLOW\|PROMOTION_BRANCHES' xtask/src/gates/qa_gate_dispatch.rs
81:pub const WORKFLOW: &str = ".github/workflows/qa-gate.yml";
93:pub const PROMOTION_BRANCHES: &[&str] = &["qa", "main"];

$ sed -n '110,120p' scripts/ci-branch-protection.sh      # the only automated protection writer
REQUIRED_CONTEXTS_JSON='[ "ci umbrella", "structure lint",
  "construction gate (…BLOCKING, on its posture)", "ship-ready" ]'   # 4 strings, all from ci.yml
```
`workflow_run` (and `schedule`) resolve the workflow file on the **default branch**. Five of these
six therefore cannot fire on a push to `qa` at all, and the sixth fires in its `main` form. Three of
the five expose contexts `.github/required-status-checks.md:53-56` declares required-on-`qa`
(`cargo-deny …`, `MCP conformance verdict`, `A2A conformance verdict`, `CodeQL (rust)`), and none of
those four is in the enforcement script's floor. The file already names this exact class for
`ship-ready` at `:41-47` ("the context cannot report AT ALL on those branches today"); it has not
been applied to the workflows themselves. `qa-gate-dispatch` — the one instrument written for it —
names a single file and asks its default-branch arm on two branches only.
ACTION:    Either (a) promote the five workflow FILES to `main` ahead of the 1.6.0 release so the
`workflow_run` registration exists, or (b) give each of the five the dispatcher shape `qa-gate.yml`
uses (logic in a script the triggering checkout supplies) — and widen
`xtask/src/gates/qa_gate_dispatch.rs` from a single `WORKFLOW` const to the **set** of
`workflow_run`-triggered workflows, discovered from `.github/workflows/*.yml` with a floor, so a
sixth one cannot be added outside the gate. Add `Voice conformance verdict` and the four qa-only
contexts to `scripts/ci-branch-protection.sh`'s `REQUIRED_CONTEXTS_JSON` **after** (a) or (b), never
before — a required context that cannot report leaves the promotion pending forever, which that
file's own `cargo-deny` note warns about.

### X-2501 · qa-codeql.yml's stated reason for existing is a property it does not have
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git show HEAD:.github/workflows/qa-codeql.yml | sed -n '14,18p;41,43p'
#   * qa-gate.yml is a DISPATCHER whose `on:`/`permissions:` block is read from the DEFAULT branch by
#     `workflow_run` … Adding a job there means the analysis cannot gate the commit that
#     introduced it until the next release. CodeQL has no such constraint, so it does not pay that cost.
  workflow_run:
    workflows: ["CI"]
    types: [completed]
```
The file is itself `workflow_run`-triggered, so GitHub loads `qa-codeql.yml` from the default branch
exactly as it loads `qa-gate.yml`. Unlike `qa-gate.yml` it has no dispatcher indirection, so 100% of
its logic comes from `main`: a CodeQL config change landed on `qa` cannot analyse the commit that
introduced it, and there is no `push` trigger on `main` to catch up. The same header names
`qa-gate-dispatch-lint.py` (`:15`), which is not in the tree (`git ls-files | grep -i qa-gate-dispatch`
→ rc=1, empty; the rule is `cargo xtask gate qa-gate-dispatch`).
ACTION:    Strike the "CodeQL has no such constraint" sentence and replace it with the honest
statement (it pays the cost in full, which is why X-2500's remedy applies to it). Repoint
`qa-gate-dispatch-lint.py` to `cargo xtask gate qa-gate-dispatch`.

### X-2502 · the Voice conformance verdict is declared required nowhere, while its two siblings are
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git show HEAD:.github/workflows/qa-conformance-voice.yml | sed -n '461,463p'
  verdict:
    name: Voice conformance verdict

$ grep -n "Voice conformance" .github/required-status-checks.md ; echo rc=$?
rc=1
$ grep -n "conformance verdict" .github/required-status-checks.md
54:| `MCP conformance verdict` | `qa-conformance-mcp.yml` | …
55:| `A2A conformance verdict` | `qa-conformance-a2a.yml` | …
$ sed -n '115,120p' scripts/ci-branch-protection.sh
REQUIRED_CONTEXTS_JSON='[ "ci umbrella", "structure lint", "construction gate (…)", "ship-ready" ]'
```
`.github/required-status-checks.md:11-12` states the rule this breaks: *"Adding a new blocking
workflow means adding its terminal status here AND to branch protection."* Voice is the third
protocol plane and its conformance workflow has eight legs, a self-test, a verdict-coverage lint and
a fan-in verdict — and nothing declares that verdict blocking.
ACTION:    Add a `| `Voice conformance verdict` | `qa-conformance-voice.yml` | …` row to the qa-only
table in `.github/required-status-checks.md`, and add the four qa-only contexts (including it) to
`REQUIRED_CONTEXTS_JSON` — sequenced after X-2500, not before.

### X-2503 · plugin-functional.yml is a 338-line capability nothing constructs
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "plugin-functional.yml" -- .github/workflows/ scripts/ qa/ | grep -v "workflows/plugin-functional.yml:"
(no output, rc=1)
$ grep -n "functional" plugins.yaml ; echo rc=$?
rc=1
$ grep -nE "^\s*gate:" plugins.yaml | awk '{print $2}' | sort | uniq -c
   1 binary
   2 smoke
   7 suite
$ git cat-file -e origin/main:.github/workflows/plugin-functional.yml ; echo rc=$?
rc=1
```
Its own header (`:45`) instructs plugin repos to call it at `GetBusbar/busbar/.github/workflows/plugin-functional.yml@main`
— the file is not on `main`. Inside this repo nothing calls it either, `qa/segments.toml` has no
functional segment, and no row in `plugins.yaml` declares `gate: functional`. The gap it was written
to close is the one `plugins.yaml`'s own header records: seven of ten plugins are `gate: suite`
(cargo test only) and headroom's published bundle could not boot while every workflow was green. The
fixtures and `verdict.sh` are all real and correct; the caller is what is missing.
ACTION:    Add a `gate: functional` value to `plugins.yaml` for the repos that should take it, and
either (a) add a `functional` segment to `qa/segments.toml` so `scripts/qa-gate-run.sh` drives
Direction A, or (b) land the file on `main` and open the adoption PR in each plugin repo. If neither
is going to happen for 1.6.0, delete the workflow rather than ship a gate nobody runs.

### X-2504 · plugin-consumer-verify.yml is a 533-line capability nothing constructs
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "plugin-consumer-verify.yml" -- .github/workflows/ scripts/ qa/ | grep -v "workflows/plugin-consumer-verify.yml:"
scripts/release-gate/fleet-checks.sh:10:# …plugin-consumer-verify.yml's header documents: the image built and pushed
scripts/release-gate/fleet-checks.sh:30:# …the same trap docker-checks.sh and plugin-consumer-verify.yml both guard.
   (two PROSE mentions; no `uses:` anywhere)
$ git cat-file -e origin/main:.github/workflows/plugin-consumer-verify.yml ; echo rc=$?
rc=1
```
Same shape as X-2503: the adoption snippet in its own header (`:42`, `:54`) points at `@main`, where
the file does not exist, and nothing in this repo calls it. It is the answer to two named, real
production failures (headroom's un-bootable published bundle; webrequest-hook v1.0.4's zero-asset
phantom release) and neither is being checked today.
ACTION:    Land the file on `main` and open the `consumer-verify.yml` adoption PR in each
first-party plugin repo, or delete it. Track adoption in `plugins.yaml` so "which repos verify what
they published" is data rather than a memory.

### X-2505 · the CI-image mirror's anonymous-pullability assertion has never executed: `git log --follow` with two pathspecs is fatal
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git log --diff-filter=A --format=%aI --follow -- \
    .github/workflows/sched-ci-images-mirror.yml .github/workflows/ci-images-mirror.yml
fatal: --follow requires exactly one pathspec        (rc=128)

# the step exactly as GitHub runs it (no `shell:` key -> bash -e {0}; the step adds `set -uo pipefail`)
$ bash -e /tmp/s16_grace.sh
STEP START
fatal: --follow requires exactly one pathspec
step rc=128                                    # the pullability loop below never starts

# and if someone "fixes" it the way plugin-consumer-verify.yml does (set +e):
$ bash /tmp/s16_grace.sh
SURVIVED the assignment; added=[]
age_days=0  (GRACE_DAYS=30)  -> grace expired? NO

# controls
$ git log --diff-filter=A --format=%aI --follow -- .github/workflows/sched-ci-images-mirror.yml | tail -1
2026-08-31T10:13:04-07:00
$ git log --diff-filter=A --format=%aI -- <both paths> | tail -1
2026-08-31T10:13:04-07:00
```
Both branches are defects, and the file's own header names each one: the step the header calls *"THE
ASSERTION THE WHOLE DESIGN RESTS ON"* dies before its first `curl`, and the mechanism the header
calls *"THE NOTICE CANNOT BECOME PERMANENT"* is disarmed because `age_days` is pinned at 0. The
workflow fires on every push to `main`/`dev` that touches `ci.yml`, so this is not a dormant path.
ACTION:    Drop `--follow` (it buys nothing across a rename that `git log` already follows for a
deleted second path) or split into two single-pathspec `git log` calls and take the earlier date:
`added="$( { git log --diff-filter=A --format=%aI --follow -- A; git log --diff-filter=A --format=%aI -- B; } | sort | head -1 )"`.
Add a refusal when `added` is empty (`echo "::error::the grace clock could not be derived"; exit 1`)
so an unreadable clock is never read as "0 days old".

### X-2506 · cost-watch's four-band exit-code contract is unreachable; a $50 soft-alarm reds the weekly job
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
# the step verbatim: no `shell:` key, so GitHub runs `bash -e {0}`; the script adds `set -uo pipefail`
$ bash -e /tmp/s16_shell_proof.sh                     # python3 exits 2 (SOFT-ALARM band)
would-be spend table
step rc=2                                             # the `case` never runs
$ bash --noprofile --norc -eo pipefail /tmp/s16_shell_proof.sh
would-be spend table
step rc=2
$ bash /tmp/s16_shell_proof.sh                        # CONTROL: the shell the comment assumes
would-be spend table
::warning::SOFT-ALARM (this line is what the workflow claims happens)
REACHED-END
step rc=0

$ sed -n '99,108p' scripts/cost-watch.py
    0   < $50  ok | 2  $50..$80 SOFT-ALARM | 3  $80..$100 REVIEW | 1  >= $100 HARD CAP | 4  tool failed
```
`set -uo pipefail` does not clear `-e`; `plugin-consumer-verify.yml:173-178` documents exactly this
(*"GitHub runs every `run:` block as `bash -e {0}`, so errexit is ALREADY ON before line 1 and
`set -uo pipefail` does not turn it off"*) and issues `set +e`. This file does not. Consequences:
the `2)`, `3)`, `4)` and `*)` arms of the `case` are dead code; the documented behaviour ("only the
hard-cap breach and a tool failure turn this job red — a soft-alarm or review is surfaced as loud
warnings") is inverted; and the weekly schedule goes red on a routine $50 crossing, which is the
"a gate that is red every week is a gate somebody puts a `|| true` in front of" shape
`xtask/src/full_gate.rs:411` warns about in so many words.
ACTION:    Add `set +e` as the first line of the step (above `set -uo pipefail`), matching
`plugin-consumer-verify.yml`'s form, and keep the explicit `exit 1` on the `1)`/`4)`/`*)` arms.
Consider a `--selftest`-style assertion in the workflow that a planted exit-2 reaches the warning
arm, so this cannot regress silently.

### X-2507 · the monthly refresh bumps a version that has not lived in that file since the workspace split
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ cur=$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/'); echo "cur=[$cur]"
cur=[]
$ grep -n "^version = \|^\[workspace" Cargo.toml
1:[workspace]
84:[workspace.dependencies]
$ grep -m1 -n '^version = ' crates/busbar/Cargo.toml       # CONTROL: where it actually lives
3:version = "1.6.0"
```
With `cur` empty, `IFS=. read -r MA MI PA <<< ""` leaves all three empty, `$((PA + 1))` evaluates to
`1`, `new` becomes `..1`, and the `sed` whose pattern is `^version = ""` matches nothing. The job
stays green, bumps no version, and opens a PR titled `Monthly dependency refresh -> v..1` on branch
`deps/monthly-refresh-v..1`. `prepare-release.yml:75` already bumps the right file
(`.github/scripts/bump_cargo.py "$V" crates/busbar/Cargo.toml`). Secondary: the PR targets
`--base main`, bypassing the dev→qa→main model every other release path in this slice enforces, and
its body tells the reader to "push tag `v$new` to cut the release", which is not how `release.yml`
works any more (it promotes a recorded staged digest).
ACTION:    Replace the `grep`/`sed` pair with `python3 .github/scripts/bump_cargo.py "$new" crates/busbar/Cargo.toml`
and read `cur` from `crates/busbar/Cargo.toml`; add `[ -n "$cur" ] || { echo "::error::could not read the current version"; exit 1; }`.
Change `--base main` to `--base dev` and rewrite the PR body to say "merge to dev, then promote
dev→qa→main".

### X-2508 · prepare-release.yml hands the reader off to a workflow that was deleted
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ ls .github/workflows/tag-on-main.yml
ls: .github/workflows/tag-on-main.yml: No such file or directory
$ git log --oneline --all -- .github/workflows/tag-on-main.yml | head -1
a1879f190 busbar 1.6.0: gates + scripts + CI
$ git show HEAD:.github/workflows/prepare-release.yml | grep -n "tag-on-main"
22:#   4. Commit + push to `dev` (NO tag — the tag is main's job).
112:      - name: Commit + push to dev (NO tag — tag-on-main.yml cuts the release when this reaches main)
119:               "Promote dev→qa (full gate) then qa→main — tag-on-main.yml will auto-tag v$V and cut the release."
```
`::notice::` at `:119` is the message a human reads at the end of every release prep, and it names a
workflow that has not existed since `a1879f190`. The actual releaser is `release.yml`'s
`promote-release`, and `release.yml:120` still carries the same stale reference
(*"exactly as tag-on-main.yml read it"*).
ACTION:    Replace both mentions with `release.yml` and correct the sentence: a push to `main`
triggers `release.yml`, which promotes the record `release-stage.yml` wrote on `qa` (it does not
"auto-tag from the prepared commit"). Fix the same string at `release.yml:120`.

### X-2509 · three jobs use a repo-local composite action with nothing checked out at the workspace root
CLASS:     config
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ python3 <yaml walk over all 29 workflows: for each job, record whether an actions/checkout with
   no `path:` precedes any `uses: ./...`>
…
.github/workflows/plugin-ci.yml   job=build-test-signoff  local-action=./.github/actions/cargo-home  root_checkout_before=False
.github/workflows/plugin-ci.yml   job=coverage            local-action=./.github/actions/cargo-home  root_checkout_before=False
.github/workflows/qa-gate.yml     job=build               local-action=./.github/actions/cargo-home  root_checkout_before=False
   (38 of the 41 sites in the tree report root_checkout_before=True)

$ git blame -L 236,238 .github/workflows/qa-gate.yml
7003b443fd (Matthew Jackson 2026-09-16 236)       - name: Resolve cargo home …
7003b443fd (Matthew Jackson 2026-09-16 237)         uses: ./.github/actions/cargo-home
133fd6ae8e (matthew         2026-08-05 222)           path: busbarAI     # the checkout it needs
```
All three jobs check out only into subdirectories (`path: busbarAI`, `path: plugin`), so
`$GITHUB_WORKSPACE/.github/actions/cargo-home` — where the runner resolves a `./` action — is not
populated. The step was bulk-added by the Latchkey migration (`7003b443fd`, 2026-09-16) six weeks
after the `path:` structure it landed in. Demoted to ADJUDICATE because I cannot execute a GitHub
runner from here; the structural asymmetry (38/41 vs 3/41) is measured and is the part I am
asserting. If the runner does resolve it, the downstream `${{ env.CARGO_HOME }}` in the cache
`path:` is empty for those three jobs, which silently caches nothing — the exact defect the action
exists to prevent.
ACTION:    In those three jobs, point the step at the checkout that exists —
`uses: ./busbarAI/.github/actions/cargo-home` for `qa-gate:build`, and
`uses: ./busbarAI/.github/actions/cargo-home` for both plugin-ci jobs — or add a bare
`actions/checkout` with no `path:` before it. Then add a one-line lint (the yaml walk above) so a
future bulk edit cannot reintroduce it.

### X-2510 · keep-proof writes its verdict onto the dispatched ref's sha, not the sha it tested
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git show HEAD:.github/workflows/manual-keep-proof.yml | grep -n 'inputs.ref\|statuses/\${GITHUB_SHA}'
104:          ref: ${{ inputs.ref || github.ref }}      # build-clippy
499:          ref: ${{ inputs.ref || github.ref }}      # gates
661:          ref: ${{ inputs.ref || github.ref }}      # oracle
901:          ref: ${{ inputs.ref || github.ref }}      # construction-gate
862:          gh api -X POST "repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}" … context="keep-proof/oracle"
975:          gh api -X POST "repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}" … context="keep-proof"
```
The workflow is `workflow_dispatch`-only and its single input exists precisely to prove **another**
ref. On such a dispatch `github.sha` is the sha of the ref the run was dispatched on, so every job
tests `inputs.ref` and both commit statuses land on a different commit. The file's own stated
purpose (`:14-15`) is *"the harvest question — 'is this hand-back green?' — becomes a lookup on the
sha"*, and a green `keep-proof` can therefore be stamped on a commit nothing tested.
ACTION:    Resolve the tested sha once (e.g. a `resolve` job that runs
`git rev-parse "${{ inputs.ref || github.ref }}"` after checkout and exports it as an output) and
POST both statuses to that value, not `${GITHUB_SHA}`. Refuse if the two disagree and the input was
empty.

### X-2511 · the plane-purity strict ratchet counts a crate spelling that was renamed out of the tree
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n 'busbar_core' xtask/src/gates/plane_purity/scanner.rs
223:            let reach = path_of(&code, "busbar_core")
224:                || extern_crate_of(&code, "busbar_core")
225:                || bound_as(&code, "busbar_core");

$ git grep -c "busbar_core::" -- 'crates/**/*.rs'
crates/busbar-kernel/src/lib.rs:1                 # <- a COMMENT, and the only hit in the tree

$ sed -n '25,29p' crates/busbar-kernel/src/lib.rs
// W4.a (#19/#37): this crate's source was absorbed INTO busbar-kernel; every internal
// `busbar_core::` spelling was rewritten to `busbar_kernel::`. …
extern crate self as busbar_kernel;

$ for k in llm mcp a2a voice; do printf "%-6s busbar_core::=%s  busbar_kernel::=%s\n" $k \
    "$(grep -rn 'busbar_core::'   crates/busbar-$k/src | wc -l|tr -d ' ')" \
    "$(grep -rn 'busbar_kernel::' crates/busbar-$k/src | wc -l|tr -d ' ')"; done
llm    busbar_core::=0  busbar_kernel::=1327
mcp    busbar_core::=0  busbar_kernel::=607
a2a    busbar_core::=0  busbar_kernel::=482
voice  busbar_core::=0  busbar_kernel::=145

$ grep -rn "busbar_kernel::" crates/busbar-mcp/src --include='*.rs' | grep -v "/tests/" | grep -v "_tests.rs" | wc -l
415                                                # PRODUCTION lines, not test code
$ grep -n "busbar-kernel = " crates/busbar-mcp/Cargo.toml
41:busbar-kernel = { path = "../busbar-kernel", default-features = false, features = ["plane-mcp"] }
```
`BACKWARDS = 33` and `[test-reach] llm=24 mcp=1 a2a=3 voice=0` are ceilings over a measured
population of zero: the rule they enforce ("a plane crate must not name core's implementation") now
has 2,561 matching lines under the new spelling and the scanner sees none of them. This is the same
defect `qa/construction.toml` already records for a different row at `:373` — *"This row named the
deleted path and therefore scanned a population of ZERO on that side — a ban over nothing, printing
PASS."* The file's cross-reference is also false: it claims agreement "to within a single line" with
`qa/construction.toml`'s `ports-only-tests`, which reads `busbar-llm = 0, busbar-mcp = 0,
busbar-a2a = 0, busbar-voice = 0`.
ACTION:    Repoint the needle in `xtask/src/gates/plane_purity/scanner.rs:223-225` from
`busbar_core` to `busbar_kernel` (and keep `busbar_core` alongside it so an unconverted file is
still caught), then **re-measure** every ceiling in `qa/plane-purity-strict.toml` against the new
population and commit the real numbers — do not carry the current ones forward. Fix the
`[test-reach]` cross-reference paragraph to quote `qa/construction.toml`'s actual values. The same
repoint is owed to `qa/construction.toml`'s `[rules.ports-only]`/`[rules.ports-only-tests]`
`needle = "busbar_core::"` (**outside this slice** — reported, not acted on).

### X-2512 · both pinned work queues are empty, and both full-strength acceptance tests are still `#[ignore]`d on the grounds that the queues are long
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -cv '^#' qa/field-coverage.missing   qa/method-coverage.missing     # data rows
0
0

$ sed -n '303,311p' crates/busbar/tests/field_coverage.rs
/// Kept at full strength and `#[ignore]`d … It is red today by design: the field work queue is
/// `qa/field-coverage.missing` and it is long …
#[ignore = "1.6.x acceptance: the field work queue in qa/field-coverage.missing is the deliverable, \
            and a visible red queue is the honest shape of a partial sweep"]
fn every_field_is_carried_or_waived() {

$ sed -n '552,556p' crates/busbar/tests/method_coverage.rs
#[ignore = "RED BY DESIGN until 1.6.0: cells are still MISSING because crates/busbar-core/src/{mcp,a2a}/ \
            are being deleted and rebuilt cell by cell. The current list is pinned in \
            qa/method-coverage.missing …"]
fn every_cell_is_implemented_or_waived() {
$ ls -d crates/busbar-core 2>&1
ls: crates/busbar-core: No such file or directory

# both ignored tests re-derived in python from the same three inputs each reads:
FIELD : inventory=412 status=412 computed-MISSING=0 pinned-MISSING=0  -> would PASS
METHOD: cells=230 na_reason=10 status=197 WAIVERS=23 computed-MISSING=0 pinned=0 -> would PASS
```
Two release-acceptance assertions — "every enumerated dialect field is carried or waived" and "every
inventory cell is implemented or waived" — are switched off, and the reason each gives for being
switched off has expired: the queues are at zero and the method ignore cites a crate path that no
longer exists. `method_coverage.rs:550` even says *"Remove the `#[ignore]` when it passes. Do not
remove it any other way."* It passes.
ACTION:    Run both with `--ignored` on a clean tree, then delete the two `#[ignore]` attributes and
the now-false doc paragraphs above them, in the commit that proves them green. Keep the empty
`.missing` files (the exactness assertions still bite on a regression). Nothing in
`qa/*.missing` should be edited to achieve this.

### X-2513 · every documented-claim "line address" is off by one, and the gate compares them to a hardcoded constant instead of the document
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
# normalised substring search of all 56 quotes against the cited document
$ python3 <see report> 
README+CHANGELOG delta (actual line - cited line): {1: 55}
still unmatched: ['README:1055']

$ sed -n '1047,1048p;1073,1074p' docs/design/inventory/1.5.5-ops-observability.md
|---|---|---|                                          # <- register says README:1047 is a claim
| "Six wire protocols, first class on both sides: …    # <- the claim is actually here, 1048
| "five built-in routing policies" | `README.md:280` … # <- register says README:1073
| `image: getbusbar/busbar:1.5.3` and "run against …   # <- the claim is actually here, 1074

$ sed -n '38,43p' scripts/documented-claims-check.py
# The two runs the binding names, as (prefix, first, last). These are line addresses into
# docs/design/inventory/1.5.5-ops-observability.md's two cross-check sections …
RUNS = (("README", 1047, 1073), ("CHANGELOG", 1087, 1115))
$ grep -n "^ROOT\|^CLAIMS\|^CELLS\|^LEDGER" scripts/documented-claims-check.py
33:ROOT = … ; 34:CLAIMS = qa/documented-claims.json ; 35:CELLS = …cells.json ; 36:LEDGER = …ledger.tsv
```
The checker opens three files and the inventory document is not one of them. It asserts the register
is contiguous over `RUNS`, and `RUNS` is a literal that was correct when it was typed. So the 56
addresses and the constant agree with each other and neither agrees with the document. This is the
defect `xtask/src/gates/reachability.rs:150-168` names by title — *"a citation nobody checks is a
citation that can be wrong for a year without anyone learning that it is"* — and that gate's
BACKWARD/FORWARD arms are the shape this one is missing.
ACTION:    Add a fourth input to `scripts/documented-claims-check.py`: read
`docs/design/inventory/1.5.5-ops-observability.md` and assert, per claim, that the cited line
carries the quote (normalised for the table's `| … |` framing and backticks). Derive `RUNS` from the
document rather than declaring it. Then re-address all 56 ids (+1) in `qa/documented-claims.json` in
the same commit, with the diff readable.

### X-2514 · the isomorphism allowlist's own preamble contradicts the feature set and its own rows
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git show HEAD:qa/plane-hook-isomorphism.allow | sed -n '18,21p'
"Voice is NOT installed in the binary/this test target (off-default, feature-gated), so its",
"skeleton asymmetries are governed by the no-deferral gate + the ledger's voice pin, not by this",
"reflection — see the test header."

$ grep -n "^default = " crates/busbar/Cargo.toml
192:default = ["auth-admin-tokens","hooks-ranking","proto-llm","plane-mcp","plane-a2a","plane-voice", …]

$ python3 -c "import json;d=json.load(open('qa/plane-hook-isomorphism.allow'));
print(sum(1 for r in d['asymmetries'] if 'voice' in r['planes_none']), 'rows declare planes_none:[voice]')"
11 rows declare planes_none:[voice]

$ grep -n 'cfg(feature = "plane-voice")' -A1 crates/busbar/tests/plane_isomorphism.rs
109:    #[cfg(feature = "plane-voice")]
110-    v.push(("voice", &busbar_voice::PLANE_DECL));
```
`plane-voice` is a default feature, so `installed_decls()` includes voice under a default
`cargo test -p busbar` and the 11 voice rows are live. If the preamble were true, the test's
exactness arm (`plane_isomorphism.rs:100-112`, `STALE allowlist row(s)`) would fail on all 11. Also
checked and clean: 27 rows, 16 distinct hooks, 4 capabilities all present in
`qa/capability-equality.json`, every `reason` ≥ 40 chars.
ACTION:    Strike the "Voice is NOT installed" paragraph from the `_doc` block and replace it with
the current fact (voice is a default feature, its asymmetries ARE reflected, and the 11 rows below
are the live declarations). If voice is ever moved off-default, the 11 rows must go with it in the
same commit.

### X-2515 · "five targets" in the prose, six in the manifest
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ python3 -c "import json;t=json.load(open('.github/release-targets.json'))['targets'];
print('published:',sum(1 for x in t if x['published']))"
published: 6
$ git grep -n "five targets\|FIVE TARGETS\|all five targets\|these five targets" -- .github/
.github/release-targets.json:31:    "GitHub now offers a native runner for every one of these five targets …"
.github/workflows/build-artifact.yml:111:      # THE BUILD. One step, one script, one env block, five targets.
.github/workflows/release-stage.yml:969:  # -- THE BUILD: ONE PIPELINE, ONE STEP, FIVE TARGETS ---
.github/workflows/release-stage.yml:1161:  # applies to all five targets automatically, …
$ git show HEAD:.github/workflows/release-stage.yml | sed -n '908,912p'
          if len(inc) < 6:
              raise SystemExit("release-targets.json declares %d PUBLISHED targets; busbar ships 6…")
```
The `aarch64-unknown-linux-gnu-armv8.0` compat variant made it six; the code floors at 6 and the
prose still says five in four places. Harmless today because nothing branches on the count — which
is exactly why it will still be wrong the next time somebody reads it to decide something.
ACTION:    Replace "five" with "six" at those four sites (and the matching "five assets" narrative
at `release-stage.yml:1155`, which is a correct historical reference to 1.5.3 and should be left
alone — only the present-tense counts change).

### X-2516 · the BOLT pipeline's output is consumed by nothing
CLASS:     missing-code
CERTAINTY: ADJUDICATE
EVIDENCE:
```
$ git grep -n "busbar-bolt" -- .github/ scripts/ qa/
.github/workflows/manual-bolt-pass.yml:166:          name: busbar-bolt-${{ inputs.arch }}
   (the upload is the only occurrence: nothing downloads it)
$ git show HEAD:.github/workflows/manual-bolt-pass.yml | sed -n '25,32p'
# WHAT IT DELIBERATELY DOES NOT DO … The BOLTed binary lands as the `busbar-bolt-<arch>` artifact of
# THIS run and nothing downstream consumes it yet … is a deliberate release-pipeline decision that
# has not been taken, not an oversight.
```
Self-declared open seam, so ADJUDICATE rather than a defect claim. Recorded because the contract's
second law is exactly this: a capability that is never constructed is a capability that does not
ship, and a measured +38% req/s is being left on the floor behind a manual dispatch whose profile
hand-off ("a run that receives the capture … whose run id is then handed to this workflow") is also
undefined.
ACTION:    Owner ruling for 1.6.0: either wire `busbar-bolt-<arch>` into what `release-stage.yml`
stages and `record-staged` records (so the promoted bytes are the BOLTed bytes, with the artifact
contract re-run against them), or mark the workflow explicitly out-of-scope for 1.6.0 in
`docs/design/BUSBAR-1.6.0.md` so nobody counts the +38% as shipped.

### X-2517 · three workflows cite a release-order lint that is not in the tree
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git ls-files | grep -i release-order ; echo rc=$?
rc=1
$ git grep -n "release-order-lint.py" -- .github/workflows/
.github/workflows/ci.yml:2932          (outside this slice)
.github/workflows/docker.yml:65,840    (outside this slice)
.github/workflows/release-stage.yml:48
.github/workflows/release.yml:64
$ ls xtask/src/gates/release_order.rs && grep -n "release-order" xtask/src/full_gate.rs | head -2
xtask/src/gates/release_order.rs
173:    "cargo xtask gate release-order --selftest",
174:    "cargo xtask gate release-order",
$ sed -n '534,543p' xtask/src/full_gate.rs
/// THERE WAS A RULE 2, AND IT WAS DEAD CODE FOR A YEAR OF COMMITS. It read "`release-order-lint.py`
/// …" … `cargo xtask gate release-order`, which CI invokes as a gate in its own right.
```
The rule is alive; only the name in the prose is dead. `release.yml:64` and `release-stage.yml:48`
are the two places a reader goes to learn what enforces "main never rebuilds, qa never names" —
R1/R10/R11/R12 are cited by number in four workflows and the file they are attributed to does not
exist. `full_gate.rs` already records that this exact stale spelling hid dead code for a year.
ACTION:    Replace every `scripts/release-order-lint.py` reference with
`cargo xtask gate release-order` (`xtask/src/gates/release_order.rs`) and check that each cited rule
number (R1, R10, R11, R12) still exists under that name in the gate; delete or renumber any that
does not. `ci.yml:2932` and `docker.yml:65,840` carry the same string and are **outside this slice**
— reported, not acted on.

### X-2518 · branch-green's API-failure refusal message cannot be printed
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
# the release.yml / release-stage.yml `api()` shape, reproduced verbatim, under GitHub's shell
$ bash -e /tmp/s16_api_proof.sh
  api read of repos/x/y/actions/runs failed (attempt 1/5)
  … 5/5
rc=1                       # the ::error:: line never printed
$ bash /tmp/s16_api_proof.sh        # CONTROL: the shell the comment assumes ("deliberately NOT -e")
  … 5/5
::error::REFUSING TO RELEASE: the API could not be read after 5 attempts
rc=1
$ git show HEAD:.github/workflows/release.yml | sed -n '346p'
          set -uo pipefail   # deliberately NOT -e: an API hiccup must be RETRIED, then refused.
```
`shell: bash` gives `bash --noprofile --norc -eo pipefail {0}`, so `-e` is on before the script's
first line and `set -uo pipefail` does not clear it (`plugin-consumer-verify.yml:173-178` documents
precisely this and issues `set +e`; these two do not). The retries still run — the `for` body's
assignment is inside the function, which is invoked from a command substitution — but the shell
exits at `runs="$(api …)"`, so `if [ $? -ne 0 ]` and both "Unknown is not green" refusals are
unreachable. Fails CLOSED (the job is red either way), so this is a lost diagnostic rather than a
false green; recorded because the comment asserts a shell behaviour the file does not have, and the
same two lines exist in `release-stage.yml:361`.
ACTION:    Add `set +e` before `set -uo pipefail` in `release.yml:344-346` and
`release-stage.yml:359-361`, matching `plugin-consumer-verify.yml`'s form, so the refusal messages
those blocks were written to print can actually print.

### X-2519 · 266 of 552 documented inventory rows have no PASSing oracle cell
CLASS:     customer-surface
CERTAINTY: PARK
EVIDENCE:
```
$ python3 -c "import json;print(len(json.load(open('qa/inventory-gaps.json'))['gaps']))"
266
$ python3 -c "import json;d=json.load(open('qa/inventory-coverage.json'));print(len(d['ids']),d['generated_at'])"
552 2026-09-10
$ python3 -c "…collections.Counter(x['family'] …)"
{'CONF': 204, 'RT': 35, 'SEC': 15, 'BOOT': 10, 'LST': 2}
# every row verified exact: 0 cited files missing, 0 rows whose file:line no longer holds the id
# (control: CONF-001 at docs/design/inventory/1.5.5-config.md:72 resolves)
```
The FILE is correct and the gate around it is live (`xtask/src/gates/inventory_coverage.rs`
`--check` plus an artifact-drift row, and a gap naming a row that no longer exists or has since been
covered is red). What is PARKed is the number: 48% of the documented 1.5.5 surface — including 204
config rows and 15 SEC rows — is named as uncovered, and `generated_at` is two weeks old.
ACTION:    Owner ruling: is 266 named gaps an acceptable 1.6.0 posture, or is a subset (SEC-* and
BOOT-* first, 25 rows) owed a citing cell before release? Whatever the answer, regenerate
`qa/inventory-gaps.json` with `cargo xtask gate inventory-coverage --write` on the release SHA so
`generated_at` is the commit being shipped. **Do not self-approve.**

### X-2520 · keep-proof's replay step writes a step output nothing reads, on a path that cannot reach it
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git show HEAD:.github/workflows/manual-keep-proof.yml | sed -n '777,791p'
      - name: Replay — candidate vs the committed golden (strict, same id-filter)
        id: replay
        continue-on-error: true
        run: |
          set -uo pipefail
          ./bin/oracle diff … --id-filter "$FAMILIES" --strict
          echo "rc=$?" >> "$GITHUB_OUTPUT"
$ git show HEAD:.github/workflows/manual-keep-proof.yml | grep -n "steps.replay"
802:          REPLAY_RC: ${{ steps.replay.outcome }}
   (no reference to steps.replay.outputs.rc anywhere)
```
The verdict correctly reads `steps.replay.outcome` (which, under `continue-on-error: true`, is the
pre-continue result and therefore carries the `--strict` verdict). The `rc` output is read by
nothing — and under `bash -e` it is never written on the only path where it would be interesting,
because the shell exits at the failing `./bin/oracle diff`. Two halves of a mechanism, neither
connected. This workflow **does** pass `--strict` (unlike `ci.yml:3342` and `oracle-proof.yml:234`),
so the verdict itself is live.
ACTION:    Delete the `echo "rc=$?" >> "$GITHUB_OUTPUT"` line — `steps.replay.outcome` is the
mechanism that works and the second one only invites a reader to trust an output that is absent.

---

## TALLY
```
files in slice:  38      (= wc -l .sweep/S16-ci-qa.txt)
verdict lines:   38
CLEAN:           14
FINDING:         24      rows raised: 21   (X-2500 .. X-2520)
DELETABLE:        0
UNREADABLE:       0
```

Rows by class: instrument-blind 8 (X-2500, X-2502, X-2505, X-2510, X-2511, X-2512, X-2513, X-2518),
drift 6 (X-2501, X-2507, X-2508, X-2514, X-2515, X-2517), missing-code 4 (X-2503, X-2504, X-2516,
X-2520), config 2 (X-2506, X-2509), customer-surface 1 (X-2519).  8+6+4+2+1 = 21.
Rows by certainty: VERIFIED 18, ADJUDICATE 2 (X-2509, X-2516), PARK 1 (X-2519).

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT (reported, not acted on)

1. **`qa/construction.toml`** (another agent's file, in-flight edits): `[rules.ports-only]` and
   `[rules.ports-only-tests]` use `needle = "busbar_core::"` with `max_per_crate = 0` for all four
   plane crates. `git grep -c "busbar_core::" -- 'crates/**/*.rs'` returns exactly one hit and it is
   a comment. Both rules scan a population of zero and print PASS while 2,561 `busbar_kernel::`
   lines sit under the four plane crates. Same root cause as X-2511.
2. **`xtask/src/gates/plane_purity/scanner.rs:223-225`** is the needle that must be repointed for
   X-2511 to be fixable; `xtask/src/gates/plane_purity/mod.rs` carries the same spelling in its row
   titles and selftest fixtures.
3. **`crates/busbar/tests/field_coverage.rs:34`** scans `crates/busbar-core/src`, which does not
   exist; `read_dir` failure is swallowed with `continue`, so there is no floor on how many roots
   were actually read. It fails SAFE today (0 carried tests live only under the unscanned
   `crates/busbar-kernel/src`), but the root list should be repointed.
4. **`crates/busbar/tests/method_coverage.rs:552`** and **`field_coverage.rs:305`** hold the two
   `#[ignore]`s X-2512 is about; both would pass today.
5. **`scripts/documented-claims-check.py:41`** holds the hardcoded `RUNS` constant X-2513 is about
   and never opens the document it addresses.
6. **`.github/required-status-checks.md`** declares four qa-only required contexts that
   `scripts/ci-branch-protection.sh`'s `REQUIRED_CONTEXTS_JSON` does not enforce, and omits
   `Voice conformance verdict` entirely (X-2500, X-2502).
7. **`.github/workflows/ci.yml:2932`** and **`docker.yml:65,840`** carry the dead
   `scripts/release-order-lint.py` reference (X-2517).
8. **`ci.yml:3342`** and **`oracle-proof.yml:234`** confirmed live as the parent described: the
   replay is run WITHOUT `--strict` under a step titled "0 divergences". For contrast,
   `manual-keep-proof.yml:790` passes `--strict` and is the shape those two should take.
   `bin/oracle`'s `replay` case forwards to `busbar-oracle diff` and no longer injects
   `--allow-harness-skew`, so the only thing standing between those two jobs and a real verdict is
   the missing flag.
