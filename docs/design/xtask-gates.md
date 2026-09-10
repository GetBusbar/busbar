# `cargo xtask gate` — converting every CI/local instrument into Rust

**Status:** design, owner-decided 2026-09-06. **Scope:** every executable under `scripts/`, plus the
`.github/scripts/` pair and the shared libraries they source. **Not in scope:** `testing/shadow-oracle/`,
which stays Python by owner decision (see the segregation section).

## The decision this document implements

1. Gate logic lives in **Rust**, in the existing `xtask` workspace member, reachable as
   `cargo xtask gate <name>`.
2. `.github/workflows/ci.yml` calls **one command per gate**. No gate logic in YAML.
3. `scripts/land.sh` becomes a thin wrapper over `cargo xtask land …`, then retires.
4. **Python is allowed only in `testing/shadow-oracle/`**, which must stay fully segregated from the
   workspace it judges. No new bash and no new Python anywhere else in this repo.
5. **The bash converts first.** The second and third audit rounds read the Rust, not the shell.

The tree today holds 58 top-level `scripts/*.sh`, 22 top-level `scripts/*.py`, 25 more `.sh` and 3 more
`.py` in `scripts/*/`, 9 `.mjs`, and the data files those read. `ci.yml` alone carries 86 invocation
sites across 24 jobs; `qa/segments.toml` carries 17 more inside segment `run` strings; the other 18
workflows carry the release, conformance and plugin paths.

---

## 1. Every script: purpose, callers, self-test, target gate, batch

Legend for **Callers**: `ci` = a `run:` step in `.github/workflows/ci.yml`; `wf:<name>` = another
workflow; `seg` = a `run` string in `qa/segments.toml`; `sh` = invoked by another script; `—` = nothing
invokes it. **ST** = the file advertises `--selftest`.

### 1.1 The every-push structure-lint job (batch 1)

These are the twenty-one gate invocations inside `ci.yml`'s `structure-lint` job, minus the four that
the owner named into batches 2 and 3 (marked below). Every one of them is a pure text/graph read of the
tree with no build, no network and no service container — which is exactly why they are the first batch.

| Script | Purpose | Callers | ST | Gate name | Batch |
| --- | --- | --- | --- | --- | --- |
| ~~`structure-lint.sh`~~ **DELETED** | code-layout invariants from `docs/code-layout.md` plus the behavioural invariants only a structural read can catch (choke-point bypasses, plane duplicate tables/modules, per-crate file census) | ci, sh | yes | `structure-lint` **(converted; see 6.1)** | 1 |
| `release-script-lint.sh` | durable guard on the release harness `release-check*.sh` (incl. the 1.5.2 watchdog `timeout` re-exec) | ci | yes | `release-script-lint` | 1 |
| `release-order-lint.py` | the release-ordering rules, including the one that keeps every workflow off a protected branch; `--prove` arm asserts a failure leaves nothing public | ci (`--selftest`, `--root .`, `--prove`), sh | yes | `release-order` | 1 |
| `duplex-ws-default-edge.sh` | no WebSocket crate in the default money-path dependency closure | ci | yes | `duplex-ws-default-edge` | 1 |
| `ci-umbrella-lint.py` | every job in `ci.yml` is either in the umbrella's `needs` or named as a deliberate exclusion with a reason | ci | yes | `ci-umbrella` | 1 |
| `no-self-filed-issues-lint.sh` | the repository does not file issues against itself | ci | yes | `no-self-filed-issues` | 1 |
| `changelog-lint.py` | CHANGELOG grammar; `--require-version` arm used by `release-stage.yml` | ci, wf:release-stage | yes | `changelog` | 1 |
| `workspace-deps-lint.py` | every crate dependency goes through the workspace table | ci | yes | `workspace-deps` | 1 |
| `qa-gate-dispatch-lint.py` | the dispatcher on the default branch matches the one in this tree (needs a fetched `origin/main`) | ci | yes | `qa-gate-dispatch` | 1 |
| `response-header-lint.sh` | the response-header consolidation cannot be bypassed | ci, sh | yes | `response-header` | 1 |
| `tracing-lint.sh` | every span is bound to an explicit Level, set in one place | ci, sh | yes | `tracing` | 1 |
| `settings-leak-lint.sh` | an admin READ never serves an operator settings bag's values | ci, sh | yes | `settings-leak` | 1 |
| `blocking-ffi-lint.sh` | a synchronous call into a dlopened plugin never runs on a Tokio worker | ci, sh | yes | `blocking-ffi` | 1 |
| `kernel-token-wire-purity-lint.sh` | the kernel never re-derives a usage token class from a raw provider wire pointer | ci, seg | yes | `kernel-token-wire-purity` | 1 |
| `inventory-ref-lint.py` | every design binding's `inventory` column names a file that exists | ci, seg, sh | yes | `inventory-ref` | 1 |
| `changelog-register-check.sh` + `.py` | every accepted `breaking` entry names a real CHANGELOG line, verbatim. The `.sh` is a 19-line wrapper over the `.py` | ci, seg, sh | yes | `changelog-register` | 1 |
| `plane-purity-lint.sh` | the enforcement gate for the plane ABI: no side channel in the neutral crates | ci, seg, sh | yes | `plane-purity` | 1 |
| `plane-transport-neutrality.sh` | no voice-transport/media noun in the neutral crates | ci, sh | yes | `plane-transport-neutrality` | 1 |
| `plane-abi-neutrality.sh` | no protocol/role noun in the plane ABI hot lane | ci, sh | no | `plane-abi-neutrality` | 1 |
| `plane-keys.sh` | sourced-only library: `PLANE_KEYS`, `PLANE_KEYS_PROTOCOL`, `plane_src_roots`, `neutral_src_roots`, `plane_keys_other` | sh (7 gates) | no | folds into `xtask::planes` | 1 (shared) |
| `plane-roots.sh` | sourced-only library: `plane_roots_resolve` — finds the one directory that *declares* a plane (`pub const PLANE_DECL`), refusing zero or ambiguous matches; carries its own `plane_roots_selftest` | sh (5 gates) | (own selftest fn) | folds into `xtask::planes` | 1 (shared) |
| `release-gate/lib.sh` | sourced-only library: `record()` (the ledger row writer), `retry`, `http_code`, `fetch`, `is_cloudflare_block`, `contract_jq`, `published_targets`, `target_field` | sh (6), wf | no | folds into `xtask::ledger` + `xtask::net` | 1 (shared) / 3 (net half) |
| `release-gate/gate.sh` | THE verdict: concatenates every leg's ledger TSV, diffs against `expected-ids.sh --describe`, RED on fail / did-not-run / non-allowlisted SKIP / zero rows | wf:release-fleet, wf:release-stage, sh | no | `xtask::ledger::verdict` + `cargo xtask gate release-verdict` | 1 (the type) / 3 (the gate) |

Two steps in that job stay pointed at batch-3 gates until batch 3 lands, because the job runs only their
`--selftest` arm and the gate proper belongs elsewhere:

| Script | Purpose | Callers | ST | Gate name | Batch |
| --- | --- | --- | --- | --- | --- |
| `verify-artifact.py` | artifact-contract wholeness — every published target's asset set, digests, embedded key | ci (`--selftest` only), wf:release-stage, sh | yes | `verify-artifact` | 3 |
| `release-check.sh` | the 1.5.0 plugin-release end-to-end gate; `--segment` fan-out drives the live-mock qa tier | ci (`--selftest` only), wf (14), seg (8), sh | yes | `release-check` | 3 |

Two more sit in the job but were named by the owner into later batches:

| Script | Purpose | Callers | ST | Gate name | Batch |
| --- | --- | --- | --- | --- | --- |
| `no-deferral-gate.sh` | every deferral marker in the tree is a floor-checked waiver in `scripts/no-deferral.waivers` | ci, seg, sh | yes | `no-deferral` | 2 |
| `plane-delete-test.sh` | the strong-form deletion test: physically removes each plane crate from the workspace members and rebuilds | ci (`--all`), sh | yes | `plane-delete` | 2 |
| `plugin-registry-check.sh` | `plugins.yaml` and its consumers stay honest; `--list` is the registry feed every other consumer derives from | ci, seg, sh (6) | no | `plugin-registry` | 3 |
| `qa-segments.sh` | the qa-gate segmentation umbrella over `qa/segments.toml` | ci (`--selftest`), seg, sh | yes | `qa-segments` | 3 |

### 1.2 Batch 2 — the enforcement gates with state on disk

| Script | Purpose | Callers | ST | Gate name | Batch |
| --- | --- | --- | --- | --- | --- |
| ~~`construction-gate.sh`~~ **DELETED** | measures how the tree is BUILT against `ARCHITECTURE.md`, against ceilings the owner tightens in `qa/construction.toml` | ci, seg, sh | yes | `construction` **(converted; parity IDENTICAL over 110 rows)** | 2 |
| ~~`construction-gate/rules.py`~~ **DELETED** (`rules_extra.py` on `keep-construction-gate-p3` is still owed: six instrument classes — gate-script-hygiene, unused-waiver, assertion-free-tests, accrued-floor-metered, live-config-pinned, claimed-path-has-arm) | the measuring half — the rule table itself | sh | yes | **folded into** `xtask::gates::construction::{rules,rules2}` | 2 |
| ~~`construction-gate/plant.py`~~ **DELETED** | the self-test's saboteur. It tarred the tree into a scratch copy and calibrated a fresh ceilings file to get a green baseline; an overlay is per-plant by construction, so none of that machinery has anything to do | sh | no | **folded into** `cargo xtask selftest construction` (21 cases, 0 skipped) | 2 |
| `loc-surface.py` | the per-crate surface-LOC meter the construction gate's ceilings are expressed in | sh (`xtask::gates::construction::external`) | no | folds into `xtask::gates::construction` — **still owed**: the gate shells out to it | 2 |
| ~~`design-bindings.sh`~~ **DELETED** | THE DESIGN BINDINGS GATE — every Appendix B binding resolves and its golden cell recorded PASS | ci, seg, sh | yes | `design-bindings` **(converted; parity IDENTICAL over 104 rows)** | 2 |
| ~~`design-bindings.py`~~ **DELETED** | the generator/checker behind it (`--write` refreshes `qa/design-bindings.json` + `qa/DESIGN-BINDINGS.md`); reads the oracle's `golden/1.5.5/ledger.tsv` as data | ci, sh | yes | **folded into** `design-bindings`; `--write` proven byte-identical with `cmp` before deletion | 2 |
| `config-stability-gate.sh` | the config drift guard and additive-only classifier | ci, seg, sh | yes | **`config-schema` (LANDED)** | 2 |
| `config-schema.py` | that gate's engine — derives the frozen 1.5.5 config grammar down to serde's `expected one of` lists | sh | no | **folded into `config-schema` (LANDED)** | 2 |
| `audit-ledger.py` | THE AUDIT LEDGER — the 1.6.0 audit's row store and its queries | sh (`verify-1.6.0-done.sh`) | yes | `audit-ledger` | 2 |
| `full-gate.sh` | runs locally what CI runs; DISCOVERS the gate and cargo sets out of `ci.yml` and fails closed on an unclassified invocation | sh | yes | `full` (see section 3.3) | 2 |
| `teller-steps-check.py` | the Teller step order and root legs | ci (3 arms), seg, sh | yes | `teller-steps` | 2 |
| `capability-equality-summary.py` | the equality ledger printer `full-gate.sh` ends on | sh (3) | yes | folds into `full` | 2 |
| `proto-deletion-gate.sh` | builds busbar without each extracted protocol crate and proves the deletion at three levels | ci, sh | no | `proto-deletion` | 2 |
| `build-provenance-gate.sh` | a built binary self-reports the expected optimization posture | ci, sh | yes | `build-provenance` | 2 |
| `g6-freeze-witness.sh` | core names zero concrete LLM family type | sh (`proof-manifest.py`) | no | folds into `plane-purity` | 2 |
| `plane-grep-gate.sh` | substring dialect-name neutrality debt meter (report-only via `GREP_GATE_REPORT_ONLY`) | seg, sh | yes | `plane-grep` | 2 |
| `plane-noun-gate.sh` | LLM-noun debt meter for the neutral crates, report-only | sh | yes | `plane-noun` | 2 |
| `plane-config-noun-gate.sh` | four-noun config-parse debt meter, report-only; segment is `reserved` | seg (reserved), sh | yes | `plane-config-noun` | 2 |
| `secret-hygiene-gate.sh` | secrets are a TYPE, not a String — debt meter | seg | yes | `secret-hygiene` | 2 |
| `no-plugins-gate.sh` | the mechanical definition of "this thing is a plugin" | ci, sh (5) | yes | `no-plugins` | 2 |
| `mcp-fixture-absence-gate.sh` | `test_*` fixtures are not in a real build | wf:mcp-conformance, sh | yes | `fixture-absence` | 2 |
| `field-inventory.py` | derives and writes `qa/field-inventory.json` | ci, sh | yes | `field-inventory` | 2 |
| `method-inventory.py` | derives and writes `qa/method-inventory.json` | ci, sh | yes | `method-inventory` | 2 |
| `inventory-coverage.py` | the honest scoreboard for the Appendix B parity claim; reads the oracle golden ledger as data | seg (reserved), sh | yes | `inventory-coverage` | 2 |
| `inventory-coverage.sh` | 22-line wrapper so the gate is invocable like its `*-gate.sh` siblings | seg, sh | yes | **retire** — the wrapper's whole job (uniform entry point) is what `cargo xtask gate` *is* | — |
| `public-hygiene-lint.py` | public-surface hygiene; also run against plugin repos by `plugin-ci.yml` | ci, wf:plugin-ci, sh | yes | `public-hygiene` | 2 |
| `executable-config-lint.py` | every documented config key is executable against a real binary (`--busbar`, `--min-docs 40`) | ci, wf:plugin-ci, sh | yes | `executable-config` | 2 |
| `verify-1.6.0-done.sh` | the 1.6.0 DONE-ORACLE: the release-time DONE claim, running the strict form of several gates | sh, docs | yes | `done-oracle` | 2 |
| `service-images-check.sh` | every `image:` in `.github/workflows/` is the digest `testing/fleet-fixtures/service-images.tsv` pins | ci, sh | yes | `service-images` | 2 |
| `no-deferral.waivers` | data: the waiver allowlist | data | — | stays data, read by `no-deferral` | 2 |

### 1.3 Batch 3 — the release path, the perf path, the umbrella runners

| Script | Purpose | Callers | ST | Gate name | Batch |
| --- | --- | --- | --- | --- | --- |
| `release-check.sh` | the plugin-release end-to-end gate, `--segment` fan-out | ci (`--selftest`), wf(14), seg(8), sh | yes | `release-check` | 3 |
| `release-check-1.5.2.sh` | the frozen 1.5.2 dev-gate phases; kept alive by `release-script-lint`'s watchdog rule | sh (`release-check.sh`) | no | `release-check-1-5-2` | 3 |
| `release-build.sh` | THE build. One script, every target, no second path | wf:build-artifact, sh | no | `cargo xtask release build` | 3 |
| `release-key-guard.sh` | a missing plugin release key fails the BUILD, not the user | sh (3) | no | folds into `release build` | 3 |
| `release-gate/gate.sh` | the release verdict (see section 1.1) | wf(21 sites), sh | no | `release-verdict` | 3 |
| `release-gate/lib.sh` | shared ledger/HTTP machinery | sh, wf | no | `xtask::ledger` + `xtask::net` | 3 |
| `release-gate/expected-ids.sh` | the owed-id list — what makes "did not run" detectable | sh | no | folds into `release-verdict` | 3 |
| `release-gate/platform-checks.sh` | assertions that need the shipped bytes EXECUTED on a native runner per target | wf:release-fleet | no | `release-platform` | 3 |
| `release-gate/docker-checks.sh` | the container half of the fan-out | wf:release-fleet, sh | no | `release-docker` | 3 |
| `release-gate/channel-checks.sh` | every downstream channel that republishes a release | wf:release-fleet, sh | no | `release-channel` | 3 |
| `release-gate/fleet-checks.sh` | the `busbar-headroom` bundle image rebuild-and-boot | wf:release-fleet, sh | no | `release-fleet` | 3 |
| `release-gate/binfmt.py` | ELF/Mach-O header reader for the platform checks | sh | no | folds into `release-platform` | 3 |
| `verify-artifact.py` | artifact-contract wholeness | ci(`--selftest`), wf:release-stage, sh | yes | `verify-artifact` | 3 |
| `signing-gate.sh` | end-to-end plugin signing verification against a real binary and ephemeral key | wf:plugin-ci, sh | no | `signing` | 3 |
| `pgo-build.sh` | the three-phase PGO build | wf(9 sites), sh | no | `cargo xtask perf pgo` | 3 |
| `bolt-pass.sh` | post-link BOLT layout pass | wf:bolt-pass, sh | no | `cargo xtask perf bolt` | 3 |
| `pgo-drift-check.sh` | does the PGO trainer still exercise what production exercises | — (mentioned only in a `pgo-build.sh` comment) | no | `perf-trainer-drift` — **wire it in or retire it**; it is a fully-written gate nothing invokes | 3 |
| `profile-lock.sh` | `[profile.release]` parity gate | ci, wf | yes | `profile-lock` | 3 |
| `qa-gate-run.sh` | the qa-gate's actual logic, versioned with the code it gates (`matrix`/`hydrate`/`fast`/`build`/`siblings`/`segment`/`loader`) | wf:qa-gate (16 sites), sh | yes | `cargo xtask qa <verb>` | 3 |
| `qa-segments.sh` | the segmentation umbrella over `qa/segments.toml` incl. the `[[segment_template]]` expansion against `plugins.yaml` | ci, seg, sh | yes | `qa-segments` | 3 |
| `proof-manifest.py` | the Build Proof Dashboard collator; re-runs cheap gates and records verdicts, changes no gate | ci, sh | yes | `proof-manifest` | 3 |
| `check-proof-manifest-public.mjs` | the public-safety guard over the emitted manifest | ci, sh | no | folds into `proof-manifest` | 3 |
| `plugin-registry-check.sh` | the registry gate + `--list` feed | ci, seg, sh(6) | no | `plugin-registry` | 3 |
| `plugin-ci-refs.sh` | which busbar commits a plugin's CI must prove against; emits a GH Actions matrix | wf:plugin-ci | yes | `plugin-ci-refs` | 3 |
| `ci-images.py` | the CI image mirror registry (`--list`, `--consumer-state`) | wf:ci-images-mirror | yes | `ci-images` | 3 |
| `.github/scripts/bump_cargo.py` | version bump in `prepare-release.yml` | wf:prepare-release | no | `cargo xtask release bump` | 3 |
| `.github/scripts/roll_changelog.py` | CHANGELOG roll in `prepare-release.yml` | wf:prepare-release | no | `cargo xtask release roll-changelog` | 3 |

### 1.4 Retire

| Script | Reason |
| --- | --- |
| `land.sh` | replaced by `cargo xtask land` (section 3.4). Retires once `pr-queue.sh`'s line grammar is read by the Rust. |
| `inventory-coverage.sh` | a 22-line wrapper whose only purpose is to give the Python gate a uniform bash entry point. `cargo xtask gate inventory-coverage` *is* that entry point. |
| `changelog-register-check.sh` | same shape — a 19-line wrapper over the `.py`. The gate name survives; the file does not. |
| `preflight.sh` | "mirrors ci.yml EXACTLY" by hand. That is the drift `full-gate.sh` was written to make impossible, and `cargo xtask gate full` makes it structurally impossible. Nothing calls it. |
| `pr-land-selftest.sh`, `pr-queue-selftest.sh`, `promote-selftest.sh` | sibling-file self-tests, invoked only via their parent's `--selftest`. They become `#[test]` functions in the `xtask` crate and `cargo xtask selftest <name>` cases. |
| `pin-missing-cells.py` | no caller anywhere: not `ci.yml`, not another workflow, not a segment, not another script. A one-off maintenance tool for `qa/method-coverage.missing`; fold the pin-rewrite into `cargo xtask gate method-coverage --write` or delete. |
| `run-mutants-ec2.sh` | no caller; an operator convenience for a manual EC2 mutation run. Not a gate. Move to `docs/` as a recipe or delete. |
| `loom.sh`, `txn-fence.sh` | thin `cargo` wrappers (44 and 45 lines) whose one job is to run one command in its own target dir with an inverted exit code. `full-gate.sh` documents both as deliberately excluded from any batch runner. Inline the two commands into the `txn-guards` job and delete. |
| `scripts/a2a-subject/h2-*.sh` (5), `scripts/mcp-subject/h2-*.sh` (6), `h2-lib.sh` ×2, `h2-mock-agent.mjs`, `h2-mock-upstream.mjs` | **UNRESOLVED — decide before batch 3, do not port blind.** On this base the whole H2 family has no caller: `a2a-conformance.yml` invokes `boot.sh --selftest/--battery/--tck`, `boot.sh` never mentions `h2-`, and no workflow, segment or script references any `h2-*` file. Fifteen files, ~1,400 lines, of a fully-written gating battery whose own headers call each file a "gating scenario" and which has never executed. But `keep-land-fullgate-voice-p3` *adds a sixteenth* (`h2-discovery-open.sh`, in both subject dirs), so the family is being actively extended. Either the battery gets wired into `boot.sh --battery` — and then it is conformance-rig fixture code that stays as-is, outside this conversion, like `testing/llm-conformance/` — or it is dead and gets deleted. What it must not do is stay unwired while growing. |
| `scripts/fixtures/full-gate/continuation-ci.yml` | stays as a **fixture**, moved to `xtask/fixtures/full-gate/` alongside the other selftest fixtures. |

### 1.5 Stays Python (oracle)

Everything under `testing/shadow-oracle/`: `enumerate-cells.py`, `capture.py`, `capture-exec.py`,
`capture-concurrent.py`, `build-request.py`, `apply-mutation.py`, `diff-cells.py`, plus
`record.sh`, `replay.sh`, `replay-selftest.sh`, `selftest.sh`, `fetch-golden.sh`, `fetch-plugin.sh`
and the `golden/1.5.5/` tree. These are the **judge**; the workspace is the **subject**. The oracle's
value comes from being written against a published binary's observable behaviour with no shared code
with the thing it grades, so converting it into the same crate as the gates would destroy the property
it exists for. It keeps its own `verdict.sh` reuse (`GATE_NAME` override) and its own selftest.

Also outside this conversion: `testing/fleet-fixtures/*` (probe scripts and `verdict.sh`) and
`testing/llm-conformance/*` — they are *fixtures and probes*, not gate logic. `verdict.sh` is the one
exception that matters, and section 2.5 says how its semantics survive.

---

## 2. The xtask architecture

### 2.1 One subcommand, one registry

```
cargo xtask gate <name> [--selftest] [--check|--report] [--format=tsv]
cargo xtask gate --list
cargo xtask selftest [<name>]
cargo xtask land [--tests …] [--families …] [--gate …] [--prove] <hash>…
cargo xtask qa <verb> …
cargo xtask release <verb> …
cargo xtask perf <verb> …
cargo xtask denylist [--selftest]        # already exists, becomes `gate denylist`
```

`main.rs` grows from its current single `denylist` arm into a dispatcher over a registry:

```rust
pub struct Registration {
    pub name:   &'static str,                 // "plane-purity"
    pub batch:  u8,                           // 1 | 2 | 3
    pub tier:   Tier,                         // Fast | Full | Release
    pub build:  fn() -> Box<dyn Gate>,
}

inventory of gates: a `&'static [Registration]` in `xtask::gates::REGISTRY`.
```

A plain `const` slice, not a proc-macro registry crate — the point of this crate is to have almost no
dependencies, and one array edit per gate is cheaper than a dependency whose whole job is to save that
edit. `cargo xtask gate --list` prints the array; `cargo xtask gate <unknown>` exits 2 naming the
nearest registered names.

### 2.2 The `Gate` trait

```rust
pub trait Gate {
    /// The gate's verdict over the real tree. Never panics on a tree it does not like;
    /// panics only on its OWN bugs.
    fn run(&self, cx: &Ctx) -> Verdict;

    /// Proves the gate can still be RED. Runs against fixtures under `xtask/fixtures/<name>/`,
    /// never against the real tree, so its verdict does not move when the tree does.
    fn selftest(&self, cx: &Ctx) -> Report;
}

pub struct Verdict {
    pub rows: Vec<Row>,          // the ledger rows this gate produced
    pub red:  bool,
}

/// One ledger row, in the shape `release-gate/lib.sh::record` writes and both
/// `release-gate/gate.sh` and `testing/fleet-fixtures/verdict.sh` read.
pub struct Row {
    pub id:     String,          // column 1
    pub status: Status,          // column 2 — Pass | Fail | Skip
    pub title:  String,          // column 3
    pub detail: String,          // column 4
}

pub struct Report { pub cases: Vec<Case>, pub failures: Vec<String> }
pub struct Case  { pub name: String, pub expected: Expect, pub got: Expect }
pub enum   Expect { Green, Red { naming: Vec<String> } }
```

**`selftest` proves RED, not merely "ran".** `Case::expected` is an `Expect`, and `Expect::Red` carries
the offender strings the fixture must be reported by name. That is the existing `xtask/src/selftest.rs`
contract generalised: `check(label, fixture, manifest, expect_offenders, fails)` already refuses a
fixture that goes green when it should go red, and refuses a red that does not *name* the planted
offender. Every ported gate inherits that shape, so "the scanner cannot be lied to" — the phrase the
bash step names use — becomes a type, not a convention.

`Report::failures` non-empty ⇒ exit 1. `Verdict::red` ⇒ exit 1. Infrastructure failure (unwritable
scratch dir, missing `git`) ⇒ **exit 3**, keeping `full-gate.sh`'s distinction between "the gate failed"
and "the gate could not run".

### 2.3 `Ctx` — the shared context and the repo walk

```rust
pub struct Ctx {
    root:    PathBuf,             // workspace root, from CARGO_MANIFEST_DIR's parent
    overlay: Option<Overlay>,     // selftest-only: path -> replacement bytes (see section 3.5)
    scratch: PathBuf,             // proven writable by writing a byte, not by `[ -w ]`
    env:     Env,                 // GITHUB_STEP_SUMMARY, RUNNER_TEMP, report-only flags
}
```

Shared helpers, each replacing one bash idiom that is currently re-implemented per script:

**`cx.walk(spec) -> impl Iterator<Item = SourceFile>`** — the repo walk with *exactly* today's
include/exclude semantics. The dominant shape in the tree is

```
find crates -name '*.rs' -not -path '*/tests/*' -not -path '*/benches/*' | sort
```

so `WalkSpec { roots, ext, exclude_path_fragments, sorted: true }` reproduces it byte-for-byte,
including the `sort` (several gates' outputs are order-sensitive) and including the property that an
**empty result is not silently green** — `WalkSpec::min_files` carries `structure-lint.sh`'s "`find
crates …` returns an empty list whenever the tree moves, and an empty list reads exactly like a clean
tree" floor. A walk that yields fewer than its floor is a `Status::Fail`, not a pass.

**`cx.production_lines(src) -> Vec<(usize, String)>`** — the `#[cfg(test)]`/`mod tests`/`//`/`/* */`
scope scanner. **This already exists**, in `xtask/src/denylist.rs::production_lines` +
`strip_comment_line`, written for the denylist's own-src scan. Every text gate that today re-implements
`TEST_SCOPE_AWK` (`structure-lint.sh`, `plane-purity-lint.sh`, `blocking-ffi-lint.sh`,
`settings-leak-lint.sh`, `response-header-lint.sh`, `tracing-lint.sh`,
`kernel-token-wire-purity-lint.sh`) points at this one function. One scanner, one selftest, one place a
bypass can hide.

**`cx.planes()`** — `plane-keys.sh` and `plane-roots.sh` as a Rust module: `PLANE_KEYS`,
`PLANE_KEYS_PROTOCOL`, `plane_src_roots()`, `neutral_src_roots()`, `plane_keys_other()`, and
`resolve_root(key) -> Result<PathBuf, PlaneRootError>` with the same three failure states
(`Missing` / `Ambiguous(candidates)` / resolved), the same ownership narrowing (a candidate directory
must itself contain a `*.rs` declaring `pub const PLANE_DECL`, which is what keeps `-codec` sibling
directories from counting as a second home), and the same test overrides (search root, grammar) so
`plane_roots_selftest`'s four cases port unchanged.

**Readers.** TOML via the vendored `xtask/src/toml_lite.rs` (already parses `[[array]]` tables, quoted
strings and inline arrays — enough for `qa/construction.toml`, `qa/denylist-allow.toml`,
`qa/segments.toml`, and every `Cargo.toml` the gates read). JSON via `serde_json`, already the crate's
only dependency. YAML via a new `yaml_lite` sized to the *workflow* subset only: jobs, steps, `run:`
block scalars (`|` vs `>`), `needs:` lists, `env:` maps, `if:` strings — **including the logical-line
folding `full-gate.sh`'s `ci_logical_lines()` awk does** (join backslash-continued lines inside a
`run:` block, honour folded vs literal scalars, drop `#` comments and `name:` labels). No `serde_yaml`:
the gates that read YAML are the ones asserting things *about* the YAML text, and a general parser that
normalises the document is the wrong tool for a gate whose subject is what a human wrote.

**Git.** Via the `git` process, never a crate. `cx.git(&["rev-parse", "HEAD"]) -> Result<String>`,
`cx.git_lines(&["diff", "--name-only", a, b])`. Reasons: `libgit2`/`gix` is a large dependency in a
crate whose selling point is having none; the gates need `git`'s *own* semantics for
`cherry-pick -x`, `ls-files`, protected-branch reads; and the process boundary is what lets a selftest
point `GIT_DIR` at a throwaway repo. `cx.git` always uses `-C <root>` and never `cd`.

**Ceilings and waivers stay data.** `qa/construction.toml`, `qa/denylist-allow.toml`,
`scripts/no-deferral.waivers`, `qa/plane-hook-isomorphism.allow`, `qa/method-coverage.status`,
`qa/field-coverage.status`, `qa/plane-purity-strict.toml`, `testing/fleet-fixtures/service-images.tsv`,
`.github/release-targets.json` — none of these move into Rust. They are owner-tightened knobs and the
whole point is that tightening one is a data edit reviewable on its own. `scripts/no-deferral.waivers`
moves to `qa/no-deferral.waivers` when `scripts/` empties out; the format does not change.
The one *new* rule: `stale_waivers` (already in `denylist.rs`) generalises — a waiver that no longer
covers a live hit is RED, so the ceilings file cannot quietly accumulate dead entries.

### 2.4 The ledger

`xtask::ledger` writes rows in the exact TSV shape `release-gate/lib.sh::record` writes:

```
<id>\t<PASS|FAIL|SKIP>\t<title>\t<detail>\n
```

with `\t` and `\n` stripped out of `title` and `detail` before writing (the same `tr '\t\n' '  '`),
appended never truncated, one file per leg under `$LEDGER_DIR`. This is load-bearing: it means
`testing/fleet-fixtures/verdict.sh` and `scripts/release-gate/gate.sh` keep working **unchanged** over
rows that Rust gates produced, so the conversion can proceed gate-by-gate without a flag day. Both
readers' quirks are preserved by leaving them alone rather than by re-deriving them:

- **Duplicate rows per id resolve by AGREEMENT, not by position.** On this base `release-gate/gate.sh`
  resolves an id with `awk '$1==i{print; exit}'` — the FIRST row wins — so a leg that reported PASS and
  then a retry that reported FAIL let the PASS stand. `keep-release-scripts-p3` fixes this: fold every
  row for an id; agreement passes; **disagreement is CONFLICT and RED**, never silently resolved.
  Port the fixed rule, in the type: `Verdict::resolve(id)` returns `Pass | Fail | Skip | Conflict`.
  `verdict.sh` still keeps the LAST row per id and is not part of that fix; leaving it alone is the
  point of keeping the TSV shape, but a Rust gate that writes two rows for one id is writing a bug, and
  the ledger writer refuses it (`debug_assert` in the writer, a `Fail` row in release).
- `verdict.sh` has **no skip allowlist**: every SKIP is RED. `release-gate/gate.sh` has exactly four
  allowlisted skip ids for the Cloudflare-403 case. Port the allowlist as data on the Rust side of
  `release-verdict`, not as a wider default.
- Both refuse a **zero-row** ledger by name, before any other logic. `xtask::ledger::Verdict` refuses
  it in the type: an empty `rows` vec with a non-empty owed set is `red = true`.

`cargo xtask gate <name> --format=tsv` emits rows; the human printer stays the default. That flag
already exists on `denylist`.

### 2.5 Layout

```
xtask/
  Cargo.toml            # deps: serde_json ONLY (see section 4)
  src/
    main.rs             # arg dispatch
    ctx.rs              # Ctx, WalkSpec, scratch proving, env
    ledger.rs           # Row, Status, TSV writer, Verdict, owed-set reconciliation
    scan.rs             # production_lines, strip_comment_line  (moved out of denylist.rs)
    planes.rs           # plane-keys.sh + plane-roots.sh
    toml_lite.rs        # exists
    yaml_lite.rs        # workflow subset + logical-line folding
    gitp.rs             # git-as-a-process
    gates/
      mod.rs            # REGISTRY
      structure_lint/   # one module per rule family; the 2.3k-line script's successor
      plane_purity.rs
      … one file per gate …
    selftest.rs         # exists; grows the Report/Expect types and a per-gate dispatch
  fixtures/
      …                 # exists; grows one dir per gate that needs planted trees
```

---

## 3. How the callers switch

### 3.1 `ci.yml`, per gate

The two-step shape is preserved exactly, because it encodes a rule: *never trust the lint's verdict
before proving the lint still works.*

```yaml
      - name: Plane-purity lint self-test (the side-channel scanner cannot be lied to)
        run: cargo xtask gate plane-purity --selftest
      - name: Plane-purity gate (BLOCKING — no side channel in the neutral crates)
        run: cargo xtask gate plane-purity
```

replacing

```yaml
        run: scripts/plane-purity-lint.sh --selftest
        run: scripts/plane-purity-lint.sh --check
```

Step **names do not change**. `ci-umbrella-lint` reads job membership, not step text, but three other
gates and the proof-manifest collator key off step names, and a rename is a change nobody asked for.

`--check` / `--report` survive as flags where a gate has both a blocking and a report-only mode
(`plane-grep`, `secret-hygiene`, `plane-config-noun`, `plane-noun`). The `GREP_GATE_REPORT_ONLY=1` /
`SECRET_GATE_REPORT_ONLY=1` env switches become `--report`, and the env vars keep working for one
release so `qa/segments.toml` rows can migrate independently.

### `--posture`: the third answer, for a gate that is red by design

A gate whose tree is legitimately red today has only two useful exit codes and neither is true.
"Green" is a lie; "red" is true and carries no information, so it gets a `continue-on-error` and
stops meaning anything. That is how the construction gate ended up with **four** independent
downgrades on it — `Excused::Whole` in `REPORT_ONLY`, `continue-on-error` in `ci.yml`,
`continue-on-error` plus `|| true` in `keep-proof.yml`, and exclusion from both umbrellas' scored
`RESULTS` — and between them a NEW red could not redden anything.

`cargo xtask gate <name> --posture` scores the gate against its `REPORT_ONLY` entry instead of
against zero reds:

* **exit 0** while the gate is red on exactly the rows the entry names, and nothing else;
* **exit 1** the moment a row appears that the list does not name — a regression;
* **exit 1** when a NAMED row goes green — the list is stale and must be struck in the commit that
  drained the row. Without this half a standing-red list only ever grows, which is the blanket
  excuse it replaces.

It runs the same `gates::excused_from_all` that `gate --all` prints, so the posture CI enforces and
the posture `--all` reports cannot drift, and the standing reds are written down in exactly one
place (`gates::CONSTRUCTION_STANDING_REDS`) rather than pasted into two workflows. A gate with no
`REPORT_ONLY` entry has nothing to score against and `--posture` is an argument error there, not a
free green.

`--selftest` is refused in combination with `--all` and `--list`: both of those branches return
before the flag is read, so `gate --all --selftest` used to print ordinary verdicts while the caller
believed the whole registry had just self-tested. The only every-gate self-test is
`cargo xtask selftest`.

The `structure-lint` job needs one new setup step ahead of the gates:

```yaml
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: ". -> target", key: xtask }
      - name: Build the gate runner once
        run: cargo build -p xtask --locked
```

This is the one real cost of the conversion: a job that today needs no toolchain at all now needs one.
It is bounded — `xtask` has a single dependency — and cached. section 5.4 covers the risk.

### 3.2 `qa/segments.toml`

Segment `run` strings become the same commands:

```toml
run = "cargo xtask gate config-stability --selftest && cargo xtask gate config-stability"
```

The `[[segment_template]]` expansion against `plugins.yaml` (via `plugin-registry-check.sh --list`)
becomes `cargo xtask gate plugin-registry --list`, same output contract — one repo per line — so the
`qa-gate.yml` checkout loop and `release-check.sh`'s suite loop are unchanged.

### 3.3 `full-gate.sh`'s successor

`full-gate.sh` discovers gates by regexing `ci.yml` for `scripts/…\.(sh|py|mjs|js|ts|rb)` and cargo
invocations by regexing folded logical lines, then fails closed on anything unclassified, with a
`MIN_GATES=8` floor. That floor sat 81 below the real ~89 invocations in `ci.yml`, and the cargo
floor of 10 existed **only inside `--selftest`, never on the run path** — so deleting most of CI's
gates from `ci.yml` still passed. `keep-land-fullgate-voice-p3` moves both floors just under the real
count and onto the run path. Its successor is **stronger still, because the registry makes the gate
set enumerable in-process**, which retires the floor rather than re-tuning it:

`cargo xtask gate full` does three things:

1. **Set equality, not a floor.** Parse `ci.yml` (via `yaml_lite`) for every `cargo xtask gate <name>`
   step. Assert `{names in ci.yml} == {REGISTRY names}` modulo an explicit `SKIP_REASON` table in Rust,
   each entry carrying a non-empty reason (the existing check that every skip entry has a reason
   survives as a `#[test]`). A registered gate absent from `ci.yml` is RED — the failure mode
   `MIN_GATES` could only approximate.
2. **Cargo classification, unchanged.** Keep `ci_logical_lines` folding and `cargo_norm` normalisation,
   keep `CARGO_LOCAL` / `CARGO_CI_ONLY` as two Rust tables, keep "an unclassified cargo invocation is a
   hard failure". Keep the `RUSTFLAGS` equality assertion between the workflow's `env:` and the runner's
   own exported value.
3. **Run them.** Prove the scratch dir writable by writing a byte (exit 3 on failure, not 1), then run
   the local cargo set and every runnable gate in-process — no subprocess per gate, which is most of the
   wall-clock win — and end on the equality ledger (`capability-equality-summary.py`'s successor).

4. **Never judge a ledger the run did not write.** `full-gate.sh`'s construction waiver deliberately
   ignores the construction gate's exit status and judges its row set instead — but the gate writes its
   ledger in place, so a gate that died before writing left the *previous healthy run's* ledger sitting
   there, and the waiver printed green over a construction gate that never executed.
   `keep-land-fullgate-voice-p3` fixes it by deleting the ledger before invoking the gate so the
   file-exists guard is honest. In Rust the ledger for an in-process gate is a returned `Verdict`, not a
   file, so the staleness is unrepresentable — but any gate that still shells out and reads a file back
   must truncate the file first, and `xtask::ledger::read_leg(path)` does that for the caller.

The `--dump-gates` / `--dump-cargo` arms survive as `cargo xtask gate full --dump gates|cargo [FILE]`,
which is what makes the continuation fixture testable. That fixture
(`scripts/fixtures/full-gate/continuation-ci.yml`) moves to `xtask/fixtures/full-gate/` and its five
assertions port verbatim: a 3-line backslash-continued `cargo test` is joined exactly; a command quoted
inside an `echo` is NOT discovered; a command in a `#` comment is NOT discovered; a command in a step
`name:` is NOT discovered; a nested `testing/planted/gate.sh` IS discovered. Plus the two floors: an
empty `ci.yml` is refused, and `.mjs`/`node` invocations are visible (the regression that fixture's
`check-proof-manifest-public.mjs` assertion exists for).

### 3.4 `land.sh` → `cargo xtask land`

```
cargo xtask land [--tests "pkg …"] [--families '<regex>'] [--gate '<rule|rule>'] [--prove] <hash>…
```

Same flags, same order of operations, same refusal to print GREEN when nothing was proven. `scripts/land.sh`
becomes, for one release:

```bash
#!/usr/bin/env bash
# Deprecated shim: scripts/land.sh is now `cargo xtask land`. Retires after 1.6.0.
exec cargo xtask land "$@"
```

and then goes away. What changes underneath:

- **The cherry-pick, the cdylib pre-build, the `--tests` derivation from touched `crates/*` dirs, the
  `--gate` row assertions and the `--families` oracle diff** port one-for-one. The oracle diff still
  shells out to `testing/shadow-oracle/record.sh` and `diff-cells.py` against the **committed** golden
  — the oracle is not converted, and `land` is one of its callers.
- **The `stamp` discipline stays.** `date +%Y%m%d-%H%M%S-$$` becomes a per-run scratch dir under
  `Ctx::scratch`; the reason (same-second collisions and stale recordings contaminating a diff) is
  unchanged.
- **The gate-tree leg changes shape.** Today it parses every touched `scripts|testing|.github` file
  (`bash -n`, `py_compile`, `node --check`, YAML load) and runs any `--selftest` it advertises. After
  the conversion there is no bash left to parse: touching a gate means touching Rust, so the leg becomes
  `cargo test -p xtask` plus `cargo xtask selftest` for every gate whose module the diff touched. The
  YAML/`.mjs` arms stay for `testing/` and `.github/` until those are empty.
- **`--gate` row semantics are preserved exactly:** at least one `^(PASS|FAIL)  ` row must exist,
  at least one row's rule name must match the pattern, and zero matching rows may be FAIL. The three
  failure messages are distinct today and stay distinct.
- **Three `land.sh` bugs that `keep-land-fullgate-voice-p3` fixes must not be re-introduced by a
  clean-room port.** `--prove <hash>` still ran the cherry-pick loop, contradicting its own "pick
  nothing" contract. The touched-file derivation measured `HEAD~1..HEAD` regardless of how many commits
  were named, silently under-covering a multi-commit landing — in Rust it is `HEAD~n..HEAD` with `n =
  hashes.len()`, and `n == 0` under `--prove` means "the tip as-is", a distinct arm. And an
  unrecognised flag fell through the `case` into the cherry-pick arm, so a typo'd flag was handed to
  `git cherry-pick` as a commit-ish; a Rust arg parser refuses unknown flags with exit 2, which is the
  whole reason to have one.
- **`land` gets a real `--selftest`.** On this base `land.sh` has none — so the gate-tree leg that
  proves every touched script's self-test could never prove the script that judges every landing.
  `cargo xtask selftest land` drives the pick/derive/gate-row/scope-honesty arms against a throwaway
  repository, the same way `pr-land-selftest.sh` stubs `gh`.
- `pr-land.sh` / `pr-queue.sh` / `promote.sh` become `cargo xtask pr land|queue|promote` in batch 3, and
  keep their sharp edges: `-x` cherry-picks never squashed (the trailers are `promote.sh`'s provenance
  source); required check names read **live** from branch protection, never hardcoded; MISSING treated
  as pending, never as pass; the push is `origin <sha>:refs/heads/<to>`, a pinned SHA and never a branch
  ref.

### 3.5 The construction gate's self-test → `cargo xtask selftest construction`

`plant.py` today: copy the tree to a scratch root, restore every file in a hand-maintained `TOUCHED`
list before each plant (so plants never stack), plant exactly one violation for the named rule, and
require exactly one FAIL row naming that rule; exit 3 means "nothing to plant" (the rule's subject is
absent from this tree) and the self-test notes it and moves on.

`TOUCHED` is the fragile part, and `plant.py` knows it — it re-derives the list by reading its own
source at import time, because a file a plant edits but nobody restores stays sabotaged for every later
plant, and "exactly one FAIL row" can then be produced by leftovers rather than by the rule under test.

**Rust removes the hazard rather than checking for it.** `Ctx` carries an `Overlay: BTreeMap<PathBuf,
Vec<u8>>`. Every gate reads files through `cx.read(path)`, which consults the overlay first. A plant is
then:

```rust
struct Plant { rule: &'static str, edits: Vec<(PathBuf, Edit)> }   // Edit = Append | Replace | Delete | Create

for plant in PLANTS {
    let cx = base_cx.with_overlay(plant.apply(&base_cx)?);   // a FRESH overlay, every time
    match construction::run(&cx) {
        v if v.rows.iter().filter(|r| r.status == Fail).count() == 1
          && v.rows.iter().any(|r| r.status == Fail && r.id == plant.rule) => pass(plant.rule),
        v => fail(plant.rule, v),
    }
}
```

There is no scratch copy, no restore step and no `TOUCHED` list, because an overlay is *by construction*
per-plant. `Subject absent` (today's exit 3) becomes `Plant::apply -> Ok(None)`, reported as
`Case { expected: Red, got: Skipped }` and counted in the report — visible, never silently green.

Every other gate's self-test uses the same overlay mechanism, which is what lets `Expect::Red { naming }`
be enforced uniformly: plant, run, require RED, require the report to name the planted offender.

Two more things the construction gate specifically must carry across. First, **the owed-row set is
derived, not maintained beside the rules** (risk 5.2(c)): a rule that emits a row id nobody owes writes FAIL
into the ledger and exits 0. Second, `keep-construction-gate-p3` establishes that a rule proven by the
rule-census does not also need a plant, and that a rule with *no* plant and *no* census proof is an
error rather than a shrug — so `Plants` is a total function over the rule table, returning
`Plant | ProvenByCensus | NothingToPlant`, and a rule that returns nothing at all does not compile.

---

## 4. The segregation rule, as a lint

The oracle judges the workspace. The gates read the workspace. Neither may become the other, and neither
may import the thing it grades. Stated as a gate:

**`cargo xtask gate segregation`** (batch 1, ~120 lines), which is RED if any of:

1. **`xtask` depends on any product crate.** `cargo metadata --manifest-path xtask/Cargo.toml`'s
   resolve closure for package `xtask` contains any package whose name starts `busbar` or equals `api`.
   Today the closure is `{xtask, serde_json, serde, itoa, ryu, memchr}` — the assertion is that it stays
   that shape. New dependencies are allowed; product crates are not.
2. **`xtask/src/**` names a product crate in source.** No `use busbar_…`, no `extern crate busbar…`,
   no `busbar_core::` path anywhere in `xtask/src/`. **xtask reads sources as text.** A gate that
   `use`s the type it is auditing is a gate whose verdict moves when the type does, which is the exact
   failure the shell gates never had.
3. **Nothing depends on `xtask`.** No `crates/*/Cargo.toml` or `Cargo.toml` `[dependencies]` /
   `[dev-dependencies]` / `[build-dependencies]` table names `xtask`.
4. **The oracle does not import xtask.** No file under `testing/shadow-oracle/` contains the token
   `xtask` — not as a `cargo xtask` invocation, not as an import, not in a comment that would tempt the
   next person. The oracle's inputs are a published binary and its own goldens; its outputs are cells
   and a ledger. Nothing else.
5. **xtask reads oracle files only as data, from an allowlist.** Three gates legitimately read the
   oracle's outputs — `design-bindings` and `inventory-coverage` read
   `testing/shadow-oracle/golden/1.5.5/ledger.tsv`, and `full` reads `golden-digests.tsv`. Those three
   paths are an explicit `ORACLE_DATA_ALLOW` list in the gate; a path read from
   `testing/shadow-oracle/` that is not on it is RED. Reading a TSV is data; running the oracle's code
   is not.

Its selftest plants each of the five violations into an overlay and requires RED naming the violation,
using the same `Expect::Red { naming }` contract as everything else.

**One open decision.** `xtask` is a workspace member (`Cargo.toml` line 66) and there is no
`default-members` table, so `cargo build --workspace` and `cargo clippy --workspace --all-targets`
build it. That is fine and probably desirable — the gate runner should be under `-D warnings` like
everything else — but it means `no-default-features`, `windows` and the release-profile builds now
compile the gate runner too. Either add a `default-members` list excluding `xtask` (and accept that
`cargo build` no longer builds it, so `full-gate`'s cargo classification tables change), or leave it in
and let those jobs carry the extra ~2s. Recommend: leave it in; revisit if a matrix leg breaks on it.

---

## 5. Risks

### 5.1 The 1.5.5-faithfulness gates compare against golden files

`design-bindings`, `inventory-coverage`, `config-stability`, `field-inventory`, `method-inventory`,
`audit-ledger` and `verify-artifact` all assert a **generated artifact equals a committed one**
(`qa/design-bindings.json`, `qa/DESIGN-BINDINGS.md`, `qa/field-inventory.json`,
`qa/method-inventory.json`, `qa/inventory-coverage.json`, `qa/audit-ledger.json`), and three of them
resolve against `testing/shadow-oracle/golden/1.5.5/ledger.tsv`.

**The risk:** a Rust generator will not byte-match a Python one on the first try — key order, float
formatting, trailing newline, Unicode escaping in `json.dumps`, the `sort` locale, how `None` renders.
`generated-artifact-drift` will go red for reasons that are entirely about the rewrite and nothing about
the tree, and the tempting fix — regenerate and commit — silently destroys the drift signal for that
release.

**The mitigation, and it is not optional:** port each generator with a **parity harness first**. Before
the Rust version is wired into `ci.yml`, add a temporary `cargo xtask gate <name> --parity` that runs
the Python, runs the Rust, and asserts byte equality of both outputs over the real tree — red if they
differ. Land the parity gate green, *then* delete the Python in a separate commit that touches no
`qa/*.json` byte. If a committed artifact must change, it changes in its own commit with the diff
reviewable, never bundled with the rewrite. `serde_json` preserves insertion order only with the
`preserve_order` feature; the generators must either emit sorted keys (matching Python's
`sort_keys=True` where it is used) or the parity harness will catch it — check each generator's actual
`json.dump` call rather than assuming.

### 5.2 Gates whose semantics depend on bash quirks that the keep-* branches just fixed

The seven `keep-*` branches carry the fixed bytes that will be converted. **Their fixes are the current
semantics.** The Rust must be written against those, not against what the shell on
`integration/oracle-phase0` does — and the danger is specific: many of those fixes exist *only* because
of a bash quirk, so a clean-room Rust port that reads the pre-fix script, or reads the fixed script
without reading its comment, will reproduce a gate that is green for the wrong reason. Five classes:

**(a) Status swallowed by a pipe, a subshell, or a process substitution.** `blocking-ffi-lint.sh` had
`h=$(scan_rule "$f") || true`, which discarded awk's exit status — a broken awk program produced empty
output for every file and read as "no findings" gate-wide. `settings-leak-lint.sh` and
`release-script-lint.sh` lost their producers' status across `< <(…)`. `qa-gate-run.sh` fed a segment
list through a herestring, which `set -e` does not catch, so a failed registry lookup reported zero
reserved slots as success. A test harness set `GATE_RC=$(…)`, dropping the value across the subshell.
**Mitigation:** `cx.run_checked(cmd) -> Result<Output>` that will not hand back stdout on a non-zero
status, and a crate-wide `#![deny(unused_must_use)]` so nobody can `let _ =` their way past it. Every
gate's scanner returns `Result`, never `Vec` with an empty vec meaning two different things.

**(b) Zero is not clean.** This is the single most repeated fix across all seven branches.
`loc-surface.py` let a renamed or emptied crate — zero measured `.rs` files — satisfy every ceiling.
`inventory-ref-lint.py`'s `doc.get("bindings", [])` turned a renamed manifest key into "zero dangling
refs", i.e. PASS. `proto-deletion-gate.sh`'s level-1 grep named a retired crate that no longer exists,
so a real violation under the current crate name was invisible. `plane-abi-neutrality.sh` scanned its
own `src/hot/tests/`, and `plane-purity-lint.sh`'s `strict_decide` accepted a ledger missing whole
category rows because the TSVs are written with `cp … || true`. `channel-checks.sh` passed vacuously on
a release with zero assets. `loom.sh` had no selftest at all and a `cargo test` filter selecting zero
tests exits 0 printing "0 passed". **Mitigation:** `WalkSpec::min_files` is not optional decoration —
every gate declares its denominator floor, an empty or below-floor scan is a named `Status::Fail`
distinct from "scanned and found nothing", and the construction gate's *rename-to-zero* rule generalises
into the framework: a rule whose subject symbol has been renamed away reports `Unproven`, never `0/0
PASS`. Three construction rules (`single-terminal`, `one-teller-loop:run_gauntlet`,
`secret-carrier-debug`) were caught by exactly this on `keep-construction-gate-p3`, and one of them
would have let the next `--calibrate` ratchet itself permanently to 0.

**(c) Floors and owed-sets that only the self-test reads.** `no-deferral-gate.sh`'s ≥50-file discovery
floor lived in `--selftest` and not on the `--check` path. `full-gate.sh`'s cargo floor, likewise.
`verify-1.6.0-done.sh`'s `DONE_GROUP_FLOOR` was a hand-maintained `19` against 20 real groups **and was
overridable downward from the environment** with no floor-only-rises guard. `construction-gate`'s
`rules_extra.py` added eight row ids that were never added to `expected_ids()`, so six enforced-looking
rules wrote FAIL rows to the ledger that `--check` ignored and exited 0 through — including
`legacy-reach`, which was genuinely failing (95 against a ratchet of 92) and never reported.
**Mitigation, and it is the strongest structural argument for the registry:** the owed set is
**derived from the registry**, not maintained beside it. A `Gate` declares the row ids it can emit; the
runner reconciles emitted against declared and is RED on either direction. A rule cannot be added
without being owed, and a floor is a `const` in the gate's own module with no env override — the only
way to lower one is a reviewable source edit.

**(d) Scanner scope: multi-line, comments, string literals, name spellings.** `secret-hygiene-gate.sh`
matched single-line statements only, so a rustfmt-wrapped `tracing::info!(` … `%key.expose_secret()`
across two lines was invisible. `tracing-lint.sh` counted parens *inside string literals*, so a message
containing `"f("` triggered a runaway that silently absorbed the rest of the file and reported every
later `#[instrument]` as clean. `release-script-lint.sh`'s watchdog rule did no comment-stripping, so a
commented-out watchdog satisfied it. `executable-config-lint.py` required `> file` *before* `<<DELIM`
and extracted nothing from the equally common `cat <<'EOF' > file` and `| tee file`.
`plane-purity-lint.sh` missed six spellings — `use x as alias`, extern-crate aliasing, mixed case
(`MCPCallRecord`, `OpenAIClient`, `LLMRouter`) and `include!()`, the last of which fell through *below*
the frozen-wire gate so a `// plane-purity: frozen-wire` pragma could launder a dual-compiled plane
source into a neutral crate. **Mitigation:** one `scan.rs` for the whole crate — `production_lines`
(comment and `#[cfg(test)]` stripping), a statement-window accumulator flushed at `;{},` at paren depth
zero, and literal-blanking before any delimiter counting — each with its own planted fixture. It is a
single point of failure by design, which is why it gets the most selftest cases in the crate.

**(e) The quirks that simply cease to exist, and must therefore be re-asserted deliberately.**
`grep -c` on a no-match file prints `0` *and* exits `1`, so `n=$(grep -c . f || echo 0)` yields the
two-line string `"0\n0"` and the `-eq 0` guard then errors out instead of taking the vacuous-run branch
— the guard against a vacuous green, silently broken by a vacuous input. `[ "$x" -lt N ]` on an empty
`$x` is a shell *error*, not `false`, so an uncomputable count means the threshold never fires. A
`jq` expression that cannot match the real shape exits 5 and prints nothing, and swallowed inside
`$(…)` it silently shrinks the owed set — which is exactly what made two `release:no-extras` assets
permanently unaccounted-for. `gate | grep -q pat` under `pipefail` **fails when grep matches and
short-circuits**, which inverted a registry-gate self-test's pass/fail arms. A `cd` with neither
`|| exit` nor `set -e` resolves every later relative path against the caller's cwd. `find A B C`
silently drops a missing root. And bash 3.2 on macOS has no `mapfile`.
**None of these can happen in Rust — and that is the risk.** "Rust cannot have that bug" is not the
same claim as "the check is still there". Every one of the guards those quirks motivated —
the zero-rows refusal, the owed-set reconciliation, the per-root existence check, the
count-is-uncomputable arm — is ported as an explicit assertion with its own selftest case, and the
selftest case is what proves it, not the absence of the quirk.

Finally: `verify-1.6.0-done.sh`, the DONE-oracle, runs the **strict** form of several gates that CI runs
in a looser form (`--strict-done`, `--root-legs`). Those strict/loose pairs are easy to collapse during
a port. Keep them as two named methods on the gate, not two values of a boolean read from an env var —
`DONE_GROUP_FLOOR`'s env-overridability is the cautionary case.

### 5.3 The qa full tier's `segments.toml` runner

`qa-segments.sh` (617 lines) and `qa-gate-run.sh` (468 lines) are the highest-risk conversion and they
are last for that reason.

- **The honesty rule is the whole gate.** An `active` segment whose `run` names a `cargo test --test
  <target>` that does not exist is a HARD FAIL naming the segment and the missing target. A segment that
  executed nothing must never be indistinguishable from one that passed. That is `verdict.sh`'s
  zero-rows rule wearing a different hat, and the Rust must assert it the same way — by *resolving* the
  target, not by trusting the exit code of a command that could not find it.
- **The `[[segment_template]]` expansion carries no plugin names.** The set comes from `plugins.yaml`
  via `plugin-registry-check.sh --list` at run time, every time, so drift is unrepresentable rather than
  checked-for. The selftest asserts the expanded id set **equals** the registry's repo set exactly. A
  Rust port that caches or hardcodes the list reintroduces exactly the failure that design prevents.
- **`fallback_for` is an exactly-one invariant.** The aggregate `plugins` segment is emitted only while
  the `plugin-{repo}` template cannot expand, and suppressed the moment the fan-out is live. Never
  neither, never both. That is three states in one string field and it is the easiest thing in this
  document to get subtly wrong.
- **The reserved set is part of the green claim's honesty.** The umbrella's final line NAMES every
  reserved segment it did not cover. Dropping that line makes a partial gate read as a full one.
- Segment `run` strings are **shell**. Several chain with `&&`, one sets an env prefix
  (`GREP_GATE_REPORT_ONLY=1 …`), one chains four cargo commands. The Rust runner must keep executing
  them through a shell (`sh -c`), not tokenise them itself — and must therefore keep `set -o pipefail`
  semantics in mind for the strings it did not write. The alternative (a structured `run` table in
  `segments.toml`) is a better end state but is a `segments.toml` migration, not part of this
  conversion.

### 5.4 A self-test that re-implements the gate proves nothing

The `keep-*` branches turn up this failure in seven gates (`field-inventory.py`, `inventory-ref-lint.py`,
`ci-umbrella-lint.py`, `inventory-coverage.py`, `pr-queue-selftest.sh`, `plugin-registry-check.sh`,
`qa-gate-dispatch-lint.py`) and it is the one a rewrite is most likely to reproduce, because writing the
assertion twice is easier than driving the real function through data.

Four distinct shapes, all of which the `Report`/`Expect` contract in section 2.2 has to be *used* to prevent
rather than merely permit:

- **The self-test re-implements the predicate** instead of calling the loader/scanner, so planting a
  removal of the real guard stays green (`field-inventory.py`'s provenance-required-key refusal).
- **Independent floors exercised only together**, so two of three can be deleted with the self-test
  still green (`ci-umbrella-lint.py`'s MIN_JOBS/MIN_NEEDS/MIN_RESULTS; `profile-lock.sh`). Each floor
  needs its own discriminating fixture — one `Case` per floor, each `Expect::Red` naming that floor.
- **An aggregate shadows the instrument that matters**: `inventory-coverage.py`'s per-family floor names
  *which* family lost rows, but a total that a family-shrinks/family-grows swap does not move meant the
  safety-relevant instrument was never driven.
- **Counts and shapes asserted instead of identity**: `pr-queue-selftest.sh` counted lander calls rather
  than checking *which hashes landed*, and `flush_batch` reusing the caller's loop variable dropped
  every landing after the first while still exiting 0 and reporting success.

**Mitigation, structural:** `Gate::selftest` receives a `&Ctx` and may only reach the gate through
`Gate::run`. It has no access to the gate's internals — the trait gives it none — so re-implementing
the predicate is not something a selftest *can* do. Each `Case` names one floor or one rule and carries
`Expect::Red { naming }`, so "something went red" is not an accepted answer. And `Report` fails if any
declared row id has no `Case` covering it, which is the same derived-owed-set rule as risk 5.2(c), applied to
the selftest instead of the run.

### 5.5 Two smaller ones

**A toolchain in the structure-lint job.** The cheapest, fastest job in CI currently needs no Rust at
all. After the conversion it needs a toolchain and a build. Mitigation: `Swatinem/rust-cache` keyed on
`xtask`, `cargo build -p xtask --locked` as one step ahead of the gates, and the segregation gate
keeping the dependency count at one so a cold build stays under a minute. Watch it; if it regresses,
the answer is a prebuilt `xtask` binary published by a nightly workflow, not more dependencies.

**Cross-repo callers.** `plugin-ci.yml` runs `busbarAI/scripts/public-hygiene-lint.py`,
`executable-config-lint.py`, `plugin-ci-refs.sh` and `signing-gate.sh` **from a checkout of this repo
inside a plugin repo's workflow**, against `--root plugin`. Those four cannot become `cargo xtask` until
the plugin repos are willing to build a Rust binary from a sibling checkout. Options, in order of
preference: (a) `cargo run --manifest-path busbarAI/xtask/Cargo.toml -- gate public-hygiene --root
plugin`, which works today and needs no new artifact; (b) publish an `xtask` binary as a release asset
the plugin workflows download. Batch 3 must pick one before it starts, because it decides whether
`--root` stays a flag on every gate (it should).

---

## 6. What the conversion INTRODUCED, and what it renamed

A port is supposed to change the implementation and nothing else, so the places where that is not
true are the places most worth writing down. Each entry below is a deliberate, owner-accepted
departure from "same semantics, same row ids" — recorded here because a departure nobody wrote down
is indistinguishable from a porting mistake the next reader has to re-derive.

### 6.1 A rule the conversion added: `ci-umbrella`'s TIER-IFF-FULL-GUARD

`ci-umbrella-lint.py` asserts only the SHAPE half of the tier column — that every `RESULTS` row
parses as `jobkey|tier|${{ needs.<job>.result }}` and carries a tier at all. Nothing in the tree
asserts that the tier a row *declares* is the tier the job it scores actually *is*.

The Rust gate adds that as `ci-umbrella:results-tier-matches-guard`: a row's tier is `full` **exactly
when** the job it scores carries the full-tier `if:` guard the umbrella's own `FULL_TIER` expression
mirrors. Not "at least when" — iff, in both directions, because both directions fail:

* a **guarded** job labelled `fast` reddens every fast-tier run for doing exactly what its guard told
  it to do, which is the kind of red that gets a gate relaxed rather than fixed;
* an **unguarded** job labelled `full` has its real skip *forgiven* — the umbrella forgives `skipped`
  only for a `full` row on a fast-tier run — so the required check quietly stops requiring that job.
  That is the same silent-membership failure the gate exists for, one column to the right.

This holds exactly on today's `ci.yml` (eleven `full` rows against the eleven guarded gating jobs;
the `!cancelled()` conformance job and the push-only proof-manifest job are correctly not full-tier),
so it lands green rather than as a ratchet. It is recorded here as **introduced, not inherited**: no
prior gate, comment or document states it, and a reader diffing the Rust against the Python will find
it with no Python behind it.

### 6.2 Row ids the conversion split, and why a static owed set forced it

Two gates could not keep their legacy ids, because those ids were not a fixed set.

**`service-images`.** `service-images-check.sh` recorded one row per image LOCATION —
`images|ci.yml:413` — so the id moved with the line number and the row set changed whenever a
workflow was edited. That cannot be a `Gate::owed` set: the owed set is what makes "a rule stopped
being emitted" detectable, and an id nobody can predict is an id nobody can miss. So the RULE became
the id and the location moved into the row detail. The split is strictly finer, not coarser: the
three distinct failures the shell folded into one dynamic id — a floating tag, an image with no row
in the pinned table, and a digest that disagrees with the table — are now three separately owed rows
with three separate RED proofs.

**`changelog-register`.** The Python prints per-ENTRY ids (one per accepted difference), which is
again a set that moves with the data file. The Rust owes rule ids and names every offending entry in
the row detail.

Consequence, and it is the reason this is written down rather than mentioned: **anything that reads
those ids out of a ledger will not find the old spellings.** The TSV shape is unchanged and the
readers still parse it; it is the id column's vocabulary that moved.

### 6.3 Where the Rust is deliberately stricter than the script it replaces

These are not parity failures. They are the zero-is-not-clean rule from risk 5.2(b) applied where the
legacy had no equivalent, and each is a named FAIL with its own selftest case:

* `changelog-register` treats a register that parsed to **zero entries** as RED. The legacy reads
  `"accepted": []` as "nothing owed" and exits 0 — a renamed key or a truncated write is then
  indistinguishable from a clean register.
* `changelog` reports an **impossible calendar date** as a named `NO-FUTURE-DATE` failure. The legacy
  raises out of `date.fromisoformat` and exits non-zero with a traceback, which is a red for the
  wrong reason and one nobody can act on.
* Every gate's walk carries a `min_files` floor and every gate's unreadable-input path emits FAIL
  rows rather than reporting a clean tree.

### 6.4 What parity does NOT cover

The parity harness compares verdicts over planted trees, so it can only cover arms the legacy script
also has. Recorded so a green parity run is not read as a wider claim than it is:

* `changelog-register --require-version` has **no legacy counterpart** — it is the register-side half
  of `changelog-lint --require-version`, added here. Nothing compares it.
* `qa-gate-dispatch`'s `default-branch-copy` arm reads the promoted workflow out of **git**, and a
  materialized scratch directory is not a repository. The declared-shape arm — the one that runs on
  every branch — is covered; the `origin/main` arm is proven by its selftest and not by parity.
* `release-order`'s graph proof (`PROVE`) is answered by the legacy under a different flag. A probe
  whose two sides are asking different questions is not a parity probe, so it is excluded.

---

## 7. Batch-1 gate list and sizing

Sizes are **estimated Rust source lines including the gate's own selftest**, derived from the script's
non-comment, non-blank line count and the shape of the port (text scan ≈ 1.3×, `cargo metadata` graph
walk ≈ 2×, Python with a data model ≈ 1.2×, wrapper ≈ 0.2×).

**Shared infrastructure first — nothing in the list below compiles without it (~1,100 lines):**

| Module | Replaces | Est. |
| --- | --- | --- |
| `ctx.rs` — `Ctx`, `WalkSpec` (+ `min_files` floor), overlay, scratch proving | the `find … -not -path` idiom, ~20 copies | 250 |
| `ledger.rs` — `Row`/`Status`/TSV writer/`Verdict`/owed-set reconciliation | `release-gate/lib.sh::record`, the verdict half of `gate.sh` | 220 |
| `scan.rs` — `production_lines`, `strip_comment_line` (moved out of `denylist.rs`) | `TEST_SCOPE_AWK`, 7 copies | 60 (move) |
| `planes.rs` | `plane-keys.sh` (24) + `plane-roots.sh` (91) + its selftest | 260 |
| `yaml_lite.rs` — workflow subset + logical-line folding | `ci_logical_lines()` awk | 300 |
| `gitp.rs` — git-as-a-process | scattered `git` calls | 120 |
| `gates/mod.rs` — the registry, `Gate`, `Verdict`, `Report`, `Expect` | — | 180 |

**Batch 1, twenty-one gates (~6,700 lines):**

| # | Gate | From | Script code LOC | Est. Rust LOC |
| --- | --- | --- | --- | --- |
| 1 | `structure-lint` | `structure-lint.sh` | 1108 | **1,450** — split into `gates/structure_lint/` with one module per rule family; it is ~20 rules plus five selftest fixture drivers, and porting it as one file will not survive review |
| 2 | `release-order` | `release-order-lint.py` | 651 | 800 |
| 3 | `plane-purity` | `plane-purity-lint.sh` (+ `g6-freeze-witness.sh`) | 546 + 47 | 700 |
| 4 | `changelog-register` | `changelog-register-check.py` + `.sh` | 331 + 19 | 430 |
| 5 | `changelog` | `changelog-lint.py` | 336 | 430 |
| 6 | `release-script-lint` | `release-script-lint.sh` | 292 | 380 |
| 7 | `ci-umbrella` | `ci-umbrella-lint.py` | 295 | 380 |
| 8 | `blocking-ffi` | `blocking-ffi-lint.sh` | 244 | 320 |
| 9 | `workspace-deps` | `workspace-deps-lint.py` | 234 | 300 |
| 10 | `qa-gate-dispatch` | `qa-gate-dispatch-lint.py` | 232 | 300 |
| 11 | `response-header` | `response-header-lint.sh` | 199 | 260 |
| 12 | `plane-transport-neutrality` | `plane-transport-neutrality.sh` | 182 | 240 |
| 13 | `settings-leak` | `settings-leak-lint.sh` | 156 | 210 |
| 14 | `inventory-ref` | `inventory-ref-lint.py` | 138 | 180 |
| 15 | `kernel-token-wire-purity` | `kernel-token-wire-purity-lint.sh` | 118 | 160 |
| 16 | `no-self-filed-issues` | `no-self-filed-issues-lint.sh` | 117 | 160 |
| 17 | `tracing` | `tracing-lint.sh` | 116 | 155 |
| 18 | `segregation` | new (section 4) | — | 120 |
| 19 | `plane-abi-neutrality` | `plane-abi-neutrality.sh` | 47 | 90 |
| 20 | `duplex-ws-default-edge` | `duplex-ws-default-edge.sh` | 42 | 90 — a `cargo metadata` closure walk, so it reuses `denylist.rs`'s runner rather than its LOC |
| 21 | `denylist` | already Rust | — | 20 (re-register under `gate`) |

**Batch 1 total: ~6,700 gate lines + ~1,100 shared = ~7,800 lines of Rust**, replacing ~4,400 lines of
shell and Python plus their embedded selftests, and deleting `scripts/plane-keys.sh`,
`scripts/plane-roots.sh`, `scripts/inventory-coverage.sh`, `scripts/changelog-register-check.sh` and
`scripts/preflight.sh` outright.

Suggested order within the batch: shared infrastructure → `segregation` (it guards everything after it)
→ the six small text scanners (15–20) → the mid-sized lints (6–14) → `plane-purity` → `structure-lint`
last, since it is the one that most benefits from a settled `WalkSpec` and `production_lines`.

### 6.1 `structure-lint`: the row split, and the deltas it carries

**The shell had ONE exit status for twenty rules.** `structure-lint.sh` printed its findings PER
LOCATION under nine `== header ==` blocks and exited 0 or 1, so "structure-lint failed" never said
which invariant, and a rule that stopped running was indistinguishable from a rule that passed. The
gate owes **one row per RULE** — thirty-six of them — and the parity harness compares the two on the
hit sets, so this section is the record of how each shell tag became a row id.

| shell tag / block | row id(s) | why the split |
| --- | --- | --- |
| `PROTO-ROOTS-MISSING` | `structure-lint:proto-roots` | — |
| `PLANE-ROOT-{MISSING,AMBIGUOUS}`, `PLANE-ROOTS-EMPTY` | `structure-lint:plane-roots` | one rule, three ways to fail it |
| the denominator `FAIL:` block | `structure-lint:candidate-floor` | — |
| `HYBRID` | `structure-lint:hybrid-modules` | — |
| `OVERSIZED` | `structure-lint:oversized` | the grandfathered lines were informational and stay informational: they are not offenders on either side |
| `INLINE-TEST` / `ALLOW-WITHOUT-REASON` | `structure-lint:inline-tests` / `…:inline-test-allow-reason` | two rules, and the second is the one a bare allow breaks. Folding them would let "there are no inline tests" be reported by a run in which every one of them carried an unreasoned allow |
| `MALFORMED-ROW` (choke points) | `structure-lint:choke-point:row-integrity` | the three tables share one tag; the row id is resolved from the id the shell printed |
| `MISSING-CLASS-TEST` | `structure-lint:choke-point:class-test` | — |
| `ALLOWED-PATH-MISSING` | `structure-lint:choke-point:allowed-path` **or** `structure-lint:axis:allowed-path` | one tag, two tables. The shell's own sentence disambiguates: "the owner's new home" is the registry, "the arm's new home" is the axis ledger |
| `ZERO-SCAN` | `structure-lint:choke-point:scan-set` | — |
| `DURABLE-BYPASS`, `EXPORT-BYPASS`, `MUTATION-BYPASS`, `ASK-NOT-OPERATOR-AUTHORED`, `TRUST-COMPARISON-BYPASS` | `structure-lint:choke-point:bypass` | five tags, one rule: "a hazard class was re-implemented outside its owner". The tag stays inside the offender string, so the hit set is unchanged |
| `SUBJECT-MISSING` (function-scoped) | `structure-lint:request-path:subject` / `structure-lint:decision-input:subject` | one runner, two tables — and a renamed `try_admit` is a different fact from a renamed `resolve` |
| `STORE-ON-REQUEST-PATH`, `ALLOC-ON-PROTOCOL-LOOKUP` | `structure-lint:request-path:purity` | — |
| `DESCRIPTION-ON-ROUTING-PATH` | `structure-lint:decision-input:purity` | — |
| `PLANE-DUPLICATE` | `structure-lint:plane-dup:unledgered` | — |
| `MALFORMED-LEDGER` | `structure-lint:plane-dup:ledger-integrity` **or** `structure-lint:axis:row-integrity` | one tag, two ledgers; the axis form quotes `` `axis|file` `` and the plane form quotes a bare name |
| `STALE-LEDGER` | `structure-lint:plane-dup:stale-ledger` **or** `structure-lint:axis:stale-ledger` | same tag, two ledgers, two different "delete this row" instructions |
| `SCOPE-MISSING` | `structure-lint:axis:scope` **or** `structure-lint:census:scope` | "the axis's new root" vs "the subject's new root" |
| `NO-SUBJECT` | `structure-lint:axis:scan-set` **or** `structure-lint:census:scan-set` | "the allowed prefixes cover…" vs "holds no production source" |
| `SCAN FAILED on the … axis` | `structure-lint:axis:row-integrity` | an aborted scan returns no hits, and no hits is the rule's pass |
| `OPERATION-BRANCH`, `TRANSPORT-BRANCH` | `structure-lint:axis:purity` | — |
| `NO-ROWS` | `structure-lint:census:row-integrity` / the two `…:subject` rows | an empty table is an unarmed rule, reported under the rule it disarmed |
| census `SUBJECT-MISSING` | `structure-lint:census:subject` | the shell reused the function-scoped tag for a different failure with a different remedy; the sentence ("occurs NOWHERE") is what tells them apart |
| every census `*-RESPELT` / `*-FORKED` / `THIRD-CATALOGUE-WALK` tag | `structure-lint:census:count` | nine tags, one rule: the count is not the declared one |
| `PLANE-SINK-SCOPE-MISSING`, `NO-PLANE-SINK` | `structure-lint:plane-sink:scan-set` | both are "this rule scanned nothing" |
| `PLANE-SINK-NOT-NARROWED` / `PLANE-SINK-WIDENED` | `structure-lint:plane-sink:not-narrowed` / `…:widened` | a sink that names neither trait and a sink that names the wrong one are two edits away from each other |
| `BOOTCTX-MISSING` / `-NOT-NARROWED` / `-WIDENED` | `structure-lint:boot-ctx:subject` / `…:not-narrowed` / `…:widened` | — |

**Two documented deltas in the offender STRINGS**, both because the shell's own text could not be
reconstructed from what it printed:

1. **`BOOTCTX-WIDENED` names the FIELD, not a line number.** The shell ran `grep -n` over the
   extracted struct BODY, so its numbers count from the `pub struct BootCtx` line rather than from
   the top of the file. A number that means one thing on one side and another on the other is a
   parity diff about counting, so the offender is the field text — which is what a reader has to
   change anyway.
2. **`PLANE-SINK-*` sites are normalised** from `grep -rn`'s `path:line:content` to
   `path:line: content`. Same three facts, one spelling.

**Three documented deltas in what a rule ASKS:**

1. **The protocol crates and the plane roots are derived from the WALK, not from `[ -d ]`.** The
   shell asked the filesystem whether a directory existed, which no overlay can answer, so the two
   "the tree stopped answering" rules were unprovable. A directory holding no source contributes
   nothing to any scan below it — which is the question `plane-roots.sh` already had to add for its
   own ownership test — so asking "does it hold a source file" is the same question asked honestly,
   and it is the question a self-test can plant against.
2. **`structure-lint:candidate-floor` no longer exits.** The shell exited 1 on a corpus below its
   floor, leaving every rule below it unreported. Here the corpus-dependent rows are emitted as
   `DID NOT RUN`, which is the same verdict said out loud: the reader is told which rules the empty
   scan set took down with it.
3. **The candidate walk honours `.gitignore`.** `find` does not, so the shell's scan set included
   whatever a build or an editor left in the tree. See `Ctx::drop_ignored`; the floor is applied
   after the filter, so an ignore rule that swallowed a scan set trips the floor rather than reading
   as a clean tree.

**`STRUCTURE_LINT_CANDIDATE_FLOOR` is gone.** Floors are `const`s and there is no environment
override: the only way to lower one is a reviewable source edit.

## 8. `kind-isolation:matrix` — the composition root is measured too

The `kind-isolation` gate landed with six rows and all six measured the WIRES. `:vocab` proves a
transport never says `a2a` and a plane never says `hyper`; `:deps` proves the kind-to-kind edges in
the manifests are the ones already measured; `:name` proves no crate name fuses a kind with another
kind's instance. Not one of them looked at `crates/busbar` — the composition root — where the tree
hand-wires one file per plane (`root/units_llm.rs`, `units_mcp.rs`, `units_a2a.rs`,
`units_voice.rs`, `units_admin/admin_mount.rs`) and where a plane-named accept loop
(`root/voice_serve.rs`, behind a `root-voice-serve` feature) was landed on a sibling branch. All of
it was green, because nothing counted it. **A gate that measures the wires and not the place the
wires are joined reports the tidy half of the tree.**

`:matrix` measures the whole matrix: for every kind `K` in the kind table and every crate `C` under
`crates/`, how many times `C` names `K`'s vocabulary.

**The vocabulary is derived, on every run.** It comes off the same census the other five rows use —
`K`'s member package names, their kind-qualified ids (`store-memory`, `plane-llm`), and, for the
plane and transport families, their bare instance ids (`llm`, `mcp`, `voice`/`streams`, `http`,
`ws`). Registering a plane teaches this row a new word in every other crate on the same commit,
which is the only way a vocabulary rule survives a growing tree. **Bare ids are limited to the two
families that HAVE an instance vocabulary, and that is the kind table's own word for it**:
`Family::Neutral` is defined in `kind_isolation.rs` as "a kind with no instance vocabulary of its
own", and it is already load-bearing in `:name` and `:vocab`. A neutral kind's members are named for
the step of the loop they run — `cost`, `wal`, `ledger`, `memory`, `usage` — which are words the
whole tree shares; counting them would report the Teller loop talking about money as the cost unit
leaking into the ledger unit.

**Nothing is stripped.** Every `.rs` and every `.toml` under the crate, whole text: identifiers,
string literals, doc comments, ordinary comments, `#[cfg(feature = …)]` attributes, Cargo dependency
names, Cargo feature names — plus the file's own path, so `root/voice_serve.rs` is a hit before a
byte of it is read. Tests are not excluded; a transport's own fixture that names a plane is that
transport naming a plane.

**Two independent scanners, and the higher number wins.** One reduces a line to a stream of
lowercase alphanumeric segments (splitting at every non-alphanumeric byte and at both camel-case
transitions) and matches a needle's segment run. The other walks the raw characters, compares
case-insensitively, and accepts a window only between boundaries. They share the needles and nothing
else. The scored count is the HIGHER of the two, never the lower, and a cell where they disagree is
RED unless the cell records the disagreement and why — a spelling one scanner cannot see is exactly
the leak that must not pass at the lower number. Twenty cells record one today, all of them the same
two shapes: `gRPC`, which splits at its own camel joint for the segment scanner and reads whole for
the window scanner, and `A2AService`, which is the mirror case.

**Why a boundary rule and not a raw byte substring.** The owner's ruling is "I'd rather have it
false-fail than not", and the boundary rule is the stricter reading of it, not the weaker one. `sse`
is a transport instance and also the middle of `assert`; `ws` is a transport instance and also the
middle of `rows`. A raw substring scan of this tree answers 35 306 for `sse` and 5 671 for `ws`,
numbers made almost entirely of English, and a ceiling pinned to them moves whenever somebody writes
an assertion. That is not a stricter gate, it is a line counter wearing one — and a gate that reds
for a reason unrelated to its rule is how a runner earns a `|| true`. The boundary rule keeps every
spelling a human would recognise as the name (`a2a_session`, `mcpFrame`, `root-voice-serve`,
`busbar_transport_http`, `VoiceServe`, the filename, the feature, the comment) and refuses the ones
that are not names at all.

**`qa/kind-isolation.toml` is the whole allowance, and it is read by ONE reader.** There is no
allow-list in the source, and no second parser either: these rows go through the same hand reader
`parse_registry` already runs over `[[transitional]]`, `[[registered]]` and `[[announced]]`, on the
same terms — a missing, empty or unknown field is REFUSED AT LOAD rather than skipped, and two rows
naming one cell are reported as two answers rather than resolved by file order. Three tables, and
the split is the same one `:deps` already makes: the SENTENCES belong to the kind-to-kind class,
because that is what a reader is reading, and the NUMBER belongs to the crate, because that is what
the ratchet moves.

```toml
[[edge]]
from = "root"
to = "plane"
cite = "none. ARCHITECTURE.md 1.1 gives the composition root a REGISTRY to assemble from …"
why = "crates of kind root naming plane vocabulary: …"
drain = "delete the per-plane wiring from crates/busbar/src/root/** and crates/busbar/src/main.rs …"

[[cell]]
crate = "busbar"
kind = "plane"
count = "1798"

[[disagreement]]                                       # only when the two scanners differ
crate = "busbar"
kind = "plane"
note = "segment scanner 1798, window scanner 1797. …"
```

**The ratchet is exact in both directions.** A count above its row is the landing that grew the
coupling. A count BELOW its row is stale slack, and stale slack is how drift hides: the number comes
down on the commit that drained it, or the gate is red. A row whose cell measures zero is a dead
allowance and must be struck; a class no crate exercises any more is struck likewise. A cell above
zero with no row at all is an UNLISTED EDGE, refused whatever `ARCHITECTURE.md` may or may not
grant, because an edge nobody wrote down is an edge nobody reviewed.

**The ship twin owes zero everywhere and does not read the file.** What is written in
`qa/kind-isolation.toml` is what 1.6.0 still has to delete, not a shape the tag is allowed to keep.

`--report` prints the whole matrix (crate × kind → count, with both scanners' totals) and then the
DRAIN LIST: every hit, `file:line`, grouped by cell. The integrator hands each file its deleting
line rather than re-deriving it.

**The self-test opens with the incident.** The head of the real `crates/busbar/src/root/voice_serve.rs`
(from `keep-streams-3` `dd96a04f3`) is planted back into the root — the plane named in the path, in
the `#![cfg(feature = "root-voice-serve")]`, in the module header's prose and in the
`use busbar_plane_voice::…` — and the row goes RED; its green twin is the same tree with the file
absent. Then: the root held to the zero a registry-driven root would measure (the finding names
`root/units_voice.rs` and the other heaviest files by hit count), a ceiling left with slack, a plane
named in a transport, the same name in that transport's own TESTS, a transport named in a plane, a
store named in the kernel, a plane named in nothing but a comment in the kernel, the two scanners
disagreeing, an edge class with no row, a second `[[cell]]` row for one cell, and the ledger absent.
A class whose citation is emptied needs no case of its own: it is refused by the shared reader's
`take_row`, which the registry row already self-tests, and the class then reads as unlisted.

**Where it runs.** `land.sh`'s `kind-isolation` token is unconditional and runs the gate whole,
without a row filter, so a landing that raises a ceiling is red on the runner. `qa/full-gate.toml`
and `full_gate.rs` invoke `cargo xtask gate kind-isolation`, which owes the row. `keep-proof.yml`'s
gate job runs `cargo xtask gate --all`, which walks the registry and therefore includes it.

## 9. The DEPENDENCY side of the gate — every manifest, every table, every edge instance

Section 8 measured the composition root's vocabulary. This section is the other half of the same
ruling — "core is core, plugins are plugins, transport, everything" — applied to what the MANIFESTS
say and to the ways into a crate that are not a `use` line at all. Three red-team passes over the
gate found fourteen ways to carry a plane into a transport with every gate in the tree green, and
they reduce to five root causes, each closed here.

**One manifest reader, and it reads every table.** `deps_of` looked for the literal section name
`dependencies` and recorded the manifest KEY. `construction::tree::read_cargo_deps_text` had the
identical shape, so fixing one would have left the other. There is now one reader,
`xtask::manifest`, and both gates call it. It reads `[dependencies]`, `[dev-dependencies]`,
`[build-dependencies]` and the per-target forms of all three, and it resolves the PACKAGE each
declaration reaches: `foo = { package = "busbar-plane-llm", … }` is an edge to the plane, not to a
crate called `foo`, and `foo = { workspace = true }` under a `[workspace.dependencies]` entry that
renames it is the same edge stated one file away. Every one of those five spellings was planted in
the real tree and left every gate green. Widening `construction`'s reader made it see one dependency
it never could — a `[target.'cfg(unix)'.dependencies] libc` that ships in every Linux artefact this
tree builds — which is now reviewed in `qa/construction.toml` rather than re-narrowed.

**The test graph is scored, on its own row.** `[dev-dependencies]` was read by the battery rule and
by nothing else, on the sentence "a test edge is not a shipped edge". That is true, and it is not a
reason to leave it unmeasured: a plane declared in a transport's `[dev-dependencies]` is a plane
compiled into that transport's test binary. `kind-isolation:test-deps` holds it against its own half
of the ledger, because folding it into `:deps` would grant the shipped artefact the same edge.

**The census is every `Cargo.toml` in the repository.** It read `crates/<dir>/Cargo.toml` and
nothing else, under its own comment "a manifest one level deeper belongs to a fixture" — and that
comment was the hole. A plane-kind crate at `vendor/busbar-plane-shim/`, path-depended from a
transport, was invisible; so was the same crate at `crates/busbar-transport-tcp/internal/shim/`; and
striking a crate from `[workspace.members]` dropped it out of every `--workspace` test, clippy and
deny run with `workspace-deps:set-equality` still PASS, because that row compared the members it
INSPECTED — derived from the declared list — against the declared list itself. Where a manifest sits
is now a finding: `off-tree-crate`, `nested-crate`, `unmembered`. The exemption is one reviewed
table, `OFF_TREE_MANIFESTS` — the runner, the gate fixtures, the standalone documentation example —
and each entry is RED the day the path it names is gone. `workspace-deps` reads that same table
rather than keeping a second one, and gained the third set its own row was missing: what is on disk.

**The ratchet moves one EDGE INSTANCE at a time.** `MEASURED_EDGES` was a table of kind-to-kind
CLASSES, and a class ratchet has unlimited slack inside a class: `transport -> unit` was one line, so
a second transport growing a dependency on a unit was green, and so was a third. An audit of all 220
workspace-internal edges found 105 the architecture grants, 87 it does not, 15 in the loader/tooling
trusted base and 13 it never rules on at all — all held by 38 lines recording which pairs of kind
WORDS had ever appeared together. So `qa/kind-isolation.toml` gained a row per (from-crate, to-crate)
pair, per half, read by the same hand reader the `[[cell]]` rows use and refused at load on a missing
field, an empty one, an unknown one or a duplicate row:

```toml
[[dep]]
from    = "busbar-transport-tls"
to      = "busbar-unit-transport-key"
half    = "shipped"
count   = "1"
verdict = "not-allowed"
cite    = "ARCHITECTURE.md 1.1 \"A transport cannot name a plane or a unit.\" …"
why     = "…"
drain   = "delete the busbar-unit-transport-key dependency from …"
```

exact in both directions, on the same terms `[[cell]]` already lives under: above is the landing that
grew the coupling, below is stale slack, a row whose edge is gone is a dead allowance, and an edge
with no row is refused whatever the architecture may grant — an edge nobody wrote down is an edge
nobody reviewed.

**A row may not grant itself an edge.** `verdict` is one of `allowed`, `tcb`, `not-allowed`,
`owner-ruling-pending`, and the first two are READINGS of `ARCHITECTURE.md` rather than opinions the
ledger is entitled to hold: the class tables `ARCHITECTURE_ALLOWED` and `ARCHITECTURE_TCB` live in
`xtask/src/gates/kind_isolation.rs`, and a row claiming an edge the architecture withholds is refused
as an unsupported verdict. The thirteen edges the architecture never rules on are
`owner-ruling-pending` and each carries a `[[question]]` row with the full question, so a ruling can
be given by reading the file and nothing else. `UNSCORED_SOURCES` and `SPEC_SINK` are gone: the
composition root and the retiring legacy crates are scored like everything else and their edges are
rows.

**The ship twin owes the architecture's graph, not yesterday's measurement.** It does not read the
ledger at all. Only the classes `ARCHITECTURE_ALLOWED` names are permitted; `tcb`, `not-allowed` and
`owner-ruling-pending` are all refused, because the criterion for a tag is not "no worse than the
last commit". The legacy drain's expiry moved to its own ship-only row,
`kind-isolation:legacy-drain`, because "the drain finished" and "the graph is the architecture's" are
two claims and neither could be proven while they shared a verdict.

### 9.1 `kind-isolation:build-inputs` — the ways in that are not a dependency

Every other row reads a dependency table or a `use` line. Five plants used neither:
`#[path = "../../busbar-plane-llm/src/meta.rs"]`, `[lib] path = "../busbar-plane-llm/src/lib.rs"`,
`include_str!` of another crate's source in a `build.rs`, a `Cargo.lock` naming an edge no manifest
has, and `[features] llm-serve = []` in a transport. The `#[path]` and `include_str!` paths are read
off the RAW line — `:vocab` blanks literals before it reads, which is exactly why they were invisible
there — and every path is resolved against the file that wrote it and asked one question: does it
leave the crate's own directory?

Two narrowings, both the rule rather than a softening of it. A path landing outside every crate is
not this row's subject: a test pinning a table against `qa/method-inventory.json` is reading a
repository artefact and there is no kind on the other end of it. And a path into a crate this one
already DEPENDS on is an edge that is written down, at its exact count, with its verdict. What is
left is the reach with no edge at all. A `[lib]` target is refused either way, because it does not
LINK the other crate — it compiles its source as this crate's own body.

The composition root's `root-*` features are the written exemption, with a green case beside the red
one, and it is an exemption with a NUMBER attached: `:matrix` counts every one of those words against
`[[cell]] busbar / plane` at an exact ceiling. `plugins.yaml`'s kind words are the tree's third kind
vocabulary, mapped once here; an entry whose crate name resolves to a kind other than the one it is
filed under is `registry-kind-mismatch`, because the registry is what the loader believes.

### 9.2 `kind-isolation:faces` — no crate implements another kind's entry face

A crate's kind is a claim about what it is; a trait implementation is the same claim made to the
COMPILER, and when the two disagree the compiler's is the one that runs. `:shape` counts a crate's
implementations of ITS OWN kind's trait, so `impl Plane for Wire` inside a transport and
`impl Transport for P` inside a plane left that row byte-identical in both directions. `:faces` asks
the other question, per-push rather than at release, because a wire that implements `Plane` is a
plane on the commit that lands it. `impl_trait_on` now reads the qualified spelling
(`impl busbar_contract::Plane for X`), which was a one-keystroke bypass of anything written on it.

Four crates implement a foreign face today; each is a `[[face]]` row at its exact count with its
citation and the line that deletes it, and the ship twin owes zero.

### 9.3 `--write` re-pins DOWN, and refuses if anything would rise

An exact ratchet taxes the landing that does the right thing: a cut that removes two of a crate's
plane hits leaves the row three too high and the gate is red until somebody edits a number by hand.
`cargo xtask gate kind-isolation --write` lowers every `[[cell]]`, `[[dep]]` and `[[face]]` count to
what the tree measures, so a landing that drains a coupling re-pins it in the same landing.

It REFUSES WHOLESALE if any count would rise, naming every row that would: a run that grew a coupling
is a landing that has to be read, and a tool that quietly re-pinned the falls in the same breath
would hand it a file that looks reviewed. The write is a line-by-line rewrite of one number per row
rather than a re-render, because this file is written by hand and its comments ARE the reasoning.

### 9.4 The self-test, and the sub-checks that had no plant

Every red-team case is a named case. Beyond them, eight arms of `:registry` had no plant of their
own — `dead-kind`, `kind-arrived`, `alias-retired`, `no-construction-kinds`, `unmapped-kind`,
`unreadable`, and the two floors — and an audit proved what that costs: gutting the `unmapped-kind`
arm left `kind-isolation: green` and `17 case(s), 0 skipped — the gate is proven RED-able` in the
same breath, because the row was still red-able through its neighbours. Each of the eight now has a
fixture that only it rejects, and the two floors fail apart: four manifests is under the census floor
and nowhere near the source floor, and four sources are the mirror.

One cost note, because it is what makes the battery runnable at all. `--selftest` re-runs the WHOLE
gate once per planted case, and this branch adds thirty of them, so the per-case cost is the whole
budget. A profile of one run put 85% of it inside `:transport-registration`, which lexed every source
file once PER WIRE for an answer that does not depend on which wire is being looked for; the wire
scan's memo (`the xtask shard: the wire scan is memoised`) is what removed it. The battery needs
`XTASK_GATE_CEILING_SECS` raised above the 300s per-gate default — `land.sh` and CI give the two long
self-tests their own hang ceiling for exactly this.

## 10. The two ratchets over the ceilings THEMSELVES

Every other rule in the construction gate measures the TREE against a number in `qa/construction.toml`.
These two measure the NUMBERS: `ceiling-rose` refuses one going UP, `ceiling-census` refuses one going
DOWN. Both were readable in ways that made them report the wrong thing, and both are stated here
because the shape of the fix is a rule about the FILE and not about the code that reads it.

### 10.1 A `[[cell]]` ceiling is named by its identity, never by its position

`ceiling-rose` compares every number in `qa/construction.toml` and `qa/kind-isolation.toml` against
the same number at the merge-base. The kind ledger is an array of tables, so the reader spelled each
count by POSITION — `cell.294.count`. A position is not a name. Strike one `[[cell]]` and every later
row renumbers by one, so `cell.294.count` on this tree and `cell.294.count` at the base are two
DIFFERENT cells, and the comparison manufactures rises where nothing rose while hiding the rises that
did. Measured on a branch that deleted one dead crate: thirty false rises, and a deletion is exactly
the landing this ratchet exists to make cheap.

So a row of an identified table is relabelled by the fields that NAME it — `cell.<crate>.<kind>.count`,
`dep.<from>.<to>.<half>.count`, `face.<crate>.<face>.count` — which is the same string on both sides of
a strike. A table the reader has no identity for, and a row missing a field that would name it, keep
the ordinal rather than dropping out of the comparison: a ceiling that cannot be named is still a
ceiling.

The same string is what a `[[gate.ceiling_raises]]` entry's `key` must be. An ORDINAL key is refused
outright rather than resolved, whatever it happens to line up with: a declaration is a transaction
about ONE ceiling, and `cell.294.count` names a slot that the next strike above it hands to a
different crate.

### 10.2 `[[gate.census_retired]]` — the only thing that lowers a census floor, and it is spent once

`[gate.census]` pins how many rule tables, plane crates and kind-glob matches this gate is supposed to
be reading, and each number is a FLOOR that may not go down — because "delete the rule table and drop
its census number" is one edit that deletes a check and the obligation to run it together, and by the
numbers alone it is indistinguishable from a legitimate retirement. Deleting a legacy crate is the
work 1.6.0 exists to do, and every such deletion drops a count: a `plane_crates` entry, a
`legacy-reach` prefix, a `[gate.plugin_kinds]` glob matching one directory fewer. Before this rule
there was no route through at all, so the retirement was red either way and the floor was a thing to
edit rather than a thing to spend.

A NAME tells the two apart. A `[[gate.census_retired]]` row says which crate went, in which commit,
which floor moved, from what to what, and WHY the tree no longer needs it, and it is checked six ways:
the crate must be GONE from the tree; the floor named must be the floor that moved; `from` must be the
number the merge-base carried; `to = from - 1` exactly (one retirement deletes one crate); the `why` is
at least sixty characters, because the numbers say what moved and only the `why` says whether it should
have; and the row must be LIVE.

AND IT EXPIRES, on the same terms a declared raise does. The row rides in the commit that deletes the
crate, so one batch later the merge-base carries both the row and the lowered floor — from then on the
row is SPENT, and a spent row admits nothing. A spent row that still names a drop this branch made is
RED by name: one deletion's ceremony buying two. A spent row that names no drop is a WARNING, never a
red (the strike cannot ride in the same batch as the deletion), and `cargo xtask gate construction
--write` strikes it. A LIVE row that names no drop is RED: the base does not carry it and the floor it
names did not move, so it is either a deletion that is not on this branch or a floor that is misspelt —
and a dead row is the door the NEXT drop of that floor walks through. The record of what 1.6.0 deleted
is the commit history the `commit` field points at, not a pile of spent rows in the ceilings file.

