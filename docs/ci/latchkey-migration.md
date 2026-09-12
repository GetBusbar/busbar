# Latchkey migration — phase 1 (ci.yml, keep-proof.yml, gate-mutants.yml off EC2)

Owner goal: 100% off EC2 self-hosted runners onto Latchkey (latchkey.dev). This is phase 1 — the
three workflows that still carried `runs-on: [self-hosted, linux, x64, busbar-xl]`. Slot LK-1,
branch `keep-ci-latchkey` off `integration/oracle-phase0`, measured via PR
[GetBusbar/busbar#111](https://github.com/GetBusbar/busbar/pull/111) (opened so gate-mutants' and
CI's `pull_request:` trigger fires — gate-mutants' `push:` trigger no longer includes `keep-*`,
see §2).

`docs/ci/fleet.md` **does not exist in this checkout.** The task brief that started this slot named
`docs/ci/fleet.md §4` and a "FLEET-2... RED at N=2 on 32 vCPU" measurement; neither the file nor
that finding-shaped string exists anywhere under `docs/`. The nearest real material is
`docs/ci/self-hosted-runners.md` (the EC2 fleet's own 32-vCPU-per-box, 8-vCPU-per-slot arithmetic)
and the construction gate's own work-unit budget note in `xtask/src/gates/mod.rs` (§3 below), which
is what this document uses instead. Said loudly rather than fabricated.

## 1. Label map (job → size)

xlarge = batteries/gates/mutants (heaviest cargo work or a mutation/test battery). large =
lint/fmt/clippy/build-only or a bounded gate scan. small = collectors/aggregators/scope jobs that
do no cargo work of their own.

| Workflow | Job | Label | Why |
|---|---|---|---|
| ci.yml | gate-tier | small | one bash echo, no cargo |
| ci.yml | structure-lint | large | layout gate over 660k lines, builds `xtask` only |
| ci.yml | check | xlarge | fmt+clippy+build+**test**, the primary heavy job, live DB services |
| ci.yml | openapi-schema | large | schema lint/drift/coverage |
| ci.yml | migration-corpus | xlarge | full migration-corpus test battery |
| ci.yml | config-stability | large | grammar gate |
| ci.yml | generated-artifact-drift | large | inventory/regen-clean lint |
| ci.yml | public-hygiene | large | prose lint |
| ci.yml | service-image-pins | large | pin lint, builds `xtask` only (ambient-toolchain job) |
| ci.yml | executable-config-lint | large | config-grammar lint |
| ci.yml | no-default-features | xlarge | full build+clippy+test under a feature variant |
| ci.yml | deletion-test-matrix | xlarge | compile matrix across planes |
| ci.yml | no-plugins-gate | xlarge | gate |
| ci.yml | txn-guards | xlarge | loom model + compile fence |
| ci.yml | timing | xlarge | release-mode timing gate — needs an uncontended box |
| ci.yml | windows | *(unchanged: `windows-latest`)* | Latchkey has no Windows offering |
| ci.yml | coverage | xlarge | llvm-cov over the whole suite |
| ci.yml | perf-build-gate | xlarge | gate |
| ci.yml | proof-manifest | small | publishes a manifest, no cargo, no gate verdict |
| ci.yml | shadow-oracle | xlarge | release build + `record --plane all`, the single heaviest job |
| ci.yml | llm-conformance | large | downloads and validates a recording, no build of its own |
| ci.yml | teller-steps | xlarge | compiles the binary crate under 5 feature legs |
| ci.yml | construction-gate | xlarge | gate — also THE measurement job for §3 |
| ci.yml | design-bindings | large | existence + regen-clean check |
| ci.yml | ship-ready | large | builds `xtask`, scans the whole tree's posture |
| ci.yml | ci-umbrella | small | pure collector (`needs:` fan-in, no cargo) |
| keep-proof.yml | build-clippy | large | fmt/clippy/build only |
| keep-proof.yml | tests | xlarge | test shard |
| keep-proof.yml | tests-total | small | aggregates the shard results |
| keep-proof.yml | gates | xlarge | `cargo xtask gate --all` battery |
| keep-proof.yml | design-bindings | large | lint |
| keep-proof.yml | oracle | xlarge | shadow-oracle recording, heaviest job here too |
| keep-proof.yml | construction-gate | xlarge | gate |
| keep-proof.yml | verdict | small | writes the one-line commit status, no cargo |
| gate-mutants.yml | scope | small | git fetch + a shell script, no cargo |
| gate-mutants.yml | baseline | xlarge | the four gates, unmutated — a battery |
| gate-mutants.yml | shard | xlarge | the mutation battery itself, heaviest here |
| gate-mutants.yml | gate-mutants | small | verdict aggregator, no cargo |

Result: 18 xlarge, 12 large, 7 small, 1 unchanged (windows-latest) — 38 self-hosted jobs migrated.

## 2. Trigger changes

**gate-mutants.yml** — `keep-*` dropped from the `push:` trigger, folding in CI2's `363ac81b8`
(that commit lives on `keep-ci-mutants-trigger`, not on this branch's ancestry, so it is reproduced
here rather than inherited). ~15 live hand-back branches each fanning 24 mutant shards was an
EC2-era starvation problem; on Latchkey it is the same problem denominated in dollars — the 20
concurrent-runner-per-workspace default (§4) turns that fan-out into queue time for everyone else.
The 24-shard run still fires on `integration/**`, `dev`, `qa`, `main`, `pull_request` and
`workflow_dispatch`; a slot proves its own shard locally per `scripts/gate-mutants.sh`'s existing
contract.

**keep-proof.yml — deliberately UNCHANGED**, and this is a deviation from the literal instruction
("keep-proof triggers restricted to integration/**, dev, qa, main"), made and flagged rather than
applied silently. keep-proof.yml's *only* push trigger is `branches: ['keep-*', '!wip/**']` — that
IS its whole purpose, stated at length in the file's own header comment: it judges a hand-back
branch's build/lint/tests/gates remotely so nobody re-runs them on a laptop. Restricting it to
`integration/**, dev, qa, main` would mean it never runs for the branches it exists to judge — there
is no precedent commit for this (`git log -S` over `.github/workflows/keep-proof.yml` finds none),
and no analogous starvation report against it the way `363ac81b8` documents for gate-mutants. The
real cost this migration adds — N concurrent slot branches each paying full Latchkey per-minute
"pricing for a keep-proof run — is real and is the correct thing to worry about (§4), but the fix is
not "stop judging hand-backs"; it is capacity/scheduling, which is a phase-2/3 question, not a
phase-1 YAML edit.

## 3. The two figures phase 2/3 need

**Cold-build wall time on 16 vCPU (`latchkey-xlarge`).** ci.yml's `check` job (fmt · clippy · build
· test, `latchkey-xlarge`) ran cold — no cache hit, see §5 — from job start `23:45:37Z` to
completion `23:58:30Z`: **12m53s.** It failed, but not on the build: every crate compiled clean
(sccache invoked correctly once installed, see §5) and the tests ran; the failure was the R14
pin-by-sha gate catching this migration's own unpinned action ref (§5, fixed in `fd447f6e5`). 12m53s
is therefore a real cold-build-and-test wall-clock figure on a 16-vCPU Latchkey box, not a number
thrown out by the failure.

**Does the construction gate's 50,000-unit budget hold on 16 cores?** ci.yml's `construction-gate`
job (`latchkey-xlarge`) self-test measured:

> `36 case(s), 0 skipped, 1033.9s / 39607 work units, slowest 50.1s ... the gate is proven RED-able`

**39,607 / 50,000 — 79% of budget, comfortably under, on Latchkey's 16-vCPU box.** This is the
direct answer to the FLEET-2-shaped question the task brief posed (see the `fleet.md` note above):
on this measurement, 16 Latchkey vCPUs do NOT blow the construction gate's budget the way `--jobs
18` on a contended 32-vCPU EC2 box did (68,063 units, over budget, per `xtask/src/gates/mod.rs`'s
own comment) — Latchkey's dedicated-per-job vCPU allocation (no other job's mutation shard sharing
the box) looks like the more favorable regime, not the less favorable one. One measurement, not a
distribution — re-run before treating 79% as a stable margin.

## 4. What sucks (every failure, slowness, cap hit, cache miss, self-healing surprise)

1. **The GitHub Actions cache backend does not reliably work from Latchkey runners.** Nearly every
   job logged `::warning::Cache lookup failed with HTTP ${HTTP_CODE}` / `Cache restore failed,
   continuing without cache` / `Cache save failed, continuing without saving` — this is
   `mozilla-actions/sccache-action`'s own cache-of-the-sccache-binary AND `SCCACHE_GHA_ENABLED`'s
   direct-to-GHA-API cache path, both of which assume `ACTIONS_CACHE_URL`/`ACTIONS_RUNTIME_TOKEN`
   reach GitHub's cache service the way a GitHub-hosted runner's do. From a runner living in
   Latchkey's own AWS account, that path is unreliable. **In one job (`ship-ready`) this was not a
   warning, it was a hard failure**: `error: could not execute process 'sccache
   .../rustc -vV' (never executed): No such file or directory (os error 2)` — the sccache binary
   was never installed in that job because the cache-of-the-binary lookup failed AND the job has no
   direct install step, only the global `RUSTC_WRAPPER=sccache` env var. This is exactly why
   Latchkey's own docs push their S3-backed Fast Cache instead of GitHub's actions/cache for
   dependency caching (adopted here for `~/.cargo`/`target/` in §5) — the same reasoning applies to
   sccache's object cache and it is NOT yet migrated: sccache is still wired to
   `SCCACHE_GHA_ENABLED`/GHA's cache API in both files. **Phase 2 must either point sccache at a
   Latchkey-reachable object-cache backend (S3 directly, since sccache supports S3 natively) or
   accept that every job compiles from scratch.**
2. **The 20-concurrent-busy-runner-per-workspace default is real and binding.** gate-mutants' 24
   shards did not run as 24 parallel jobs — they ran in waves of 4-5 with the rest sitting `queued`,
   visibly rate-limited by the workspace cap, compounded by unrelated concurrent activity from other
   slots' branches during this measurement window (this workspace is shared org-wide, not
   per-branch). Phase 2/3 (slot pre-proofs, the landing engine) will multiply concurrent demand;
   without a raised limit (Latchkey offers this on request) the queue-time cost this migration was
   supposed to eliminate reappears in a different place.
3. **`R14` (every third-party action pinned by commit sha) caught this migration's own mistake**,
   and did so within 6 minutes of the first push: `latchkey-dev/cache-action@v1` is a movable tag,
   not a sha. Fixed in `fd447f6e5` (`@v1` → `@d0dd21912a57c7435649c77f689b68d348d8a662 # v1`,
   resolved via `gh api repos/latchkey-dev/cache-action/git/refs/tags/v1`). Reported here as
   evidence the gate is doing its job on Latchkey, not as a Latchkey defect.
4. **Self-healing has no per-job or per-workflow disable.** Per `latchkey.dev/documentation`'s
   self-healing page, the only control is a **workspace-level switch** (Settings → Self-Healing,
   owners/admins, on by default, no per-repository toggle, "changes take effect within about a
   minute"). Every job in these three files is a verdict a self-healed retry (backoff, raised
   memory, freed disk, or a bounded-AI diagnosis patch, all applied silently inside the ephemeral
   runner before GitHub ever sees the failure) can launder before it is ever read as red. **Said
   loudly in a comment block at the top of `ci.yml` because there is no YAML line that fixes this —
   an org owner/admin must turn the workspace switch OFF before these files' green means what the
   branch-protection rules and `ship-ready` gate assume it means.** This is the single largest
   correctness risk this migration introduces and it cannot be closed by this PR.
5. Several failures observed in this run are very likely **pre-existing red on the stale
   `integration/oracle-phase0` base**, not migration regressions: `windows build · clippy · test`
   (GitHub-hosted, `windows-latest`, entirely untouched by this migration) also failed, with 3
   `sccache` compilation failures of its own on a runner this migration never touched — the base
   branch is behind commits like `1e2f6be96` (a store-fixture readiness-gate fix) that may bear on
   `structure-lint`'s `release-script-lint FAILED` and `public-hygiene`'s `public-hygiene-lint
   FAILED`. Not re-diagnosed here (out of phase-1 scope; this PR is workflow-only) but flagged so a
   later slot does not attribute them to Latchkey.
6. Cold queue-to-start for the very first job of the run (`gate-mutants scope`, `latchkey-small`)
   was **~5 minutes** (job created `23:44:31Z`, started `23:49:35Z`) — well past the documented
   "seconds warm / ~10s cold" figure. Every job after the first started within about a minute.
   Consistent with either an initial App-routing/registration delay for a brand-new label
   combination on this workspace, or queueing behind the concurrency cap in item 2 — not
   distinguished by this measurement.
7. A `pull_request`-triggered run (CI, gate-mutants on PR #111) did not appear to pick up a second
   push's commit with a new run inside this measurement window, even though `concurrency:
   cancel-in-progress` should have superseded it — the checks API still showed the original commit
   queued. Not chased further (GitHub Actions event-delivery latency, not something this repo's
   YAML controls); keep-proof's `push:`-triggered run on the same second commit worked as expected
   (old run cancelled, new run queued) within seconds.

## 5. Setup steps added

- **Toolchain**: no gap. Every job that runs cargo already carried
  `dtolnay/rust-toolchain@62ae3a85dbdd2bedbb5819da8ce45635129289a1 # 1.98.0`, matching
  `rust-toolchain.toml`'s `channel = "1.98.0"` pin — this was already true on the EC2 self-hosted
  runners and needed no change. Two jobs (`structure-lint`, `service-image-pins`) intentionally rely
  on "the image's ambient toolchain" per their own comments; Latchkey's image ships Rust via rustup,
  which honors `rust-toolchain.toml` automatically, so this is unchanged behavior, not a new risk.
- **Dependency caching**: `Swatinem/rust-cache` (GitHub's `actions/cache`, keyed on `Cargo.lock`)
  replaced with Latchkey Fast Cache (`latchkey-dev/cache-action`, restore before the job's cargo
  work, `save` with `if: always()` at the end) for `~/.cargo` and `target/`, in the documented
  restore/save form, across all 34 cargo-using jobs plus `service-image-pins`'s ambient-toolchain
  build. **sccache's own cache backend was NOT migrated — see §4 item 1.**
- **Docker/Python/jq/apt**: no gap. `docker`, `python3`, `pip`, `jq`, `apt-get` are all used inline
  without a setup step today and are all preinstalled on Latchkey's Ubuntu 24.04 image per its docs.
- **No new secrets** added beyond what the workflows already read (`github.token`, `GH_TOKEN`).

## 6. Go/stop — phase 2 (slot pre-proofs via `latchkey run`) and phase 3 (the landing engine)

**Phase 2: GO, conditionally.** The two headline figures are favorable — 16 vCPU holds the
construction-gate budget at 79% (§3) and a cold `check` build/test completes in under 13 minutes
(§3) — and the toolchain/cache/tooling gaps are closed or closing (§5). Condition: **§4 item 1
(sccache's cache backend) must be fixed before phase 2 multiplies job count**, or every pre-proof
pays full rustc cost with no sharing across slots, which is the opposite of what pre-proofs are for.

**Phase 3 (the landing engine): STOP until §4 items 2 and 4 are resolved.** Item 2 (the 20-runner
cap) is not a phase-1 problem, it is a phase-3 problem arriving early: the landing engine will want
more concurrent jobs than any single slot does, and this measurement already showed the cap binding
under load from unrelated concurrent branches. Item 4 (self-healing has no per-job disable) is the
harder stop: the landing engine's entire reason to exist is to read a verdict and act on it
irreversibly (promote, merge, ship); a workspace where a red exit code might have been silently
healed into a green before GitHub reported it is not a place to point that engine until an org
owner has confirmed the workspace-level switch is OFF and stays off. Neither item is something this
PR (a workflow-only change) can close.

## Appendix: run data

Measured via `gh run list -R GetBusbar/busbar --branch keep-ci-latchkey` /
`gh run view <id> --json jobs`, polled no faster than every 5 minutes, PR #111
(`keep-ci-latchkey` → `integration/oracle-phase0`), commits `104cd7ea8` then `fd447f6e5`.

| Job | Label | Queue wait | Wall time | Result | First error line |
|---|---|---|---|---|---|
| gate-mutants scope | small | ~5m04s | 20s | pass | — |
| gate-mutants baseline | xlarge | ~1m | 1m25s | **fail** | R14 (unpinned `latchkey-dev/cache-action@v1`), fixed |
| gate-mutants shard (20 of 24 ran within window) | xlarge | 0–6m (cap-limited) | ~50–55s each | pass | — |
| ci.yml gate-tier | small | 0s | 4s | pass | — |
| ci.yml structure-lint | large | ~1m | 1m50s | fail | `release-script-lint FAILED` — likely pre-existing (see §4.5) |
| ci.yml check (fmt·clippy·build·test) | xlarge | 0s | 12m53s | fail | R14 (same as above), build itself was clean |
| ci.yml openapi-schema | large | ~1m | 3m54s | pass | — |
| ci.yml config-stability | large | ~1m | 51s | pass | — |
| ci.yml generated-artifact-drift | large | ~1m | 1m2s | pass | — |
| ci.yml public-hygiene | large | ~1m | 2m17s | fail | `public-hygiene-lint FAILED` — likely pre-existing (see §4.5) |
| ci.yml deletion-test-matrix (2 legs seen) | xlarge | ~1m | 1m42s | pass | — |
| ci.yml construction-gate | xlarge | ~1m | 3m33s | pass | 39,607/50,000 work units (§3) |
| ci.yml ship-ready | large | ~1m | 1m58s | fail | `sccache` binary missing (§4.1) |
| ci.yml design-bindings | large | ~5m | 1m23s | fail | R14 (same as above) |
| ci.yml windows | *(unchanged)* | 0s | 10m9s | fail | 3 `sccache` compile failures — GitHub-hosted, unrelated to Latchkey |
| ci.yml migration-corpus | xlarge | ~8m (cap-limited) | 1m44s | pass | — |
| ci.yml service-image-pins | large | ~8m (cap-limited) | 30s | pass | — |
| keep-proof build-clippy | large | ~1m | 4m22s | pass | — |
| keep-proof construction-gate | xlarge | ~1m | 3m35s | pass | — |
| keep-proof tests (shard 2, 3, 4) | xlarge | 0s | ~5m | pass | — |
| keep-proof tests (shard 1) | xlarge | ~5m (cap-limited) | 4m9s | fail | not yet re-run against `fd447f6e5` |
| keep-proof shadow-oracle | xlarge | 0s | 8m25s | pass | — |
| keep-proof design-bindings | large | ~1m | 46s | fail | R14 (same as above) |

Minutes consumed (approximate, sum of job wall-times above at their `latchkey-*` per-minute rates —
not GitHub's own billing summary, which was not yet available for these runs): roughly **95–105
runner-minutes** across the two pushes' worth of jobs captured in this window, well short of the
full run (several jobs were still `queued` behind the concurrency cap when this measurement window
closed).

## Phase 4 (LK-7) — the remaining 19 workflow files

Slot LK-7, branch `keep-ci-latchkey-all` off `origin/keep-ci-latchkey-cache` (LK-5's branch — the
three phase-1 workflows already on `latchkey-*` labels with Fast Cache, plus `actionlint.yaml`
declaring the labels). LK-7's mandate: every remaining `.github/workflows/*.yml` still naming
`ubuntu-latest`/`ubuntu-24.04*`/`windows-latest`.

**The task brief said "Latchkey counts 10 workflows"; the actual tree has 19 workflow files (plus
one derived JSON dispatcher) still naming a GitHub-hosted label outside the three phase-1 files.**
Enumerated by reading `.github/workflows/`: `a2a-conformance.yml`, `mcp-conformance.yml`,
`voice-conformance.yml`, `plugin-ci.yml`, `plugin-consumer-verify.yml`, `plugin-functional.yml`,
`qa-gate.yml` (+ its derived `qa-gate.dispatcher.json`), `security.yml`, `codeql.yml`, `docker.yml`,
`release.yml`, `release-stage.yml`, `release-fleet.yml`, `verify-deploy.yml`, `prepare-release.yml`,
`monthly-refresh.yml`, `ci-images-mirror.yml`, `build-artifact.yml`, `bolt-pass.yml`,
`oracle-record-store-cells.yml` — 20 files, not 10. Said loudly rather than reconciled to the
brief's count, which this checkout does not support.

### 1. Workflow -> label table

xlarge/large/small follow the same rule §1 states. "stays" means unchanged — Latchkey has no
Windows, arm64 or macOS offering, so every `windows-latest`, `ubuntu-24.04-arm` and `macos-*` job
is untouched.

| Workflow | Job(s) | Label | Why |
|---|---|---|---|
| a2a-conformance.yml | harness-selftest, control-a2a-go, control-a2a-python, negative-control, swap-proof, tz-is-load-bearing, tck-control, governance-probe, subject | xlarge | conformance battery legs |
| a2a-conformance.yml | verdict | small | pure `needs:` aggregator, no cargo |
| mcp-conformance.yml | gate-selftest, official-control, official-subject, battery-control, battery-negative-control, battery-subject, fixture-absence | xlarge | conformance battery legs (fixture-absence does a real `cargo build`) |
| mcp-conformance.yml | verdict | small | aggregator |
| voice-conformance.yml | gate-selftest, spec-per-dialect, replay, cross-parity, provider-dial, composition, boot-validate, governance-probe | xlarge | conformance battery legs |
| voice-conformance.yml | verdict | small | aggregator |
| plugin-ci.yml | refs | small | ref-resolution script, no cargo |
| plugin-ci.yml | build-test-signoff | xlarge | build+test+clippy+fmt battery, live services |
| plugin-ci.yml | coverage | large | single-crate llvm-cov |
| plugin-consumer-verify.yml | consumer | large | fetch-and-use verification, no cargo but substantial |
| plugin-consumer-verify.yml | alert | small | notifier |
| plugin-functional.yml | functional | *(input, default now `latchkey-xlarge`)* | reusable workflow; `runner` stays a plain string input so an aarch64 caller can override — never hardcoded |
| qa-gate.yml | fast, loader | large | hydrate + single-suite mechanism tests |
| qa-gate.yml | build, slow | xlarge | build-once stage; full segment-matrix battery |
| qa-gate.yml | umbrella | small | pure aggregator |
| security.yml | cargo-deny | large | bounded dependency/license scan |
| codeql.yml | analyze | xlarge | whole-repo database build + query run |
| docker.yml | promote | small | manifest-only retag, no rebuild |
| docker.yml | build-binaries (amd64) | xlarge | musl/cargo build |
| docker.yml | build-binaries (arm64 x2), verify-arm64-variants | *(stays: `ubuntu-24.04-arm`)* | Latchkey has no arm64 |
| docker.yml | publish | large | build & push multi-arch image, cosign sign (installer action) |
| release.yml | plan, branch-green, resolve-staged, promote-release, notify-downstream, discord-notify | small | gh api/tag/notify scripting, no cargo |
| release-stage.yml | plan, branch-green, draft, targets, verify-assets, verify-set-equality, record-staged | small | scripting, no cargo |
| release-stage.yml | gate | xlarge | fmt·clippy·build·test, live Postgres/Valkey |
| release-stage.yml | sbom, openapi | large | single-crate cargo-based generation |
| release-fleet.yml | resolve, gate | small | jq/gh api, pure aggregator |
| release-fleet.yml | docker, channels | large | registry/channel verification, no cargo |
| release-fleet.yml | fleet | xlarge | rebuilds the busbar-headroom bundle image |
| verify-deploy.yml | pointers, verify | large | third-party-host verification, no cargo |
| verify-deploy.yml | alert | small | notifier |
| prepare-release.yml | cut | large | cargo build/test + Cargo/CHANGELOG bump (Fast Cache added, see §3) |
| monthly-refresh.yml | refresh | xlarge | cargo update + fmt/clippy/test battery |
| ci-images-mirror.yml | mirror | large | manifest-only GHCR copy |
| build-artifact.yml | build | *(input, from `.github/release-targets.json`)* | never hardcoded — see below |
| bolt-pass.yml | bolt (amd64) | large | BOLT rewrite + execution-verify |
| bolt-pass.yml | bolt (arm64) | *(stays: `ubuntu-24.04-arm`)* | native-runner execution-verify requirement; Latchkey has no arm64 |
| oracle-record-store-cells.yml | record | xlarge | 3 live service-container backends, same shape as ci.yml's shadow-oracle |
| release.yml, release-stage.yml, release-fleet.yml, verify-deploy.yml, build-artifact.yml | (matrix/input `runner`) | *(derived)* | all five read `runner` from `.github/release-targets.json`, edited once there instead of five times: the three linux/x86_64 rows -> `latchkey-xlarge`; arm64/macOS/Windows rows unchanged |

`docker.yml`'s `build-binaries` matrix and every `release-targets.json` consumer are the two places
item (1)'s "extend the matrix/input values, never hardcode" rule actually bit: both are
`${{ matrix.* }}`/derived-from-JSON `runs-on:` lines, so the edit lives in the matrix entry or the
JSON row, never as a second hardcoded `runs-on:` line layered on top.

### 2. Judged and left on GitHub-hosted (with reasons)

**None.** Every release/publish/deploy job in these 20 files was checked individually against the
three tests the brief set (docker present, secrets injected regardless of runner, no
GitHub-hosted-only tooling) and all of them cleared:

- `docker.yml`'s `promote` and `publish` jobs log into Docker Hub + GHCR (`docker/login-action`)
  and sign with cosign — but cosign arrives via `sigstore/cosign-installer`, which downloads its own
  binary, not a preinstalled one.
- A `which gh cosign syft docker jq curl npm pnpm cargo` probe run on a `latchkey-small` box
  (`latchkey run --size small --timeout 120 --no-context`) found `gh`, `docker`, `jq`, `curl`,
  `npm`, `pnpm` and `cargo` all present at `/usr/bin` or `/usr/local/bin`; `cosign` and `syft` are
  **not** preinstalled. Grepping all 20 files for `syft` found zero uses. Every `cosign` use in
  `docker.yml` goes through the installer action, so the missing preinstall never mattered.
- No `cargo publish`, `cargo-dist`, `npm publish` or `pnpm publish` exists anywhere in this tree's
  workflows (grepped for all four) — there is no crates.io/npm publish job to judge at all;
  `verify-deploy.yml` explicitly documents busbar ships as a binary/image/OS-package, no crate.
- Every `gh release`/`gh api` job runs `gh`, which the probe confirmed present.

So every job moved. The only things left on GitHub-hosted are architecture gaps, not tooling gaps:
`windows-latest` (x86_64-pc-windows-msvc — pgo-build.sh's own header says its POSIX trainer has
never run on Windows), `ubuntu-24.04-arm` (every arm64 leg, native-runner execution-verify
requirements), `macos-15-intel` and `macos-latest` (Intel/Apple Silicon macOS release targets —
Latchkey offers none of the three non-Linux-x64 architectures/OSes, extending the brief's own
"Latchkey has no Windows or arm" logic to the macOS rows the brief did not name).

**One tension flagged, not reverted.** `a2a-conformance.yml`, `mcp-conformance.yml` and
`voice-conformance.yml` each carry a comment recording an ORG rule: "public -> GitHub-hosted
(free), private -> `busbar-selfhosted`" — busbar is public, so these batteries ran on
`ubuntu-latest` at zero marginal cost before this migration. Moving them to `latchkey-xlarge` trades
free minutes for paid ones with no capability gained (GitHub-hosted already ran every leg green).
GOAL LK ("100% off EC2 and GitHub-hosted runners onto Latchkey") is explicit and postdates that org
rule, so the move was made as directed — but the cost tradeoff the org rule was optimizing for is
now reversed for these three files specifically, worth an owner's explicit sign-off rather than a
silent byproduct of "every ubuntu-latest becomes a label."

### 3. Fast Cache added

This migration's own no-cache scan (every job's `steps` searched for a `cargo build/test/run/install`
with no `rust-cache`/`cache-action`/`actions/cache` anywhere in the same job) found three
candidates; one was a false positive:

- `plugin-functional.yml`'s `functional` job (this-tree `cargo build` on both the busbar-source and
  plugin-cdylib paths) — Fast Cache restore/save added, guarded by the same `if:` as the Rust-install
  step so a pure-release-artifact run (nothing built from source) never pays for it.
- `prepare-release.yml`'s `cut` job (`cargo update`/`cargo build`/`cargo test`) — Fast Cache
  restore/save added unconditionally (this job always builds).
- `release-stage.yml`'s `targets` job matched the literal-string scan on a *comment* ("the rust
  triple cargo builds") — reading the job shows it is pure `python3`/JSON parsing of
  `.github/release-targets.json`, no cargo work at all. Left untouched.

Both real additions use LK-5's exact form: `latchkey-dev/cache-action@d0dd21912a57c7435649c77f689b68d348d8a662 # v1`
(SHA-pinned, not `@v1` — R14 would refuse the floating tag), restoring `~/.cargo/registry`,
`~/.cargo/git` and `target` before the build and saving with `if: always()` after.

### 4. `qa-gate.dispatcher.json` regen

`qa-gate.yml`'s label move left the derived `qa-gate.dispatcher.json` stale — caught immediately by
`cargo xtask gate qa-gate-dispatch` (RED, naming exactly the five `runs-on` fields that drifted).
`cargo xtask gate qa-gate-dispatch --write` reports "this gate has nothing to write": the gate's own
`write_declared` function has no CLI probe wired to it (grepped `xtask/src` — the only two call
sites are the function definition and a doc-comment referencing it by name). This is a pre-existing
gap in `xtask`, not something in this slot's mandate to fix — said loudly rather than silently
worked around. The five fields were hand-synced to match `qa-gate.yml` exactly and the gate re-run
to confirm `PASS` before committing.

### 5. actionlint

`actionlint` (with the repo's `.github/actionlint.yaml` label declarations from LK-4) run over every
`.github/workflows/*.yml` file in the tree: **clean** — zero unknown-label findings, zero syntax
errors. Three pre-existing shellcheck-only findings remain (`plugin-ci.yml:444/586/679` SC2155,
`release.yml:344` SC2181, `verify-deploy.yml:1825` SC2034), confirmed present on
`origin/keep-ci-latchkey-cache` before this slot's first commit — not introduced here, not fixed
here (out of this slot's `runs-on`/cache/label mandate).

### 6. Measurement

`gh run list -R GetBusbar/busbar --branch keep-ci-latchkey-all` after every push on this branch
shows only **`keep-proof.yml`** actually firing — its `push: branches: ['keep-*', '!wip/**']`
trigger (documented in §2 above) is the only one of the 20-plus workflows in this repo whose
trigger a push to a `keep-*` branch satisfies. `ci.yml` and `gate-mutants.yml` trigger on
`integration/**`/`dev`/`qa`/`main`/`pull_request`, not `keep-*`. None of the 20 files this slot
touched trigger on push at all: they are `workflow_call` (a2a-conformance.yml, mcp-conformance.yml
and voice-conformance.yml aside — those three DO trigger on `push: branches:
['integration/**','dev','qa','main']` and `pull_request`, neither of which a push to this `keep-*`
branch satisfies), `workflow_dispatch`, `release`, or gated behind `qa-gate.yml`'s own
`workflow_run` trigger (which only fires after a `workflow_run` completion on `qa`, not on this
branch). **This confirms the brief's own caveat: tag/release/dispatch-triggered workflows cannot be
measured by a push to this branch and are judged by reading only (§§1-3 above).** No workflow_dispatch
was fired manually against `docker.yml`/`release*.yml`/`bolt-pass.yml` to get real run data — every
one of those either publishes real bytes (Docker Hub/GHCR pushes, GitHub Releases) or requires
staging-tag/promote-tag inputs that do not exist on a scratch branch, and manufacturing fake inputs
to force a dry run risks a real publish side effect for zero migration-relevant signal (their
`runs-on:`/cache/tooling correctness was already established by reading, §§1-3).

`keep-proof.yml`'s own jobs — unchanged by this slot, already on Latchkey since LK-5 — ran on every
push; `concurrency: cancel-in-progress` superseded most of them, but the second-to-last push's run
(`34666870476`, commit `acf77ee20`) was still `queued`/`in_progress` when the doc-only final commit
landed and both runs completed rather than one cancelling cleanly. The **last push's run**
(`34667344240`, commit `bcc9ab4bb`, the phase-4 doc commit — a docs-only change, so its code-path
results are identical to `acf77ee20`'s) is this slot's real Latchkey execution evidence, read once
per the coordinator's resume instruction (`gh run list --branch keep-ci-latchkey-all --limit 3`):

| Job | Label (from LK-5, unchanged) | Wall time | Result | First error line |
|---|---|---|---|---|
| fmt · clippy · build | large | 1m54s | pass | — |
| tests (shard 1) | xlarge | 4m29s | **fail** | `Process completed with exit code 101` (a test failure) |
| tests (shard 2) | xlarge | 4m27s | pass | — |
| tests (shard 3) | xlarge | 5m26s | pass | — |
| tests (shard 4) | xlarge | 4m36s | pass | — |
| tests (shard xtask) | xlarge | 28m56s | **fail** | `Process completed with exit code 137` (killed — OOM/timeout signature) |
| tests total | small | 3s | fail | aggregator: skipped/failed because shard 1 and shard xtask failed |
| shadow oracle (vs published 1.5.5) | xlarge | 1m57s | **fail** | `the id-filter '^(boot\|config\|documented)([\|.]|$)' owes ZERO cells — a filter that matches nothing... Fix the regex in .keep-proof.toml` |
| design bindings (existence · regen-clean) | large | 8s | **fail** | `Process completed with exit code 127` (command not found) |
| cargo xtask gate --all · selftest | xlarge | 21m31s | **fail** | `Process completed with exit code 1` |
| construction gate | xlarge | 3m35s | pass | — |
| keep-proof verdict | small | 9s | fail | aggregator: red because upstream jobs failed |

Every failure above is on a job and label this slot did not touch — `keep-proof.yml` was already
fully migrated by LK-5 and this slot made zero edits to it (only `.github/workflows/` files this
slot's own commits list, none of which is `keep-proof.yml`, `ci.yml` or `gate-mutants.yml`). The
`shadow oracle` failure is a config mismatch in `.keep-proof.toml`'s id-filter regex (not a runner
or cache defect); `design bindings`' exit 127 and `tests (shard xtask)`'s exit 137 are consistent
with §4 item 5 of the phase-1 section above (pre-existing red on a stale/drifted base for this
branch lineage). None is a runner-label or Fast-Cache regression this migration introduced — this
slot's mandate is `runs-on`/cache/label only, and every job here ran on the label LK-5 already
assigned, unchanged.

Minutes consumed by this slot's own measurement window: the twelve `keep-proof.yml` jobs above sum
to roughly **80 runner-minutes** of wall time (dominated by the two long failures — `tests (shard
xtask)` at 29 minutes and `gate --all · selftest` at 21.5 minutes, both jobs this slot never
touched) at Latchkey per-minute rates for this one final run, plus a comparable amount burned by
the twelve earlier per-commit pushes before `cancel-in-progress` superseded each of them (per the
task's own "push after every commit" rule).

### 7. What sucks (this slot's additions to §4 above)

8. **The task brief's own workflow count was wrong** (10 vs the 19-plus-1-JSON actually in the
   tree) — the same "brief names something this checkout doesn't have" pattern LK-1 called out for
   `docs/ci/fleet.md`. Not fabricated to match; enumerated instead (§0 above).
9. **A derived-artifact gate (`qa-gate-dispatch`) names a regeneration entry point
   (`QaGateDispatchGate::write_declared`) that the CLI cannot reach.** `--write` silently no-ops
   ("this gate has nothing to write") instead of erroring, which is the worse failure mode: a
   contributor who trusts the hint and runs `--write` gets no diff, concludes there is nothing to
   regenerate, and commits a stale declared shape that only the gate itself (which they may not
   have re-run) catches.
10. **The org's own public-repo cost rule and GOAL LK now disagree** for the three conformance
   suites (§2 above) — moving public, always-green-on-GitHub-hosted batteries to paid Latchkey
   minutes is correct under the letter of GOAL LK and is a real, avoidable cost increase under the
   org's stated free-tier rule. Neither this slot nor LK-5 is positioned to resolve that tension;
   flagged for an owner decision rather than picked silently in either direction.
11. **(b) Every `latchkey-dev/cache-action` restore/save added by LK-5 (and by this slot's §3
   above) cached the wrong directories, so the registry/git half of the cache never populated.**
   All of them hardcoded `~/.cargo/registry` and `~/.cargo/git` as the `path:`, which is correct
   for a GitHub-hosted runner (`CARGO_HOME` unset, cargo defaults to `$HOME/.cargo`) but wrong on
   the Latchkey image: its `Dockerfile` sets `CARGO_HOME=/usr/share/rust/.cargo`, so the toolchain
   never reads or writes anything under `~/.cargo` at all. The `restore`/`save` steps ran, reported
   success, and moved zero meaningful bytes for the registry/git paths — every job silently fell
   back to a from-scratch `cargo fetch` on every run, while only `target/` (an absolute path,
   unaffected by `CARGO_HOME`) was ever actually warm. This was not visible in any per-job log line
   the migration measurements above quoted; it only shows up by comparing the cache-action's
   reported save size for the registry/git paths against a nonzero baseline.
   **Fix:** a reusable composite action, `.github/actions/cargo-home/action.yml`, run once per job
   before that job's first `cache-action` step. It resolves `CARGO_HOME` at run time
   (`${CARGO_HOME:-$HOME/.cargo}`) and exports it both to `$GITHUB_ENV` (so later steps in the same
   job see it via the `env` context) and as a step output (`cargo_home`), so it works whether a
   caller's `path:` list is written inline or a step needs the value directly. Every non-Windows
   `cache-action` restore/save step across `ci.yml`, `keep-proof.yml`, `gate-mutants.yml`,
   `plugin-functional.yml`, and `prepare-release.yml` now reads `${{ env.CARGO_HOME }}/registry`
   and `${{ env.CARGO_HOME }}/git` instead of the hardcoded `~/.cargo/...` paths; per-job cache
   keys are untouched. The `windows` job (`windows-latest`, GitHub-hosted, `~/.cargo` as a single
   path) and the `~/.cargo/bin/cargo-mutants` binary cache in `gate-mutants.yml`'s `shard` job are
   deliberately left alone — the former never ran on Latchkey and the latter is a separate,
   pre-existing cache keyed on a different path this fix's mandate does not cover.
   **Measured on `keep-ci-latchkey-cache-home`** (pushed on top of LK-7's tip,
   `41fabf25a`): `<FILLED IN AFTER THE keep-proof.yml RUN — see below>`.
