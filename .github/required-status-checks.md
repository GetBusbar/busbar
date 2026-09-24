# Required status checks — the cross-workflow "nothing red goes unnoticed" gate

GitHub Actions has **no cross-workflow `needs:`**. A job in `ci.yml` cannot depend on a job in
`qa-security.yml`, so no single workflow-level job can aggregate every workflow. The umbrella pattern
(`if: always()` + a `needs:`-fan that asserts each need's `result`) therefore closes the gap only
**inside one workflow**. Across workflows, the aggregator is **branch protection**: each blocking
workflow exposes ONE terminal aggregator status, and branch protection marks that status **required**.

If a required status is not listed here and wired in branch protection, a workflow can go red and the
PR/promotion still merges — which is exactly the "1 going red shouldn't have gone unnoticed" failure
this file exists to prevent. **Adding a new blocking workflow means adding its terminal status here
AND to branch protection.**

## Mark this REQUIRED on `main` and `qa` (both are FULL_TIER refs)

Use the exact **check-run name** (the job's `name:`), not the workflow name:

| Required status (context name) | Workflow | What it aggregates |
| --- | --- | --- |
| `ci umbrella` | `ci.yml` | Every CI code gate via `needs`: structure-lint, fmt/clippy/build/test, openapi-schema drift, migration-corpus, config-stability, **generated-artifact-drift**, public-hygiene, executable-config, no-default-features, no-plugins, txn-guards, timing, windows. One required context that never has to change as jobs are renamed/added — a renamed or dropped job turns the umbrella red instead of silently leaving the gate. |

`ci umbrella` is now the ONLY **push/pull_request** workflow-level aggregator that gates code
correctness on every PR. An earlier version of this file also listed `cargo-deny`, the MCP/A2A
conformance verdicts and `CodeQL (rust)` here — that stopped being true when DECISIONS #78 (the CI
cost overhaul) moved all four off `push`/`pull_request` entirely and onto a `workflow_run`-after-`qa`
shape. They are listed in the next section now; requiring any of them here, the way this file used to
say to, leaves every PR to `main`/`qa` pending forever on a context that can never fire for a PR (see
the `cargo-deny` warning below for the mechanism).

`gate-mutants` (`gate-mutants.yml`) is **deliberately not listed here**: it is `workflow_dispatch`-only
and `disabled_manually` on GitHub — it is a test-effectiveness check, not a release-breaking one,
so it is not a release gate. `scripts/ci-branch-protection.sh` is the enforcement
point for that ruling: it explicitly strips `gate-mutants` out of whatever branch protection already
has, rather than merely not adding it, because a plain required-contexts union can never remove a
context that is already required — see that script's header.

`structure lint` and `construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on its
posture)` are also required on `main`/`qa`, per `scripts/ci-branch-protection.sh`'s own floor, but they
are jobs *inside* `ci.yml`, not separate workflows needing their own cross-workflow aggregator entry —
they are outside this file's scope by the same logic the intro paragraph states (`ci.yml`'s own
`needs:` fan already covers same-workflow jobs). `ship-ready` is the same case structurally, with a
live gap worth flagging here: as of this writing it is only PRESENT in `ci.yml` on `predev` and
`integration/1.6.0-dev-green` — `dev`/`qa`/`main` have not been promoted since `ship-ready` and
`construction gate` were added to `ci.yml`, so the context cannot report AT ALL on those branches
today. That is a promotion-freshness problem, not a branch-protection-declaration problem: the context
being ticked in Settings does nothing until a `dev`→`qa`→`main` promotion actually carries the updated
`ci.yml` onto those branches.

## Mark these REQUIRED on `qa` ONLY — and deliberately **not** on `main`

| Required status (context name) | Workflow | What it aggregates |
| --- | --- | --- |
| `cargo-deny (advisories · licenses · sources · bans) + cargo-audit` | `qa-security.yml` | Single-job workflow; its own status is the aggregator. **Promotion-freshness gap, same shape as the `ship-ready`/`construction gate` one above:** this context name is `qa-security.yml`'s job `name:` as of `predev` today (the `+ cargo-audit` suffix and the `security.yml`→`qa-security.yml` rename both landed there). `main`/`dev`/`qa` have not been promoted since; they still run the pre-rename `security.yml`, whose job `name:` is `cargo-deny (advisories · licenses · sources · bans)` with **no** `+ cargo-audit` suffix and no `cargo-audit` step. Until a `dev`→`qa`→`main` promotion carries `qa-security.yml` onto those branches, ticking the `+ cargo-audit` name in Settings never reports there — tick the pre-rename name instead until that promotion lands, then switch. |
| `MCP conformance verdict` | `qa-conformance-mcp.yml` | `verdict` job fans in over every MCP conformance leg (control/subject/battery/fixture-absence). |
| `A2A conformance verdict` | `qa-conformance-a2a.yml` | `verdict` job fans in over every A2A conformance leg. |
| `CodeQL (rust)` | `qa-codeql.yml` | Single-job workflow; its own status is the aggregator. Builds the CodeQL database for the Rust workspace (`build-mode: none`) and uploads the SARIF to code scanning. |
| `Voice conformance verdict` | `qa-conformance-voice.yml` | `verdict` job fans in over every Voice conformance leg named in its own `needs:` list (gate-selftest, spec-per-dialect, replay, cross-parity, provider-dial, tool-reply, composition, boot-validate, governance-probe, as of this writing — read `verdict`'s `needs:` in the workflow for the current, authoritative set rather than trusting a count copied here, since a leg can be added, as `tool-reply` was). Unrequired today, a red Voice battery (the verdict job plus every leg it needs) blocks nothing on promotion. |
| `cargo-fuzz (bounded, qa boundary)` | `qa-fuzz.yml` | Single-job workflow; its own status is the aggregator. Different shape from the four above: triggers directly on `push: [qa]` (plus `workflow_dispatch`), not `workflow_run`-after-CI — still qa-only, never `main`, for the same promotion-is-already-analysed reason. Unrequired today, a red fuzz gate blocks nothing on promotion. |

**Why `qa` and not `main`, and why six checks live here now.** Before DECISIONS #78, `cargo-deny` and
the MCP/A2A conformance verdicts triggered on `push`/`pull_request` like `ci umbrella`, and only
`CodeQL` (`codeql.yml`, since renamed `qa-codeql.yml`) was qa-only, triggering on `push: [qa]` and
`workflow_dispatch`. The #78 CI cost overhaul put those four on the SAME shape `CodeQL` already used:
each now triggers on `workflow_run` (`workflows: ["CI"]`, `types: [completed]`) gated by a job-level
`if:` that only proceeds when that CI run concluded `success` on branch `qa`, plus its own
schedule/dispatch — never on `push` or `pull_request` directly (see each workflow's own `on:` block).
`Voice conformance verdict` uses the identical `workflow_run`-after-`qa`-CI shape. `cargo-fuzz` is the
odd one out — it triggers directly on `push: [qa]`, the same shape `CodeQL` used pre-#78 — but is
qa-only for the same cost-boundary reason as the rest. That is the cost boundary the branch model
draws: `dev` gets the cheap per-push gate (`ci.yml`), and the expensive, exhaustive "may this ship"
battery — conformance, CodeQL, supply-chain, fuzzing — is what a `dev`→`qa` promotion buys, spent ONCE
per promotion instead of on every push.

The consequence for branch protection is the one the `cargo-deny` note below has always warned about,
now true for all six: **a required status check that never reports does not pass — GitHub leaves the
merge pending on it forever.** Ticking any of these six on `main`, or on a `pull_request` context on
either branch, would block every promotion/PR outright, because none of them ever fires off a `push`
or a PR aimed at `main`/PR — only off a `workflow_run` keyed to a CI run that itself ran on `qa`, or
(for `cargo-fuzz`) a `push` to `qa` itself. Tick them on **`qa` only**, as a branch (`push`-shaped)
required check, never as a PR check.

That is not a weaker gate. A push to `main` is a *promotion* of the exact bytes `qa` already analysed,
so the verdict that matters has already been rendered — before the promotion, which is what `qa` is
for. Re-running any of them on `main` would spend the analysis again to learn the same fact, and a red
there would be a red against a commit already being released.

> **`cargo-deny` is NOT path-filtered, and it must stay that way.** `qa-security.yml` (renamed from
> `security.yml`) once triggered only on changes to `Cargo.toml`, `Cargo.lock`, `deny.toml` and its own
> file; that path filter was removed so the job would run on every push/PR. DECISIONS #78 then moved
> it off `push`/`pull_request` entirely onto the `workflow_run`-after-`qa` shape described above — a
> different reporting caveat, not a return of the old one. A required status check that never reports
> does not pass — GitHub leaves the PR pending on it forever — so **do not reintroduce a `paths:`
> filter on `qa-security.yml`, and do not require any of these six checks (including `Voice
> conformance verdict` and `cargo-fuzz (bounded, qa boundary)`) on a `pull_request`
> context**: they are `qa`-promotion checks now, not PR gates, and requiring them as PR gates
> reintroduces the exact "never reports" hazard this note exists to prevent.

## Intentionally NOT branch-protection-required (and why)

- **`gate-mutants`** (`gate-mutants.yml`) — `workflow_dispatch`-only and `disabled_manually` on
  GitHub. It is a test-effectiveness check, not a release-breaking one, so it does not
  gate a release; run it on demand when hardening tests. It must not be a required context on
  `qa`/`main` — see `scripts/ci-branch-protection.sh` for how a stale required context like this one
  is actually removed, not just left unadded.
- **`release gate`** (`fleet-autoscaler.yml`, file renamed from `release-fleet.yml`; the workflow's own
  `name:` is still `release-fleet`, so the check-run context is unchanged) — verifies the bytes of the
  **latest published release** across platforms/channels. On a PR it asserts the *published* release,
  not the PR's code, so it is a release-integrity **monitor**, not a code merge gate. It must still be
  watched (its red = a shipped release regressed); keep its alert path, don't make it a PR merge
  blocker.
- **`qa-gate` `umbrella`** — the ~2h full promotion gate; runs via `workflow_run` after CI on the
  promotion branches, so it gates **promotion**, not each PR. Watch it on `dev→qa→main` promotions.
- **`mirror`** (`sched-ci-images-mirror.yml`, renamed from `ci-images-mirror.yml`) — infra image
  mirror on push/schedule; advisory.
- **`release.yml`, `prepare-release.yml`, `verify-deploy.yml`, `sched-monthly-refresh.yml`** (the last
  renamed from `monthly-refresh.yml`) — release-time, dispatch, or scheduled; not PR code gates. Each
  still aggregates within its own run.
- **Reusable workflows** (`plugin-ci.yml`, `plugin-functional.yml`, `plugin-consumer-verify.yml`,
  `build-artifact.yml`, `docker.yml`) — `workflow_call` only. Their status bubbles up into the
  **caller's** job, so require the caller's job, never these directly.
