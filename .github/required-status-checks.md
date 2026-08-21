# Required status checks — the cross-workflow "nothing red goes unnoticed" gate

GitHub Actions has **no cross-workflow `needs:`**. A job in `ci.yml` cannot depend on a job in
`security.yml`, so no single workflow-level job can aggregate every workflow. The umbrella pattern
(`if: always()` + a `needs:`-fan that asserts each need's `result`) therefore closes the gap only
**inside one workflow**. Across workflows, the aggregator is **branch protection**: each blocking
workflow exposes ONE terminal aggregator status, and branch protection marks that status **required**.

If a required status is not listed here and wired in branch protection, a workflow can go red and the
PR/promotion still merges — which is exactly the "1 going red shouldn't have gone unnoticed" failure
this file exists to prevent. **Adding a new blocking workflow means adding its terminal status here
AND to branch protection.**

## Mark these REQUIRED on `main` and `qa` (both are FULL_TIER refs)

Use the exact **check-run name** (the job's `name:`), not the workflow name:

| Required status (context name) | Workflow | What it aggregates |
| --- | --- | --- |
| `ci umbrella` | `ci.yml` | Every CI code gate via `needs`: structure-lint, fmt/clippy/build/test, openapi-schema drift, migration-corpus, config-stability, **generated-artifact-drift**, public-hygiene, executable-config, no-default-features, no-plugins, txn-guards, timing, windows. One required context that never has to change as jobs are renamed/added — a renamed or dropped job turns the umbrella red instead of silently leaving the gate. |
| `cargo-deny (advisories · licenses · sources · bans)` | `security.yml` | Single-job workflow; its own status is the aggregator. |
| `MCP conformance verdict` | `mcp-conformance.yml` | `verdict` job fans in over every MCP conformance leg (control/subject/battery/fixture-absence). |
| `A2A conformance verdict` | `a2a-conformance.yml` | `verdict` job fans in over every A2A conformance leg. |

These four are the complete set of **push/pull_request** workflows that gate code correctness. Each
already terminates in a single aggregator job — nothing further is needed inside the workflows; the
only manual step is ticking these four in **Settings → Branches → branch protection → Require status
checks to pass** for `main` and `qa`.

## Intentionally NOT branch-protection-required (and why)

- **`release gate` (`release-fleet.yml`)** — verifies the bytes of the **latest published release**
  across platforms/channels. On a PR it asserts the *published* release, not the PR's code, so it is a
  release-integrity **monitor**, not a code merge gate. It must still be watched (its red = a shipped
  release regressed); keep its alert path, don't make it a PR merge blocker.
- **`qa-gate` `umbrella`** — the ~2h full promotion gate; runs via `workflow_run` after CI on the
  promotion branches, so it gates **promotion**, not each PR. Watch it on `dev→qa→main` promotions.
- **`mirror` (`ci-images-mirror.yml`)** — infra image mirror on push/schedule; advisory.
- **`release.yml`, `prepare-release.yml`, `verify-deploy.yml`, `monthly-refresh.yml`** — release-time,
  dispatch, or scheduled; not PR code gates. Each still aggregates within its own run.
- **Reusable workflows** (`plugin-ci.yml`, `plugin-functional.yml`, `plugin-consumer-verify.yml`,
  `build-artifact.yml`, `docker.yml`) — `workflow_call` only. Their status bubbles up into the
  **caller's** job, so require the caller's job, never these directly.
