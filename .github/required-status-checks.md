# Required status checks

busbar has ONE pipeline workflow, `.github/workflows/promote.yml`. Every same-repo pull request is one
hop up the branch ladder (predev, dev, qa, main): busbar-release's engine plans the hop from the PR's
base branch and runs exactly what entering it needs. Nothing else in this repository reports a status
on a pull request.

## Mark these REQUIRED on `qa` and `main`

Use the exact **check-run name** (the job's `name:`), not the workflow name:

| Required status (context name) | Workflow | What it covers |
| --- | --- | --- |
| `preflight` | `promote.yml` | The checks that need no build of the product, on a free runner: formatting, `Cargo.lock` current, the generated C header current. A red here costs a minute, not a gate battery. |
| `hop` | `promote.yml` | The hop itself (job id `hop`, no `name:`, so the context reads `hop`): the turnstile admits the candidate (every registered `cargo xtask gate`, plus the oracle and conformance where the rung's ladder entry asks for them) and, on a green rung, the base branch is fast-forwarded to the tested SHA. |

`scripts/ci-branch-protection.sh` is the enforcement point: it unions these two contexts into whatever
branch protection already has, strips the contexts of the deleted workflows (`ci umbrella`,
`structure lint`, the construction gate job, `ship-ready`, `qa-gate umbrella`, `gate-mutants`) because
none can report any more and a required context that never reports holds the branch unmergeable
forever, and refuses to write a context that no job at the feeder branch can report.

## Reusable workflows (plugin repos call these)

`plugin-ci.yml`, `plugin-consumer-verify.yml`, `plugin-repin.yml` and `plugin-release.yml` are
`workflow_call` only, called by the plugin repos' rendered callers (busbar-release `template/`, `busbar-release plugin sync`). Their status bubbles up
into the **caller's** job, so require the caller's job in the plugin repo, never these directly.
