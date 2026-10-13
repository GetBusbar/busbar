# Required status checks

Branch protection lives in repository rulesets. No script writes it.

| Branch | Ruleset | Required |
| --- | --- | --- |
| `predev` | 24945926 | ModernCI's `ci` check. ModernCI judges the PR (`.ci/default.yaml`) and lands it. |
| `dev` | 24340358 | `preflight` and `hop`, both from `.github/workflows/promote.yml` (the predev to dev promotion). |
| `qa`, `main` | 24334334 | Owner-only; no status check stands in for the owner. |

Use the exact **check-run name** (the job's `name:`), not the workflow name. In `promote.yml`, `hop`
is the job id with no `name:`, so its context reads `hop`.

* `preflight`: formatting, `Cargo.lock` current, the generated C header current, on a free runner.
* `hop`: the pinned busbar-release engine plans the hop and admits the candidate (every registered
  `cargo xtask gate`, plus the oracle and conformance where the rung asks for them).

## Reusable workflows (plugin repos call these)

`plugin-ci.yml`, `plugin-consumer-verify.yml`, `plugin-repin.yml` and `plugin-release.yml` are
`workflow_call` only, called by the plugin repos' rendered callers (busbar-release `template/`,
`busbar-release plugin sync`). Their status bubbles up into the **caller's** job, so require the
caller's job in the plugin repo, never these directly.

## Branch hygiene

No workflow may push a commit to `qa` or `main` (`workflow-rules` R11). Keep linear history and
disallow force-pushes and deletions on the protected branches.
