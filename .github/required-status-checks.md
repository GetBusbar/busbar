# Required status checks

Branch protection lives in repository rulesets. No script writes it.

| Branch | Ruleset | Required |
| --- | --- | --- |
| `predev` | 24945926 | ModernCI's `ci` check. ModernCI judges the PR (`.ci/default.yaml`) and lands it. |
| `dev` | 24340358 | ModernCI's `ci` check on the predev to dev move (`.ci/predev.yaml`). The ruleset still names `preflight` and `hop`, the jobs of the deleted `promote.yml`: the owner replaces them with `ci`. |
| `qa`, `main` | 24334334 | Owner-only; no status check stands in for the owner. |

Use the exact **check name** the judge posts. ModernCI posts one check, `ci`, per pull request head.

## Reusable workflows (plugin repos call these)

`plugin-ci.yml`, `plugin-consumer-verify.yml`, `plugin-repin.yml` and `plugin-release.yml` are
`workflow_call` only, called by the plugin repos' rendered callers (busbar-release `template/`,
`busbar-release plugin sync`). Their status bubbles up into the **caller's** job, so require the
caller's job in the plugin repo, never these directly. They stay until each plugin repo is
registered with ModernCI and judged by its own branch files.

## Branch hygiene

No workflow may push a commit to `qa` or `main` (`workflow-rules` R11). Keep linear history and
disallow force-pushes and deletions on the protected branches.
