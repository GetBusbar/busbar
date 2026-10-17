# Required status checks

Branch protection lives in repository rulesets. No script writes it.

| Branch | Ruleset | Required |
| --- | --- | --- |
| `dev` | 24340358 | ModernCI's `ci` check on lanes (`.ci/default.yaml`). ModernCI judges the PR and lands it. The `dev` → `qa` move is `.ci/dev.yaml`. |
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
