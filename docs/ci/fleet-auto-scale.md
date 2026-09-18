# Fleet auto-scale: "running or DOWN, never idle"

The self-hosted EC2 runner floor (see [self-hosted-runners.md](./self-hosted-runners.md)) should exist
only while there is CI work for it. `fleet-control` is a GitHub-hosted control workflow that keeps the
floor in one of two states — **UP** while self-hosted jobs are queued/running, **DOWN** (fully torn
down, on-demand floor included) once the queue drains — and never leaves boxes idling on the clock.

It **ships inert**: `FLEET_CONTROL_ENFORCE` defaults to `report-only`, so merging it changes nothing.
It logs the decision and what it *would* do, and makes zero AWS calls, until you flip the flag.

## Moving parts

| Piece | Where | Role |
| --- | --- | --- |
| `fleet-control.yml` | `.github/workflows/` | The controller. Runs on `ubuntu-latest` (GitHub-hosted) so it works even when the self-hosted floor is at zero. |
| `ci-fleet-decision.sh` | `scripts/` | Read-only. Answers `up`/`down` for a single instant. Only `gh api` GETs — never mutates, safe to run anytime. |
| `ci-runners-up.sh` | `scripts/` | Idempotent bring-up (on-demand floor + `CI_RUNNER_COUNT` spot). Already existed. |
| `ci-runners-down.sh --all` | `scripts/` | Full teardown, floor included. Already existed. |
| `busbar-ci-fleet-controller` | IAM role | The OIDC role the workflow assumes. No long-lived secrets. |

## The decision (and why it is safe)

`ci-fleet-decision.sh` returns `up` if **either**

- **Signal A** — any org self-hosted runner is currently `busy` (a job is executing), or
- **Signal B** — any active (`queued`/`in_progress`/`waiting`/`requested`/`pending`) workflow run has
  a job whose runner labels target our fleet: `busbar-xl`, `self-hosted`, or `latchkey-*`.

It returns `down` only when **both** are empty. Every ambiguous case errs toward `up`.

**Never tear down live work.** The teardown path in the workflow requires **two consecutive empty
reads**, `FLEET_DEBOUNCE_SECONDS` apart (default 180s). A single empty read only arms a re-check; the
gap between two jobs in one run — or a runner picking up its next job — cannot be mistaken for a
drained queue. A bring-up, by contrast, is idempotent and fires on the first `up` read with no debounce.

**Token scope.** In Actions, the default `github.token` can read *this repo's* runs and jobs
(`actions: read`), which is enough for Signal B and therefore for correctness on `GetBusbar/busbar`.
Signal A (org-wide busy runners) needs `admin:org` read; supply a PAT as the optional
`FLEET_CONTROL_GH_TOKEN` secret to enable it. Without it the script degrades gracefully to the repo view.

## Triggers

- `pull_request`, `push` — pre-warm: ensure the floor is UP as work arrives.
- `workflow_run` on `CI` / `gate-mutants` / `keep-proof` `completed` — re-evaluate as the queue drains.
- `schedule` every 15 min — safety reaper that catches anything the event-driven passes missed.
- `workflow_dispatch` — manual, with an `enforce` input to override the flag for one run.

## Cold-start tradeoff

DOWN means **zero** boxes: the next self-hosted job after an idle period pays the full bootstrap —
apt, rustup, the runner agent, and a pre-warm build — which is **~8–12 minutes** before the first job
starts (see `ci-runners-up.sh`). That is the deliberate price of "never idle": you trade a first-job
latency spike after quiet periods for not paying for idle 32-vCPU boxes. If a workload can't tolerate
the cold start (e.g. a release window), either keep enforcement off during it or set the on-demand
floor via `CI_RUNNER_ONDEMAND_FLOOR` so a warm floor always survives. Because `push`/`pull_request`
pre-warm on the way in, most human-driven work triggers the bring-up before its CI even queues.

## Turning it on

1. **Dry-run it first.** Run `bash scripts/ci-fleet-decision.sh` locally (needs `gh` auth) any time to
   see the live verdict, or trigger the workflow via *Actions → fleet-control → Run workflow* with
   `enforce = report-only`. It prints the decision and the exact command it *would* run.
2. **Flip the flag.** Set a repository **variable** (not secret) `FLEET_CONTROL_ENFORCE=enforce`
   (*Settings → Secrets and variables → Actions → Variables*), or run a one-off dispatch with the
   `enforce` input set to `enforce`. Anything other than exactly `enforce` stays report-only.
3. **Optional** — add the `FLEET_CONTROL_GH_TOKEN` secret (PAT, `admin:org` read) for org-wide busy
   detection.

To pause it again, set the variable back to `report-only` (or delete it). The IAM role can stay; it is
harmless while nothing assumes it.

## The IAM role and policy

The workflow assumes `arn:aws:iam::457667483187:role/busbar-ci-fleet-controller` via GitHub's OIDC
provider (`token.actions.githubusercontent.com`) — no stored AWS keys. The trust policy allows
**only** `repo:GetBusbar/busbar:*` with audience `sts.amazonaws.com`.

Its inline policy (`fleet-control-least-privilege`) grants exactly the actions
`ci-runners-up.sh` / `ci-runners-down.sh` call — EC2 describe/run/create-fleet/terminate/launch-template,
the egress-only security-group create/revoke, SSM `SendCommand`/`DescribeInstanceInformation`/
`ListCommandInvocations` and the Canonical Ubuntu AMI `GetParameter`, the sccache S3 bucket lifecycle,
and the runner IAM role/instance-profile provisioning. `iam:PassRole` is scoped to the runner role
(`busbar-ci-runner-role`) only, and only when passed to `ec2.amazonaws.com`. No `*:*`. To review or
update it: `aws iam get-role-policy --role-name busbar-ci-fleet-controller --policy-name fleet-control-least-privilege`.
