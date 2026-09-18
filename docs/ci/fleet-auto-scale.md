# Fleet auto-scale: size to load, never pay for an idle box

The self-hosted EC2 runner fleet (see [self-hosted-runners.md](./self-hosted-runners.md)) should exist
only while there is CI work for it, and it should be **~90%+ utilized** whenever it is up. `fleet-control`
is a GitHub-hosted control workflow that sizes the fleet **to the actual backlog**: one runner slot per
pending self-hosted job, capacity tracking the queue, and **zero boxes** once the queue drains.

> **The owner rule.** "Increase EC2 to whatever number, but it MUST be ~90%+ utilized — never pay for a
> box sitting at 10%." There is no standing floor on a timer. The on-demand floor exists only *while work
> exists* (it is the guaranteed capacity underneath a burst); an empty queue tears everything down.

It **enforces by default**: `FLEET_CONTROL_ENFORCE` defaults to `enforce`, and with the repo variable
unset the workflow still enforces — it cannot silently no-op. Set the variable to `report-only` (or
dispatch with the `report-only` input) to make it log the decision and the AWS calls it *would* make
without mutating the fleet.

## Moving parts

| Piece | Where | Role |
| --- | --- | --- |
| `fleet-control.yml` | `.github/workflows/` | The controller. Runs on `ubuntu-latest` (GitHub-hosted) so it works even when the fleet is at zero. |
| `ci-fleet-decision.sh` | `scripts/` | Read-only. Measures demand + capacity and sizes the fleet for a single instant. Only `gh api` GETs — never mutates, never touches AWS, safe to run anytime. |
| `ci-runners-up.sh` | `scripts/` | Idempotent bring-up / top-up (on-demand floor + `CI_RUNNER_COUNT` spot). Already existed. |
| `ci-runners-down.sh --to-boxes N` | `scripts/` | Drain the over-provisioned excess down to N boxes — **idle spot boxes only**. New. |
| `ci-runners-down.sh --all` | `scripts/` | Full teardown, floor included. Already existed. |
| `busbar-ci-fleet-controller` | IAM role | The OIDC role the workflow assumes. No long-lived secrets. |

## The decision: size to load

`ci-fleet-decision.sh` measures, at one instant:

- **Demand** — `pending` = the count of `queued` + `in_progress` jobs, across this repo's active
  workflow runs, whose `runs-on` targets our fleet (`busbar-xl` / `self-hosted` / `latchkey-*`). Demand
  is derived from each run's job list. **A per-job label filter is not trusted on its own**: GitHub
  leaves `.labels` empty on a not-yet-dispatched job in some states, and a naive filter then silently
  counts it as 0 (this undercounted demand to zero in testing). So when a job's labels are present we
  use them; when they are empty we fall back to whether the *run* is a self-hosted workflow (`CI`,
  `gate-mutants`, `keep-proof`) rather than dropping the job.
- **Capacity** — `slots` (online runner agents), `busy` (agents executing a job), and `cur_boxes`
  (distinct EC2 boxes those agents belong to, from the `ec2-<id>-<agent>` runner names).

Then it sizes:

```
desired_slots = pending                                  # 1 slot per pending job -> ~100% util
desired_boxes = ceil(desired_slots / AGENTS_PER_BOX)     # AGENTS_PER_BOX = 4
              clamped to [0, MAX_BOXES]                  # MAX_BOXES = vars.FLEET_MAX_BOXES, default 16
```

and picks an action by comparing `desired_boxes` to `cur_boxes`:

| Condition | Action | What runs |
| --- | --- | --- |
| `pending == 0` | **down-all** | `ci-runners-down.sh --all` — fleet to ZERO, floor included |
| `desired_boxes > cur_boxes` | **up** | `CI_RUNNER_COUNT=<desired-floor> ci-runners-up.sh` — top up toward `desired_boxes` |
| `desired_boxes < cur_boxes` | **down-to** | `ci-runners-down.sh --to-boxes <desired>` — drain over-provisioned idle spot |
| `desired_boxes == cur_boxes` | **hold** | nothing — online capacity already matches the backlog |

It prints the **utilization math every run** (pending, slots, busy, current util%, desired boxes,
projected util%, action) to stderr, and one `KEY=VALUE` decision line to stdout for the workflow.

## Why it is safe

**Never tear down live work.**

- A **full teardown** (`down-all`) fires only after **two consecutive "queue empty" reads**,
  `FLEET_DEBOUNCE_SECONDS` apart (default 180s). The gap between two jobs in one run cannot be mistaken
  for a drained queue.
- A **drain** (`down-to`) likewise requires two consecutive reads that agree we are over-provisioned (a
  transient queue dip never sheds capacity), and `ci-runners-down.sh --to-boxes` terminates **only boxes
  whose agents are ALL idle** (`idle_spot_boxes`): a box with any busy agent, or one still bootstrapping,
  is never touched. If there is no fully-idle spot box to shed, it does nothing and says so.
- A **bring-up** (`up`) is idempotent and fires on the first read with no debounce. `ci-runners-up.sh`
  counts real EC2 instances, so if boxes are mid-bootstrap the top-up reconciles to the target without
  double-launching.

**Conservative degrade.** Sizing UP and full teardown need only *this repo's* runs/jobs, readable by the
default `github.token` (`actions: read`). Current utilization and the drain path additionally need the
online-runner list (`admin:org` read) — supply a PAT as the optional `FLEET_CONTROL_GH_TOKEN` secret. If
it is absent, `cur_boxes` reads as unknown/0, so the verdict can only be `up` or `down-all`, never a
downscale the controller cannot justify.

## Triggers

- `pull_request`, `push` — pre-warm: bring capacity up as work arrives.
- `workflow_run` on `CI` / `gate-mutants` / `keep-proof` `completed` — re-size as the queue drains.
- `schedule` every 15 min — safety reaper that catches anything the event-driven passes missed.
- `workflow_dispatch` — manual, with an `enforce` / `report-only` input to override the flag for one run.

## Cold-start tradeoff

`down-all` means **zero** boxes: the next self-hosted job after an idle period pays the full bootstrap —
apt, rustup, the runner agent, and a pre-warm build — which is **~8–12 minutes** before the first job
starts (see `ci-runners-up.sh`). That is the deliberate price of "never idle". Because `push`/`pull_request`
pre-warm on the way in, most human-driven work triggers the bring-up before its CI even queues. If a
workload cannot tolerate the cold start (e.g. a release window), set `FLEET_CONTROL_ENFORCE=report-only`
during it.

## Turning it on / pausing it

It is **on by default** (`FLEET_CONTROL_ENFORCE` defaults to `enforce`; the repo variable
`FLEET_CONTROL_ENFORCE=enforce` is also set explicitly). To watch it without acting first:

1. Run `bash scripts/ci-fleet-decision.sh` locally (needs `gh` auth) any time to see the live
   utilization math and the action it would take, or trigger the workflow via *Actions → fleet-control →
   Run workflow* with `enforce = report-only`.
2. **To pause enforcement**, set the repo variable `FLEET_CONTROL_ENFORCE` to `report-only`
   (*Settings → Secrets and variables → Actions → Variables*). Anything other than exactly `enforce` is
   report-only.
3. **Optional** — add the `FLEET_CONTROL_GH_TOKEN` secret (PAT, `admin:org` read) to enable current-util
   measurement and the drain-down path. Also raise/lower the ceiling with `vars.FLEET_MAX_BOXES`.

## The IAM role and policy

The workflow assumes `arn:aws:iam::457667483187:role/busbar-ci-fleet-controller` via GitHub's OIDC
provider (`token.actions.githubusercontent.com`) — no stored AWS keys. The trust policy allows
**only** `repo:GetBusbar/busbar:*` with audience `sts.amazonaws.com`.

Its inline policy (`fleet-control-least-privilege`) grants exactly the actions `ci-runners-up.sh` /
`ci-runners-down.sh` call — EC2 describe/run/create-fleet/terminate/launch-template, the egress-only
security-group create/revoke, SSM `SendCommand`/`DescribeInstanceInformation`/`ListCommandInvocations`
and the Canonical Ubuntu AMI `GetParameter`, the sccache S3 bucket lifecycle, and the runner IAM
role/instance-profile provisioning. The `--to-boxes` drain reuses these same actions
(`DescribeInstances` + `TerminateInstances` + the SSM trio), so it needs **no policy change**.
`iam:PassRole` is scoped to the runner role (`busbar-ci-runner-role`) only, and only when passed to
`ec2.amazonaws.com`. No `*:*`. To review it:
`aws iam get-role-policy --role-name busbar-ci-fleet-controller --policy-name fleet-control-least-privilege`.
