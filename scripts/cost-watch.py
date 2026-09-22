#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""cost-watch.py -- the CI cost gate DECISIONS #78 claims exists and did not.

docs/design/BUSBAR-1.6.0.md (Part 2) row #78 (OWNER-LOCKED 2026-09-20) reads, in the part this script exists
to satisfy:

    "Hard cap $100/period total infra; $50 soft-alarm, $80 review -> on breach find the top
    workflow and cut its trigger/right-size."

and its acceptance criterion is: "cost-watch checks the LK Cost-Analysis each period". Before this
file, nothing did: a repo-wide search for cost-watch/budget/$100/$50/$80, any AWS Budgets/Cost-
Explorer/CloudWatch dependency, or any Latchkey billing call found only the DECISIONS-row prose
above. Nothing noticed a runaway job but the invoice. This is the tool.

WHAT IT DOES. Enumerates every completed workflow run in a trailing window (`--period` days,
default 7) via the GitHub Actions REST API (through `gh api`, the only network call this file
makes unconditionally -- see `gh_api_lines()`), pulls each job's requested runner label and its
wall-clock duration, converts that to dollars with the MEASURED Latchkey rate table below, compares
the period total against the three DECISIONS #78 thresholds, and ranks workflows by spend so the
stated remedy ("find the top workflow") is one glance away. If `LATCHKEY_API_TOKEN` is set it also
makes one optional, read-only GET to Latchkey's own Jobs API to cross-check the wall-clock basis
against Latchkey's own `duration_ms` for a sample of recent jobs -- see "LATCHKEY MINUTES ARE AN
ESTIMATE" below, this is the whole reason that cross-check exists.

RATES ARE MEASURED, NEVER INVENTED. Cited at the point of use:

  1. Latchkey: crates/busbar-release-autoscaler/LATCHKEY-COST-METRICS.md in the sibling
     `busbar-release` repo (measured 2026-09-18), cross-confirmed against Latchkey's own published
     per-minute pricing page (checked 2026-09-21). Flat $0.075/vCPU-hr at every published size --
     small $0.15/hr = $0.0025/min (2 vCPU), medium $0.30/hr = $0.0050/min (4 vCPU), large $0.60/hr
     = $0.0100/min (8 vCPU), xlarge $1.20/hr = $0.0200/min (16 vCPU).
  2. GitHub-hosted standard runners: GitHub's published Actions billing rates (fetched 2026-09-21,
     https://docs.github.com/en/billing/concepts/product-billing/github-actions) -- Linux x64
     $0.006/min, Linux arm64 $0.005/min, Windows x64 $0.010/min, macOS $0.062/min. The same page
     states standard GitHub-hosted runner minutes are unconditionally free on PUBLIC repositories,
     which is checked at runtime against the real repo (`fetch_repo_is_private`), never assumed.
  3. This repo's own EC2 self-hosted fleet (`busbar-xl`): the SAME LATCHKEY-COST-METRICS.md
     document, which names this fleet directly ("the busbar fleet runs c7a.8xlarge with
     AGENTS=4") -- cross-checked against `scripts/ci-runners-lib.sh`'s own `ITYPE`/`AGENTS`
     defaults. See "EC2 IS OVERFLOW-ONLY NOW" below -- the owner confirmed 2026-09-21 that the
     account has zero running/stopped EC2 instances, so this category is dormant, not deleted.

A runner label this script does not recognise (nothing in the Latchkey size table, nothing in the
GitHub-hosted table, not the exact `self-hosted`+`busbar-xl` pairing the EC2 fleet registers
under -- see `classify_runner`) is reported as `unknown` and priced as `unknown`, never guessed.
"Where a rate is unknown, say unknown rather than guess" is a hard constraint on this file.

ROUNDING. Per DECISIONS #78, Latchkey "bills PER JOB-MINUTE, rounded up per job". Every job's
billed duration is `ceil(seconds / 60)`, per job, never averaged or summed-then-rounded (see
`job_minutes()` for the GitHub-wall-clock basis, `latchkey_sample_job_minutes()` for the
Latchkey-`duration_ms` basis).

LATCHKEY MINUTES ARE A WALL-CLOCK ESTIMATE, NOT LATCHKEY'S BILLED MINUTES. This script has no way
to read Latchkey's actual per-job billed duration for a full period: Latchkey's Jobs API
(`https://api.latchkey.dev`, OpenAPI spec at `https://latchkey.dev/openapi.json`, checked
2026-09-21) has no usage/billing endpoint at all (`/usage`, `/billing`, `/account`, `/costs`, `/me`,
`/whoami`, `/quota` all 404 -- confirmed directly), and its one jobs-listing endpoint (`GET /jobs`)
returns at most the 100 most-recent jobs FOR THE WHOLE ORG, newest first, with no date filter and
no pagination cursor -- so even with a valid token it cannot serve a multi-thousand-job period
total (this repo's periods run into the thousands). So the `would_be_usd`/`actual_usd` totals below
are computed from the GitHub Actions job's own `started_at`->`completed_at` span
(`job_minutes()`), which is WALL CLOCK, not billed execution time: it includes the time a job
spends queued and having a runner provisioned before it starts real work. Latchkey does NOT bill
that wait -- confirmed directly in the sibling `busbar-release` repo's own beta test
(`LATCHKEY-FINDINGS.md` F1: a trivial `echo hi` job with ~0s of real compute still shows ~65-80s of
wall time, all of it cold-start/provisioning). Reconciled against the owner's own Latchkey
dashboard (2026-09-21, "Managed Runners" panel), this wall-clock basis reads roughly 2.4x-3x what
Latchkey actually bills. TREAT THE `latchkey` FIGURES BELOW AS AN UPPER-BOUND ESTIMATE, GOOD FOR
RELATIVE RANKING (which workflow/size is biggest), NOT AS LATCHKEY'S REAL BILL -- trust the
dashboard for that. When `LATCHKEY_API_TOKEN` is set, the report also prints a small cross-check
sample priced on Latchkey's own `duration_ms` (the field that mechanism points at) for whatever
jobs the API will hand back, explicitly labelled as a sample, not a period total.

THE LATCHKEY FREE-TIER POOL. Latchkey's own dashboard applies a period-wide free-minute allowance
before billing (currently 32,000 min/period, 30,000 of which is a bonus expiring 2026-09-30 -- see
`LATCHKEY_FREE_MINUTES_PER_PERIOD`'s citation). This script models that pool against the
(wall-clock-estimated, see above) Latchkey minute total to produce an `actual_usd` for the Latchkey
share instead of silently reporting $0 -- see `apply_latchkey_free_tier()`. Because the pool is
applied to an inflated minute count, the resulting `actual_usd` is ALSO inflated relative to
Latchkey's own billable figure; it is directionally useful (is the pool close to exhausted?) but
not a substitute for the dashboard's own billable number.

EC2 IS OVERFLOW-ONLY NOW. The owner's 2026-09-20 EC2 spend (~$2,000/period) was the reason the repo
migrated to Latchkey; that migration is now complete -- the owner confirmed 2026-09-21 the AWS
account has zero running/stopped EC2 instances, zero unattached EBS volumes, zero NAT gateways.
This script does NOT query AWS at all (no Cost Explorer, no EC2 API) -- it only prices whatever GH
Actions jobs still land on the legacy `busbar-xl` self-hosted label, which is expected to be zero
now that Latchkey is primary. That pricing path is kept, not deleted, in case the fleet is ever
used again for overflow, but it is NOT a full AWS bill (no idle time, EBS, NAT, or other-service
spend) and the report says so every run -- see "EC2:" in `print_human_report`.

THE BAND DRIVING THE EXIT CODE IS would_be_usd, NOT actual_usd. would_be_usd tracks (estimated)
job-minutes directly and is the number that would become real Latchkey spend the day the free-tier
pool is exhausted or the repo's GitHub-hosted minutes stop being free, so banding on actual would
hide exactly the runaway this tool exists to catch. Both totals are always computed and printed.

EXIT CODE CONTRACT -- the money bands (distinct from --selftest's own pass/fail exit code, below):

    0   total (would_be_usd) < $50             -- ok
    2   $50  <= total < $80                     -- SOFT-ALARM (DECISIONS #78's $50 line)
    3   $80  <= total < $100                    -- REVIEW (DECISIONS #78's $80 line)
    1   total >= $100                           -- HARD CAP BREACH (DECISIONS #78's $100 line)
    4   the tool itself could not complete (a `gh api` call failed, no network, bad --repo, a bad
        --period, ...) -- distinct from every money band on purpose: a caller must never read
        "the tool could not run" as "spend is fine".

--selftest is a DIFFERENT exit code space: 0 if every planted-fixture assertion passed, 1 if any
failed. It never touches the network -- it shims `gh` on $PATH the same way
`scripts/promote-selftest.sh` shims it -- and drives the real end-to-end path (`main()`, through
the same `gh_api_lines()` used against the real API, only pointed at the fake `gh`) through all
four money bands, plus the rounding, classification and unknown-label rules in isolation.

Usage:
    scripts/cost-watch.py                    # last 7 days, human-readable, real API
    scripts/cost-watch.py --period 30        # last 30 days
    scripts/cost-watch.py --json             # machine-readable report on stdout
    scripts/cost-watch.py --repo OWNER/NAME  # default: $GITHUB_REPOSITORY, else the origin remote
    scripts/cost-watch.py --selftest         # prove the four bands and the pricing rules, offline
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ── DECISIONS #78's three thresholds, owner-locked 2026-09-20. Not CLI-overridable on purpose --
# these are policy numbers, not a tuning knob. -----------------------------------------------------
SOFT_ALARM_USD = 50.0
REVIEW_USD = 80.0
HARD_CAP_USD = 100.0

# ── Latchkey rate table -- MEASURED, crates/busbar-release-autoscaler/LATCHKEY-COST-METRICS.md in
# the sibling busbar-release repo, measured 2026-09-18. Flat $0.075/vCPU-hr at every size. ---------
LATCHKEY_RATE_PER_VCPU_HOUR = 0.075
LATCHKEY_VCPU = {
    "latchkey-small": 2,
    "latchkey-medium": 4,
    "latchkey-large": 8,
    "latchkey-xlarge": 16,
}
LATCHKEY_HOURLY = {name: vcpu * LATCHKEY_RATE_PER_VCPU_HOUR for name, vcpu in LATCHKEY_VCPU.items()}
# small=$0.15/hr medium=$0.30/hr large=$0.60/hr xlarge=$1.20/hr -- matches the published table.

# ── GitHub-hosted standard runner rates -- GitHub's published Actions billing docs, fetched
# 2026-09-21: https://docs.github.com/en/billing/concepts/product-billing/github-actions -----------
GITHUB_HOSTED_PER_MINUTE = {
    "ubuntu-latest": 0.006,
    "ubuntu-24.04": 0.006,
    "ubuntu-22.04": 0.006,
    "ubuntu-20.04": 0.006,
    "ubuntu-24.04-arm": 0.005,
    "ubuntu-22.04-arm": 0.005,
    "windows-latest": 0.010,
    "windows-2022": 0.010,
    "windows-2019": 0.010,
    "macos-latest": 0.062,
    "macos-14": 0.062,
    "macos-13": 0.062,
}
# That source page also states standard GitHub-hosted runner minutes are free, unconditionally, on
# PUBLIC repositories -- checked at runtime against the real repo (`fetch_repo_is_private`), never
# assumed, because assuming the wrong way (assuming public when actually private) would quietly
# hide a real bill.

# ── This repo's own EC2 self-hosted fleet -- MEASURED, the SAME source as the Latchkey table
# (LATCHKEY-COST-METRICS.md, measured 2026-09-18), which describes THIS repo's fleet by name: "The
# busbar fleet runs c7a.8xlarge with AGENTS=4, i.e. an 8-vCPU slot per CI job." Cross-checked
# directly against this repo's own scripts/ci-runners-lib.sh: `ITYPE` default is c7a.8xlarge
# (32 vCPU), `AGENTS` default is 4 -> 8 vCPU per concurrent job slot, with a same-class `ITYPES`
# spot fallback pool (m7a/c6a/c7i.8xlarge, all 32 vCPU x86-64). Unlike Latchkey (free beta
# credits) and GitHub-hosted (free on this public repo), EC2 is billed to AWS for real, today --
# so for this category actual_usd == would_be_usd, never $0.
#
# CAVEAT, stated rather than hidden: the Jobs API's `runner_name` (e.g. `ec2-<instance-id>-<n>`,
# confirmed against real job data before this was written) does not say WHICH of the four
# same-class fallback instance types ran a given job, and only c7a.8xlarge's rate was measured.
# Every `busbar-xl` job is priced at that one measured rate -- the fleet's documented default --
# which is an approximation of a MEASURED number (and the same per-slot formula
# LATCHKEY-COST-METRICS.md itself uses), not an invented one.
EC2_SPOT_HOURLY_C7A_8XLARGE = 0.637        # c7a.8xlarge spot, 32 vCPU (LATCHKEY-COST-METRICS.md)
EC2_ONDEMAND_HOURLY_C7A_8XLARGE = 1.642    # c7a.8xlarge on-demand, 32 vCPU (same source)
EC2_FLEET_AGENTS = 4                       # scripts/ci-runners-lib.sh: CI_RUNNER_AGENTS default
EC2_SPOT_PER_SLOT_HOURLY = EC2_SPOT_HOURLY_C7A_8XLARGE / EC2_FLEET_AGENTS          # $0.15925/hr
EC2_ONDEMAND_PER_SLOT_HOURLY = EC2_ONDEMAND_HOURLY_C7A_8XLARGE / EC2_FLEET_AGENTS  # $0.41050/hr
# The custom label scripts/ci-runners-lib.sh / ci-runner-bootstrap.sh register the fleet under
# (`RUNNER_LABELS`, default "busbar-xl"). A job is priced as this fleet only if its labels include
# BOTH the GitHub-added `self-hosted` system label and this custom label -- the same pairing every
# sampled job's `runner_name` (a real `ec2-*` instance) independently confirmed before this was
# written. Any OTHER self-hosted label combination is reported `unknown`, not guessed at.
EC2_FLEET_LABEL = "busbar-xl"

# ── Latchkey free-tier pool -- owner's Latchkey dashboard ("Managed Runners" panel), read directly
# 2026-09-21: "Free Tier: 32000 / 32000 min (includes 30,000 bonus minutes through September 30)".
# This is a PROMOTIONAL balance, not a permanent rate: 30,000 of the 32,000 is a bonus that expires
# on the date below, after which the pool almost certainly drops and this constant goes stale. It
# is not auto-detected because Latchkey's Jobs API has no usage/quota endpoint to read it from (see
# LATCHKEY_API_BASE below and LATCHKEY-FINDINGS.md F5 in the sibling busbar-release repo, which
# flagged this exact gap). Re-read the dashboard and update this constant after the expiry date --
# do not let it go stale silently.
LATCHKEY_FREE_MINUTES_PER_PERIOD = 32000
LATCHKEY_FREE_MINUTES_BONUS_EXPIRES = "2026-09-30"

# ── Latchkey Jobs API -- OPTIONAL cross-check, never the basis for the band/exit code. Same base
# URL and auth env var as the sibling busbar-release repo's real client
# (crates/busbar-release-autoscaler/src/latchkey.rs / config.rs, read-only, confirmed 2026-09-21).
# `GET /jobs` is the ONLY read-only, non-mutating endpoint that returns real per-job `duration_ms`
# (Latchkey's own measure of EXECUTION time, confirmed empirically: a job with ~0ms of real compute
# still spans ~70s of `queued_at`->`completed_at`, i.e. `duration_ms` excludes the provisioning wait
# that GitHub's job span does not -- see the module docstring's wall-clock-estimate section). It is
# capped at `limit<=100` jobs, newest first, for the WHOLE ORG, with no date filter and no
# pagination cursor (confirmed against the public OpenAPI spec, https://latchkey.dev/openapi.json,
# and by probing /usage /billing /account /costs /me /whoami /quota directly -- all 404) -- so it
# can only ever be a small, recent, org-wide SAMPLE, never a period total. This script never reads
# the token from anywhere but the env var below; it does not go looking for it on disk.
LATCHKEY_API_BASE = "https://api.latchkey.dev"
LATCHKEY_TOKEN_ENV = "LATCHKEY_API_TOKEN"  # same env var busbar-release's LatchkeyConfig reads
LATCHKEY_JOBS_LIMIT = 100  # the API's own documented maximum for `GET /jobs?limit=`
LATCHKEY_API_TIMEOUT = 20  # seconds; one optional GET, must not hang the whole gate

GH_TIMEOUT = 60  # seconds per `gh api` call; a hung call must not hang the whole gate.
_GH_HOSTED_LOOKS_LIKE = re.compile(r"^(ubuntu|windows|macos)-")


@dataclass
class JobCost:
    workflow: str
    job: str
    run_id: object
    category: str  # "latchkey" | "github-hosted" | "ec2" | "unknown"
    key: str
    minutes: Optional[int]
    actual_usd: Optional[float]
    would_be_usd: Optional[float]
    note: str


@dataclass
class LatchkeyApiResult:
    """Outcome of the OPTIONAL `GET /jobs` cross-check against Latchkey's own API.

    `status` is one of "not_available" (no `LATCHKEY_API_TOKEN`), "unavailable" (token present but
    the request/parse failed -- `detail` says why), or "ok". `sample` is a dict keyed by
    `runner_size` -> {"jobs": int, "minutes": int, "usd": float} for `size in LATCHKEY_HOURLY`, plus
    `"unknown_size_jobs": int` for anything else, priced on Latchkey's own `duration_ms` -- never a
    period total, always at most `LATCHKEY_JOBS_LIMIT` jobs, org-wide, newest first.
    """
    status: str
    sample: Optional[dict]
    detail: str


@dataclass
class Report:
    repo: str
    period_days: int
    since: str
    until: str
    generated_at: str
    repo_is_private: Optional[bool]
    total_actual_usd: float
    total_would_be_usd: float
    band: str
    exit_code: int
    thresholds: dict
    by_category_would_be: dict
    top_workflows: list
    job_count: int
    unknown_job_count: int
    unknown_labels: list
    unbillable_job_count: int  # missing/unusable timestamps
    fetch_errors: list
    latchkey_minutes_total: int  # wall-clock ESTIMATE, see module docstring
    latchkey_free_minutes_pool: int
    latchkey_billable_minutes: int  # wall-clock minutes above the free-tier pool
    latchkey_api: LatchkeyApiResult
    warnings: list = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "repo": self.repo,
            "period_days": self.period_days,
            "since": self.since,
            "until": self.until,
            "generated_at": self.generated_at,
            "repo_is_private": self.repo_is_private,
            "total_actual_usd": round(self.total_actual_usd, 4),
            "total_would_be_usd": round(self.total_would_be_usd, 4),
            "band": self.band,
            "exit_code": self.exit_code,
            "thresholds_usd": self.thresholds,
            "by_category_would_be_usd": {k: round(v, 4) for k, v in self.by_category_would_be.items()},
            "top_workflows_would_be_usd": [
                {"workflow": w, "would_be_usd": round(v, 4)} for w, v in self.top_workflows
            ],
            "job_count": self.job_count,
            "unknown_job_count": self.unknown_job_count,
            "unknown_labels": self.unknown_labels,
            "unbillable_job_count": self.unbillable_job_count,
            "fetch_errors": self.fetch_errors,
            "latchkey_minutes_total_estimate": self.latchkey_minutes_total,
            "latchkey_free_minutes_pool": self.latchkey_free_minutes_pool,
            "latchkey_billable_minutes_estimate": self.latchkey_billable_minutes,
            "latchkey_api_cross_check": {
                "status": self.latchkey_api.status,
                "detail": self.latchkey_api.detail,
                "sample": self.latchkey_api.sample,
            },
            "warnings": self.warnings,
        }


# ── network: the ONLY function in this file that shells out to `gh` ---------------------------------
def gh_api_lines(path_and_query: str, jq_expr: str, *, paginate: bool = False) -> list:
    """Run `gh api [--paginate] <path> --jq <expr>` and parse stdout as NDJSON (one value/line).

    `gh api --paginate ... --jq EXPR` walks every page and concatenates each page's jq output,
    newline-separated -- confirmed directly against this repo's real Actions history before this
    script was written (255 runs over multiple pages via `created=>=...`, matching `total_count`
    exactly). A fake `gh` on $PATH serves the same shape for --selftest; see `_FakeGhShim`.
    """
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    cmd += [path_and_query, "--jq", jq_expr]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"`gh api {path_and_query}` could not run: {e}") from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"`gh api {path_and_query}` exited {proc.returncode}: {proc.stderr.strip()[:500]}"
        )
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def fetch_repo_is_private(repo: str) -> Optional[bool]:
    """True/False, or None if it could not be determined (never assumed)."""
    try:
        vals = gh_api_lines(f"repos/{repo}", ".private")
    except (RuntimeError, ValueError):
        return None
    return bool(vals[0]) if vals else None


def fetch_completed_runs(repo: str, since_date: str) -> list:
    path = f"repos/{repo}/actions/runs?per_page=100&status=completed&created=%3E%3D{since_date}"
    return gh_api_lines(path, ".workflow_runs[]", paginate=True)


def fetch_jobs_for_run(repo: str, run_id) -> list:
    path = f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"
    return gh_api_lines(path, ".jobs[]", paginate=True)


def fetch_latchkey_jobs_sample() -> LatchkeyApiResult:
    """One optional, read-only `GET /jobs?limit=<LATCHKEY_JOBS_LIMIT>` against Latchkey's own API.

    Never touches disk looking for a token -- only `LATCHKEY_TOKEN_ENV` (see its citation above).
    If that env var is unset, this is NOT an error: it degrades to `status="not_available"` with a
    detail naming the exact env var to set, per the hard constraint that a missing credential must
    say so plainly rather than silently falling back to a worse basis. A present-but-failing token
    (network error, 401, bad JSON, ...) is `status="unavailable"` with the failure in `detail`.
    """
    token = os.environ.get(LATCHKEY_TOKEN_ENV)
    if not token:
        return LatchkeyApiResult("not_available", None, f"Latchkey: UNAVAILABLE (set {LATCHKEY_TOKEN_ENV})")

    req = urllib.request.Request(
        f"{LATCHKEY_API_BASE}/jobs?limit={LATCHKEY_JOBS_LIMIT}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=LATCHKEY_API_TIMEOUT) as resp:
            body = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as e:
        return LatchkeyApiResult("unavailable", None, f"Latchkey Jobs API request failed: {e}")

    try:
        doc = json.loads(body)
    except json.JSONDecodeError as e:
        return LatchkeyApiResult("unavailable", None, f"Latchkey Jobs API returned unparseable JSON: {e}")

    jobs = doc.get("jobs")
    if not isinstance(jobs, list):
        return LatchkeyApiResult("unavailable", None,
                                  f"Latchkey Jobs API response had no `jobs` array (keys: {sorted(doc.keys())!r})")

    sample = price_latchkey_jobs_sample(jobs)
    truncated = (
        f"{len(jobs)} most-recent org-wide jobs sampled (Latchkey's `GET /jobs` caps at "
        f"{LATCHKEY_JOBS_LIMIT}, newest first, with no date filter or pagination -- this is a "
        f"SAMPLE, not a period total; see the module docstring)"
    )
    return LatchkeyApiResult("ok", sample, truncated)


def default_repo() -> Optional[str]:
    env_repo = os.environ.get("GITHUB_REPOSITORY")
    if env_repo:
        return env_repo
    try:
        out = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"github\.com[:/](.+?)(?:\.git)?\s*$", out.stdout.strip())
        if m:
            return m.group(1)
    except OSError:
        pass
    return None


# ── pure computation: classify, round, price. No network below this line. ---------------------------
def classify_runner(labels: list) -> tuple:
    """(category, key) from a job's `labels` (the label set GitHub echoes back on the job).

    Membership-based, not `labels[0]`-based: Latchkey jobs are observed to carry exactly one
    label (`["latchkey-large"]`), but this repo's own EC2 fleet registers each runner under
    FOUR (`["self-hosted", "linux", "x64", "busbar-xl"]`, confirmed against real job data before
    this was written) -- so a first-element check would misclassify a real, currently-billing EC2
    job as some GitHub-hosted guess or drop it silently. Set membership is correct regardless of
    which order GitHub reports the labels in.

    EC2 is priced ONLY for the exact `self-hosted` + `busbar-xl` pairing this repo's own fleet
    registers under (see the `EC2_*` constants above for the citation). Any other self-hosted
    label combination -- a fleet this table does not know, a rename, a one-off custom runner --
    is reported `unknown`, never guessed at.
    """
    if not labels:
        return ("unknown", "<no-labels>")
    label_set = {str(l) for l in labels}

    lk = label_set & set(LATCHKEY_VCPU)
    if lk:
        return ("latchkey", sorted(lk)[0])
    lk_unknown = {l for l in label_set if l.startswith("latchkey-")}
    if lk_unknown:
        return ("unknown", sorted(lk_unknown)[0])  # a Latchkey size unknown to this table

    gh = label_set & set(GITHUB_HOSTED_PER_MINUTE)
    if gh:
        return ("github-hosted", sorted(gh)[0])

    if "self-hosted" in label_set and EC2_FLEET_LABEL in label_set:
        return ("ec2", EC2_FLEET_LABEL)
    if "self-hosted" in label_set:
        extra = sorted(label_set - {"self-hosted", "linux", "windows", "macos", "x64", "arm64", "arm"})
        return ("unknown", "self-hosted:" + (",".join(extra) if extra else "<no custom label>"))

    primary = sorted(label_set)[0]
    if _GH_HOSTED_LOOKS_LIKE.match(primary):
        return ("unknown", primary)  # looks GitHub-hosted but not a size this table has a rate for
    return ("unknown", primary)


def _parse_gh_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def job_minutes(started_at, completed_at, conclusion) -> Optional[int]:
    """Whole minutes billed for one job, per DECISIONS #78 ("rounded up per job").

    A `skipped` job never provisioned a runner -- GitHub does not bill it -- so it is 0, not
    excluded (excluding it would silently drop it from job-count reasoning elsewhere). A job
    missing either timestamp cannot be measured and returns None, reported as unbillable rather
    than guessed at.
    """
    if conclusion == "skipped":
        return 0
    if not started_at or not completed_at:
        return None
    try:
        start = _parse_gh_ts(started_at)
        end = _parse_gh_ts(completed_at)
    except ValueError:
        return None
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        return 0
    return math.ceil(seconds / 60.0)


def latchkey_sample_job_minutes(duration_ms) -> int:
    """Whole minutes billed for one Latchkey job, per DECISIONS #78, on Latchkey's OWN
    `duration_ms` (execution time -- excludes the provisioning wait `job_minutes()`'s GitHub
    wall-clock basis cannot separate out). Anything non-positive or unparseable is 0, never
    guessed."""
    try:
        ms = float(duration_ms)  # F2 (LATCHKEY-FINDINGS.md): duration_ms is sent as a JSON string
    except (TypeError, ValueError):
        return 0
    if ms <= 0:
        return 0
    return math.ceil((ms / 1000.0) / 60.0)


def price_latchkey_jobs_sample(jobs: list) -> dict:
    """Price a raw `GET /jobs` sample on Latchkey's own `duration_ms`, grouped by `runner_size`.

    Latchkey's own API uses BARE size names ("small"/"medium"/"large"/"xlarge" -- confirmed
    against its published pricing page and the sibling busbar-release repo's beta test), while
    this script's `LATCHKEY_HOURLY` table keys on the GitHub Actions runner-LABEL convention this
    repo's Latchkey runners register under ("latchkey-xlarge", etc, per `classify_runner`) -- the
    two vocabularies are normalised together here so a real API response prices correctly.

    Returns {size: {"jobs": n, "minutes": m, "usd": $}} for every size in `LATCHKEY_HOURLY`, plus
    `"unknown_size_jobs": n` for any `runner_size` neither vocabulary has a rate for (counted,
    never priced at a guess -- the same "unknown, not guessed" rule `classify_runner` applies to
    the GitHub-side label lookup).
    """
    out = {size: {"jobs": 0, "minutes": 0, "usd": 0.0} for size in LATCHKEY_HOURLY}
    unknown_size_jobs = 0
    for j in jobs:
        raw_size = j.get("runner_size") or ""
        size = raw_size if raw_size in LATCHKEY_HOURLY else f"latchkey-{raw_size}"
        minutes = latchkey_sample_job_minutes(j.get("duration_ms"))
        if size not in LATCHKEY_HOURLY:
            unknown_size_jobs += 1
            continue
        out[size]["jobs"] += 1
        out[size]["minutes"] += minutes
        out[size]["usd"] += minutes / 60.0 * LATCHKEY_HOURLY[size]
    out["unknown_size_jobs"] = unknown_size_jobs
    return out


def apply_latchkey_free_tier(minutes_total: int, would_be_total: float, pool_minutes: int) -> tuple:
    """(billable_minutes, billable_fraction, actual_usd) after subtracting a period-wide free-tier
    pool shared across every Latchkey job regardless of size (see `LATCHKEY_FREE_MINUTES_PER_PERIOD`
    for its citation).

    Latchkey's own per-tier allocation order inside the pool is not published and its Jobs API has
    no usage endpoint to read it back (LATCHKEY-FINDINGS.md F5), so this applies the pool UNIFORMLY
    across every Latchkey job by minute-share rather than guessing which specific jobs it covers.
    The pool TOTAL subtracted is exact; only its allocation across differently-priced jobs is an
    approximation -- both facts are printed, never hidden. `pool_minutes` is a parameter (not the
    bare constant) purely so --selftest can exercise this against small fixture numbers instead of
    needing 32,000 minutes of planted jobs.
    """
    if minutes_total <= 0:
        return (0, 0.0, 0.0)
    billable_minutes = max(0, minutes_total - pool_minutes)
    billable_fraction = billable_minutes / minutes_total
    return (billable_minutes, billable_fraction, would_be_total * billable_fraction)


def cost_one_job(rec: dict, repo_is_private: Optional[bool]) -> JobCost:
    """Price a single adapted job record. `repo_is_private=None` (unknown) is treated as private
    for `actual_usd` -- a missed real cost is worse than an over-cautious one."""
    minutes = job_minutes(rec.get("started_at"), rec.get("completed_at"), rec.get("conclusion"))
    category, key = classify_runner(rec.get("labels") or [])

    if minutes is None:
        return JobCost(rec["workflow"], rec["job"], rec.get("run_id"), category, key,
                        None, None, None,
                        "no start/end timestamp -- cost unknown, not guessed")

    if category == "latchkey":
        hourly = LATCHKEY_HOURLY[key]
        would_be = minutes / 60.0 * hourly
        # `actual_usd` for latchkey jobs is filled in by build_report(), in aggregate, once the
        # period's free-tier pool allocation is known (apply_latchkey_free_tier()) -- it cannot be
        # decided per-job because the pool is shared across every latchkey job in the period.
        actual = None
        note = (f"latchkey {key}: {LATCHKEY_VCPU[key]} vCPU x "
                f"${LATCHKEY_RATE_PER_VCPU_HOUR}/vCPU-hr list price "
                f"(${hourly:.2f}/hr); WALL-CLOCK ESTIMATE minutes, see module docstring; "
                f"actual pending free-tier pool allocation")
    elif category == "github-hosted":
        per_min = GITHUB_HOSTED_PER_MINUTE[key]
        would_be = minutes * per_min
        if repo_is_private is False:
            actual = 0.0
            note = (f"github-hosted {key}: ${per_min}/min list price; "
                     "actual $0 (public-repo standard runners are free)")
        else:
            actual = would_be
            vis = "private" if repo_is_private else "visibility unknown -- treated as private/paid"
            note = f"github-hosted {key}: ${per_min}/min list price, repo is {vis}"
    elif category == "ec2":
        hourly = EC2_SPOT_PER_SLOT_HOURLY
        would_be = minutes / 60.0 * hourly
        actual = would_be  # real AWS spend today -- no beta credit covers this fleet
        note = (f"ec2 {key}: c7a.8xlarge spot, {EC2_FLEET_AGENTS} agents/box -> "
                f"${hourly:.5f}/hr per job slot; actual == would-be (real AWS spend)")
    else:
        would_be = None
        actual = None
        note = f"unrecognised runner label {key!r} -- no rate in the table; not guessed"

    return JobCost(rec["workflow"], rec["job"], rec.get("run_id"), category, key,
                    minutes, actual, would_be, note)


def to_job_record(run: dict, job: dict) -> dict:
    """Adapt one GitHub API (run, job) pair into the flat shape `cost_one_job` consumes."""
    return {
        "workflow": run.get("name") or run.get("path") or "<unknown workflow>",
        "run_id": run.get("id"),
        "job": job.get("name") or "<unnamed job>",
        "labels": job.get("labels") or [],
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "conclusion": job.get("conclusion"),
    }


def band_for(total_would_be_usd: float) -> tuple:
    if total_would_be_usd >= HARD_CAP_USD:
        return ("hard-cap", 1)
    if total_would_be_usd >= REVIEW_USD:
        return ("review", 3)
    if total_would_be_usd >= SOFT_ALARM_USD:
        return ("soft-alarm", 2)
    return ("ok", 0)


def build_report(records: list, *, repo: str, period_days: int, since: datetime, until: datetime,
                  repo_is_private: Optional[bool], top_n: int = 10,
                  fetch_errors: Optional[list] = None,
                  latchkey_free_minutes_pool: int = LATCHKEY_FREE_MINUTES_PER_PERIOD,
                  latchkey_api: Optional[LatchkeyApiResult] = None) -> Report:
    costs = [cost_one_job(r, repo_is_private) for r in records]
    known = [c for c in costs if c.would_be_usd is not None]
    unbillable = [c for c in costs if c.would_be_usd is None and c.minutes is None]
    unknown = [c for c in costs if c.would_be_usd is None and c.minutes is not None]

    # Latchkey free-tier pool: shared across every latchkey job in the period, so it must be
    # applied in aggregate, not per-job -- see apply_latchkey_free_tier(). This is also where each
    # latchkey JobCost's `actual_usd` (left None by cost_one_job on purpose) gets filled in.
    latchkey_jobs = [c for c in known if c.category == "latchkey"]
    latchkey_minutes_total = sum(c.minutes for c in latchkey_jobs)
    latchkey_would_be_total = sum(c.would_be_usd for c in latchkey_jobs)
    latchkey_billable_minutes, latchkey_billable_fraction, _latchkey_actual_total = (
        apply_latchkey_free_tier(latchkey_minutes_total, latchkey_would_be_total, latchkey_free_minutes_pool)
    )
    for c in latchkey_jobs:
        c.actual_usd = c.would_be_usd * latchkey_billable_fraction

    total_would_be = sum(c.would_be_usd for c in known)
    total_actual = sum(c.actual_usd for c in known)

    by_category: dict = defaultdict(float)
    for c in known:
        by_category[c.category] += c.would_be_usd

    by_workflow: dict = defaultdict(float)
    for c in known:
        by_workflow[c.workflow] += c.would_be_usd
    top_workflows = sorted(by_workflow.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    # Band on the CENT-rounded total, not the raw float. Repeated minutes/60.0*rate arithmetic
    # lands a job-minute total that is exactly $100.00 in dollars-and-cents terms on
    # 99.99999999999999 in IEEE-754 terms (measured: 5000 latchkey-xlarge minutes), which would
    # silently misclassify a hard-cap breach as "review" one part in 1e15 below the line. A
    # financial control that can be defeated by float epsilon is worse than one that cannot run.
    band, exit_code = band_for(round(total_would_be, 2))

    latchkey_api = latchkey_api or LatchkeyApiResult(
        "not_available", None, f"Latchkey: UNAVAILABLE (set {LATCHKEY_TOKEN_ENV})"
    )

    warnings = [
        "EC2/AWS spend is NOT queried by this tool (no Cost Explorer, no EC2 API) -- the 'ec2' "
        "category below, if nonzero, only prices GitHub Actions jobs on the legacy busbar-xl "
        "self-hosted label, and is NOT a full AWS bill. See 'EC2 IS OVERFLOW-ONLY NOW' in the "
        "module docstring.",
        "Latchkey minutes/dollars below are a GitHub-Actions WALL-CLOCK ESTIMATE (started_at-> "
        "completed_at), not Latchkey's billed minutes -- it includes queue+provisioning wait "
        "Latchkey does not bill, and reads roughly 2.4x-3x high versus the Latchkey dashboard. "
        "Trust the dashboard for the real Latchkey bill; use this estimate only for relative "
        "ranking. See the module docstring for the full mechanism and citations.",
        "The free-tier-adjusted 'actual'/billable Latchkey figures below are EVEN LESS reliable "
        "than the would-be figures above them, not just as reliable: the free-tier pool is a "
        "FIXED subtraction, so applying it to an inflated (wall-clock) minute total leaves a "
        "disproportionately larger 'billable' remainder than applying it to Latchkey's true, "
        "smaller total would -- once the estimate is even modestly over the pool size, the error "
        "in 'billable minutes' can be many times larger than the error in the raw minute total. "
        "Do not treat the actual/billable figures here as a bill estimate; they exist only to "
        "show whether the pool looks close to exhausted, directionally.",
    ]
    if latchkey_api.status == "not_available":
        warnings.append(latchkey_api.detail)
    elif latchkey_api.status == "unavailable":
        warnings.append(f"Latchkey Jobs API cross-check requested but failed: {latchkey_api.detail}")

    return Report(
        repo=repo,
        period_days=period_days,
        since=since.isoformat(),
        until=until.isoformat(),
        generated_at=datetime.now(timezone.utc).isoformat(),
        repo_is_private=repo_is_private,
        total_actual_usd=total_actual,
        total_would_be_usd=total_would_be,
        band=band,
        exit_code=exit_code,
        thresholds={"soft_alarm": SOFT_ALARM_USD, "review": REVIEW_USD, "hard_cap": HARD_CAP_USD},
        by_category_would_be=dict(by_category),
        top_workflows=top_workflows,
        job_count=len(costs),
        unknown_job_count=len(unknown),
        unknown_labels=sorted({c.key for c in unknown}),
        unbillable_job_count=len(unbillable),
        fetch_errors=fetch_errors or [],
        latchkey_minutes_total=latchkey_minutes_total,
        latchkey_free_minutes_pool=latchkey_free_minutes_pool,
        latchkey_billable_minutes=latchkey_billable_minutes,
        latchkey_api=latchkey_api,
        warnings=warnings,
    )


# ── report printing -----------------------------------------------------------------------------
def print_human_report(report: Report) -> None:
    print(f"cost-watch: {report.repo}  period={report.period_days}d  "
          f"({report.since[:10]}..{report.until[:10]})")
    if report.repo_is_private is None:
        print("  repo visibility: UNKNOWN -- GitHub-hosted actual cost treated as PAID (conservative)")
    else:
        print(f"  repo visibility: {'private' if report.repo_is_private else 'public'}")
    print(f"  jobs measured: {report.job_count}  "
          f"(unknown-rate: {report.unknown_job_count}, unbillable/no-timestamp: {report.unbillable_job_count})")
    if report.unknown_labels:
        print(f"  unrecognised runner labels: {', '.join(report.unknown_labels)}")
    if report.fetch_errors:
        print(f"  fetch errors ({len(report.fetch_errors)}):")
        for e in report.fetch_errors[:10]:
            print(f"    {e}")
    print()
    print("  " + "#" * 78)
    print("  # EC2/AWS SPEND IS NOT INCLUDED IN THE TOTALS OR EXIT-CODE BAND BELOW.")
    print("  # This tool only prices GitHub Actions job data (Latchkey + GH-hosted + the legacy")
    print("  # busbar-xl EC2 label). It does not query AWS. See the 'EC2:' line further down.")
    print("  " + "#" * 78)
    print()
    print(f"  TOTAL actual (billed today, ESTIMATE -- see LATCHKEY below): ${report.total_actual_usd:,.4f}")
    print(f"  TOTAL would-be (list price, ESTIMATE):                       ${report.total_would_be_usd:,.4f}"
          f"   <- band is on this number")
    print(f"  thresholds: soft-alarm >= ${SOFT_ALARM_USD:.0f}, review >= ${REVIEW_USD:.0f}, "
          f"hard cap >= ${HARD_CAP_USD:.0f}")
    print()
    print("  by category (would-be $):")
    for cat, usd in sorted(report.by_category_would_be.items(), key=lambda kv: kv[1], reverse=True):
        print(f"    {cat:<16} ${usd:,.4f}")
    if "ec2" not in report.by_category_would_be:
        print(f"    {'ec2':<16} $0.0000  (no jobs on the '{EC2_FLEET_LABEL}' label this period)")
    print()
    print(f"  top workflows by would-be spend (top {len(report.top_workflows)}):")
    for i, (wf, usd) in enumerate(report.top_workflows, 1):
        print(f"    {i:>2}. {wf:<40} ${usd:,.4f}")
    print()
    print("  *** LATCHKEY MINUTES ARE A WALL-CLOCK ESTIMATE, NOT LATCHKEY'S BILLED MINUTES ***")
    print(f"  latchkey minutes this period (GH job started_at->completed_at, OVER-COUNTS ~2.4x-3x "
          f"vs Latchkey's real bill -- see module docstring): {report.latchkey_minutes_total:,}")
    print(f"  latchkey free-tier pool (LATCHKEY_FREE_MINUTES_PER_PERIOD, {LATCHKEY_FREE_MINUTES_BONUS_EXPIRES} "
          f"bonus-expiry caveat -- see the constant's citation): {report.latchkey_free_minutes_pool:,} min")
    print(f"  latchkey billable minutes (estimate, pool-adjusted):        {report.latchkey_billable_minutes:,}")
    print("  Trust the Latchkey dashboard for the real bill -- this tool cannot read it (no usage/"
          "billing API endpoint exists; see below).")
    print()
    print("  latchkey Jobs API cross-check (duration_ms basis, sample only -- never a period total):")
    if report.latchkey_api.status == "ok":
        print(f"    {report.latchkey_api.detail}")
        for size, stats in sorted(report.latchkey_api.sample.items()):
            if size == "unknown_size_jobs":
                continue
            if stats["jobs"]:
                print(f"    {size:<16} jobs={stats['jobs']:<5} minutes={stats['minutes']:<6} "
                      f"${stats['usd']:,.4f}")
        if report.latchkey_api.sample.get("unknown_size_jobs"):
            print(f"    unrecognised runner_size: {report.latchkey_api.sample['unknown_size_jobs']} job(s), not priced")
    else:
        print(f"    {report.latchkey_api.detail}")
    print()
    ec2_would_be = report.by_category_would_be.get("ec2", 0.0)
    print(f"  EC2: ${ec2_would_be:,.4f} this period (job-minutes estimate for the legacy "
          f"'{EC2_FLEET_LABEL}' self-hosted label ONLY -- NOT a full AWS bill; this tool does not "
          f"query AWS). Fleet is OVERFLOW-ONLY now -- owner confirmed 2026-09-21 zero running/"
          f"stopped EC2 instances; Latchkey is primary.")
    print()
    if report.warnings:
        print("  WARNINGS:")
        for w in report.warnings:
            print(f"    - {w}")
        print()
    label = {
        "ok": "GREEN -- under $50",
        "soft-alarm": f"SOFT-ALARM -- would-be total >= ${SOFT_ALARM_USD:.0f}",
        "review": f"REVIEW -- would-be total >= ${REVIEW_USD:.0f}",
        "hard-cap": (f"HARD CAP BREACH -- would-be total >= ${HARD_CAP_USD:.0f}. "
                     "DECISIONS #78: find the top workflow above and cut its trigger/right-size."),
    }[report.band]
    print(f"  VERDICT: {label}  (exit {report.exit_code})")


# ── main ------------------------------------------------------------------------------------------
def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=None, help="OWNER/NAME; default $GITHUB_REPOSITORY or origin remote")
    ap.add_argument("--period", type=int, default=7, metavar="DAYS")
    ap.add_argument("--top", type=int, default=10, metavar="N")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true",
                     help="prove the four money bands and the rounding/classification rules, then exit")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()

    if a.period <= 0:
        print(f"cost-watch: RED -- --period must be a positive number of days, got {a.period}",
              file=sys.stderr)
        return 4

    repo = a.repo or default_repo()
    if not repo:
        print("cost-watch: RED -- no --repo given and none could be derived "
              "($GITHUB_REPOSITORY unset, no origin remote)", file=sys.stderr)
        return 4

    until = datetime.now(timezone.utc)
    since = until - timedelta(days=a.period)

    fetch_errors: list = []
    try:
        repo_is_private = fetch_repo_is_private(repo)
    except RuntimeError as e:
        fetch_errors.append(str(e))
        repo_is_private = None

    try:
        runs = fetch_completed_runs(repo, since.date().isoformat())
    except RuntimeError as e:
        print(f"cost-watch: RED -- could not fetch workflow runs for {repo}: {e}", file=sys.stderr)
        return 4

    records = []
    for run in runs:
        created_at = run.get("created_at")
        if created_at:
            try:
                if _parse_gh_ts(created_at) < since:
                    continue  # belt-and-braces: the server-side `created` filter already does this
            except ValueError:
                pass
        try:
            jobs = fetch_jobs_for_run(repo, run.get("id"))
        except RuntimeError as e:
            fetch_errors.append(str(e))
            continue
        for job in jobs:
            records.append(to_job_record(run, job))

    # Optional, read-only Latchkey Jobs API cross-check -- see fetch_latchkey_jobs_sample()'s
    # docstring. Cheap (one GET), so it is always attempted, never gated behind a flag; it degrades
    # to "not_available" rather than erroring when LATCHKEY_API_TOKEN is unset (the common case in
    # CI today -- this workflow does not set that secret).
    latchkey_api = fetch_latchkey_jobs_sample()

    report = build_report(records, repo=repo, period_days=a.period, since=since, until=until,
                           repo_is_private=repo_is_private, top_n=a.top, fetch_errors=fetch_errors,
                           latchkey_api=latchkey_api)

    if a.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print_human_report(report)

    return report.exit_code


# ══ SELF-TEST ══ a cost figure nothing has watched be wrong is a guess with a dollar sign on it.
#
# Two layers:
#   1. PURE-FUNCTION cases: job_minutes' rounding, classify_runner's table lookups, cost_one_job's
#      pricing (including the actual-vs-would-be split and the unknown-label refusal), band_for's
#      four boundaries, and build_report's aggregation -- all called directly, no subprocess.
#   2. END-TO-END cases: the real `main()`, through the real `gh_api_lines()`, pointed at a fake
#      `gh` planted on $PATH (`_install_fake_gh`) -- the same shim style
#      `scripts/promote-selftest.sh` uses for `gh`. This proves the wiring (path construction,
#      NDJSON parsing, the run->job adapter, the exit-code contract) end to end without a real
#      network call.
def _install_fake_gh(tmp: Path, *, runs: list, jobs_by_run: dict, private: bool) -> str:
    """Write a fake `gh` that serves the given fixtures, return the bin dir to prepend to $PATH."""
    bindir = tmp / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    fixtures = tmp / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)

    runs_file = fixtures / "runs.ndjson"
    runs_file.write_text("\n".join(json.dumps(r) for r in runs) + ("\n" if runs else ""),
                          encoding="utf-8")

    jobs_dir = fixtures / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    for run_id, jobs in jobs_by_run.items():
        (jobs_dir / f"{run_id}.ndjson").write_text(
            "\n".join(json.dumps(j) for j in jobs) + ("\n" if jobs else ""), encoding="utf-8"
        )

    (fixtures / "private.txt").write_text("true" if private else "false", encoding="utf-8")

    shim = bindir / "gh"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        "set -uo pipefail\n"
        f'RUNS_FILE="{runs_file}"\n'
        f'JOBS_DIR="{jobs_dir}"\n'
        f'PRIVATE_FILE="{fixtures / "private.txt"}"\n'
        'if [ "${1:-}" != "api" ]; then echo "fake gh: unsupported: $*" >&2; exit 1; fi\n'
        'shift\n'
        'path=""; jq_expr=""\n'
        'while [ $# -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    --paginate) shift ;;\n'
        '    --jq) jq_expr="$2"; shift 2 ;;\n'
        '    *) path="$1"; shift ;;\n'
        '  esac\n'
        'done\n'
        'if [[ "$path" == *"/actions/runs/"*"/jobs"* ]]; then\n'
        '  run_id="$(printf %s "$path" | sed -E "s#.*/actions/runs/([0-9]+)/jobs.*#\\1#")"\n'
        '  f="$JOBS_DIR/$run_id.ndjson"\n'
        '  [ -f "$f" ] && cat "$f"\n'
        '  exit 0\n'
        'fi\n'
        'if [[ "$path" == *"/actions/runs?"* ]]; then cat "$RUNS_FILE"; exit 0; fi\n'
        'if [[ "$jq_expr" == ".private" ]]; then cat "$PRIVATE_FILE"; echo; exit 0; fi\n'
        'echo "fake gh: unrecognised: path=$path jq=$jq_expr" >&2\n'
        'exit 1\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return str(bindir)


def _run_main_under_shim(tmp: Path, argv: list, *, runs: list, jobs_by_run: dict, private: bool):
    """Run main(argv) with `gh` shimmed to serve the given fixtures; return (exit_code, stdout).

    Also force-clears LATCHKEY_TOKEN_ENV for the duration of the call: --selftest must never touch
    the real network, and main() always attempts the optional Latchkey Jobs API cross-check -- if
    the token happened to be exported in whatever environment runs --selftest, this would otherwise
    make a real HTTP call. `not_available` is the only outcome --selftest may observe from it.
    """
    import contextlib
    import io

    bindir = _install_fake_gh(tmp, runs=runs, jobs_by_run=jobs_by_run, private=private)
    old_path = os.environ.get("PATH", "")
    old_token = os.environ.pop(LATCHKEY_TOKEN_ENV, None)
    os.environ["PATH"] = f"{bindir}{os.pathsep}{old_path}"
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            code = main(argv)
    finally:
        os.environ["PATH"] = old_path
        if old_token is not None:
            os.environ[LATCHKEY_TOKEN_ENV] = old_token
    return code, buf.getvalue()


def _mk_run(run_id: int, name: str) -> dict:
    # created_at must be "recent" relative to whenever the selftest actually runs, or main()'s
    # belt-and-braces `created_at < since` check (real code, exercised on purpose) would drop the
    # fixture and every case below would silently price at $0 instead of proving anything.
    created = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return {"id": run_id, "name": name, "created_at": created, "status": "completed"}


def _mk_job(name: str, label, minutes: int, *, conclusion: str = "success") -> dict:
    """`label` is either one label (str) or the full label list (for multi-label fleets like EC2's
    `["self-hosted", "linux", "x64", "busbar-xl"]`)."""
    started = datetime(2026, 9, 15, tzinfo=timezone.utc)
    ended = started + timedelta(minutes=minutes)
    return {
        "name": name,
        "labels": label if isinstance(label, list) else [label],
        "conclusion": conclusion,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": ended.isoformat().replace("+00:00", "Z"),
    }


def selftest() -> int:
    import tempfile

    print("== cost-watch SELF-TEST ==")
    bad = 0

    def say(ok: bool, msg: str) -> None:
        nonlocal bad
        print(("PASS  " if ok else "FAIL  ") + msg)
        if not ok:
            bad += 1

    # ── 1. job_minutes: rounding UP to the minute, per DECISIONS #78 ──────────────────────────
    def dur(seconds: int) -> tuple:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(seconds=seconds)
        return start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")

    for seconds, want in ((1, 1), (59, 1), (60, 1), (61, 2), (120, 2), (121, 3)):
        s, e = dur(seconds)
        got = job_minutes(s, e, "success")
        say(got == want, f"job_minutes: {seconds}s rounds up to {want}min (got {got})")

    say(job_minutes("2026-01-01T00:00:00Z", "2026-01-01T05:00:00Z", "skipped") == 0,
        "job_minutes: a skipped job never provisioned a runner -- 0, not excluded")
    say(job_minutes(None, "2026-01-01T00:00:00Z", "success") is None,
        "job_minutes: missing started_at -- unbillable (None), not guessed")
    say(job_minutes("2026-01-01T00:00:00Z", None, "success") is None,
        "job_minutes: missing completed_at -- unbillable (None), not guessed")

    # ── 2. classify_runner: table lookups, and unknowns stay unknown ──────────────────────────
    say(classify_runner(["latchkey-xlarge"]) == ("latchkey", "latchkey-xlarge"),
        "classify_runner: latchkey-xlarge -> latchkey")
    say(classify_runner(["ubuntu-latest"]) == ("github-hosted", "ubuntu-latest"),
        "classify_runner: ubuntu-latest -> github-hosted")
    say(classify_runner(["windows-2022"]) == ("github-hosted", "windows-2022"),
        "classify_runner: windows-2022 -> github-hosted")
    say(classify_runner(["mystery-box"]) == ("unknown", "mystery-box"),
        "classify_runner: an unrecognised label is unknown, not guessed")
    say(classify_runner(["latchkey-nano"]) == ("unknown", "latchkey-nano"),
        "classify_runner: a Latchkey SIZE this table does not know is unknown, not guessed")
    say(classify_runner([]) == ("unknown", "<no-labels>"),
        "classify_runner: no labels at all is unknown")
    say(classify_runner(["self-hosted", "linux", "x64", "busbar-xl"]) == ("ec2", "busbar-xl"),
        "classify_runner: this repo's EC2 fleet's real 4-label set -> ec2 (order-independent)")
    say(classify_runner(["busbar-xl", "x64", "linux", "self-hosted"]) == ("ec2", "busbar-xl"),
        "classify_runner: the same 4 labels in a DIFFERENT order still classify as ec2")
    say(classify_runner(["self-hosted", "linux", "x64"])[0] == "unknown",
        "classify_runner: self-hosted WITHOUT the busbar-xl pairing is unknown, not guessed")

    # ── 3. cost_one_job: pricing, actual-vs-would-be split, the public-repo $0 rule ───────────
    rec = to_job_record(_mk_run(1, "wf"), _mk_job("j", "latchkey-large", 60))
    c = cost_one_job(rec, repo_is_private=False)
    say(abs(c.would_be_usd - 0.60) < 1e-9,
        f"cost_one_job: latchkey-large x 60min = $0.60 would-be (got {c.would_be_usd})")
    say(c.actual_usd is None,
        "cost_one_job: latchkey actual is deferred (None) until build_report applies the free-tier pool")

    rec = to_job_record(_mk_run(1, "wf"), _mk_job("j", "ubuntu-latest", 10))
    c_public = cost_one_job(rec, repo_is_private=False)
    say(abs(c_public.would_be_usd - 0.06) < 1e-9,
        f"cost_one_job: ubuntu-latest x 10min = $0.06 would-be (got {c_public.would_be_usd})")
    say(c_public.actual_usd == 0.0,
        "cost_one_job: github-hosted actual is $0 on a PUBLIC repo")
    c_private = cost_one_job(rec, repo_is_private=True)
    say(c_private.actual_usd == c_private.would_be_usd,
        "cost_one_job: github-hosted actual == would-be on a PRIVATE repo")
    c_unknown_vis = cost_one_job(rec, repo_is_private=None)
    say(c_unknown_vis.actual_usd == c_unknown_vis.would_be_usd,
        "cost_one_job: unknown repo visibility is treated as paid (conservative), not free")

    rec = to_job_record(_mk_run(1, "wf"), _mk_job("j", "mystery-box", 60))
    c_unk = cost_one_job(rec, repo_is_private=False)
    say(c_unk.would_be_usd is None and c_unk.actual_usd is None,
        "cost_one_job: an unrecognised label prices as unknown, never a guessed number")

    rec = to_job_record(_mk_run(1, "wf"),
                         _mk_job("j", ["self-hosted", "linux", "x64", "busbar-xl"], 60))
    c_ec2 = cost_one_job(rec, repo_is_private=False)
    say(abs(c_ec2.would_be_usd - EC2_SPOT_PER_SLOT_HOURLY) < 1e-9,
        f"cost_one_job: ec2 busbar-xl x 60min = ${EC2_SPOT_PER_SLOT_HOURLY:.5f} would-be "
        f"(got {c_ec2.would_be_usd})")
    say(c_ec2.actual_usd == c_ec2.would_be_usd,
        "cost_one_job: ec2 actual == would-be -- real AWS spend, no beta credit covers it")

    # ── 4. band_for: the four DECISIONS #78 bands, at their exact boundaries ──────────────────
    for total, want_band, want_code in (
        (0.0, "ok", 0), (49.99, "ok", 0),
        (50.0, "soft-alarm", 2), (79.99, "soft-alarm", 2),
        (80.0, "review", 3), (99.99, "review", 3),
        (100.0, "hard-cap", 1), (250.0, "hard-cap", 1),
    ):
        band, code = band_for(total)
        say((band, code) == (want_band, want_code),
            f"band_for(${total}) == ({want_band!r}, {want_code}) (got {(band, code)})")

    # ── 5. build_report: aggregation, top-workflow ranking, unknown/unbillable accounting ─────
    records = [
        to_job_record(_mk_run(1, "big-spender"), _mk_job("a", "latchkey-xlarge", 100)),
        to_job_record(_mk_run(1, "big-spender"), _mk_job("b", "latchkey-large", 50)),
        to_job_record(_mk_run(2, "small-spender"), _mk_job("c", "latchkey-small", 10)),
        to_job_record(_mk_run(3, "mystery-workflow"), _mk_job("d", "some-custom-label", 40)),
        to_job_record(_mk_run(4, "broken-job"), {"name": "e", "labels": ["latchkey-small"],
                                                  "conclusion": "failure",
                                                  "started_at": None, "completed_at": None}),
        to_job_record(_mk_run(5, "ec2-legacy-job"),
                      _mk_job("f", ["self-hosted", "linux", "x64", "busbar-xl"], 60)),
    ]
    since = datetime(2026, 9, 14, tzinfo=timezone.utc)
    until = datetime(2026, 9, 21, tzinfo=timezone.utc)
    report = build_report(records, repo="acme/example", period_days=7, since=since, until=until,
                           repo_is_private=False, top_n=5)
    want_total = (100 / 60.0 * 1.20) + (50 / 60.0 * 0.60) + (10 / 60.0 * 0.15) + EC2_SPOT_PER_SLOT_HOURLY
    say(abs(report.total_would_be_usd - want_total) < 1e-6,
        f"build_report: would-be total sums known jobs only (got {report.total_would_be_usd}, want {want_total})")
    say(report.top_workflows[0][0] == "big-spender",
        f"build_report: top workflow ranked first by spend (got {report.top_workflows[0][0]!r})")
    say(report.unknown_job_count == 1, "build_report: the unrecognised-label job is counted unknown")
    say(report.unbillable_job_count == 1, "build_report: the no-timestamp job is counted unbillable")
    say(report.unknown_labels == ["some-custom-label"],
        f"build_report: unknown labels are named (got {report.unknown_labels})")
    say(report.job_count == 6, "build_report: every job is counted, priced or not")
    say(abs(report.by_category_would_be.get("ec2", 0) - EC2_SPOT_PER_SLOT_HOURLY) < 1e-9,
        "build_report: the ec2 category is broken out separately, per-task requirement")
    say(abs(report.total_actual_usd - (EC2_SPOT_PER_SLOT_HOURLY)) < 1e-9,
        f"build_report: actual total is EC2-only here (the 160 latchkey minutes in this fixture "
        f"are fully inside the default 32,000min free-tier pool; gh-hosted is $0, public repo) "
        f"(got {report.total_actual_usd})")
    say(report.latchkey_minutes_total == 160,
        f"build_report: latchkey_minutes_total sums every latchkey job's minutes (got {report.latchkey_minutes_total})")
    say(report.latchkey_billable_minutes == 0,
        "build_report: 160 latchkey minutes is fully inside the default free-tier pool -- 0 billable")
    say(report.latchkey_api.status == "not_available",
        "build_report: with no latchkey_api passed in, it defaults to not_available, never silently omitted")
    say(any("EC2/AWS spend is NOT queried" in w for w in report.warnings),
        "build_report: the EC2-not-included warning is always present")
    say(any("WALL-CLOCK ESTIMATE" in w for w in report.warnings),
        "build_report: the latchkey wall-clock-overcount warning is always present")

    # ── 5b. apply_latchkey_free_tier: the free-minute pool, pure ──────────────────────────────
    say(apply_latchkey_free_tier(0, 0.0, 32000) == (0, 0.0, 0.0),
        "apply_latchkey_free_tier: no latchkey minutes -> nothing billable")
    b_min, b_frac, b_actual = apply_latchkey_free_tier(100, 10.0, 32000)
    say((b_min, b_actual) == (0, 0.0),
        f"apply_latchkey_free_tier: 100min well inside a 32000min pool -> fully free (got {(b_min, b_actual)})")
    b_min, b_frac, b_actual = apply_latchkey_free_tier(40000, 400.0, 32000)
    say(b_min == 8000, f"apply_latchkey_free_tier: 40000min - 32000min pool = 8000 billable (got {b_min})")
    say(abs(b_frac - 0.2) < 1e-9,
        f"apply_latchkey_free_tier: 8000/40000 = 0.2 billable fraction (got {b_frac})")
    say(abs(b_actual - 80.0) < 1e-9,
        f"apply_latchkey_free_tier: $400 would-be x 0.2 billable fraction = $80 actual (got {b_actual})")

    # ── 5c. build_report with an injected small free-tier pool (the real 32000 pool would need
    #        32000 minutes of fixture jobs to ever go billable) ──────────────────────────────
    big_latchkey_records = [
        to_job_record(_mk_run(9, "xlarge-heavy"), _mk_job("z", "latchkey-xlarge", 6000)),  # 6000min
    ]
    report_small_pool = build_report(big_latchkey_records, repo="acme/example", period_days=7,
                                      since=since, until=until, repo_is_private=False, top_n=5,
                                      latchkey_free_minutes_pool=1000)
    want_would_be = 6000 / 60.0 * LATCHKEY_HOURLY["latchkey-xlarge"]
    want_billable_minutes = 6000 - 1000
    want_fraction = want_billable_minutes / 6000
    want_actual = want_would_be * want_fraction
    say(abs(report_small_pool.total_would_be_usd - want_would_be) < 1e-6,
        f"build_report: would-be total is unaffected by the free-tier pool (got {report_small_pool.total_would_be_usd})")
    say(report_small_pool.latchkey_billable_minutes == want_billable_minutes,
        f"build_report: billable minutes = total - pool (got {report_small_pool.latchkey_billable_minutes}, want {want_billable_minutes})")
    say(abs(report_small_pool.total_actual_usd - want_actual) < 1e-6,
        f"build_report: actual total reflects the injected free-tier pool (got {report_small_pool.total_actual_usd}, want {want_actual})")

    # ── 5d. latchkey_sample_job_minutes / price_latchkey_jobs_sample: the duration_ms basis ────
    say(latchkey_sample_job_minutes(0) == 0, "latchkey_sample_job_minutes: 0ms is 0min, not guessed")
    say(latchkey_sample_job_minutes("3000") == 1,
        "latchkey_sample_job_minutes: duration_ms as a STRING (F2) still parses -- 3000ms -> 1min")
    say(latchkey_sample_job_minutes(61000) == 2, "latchkey_sample_job_minutes: 61000ms rounds up to 2min")
    say(latchkey_sample_job_minutes(None) == 0, "latchkey_sample_job_minutes: missing duration -- 0, not guessed")

    sample_jobs = [
        {"runner_size": "xlarge", "duration_ms": "660000"},   # 11min
        {"runner_size": "xlarge", "duration_ms": "60000"},    # 1min
        {"runner_size": "large", "duration_ms": "30000"},     # 1min (rounds up)
        {"runner_size": "small", "duration_ms": "0"},         # 0min
        {"runner_size": "nano", "duration_ms": "5000"},       # unrecognised size
    ]
    priced = price_latchkey_jobs_sample(sample_jobs)
    say(priced["latchkey-xlarge"]["jobs"] == 2 and priced["latchkey-xlarge"]["minutes"] == 12,
        f"price_latchkey_jobs_sample: 2 xlarge jobs, 12 total minutes (got {priced['latchkey-xlarge']})")
    say(abs(priced["latchkey-xlarge"]["usd"] - (12 / 60.0 * LATCHKEY_HOURLY["latchkey-xlarge"])) < 1e-9,
        f"price_latchkey_jobs_sample: xlarge sample priced at the measured rate (got {priced['latchkey-xlarge']['usd']})")
    say(priced["latchkey-large"]["jobs"] == 1 and priced["latchkey-large"]["minutes"] == 1,
        "price_latchkey_jobs_sample: large job rounds 30000ms up to 1min")
    say(priced["latchkey-small"]["jobs"] == 1 and priced["latchkey-small"]["minutes"] == 0,
        "price_latchkey_jobs_sample: a genuinely 0ms job bills 0min, not excluded")
    say(priced["unknown_size_jobs"] == 1,
        f"price_latchkey_jobs_sample: an unrecognised runner_size is counted, never priced at a guess (got {priced['unknown_size_jobs']})")

    # ── 5e. fetch_latchkey_jobs_sample: no LATCHKEY_API_TOKEN -> not_available, never a network call ──
    old_token = os.environ.pop(LATCHKEY_TOKEN_ENV, None)
    try:
        lk = fetch_latchkey_jobs_sample()
    finally:
        if old_token is not None:
            os.environ[LATCHKEY_TOKEN_ENV] = old_token
    say(lk.status == "not_available",
        f"fetch_latchkey_jobs_sample: no {LATCHKEY_TOKEN_ENV} -> not_available (got {lk.status})")
    say(LATCHKEY_TOKEN_ENV in lk.detail,
        f"fetch_latchkey_jobs_sample: detail names the exact env var to set (got {lk.detail!r})")
    say(lk.sample is None, "fetch_latchkey_jobs_sample: not_available never reports a (silently-zero) sample")

    # ── 6. main() argument validation, no network needed ──────────────────────────────────────
    say(main(["--period", "0", "--repo", "acme/example"]) == 4,
        "main: --period 0 is refused with the tool-error exit code (4), not a money band")

    # ── 7. end-to-end through a shimmed `gh`, all the way to the exit code ────────────────────
    with tempfile.TemporaryDirectory(prefix="cost-watch-selftest-") as td:
        tmp = Path(td)

        # 7a. a small, well-under-$50 period -> exit 0, "ok"
        runs = [_mk_run(101, "tiny-ci")]
        jobs = {101: [_mk_job("build", "latchkey-small", 10)]}
        code, out = _run_main_under_shim(tmp, ["--repo", "acme/example", "--period", "7"],
                                          runs=runs, jobs_by_run=jobs, private=False)
        say(code == 0, f"end-to-end: a tiny period exits 0 (got {code})\n{out if code != 0 else ''}")
        say("GREEN" in out, "end-to-end: the ok band prints GREEN")

        # 7b. enough latchkey-xlarge minutes to land exactly on each boundary, one run at a time
        for minutes, want_code, want_marker in (
            (2499, 0, "GREEN"),           # $49.98 -- under
            (2500, 2, "SOFT-ALARM"),      # $50.00 exactly
            (4000, 3, "REVIEW"),          # $80.00 exactly
            (5000, 1, "HARD CAP"),        # $100.00 exactly
        ):
            runs = [_mk_run(202, "the-expensive-one")]
            jobs = {202: [_mk_job("compile", "latchkey-xlarge", minutes)]}
            code, out = _run_main_under_shim(tmp, ["--repo", "acme/example", "--period", "7"],
                                              runs=runs, jobs_by_run=jobs, private=False)
            say(code == want_code,
                f"end-to-end: {minutes}min latchkey-xlarge -> exit {want_code} (got {code})")
            say(want_marker in out,
                f"end-to-end: {minutes}min latchkey-xlarge report names {want_marker!r}")

        # 7c. --json is valid JSON, and its exit_code field agrees with the process exit code
        runs = [_mk_run(303, "hard-cap-wf")]
        jobs = {303: [_mk_job("compile", "latchkey-xlarge", 5000)]}
        code, out = _run_main_under_shim(tmp, ["--repo", "acme/example", "--period", "7", "--json"],
                                          runs=runs, jobs_by_run=jobs, private=False)
        try:
            doc = json.loads(out)
            say(doc.get("exit_code") == code == 1,
                f"end-to-end --json: exit_code field ({doc.get('exit_code')}) matches process exit ({code})")
            say(abs(doc.get("total_would_be_usd", 0) - 100.0) < 1e-6,
                f"end-to-end --json: total_would_be_usd is $100.00 (got {doc.get('total_would_be_usd')})")
        except json.JSONDecodeError as e:
            say(False, f"end-to-end --json: output did not parse as JSON ({e})")

        # 7d. repo visibility flows through: same job, private repo -> actual == would-be
        runs = [_mk_run(404, "priv-wf")]
        jobs = {404: [_mk_job("build", "ubuntu-latest", 100)]}
        code, out = _run_main_under_shim(tmp, ["--repo", "acme/example", "--period", "7", "--json"],
                                          runs=runs, jobs_by_run=jobs, private=True)
        doc = json.loads(out)
        say(abs(doc["total_actual_usd"] - doc["total_would_be_usd"]) < 1e-9,
            "end-to-end: a PRIVATE repo bills github-hosted actual == would-be")

        # 7e. the real 4-label EC2 fleet shape, through the full fetch->adapt->price->band path,
        # and its actual_usd is REAL (unlike latchkey/github-hosted on this repo today).
        runs = [_mk_run(505, "legacy-ec2-workflow")]
        jobs = {505: [_mk_job("build", ["self-hosted", "linux", "x64", "busbar-xl"], 60)]}
        code, out = _run_main_under_shim(tmp, ["--repo", "acme/example", "--period", "7", "--json"],
                                          runs=runs, jobs_by_run=jobs, private=False)
        doc = json.loads(out)
        # --json rounds to 4dp (round(EC2_SPOT_PER_SLOT_HOURLY, 4) == 0.1593, not 0.15925), so the
        # tolerance is against the rounded figure, not the raw rate.
        say(abs(doc["total_would_be_usd"] - round(EC2_SPOT_PER_SLOT_HOURLY, 4)) < 1e-9,
            f"end-to-end: a real-shape EC2 job prices at ${EC2_SPOT_PER_SLOT_HOURLY:.5f} "
            f"(got {doc['total_would_be_usd']})")
        say(abs(doc["total_actual_usd"] - doc["total_would_be_usd"]) < 1e-9,
            "end-to-end: EC2 actual == would-be even though this run is NOT marked private "
            "-- EC2 is real spend regardless of repo visibility or the Latchkey free-tier pool")
        say(doc["by_category_would_be_usd"].get("ec2") is not None,
            "end-to-end --json: the ec2 category appears in by_category_would_be_usd")

    print()
    if bad:
        print(f"cost-watch selftest: RED ({bad} case(s) failed)")
        return 1
    print("cost-watch selftest: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
