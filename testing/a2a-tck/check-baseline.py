#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Compare an a2a-tck compatibility report against a pinned baseline.

WHY A BASELINE AND NOT "THE TCK MUST BE GREEN". The official TCK is not green against any
implementation we have, including the pinned third-party control it is pointed at here. That is
not a reason to skip it: a suite whose result is UNCHANGING is still a gate, because the thing a
gate has to catch is a CHANGE. So the control leg pins the exact per-requirement verdict map, and
any movement in either direction -- a requirement that started failing, a requirement that started
passing, a requirement that appeared or vanished -- is a human's problem before any subject result
is believed.

THE FAILURE MODE THIS FILE EXISTS TO PREVENT. The TCK reports a transport with 0 of 72 tests
executed as a tick:

    grpc:          0/72 (72 skipped) OK

A comparison that only looked at PASS/FAIL would read that as success. So equality is checked on
the FULL requirement set, and two independent FLOORS are enforced on top of it: how many
requirements must exist at all, and how many must have actually EXECUTED (status not SKIP). A run
that executes nothing cannot match a baseline that executed something, and a baseline that itself
recorded nothing is refused at load time.

A REPORT IS ONLY EVIDENCE OF THE RUN THAT WROTE IT. The runner's output directory lives in a
persistent cache, so a suite that crashes before writing its report would otherwise leave the last
good run's report in place, and comparing that against the baseline would match. The runner removes
the report before the suite starts AND passes `--run-started`; a report whose modification time is
older than that moment is refused here, whichever of the two the next edit breaks.

A BASELINE IS ONLY A BASELINE OF WHAT IT SAYS IT IS OF. It records the suite commit, the control and
the time zone it was measured under; the runner states the same three for the run in front of it
(`A2A_TCK_REF`, `A2A_TCK_CONTROL`, `TZ`), and any disagreement refuses the comparison rather than
judging one peer against another peer's pin.

USAGE
    check-baseline.py --report <compatibility.json> --baseline <baseline.json> --run-started <epoch>
    check-baseline.py --record --report <compatibility.json> --baseline <out.json> \
        --label "<what this baseline is of>" --run-started <epoch>
    check-baseline.py --report-only --report <compatibility.json> --run-started <epoch>
        (a leg that is reported and never pinned: the report must exist, be this run's, be an
        a2a-tck report, and clear the plausibility minimums -- nothing is compared. Its one caller,
        `run-tck.sh control-scenario`, is run by hand and not in CI; in CI this mode is exercised
        only by the selftests)

EXIT
    0  identical to the baseline, and the floors held (or, --report-only, the report is usable)
    1  a difference, or a floor breached
    2  the comparison could not be made at all (missing/empty/malformed/stale input, or a
       baseline of something other than this run)
"""

import argparse
import json
import os
import sys


# A baseline that recorded fewer executed requirements than this is not a baseline, it is a
# record of a broken run being blessed. Chosen well below what the pinned control executes -- 73 on
# HTTP+JSON and 78 on JSON-RPC, the `floor_executed` its two baselines record -- so it fails on a
# collapse rather than on ordinary movement.
MIN_PLAUSIBLE_EXECUTED = 40

# Likewise for the total discovered requirement set. The pinned TCK declares 129 requirements (the
# `floor_total` both baselines record); a report carrying a handful means discovery broke, not that
# the spec shrank.
MIN_PLAUSIBLE_TOTAL = 100

# The provenance a baseline records and the runner states for the run in front of it:
# (baseline key, environment variable the runner sets).
PROVENANCE = (("tck_ref", "A2A_TCK_REF"), ("control", "A2A_TCK_CONTROL"), ("tz", "TZ"))

# Statuses that mean NOTHING RAN. `NOT TESTED` is on this list because it was found here the
# expensive way: the first cut of this file counted it as executed, and the "100 of 129 executed"
# floor it produced was really 73 -- 27 requirements the TCK had reported as untested were being
# counted as evidence. Normalised (upper, spaces to underscores) before lookup, so a status the
# TCK renders as `NOT TESTED` and one it renders as `not_tested` cannot land on opposite sides.
SKIP_STATUSES = {"SKIP", "SKIPPED", "NOT_APPLICABLE", "NOT_RUN", "NOT_TESTED", "UNKNOWN", ""}


def _norm(status):
    return str(status).strip().upper().replace(" ", "_").replace("-", "_")


def die(msg, code=2):
    sys.stderr.write("\n" + "=" * 78 + "\n")
    sys.stderr.write("A2A TCK BASELINE CHECK CANNOT RUN\n")
    sys.stderr.write("=" * 78 + "\n")
    sys.stderr.write(msg.rstrip() + "\n")
    sys.stderr.write("=" * 78 + "\n\n")
    sys.exit(code)


def load_json(path, what):
    if not os.path.exists(path):
        die("The %s does not exist: %s\n\n"
            "Nothing was compared. This is RED because the check could not run, not "
            "because a requirement regressed." % (what, path))
    if os.path.getsize(path) == 0:
        die("The %s is EMPTY: %s\n\n"
            "A zero-byte report is what a crashed run leaves behind. It is not a pass."
            % (what, path))
    try:
        with open(path) as fh:
            return json.load(fh)
    except ValueError as exc:
        die("The %s is not valid JSON (%s): %s" % (what, exc, path))


def load_report(path, run_started):
    """The report, refused unless it was written by the run that started at `run_started`."""
    report = load_json(path, "report")
    written = os.path.getmtime(path)
    if written < run_started:
        die("The report PREDATES this run: %s was written at %d, the run started at %d.\n\n"
            "A report older than the run is an earlier run's report. It is what a suite that "
            "crashed before writing anything leaves behind, and it is not a pass."
            % (path, int(written), run_started))
    return report


def stated_provenance():
    """The run's own provenance, as the runner states it; refused when any part is unstated."""
    out = {}
    for key, env in PROVENANCE:
        val = os.environ.get(env, "")
        if not val:
            die("%s is not set. The runner states the suite commit (A2A_TCK_REF), the control "
                "(A2A_TCK_CONTROL) and the time zone (TZ) of every run, so that a baseline is "
                "only ever compared with, or recorded from, the run it describes." % env)
        out[key] = val
    return out


def statuses(report):
    """requirement id -> status, from a TCK compatibility.json."""
    per = report.get("per_requirement")
    if not isinstance(per, dict):
        die("The report has no `per_requirement` object. This is not an a2a-tck "
            "compatibility report, or the TCK's report shape changed -- either way a "
            "human has to look before any verdict here means anything.")
    out = {}
    for req, body in per.items():
        if not isinstance(body, dict) or "status" not in body:
            die("Requirement %r has no `status`. The TCK's report shape changed." % req)
        out[req] = body["status"]
    return out


def executed_count(st):
    return sum(1 for s in st.values() if _norm(s) not in SKIP_STATUSES)


def record(args):
    report = load_report(args.report, args.run_started)
    prov = stated_provenance()
    st = statuses(report)
    ex = executed_count(st)
    if len(st) < MIN_PLAUSIBLE_TOTAL:
        die("Refusing to record a baseline from a run that discovered only %d "
            "requirements (floor %d). Recording this would pin the broken run as the "
            "expectation." % (len(st), MIN_PLAUSIBLE_TOTAL))
    if ex < MIN_PLAUSIBLE_EXECUTED:
        die("Refusing to record a baseline from a run that EXECUTED only %d requirements "
            "(floor %d); %d were skipped. A baseline of a run that did nothing is a "
            "licence to do nothing forever." % (ex, MIN_PLAUSIBLE_EXECUTED, len(st) - ex))
    out = {
        "label": args.label,
        "recorded_by": "testing/a2a-tck/check-baseline.py --record",
        "tck_ref": prov["tck_ref"],
        "control": prov["control"],
        "tz": prov["tz"],
        "floor_total": len(st),
        "floor_executed": ex,
        "summary": report.get("summary", {}),
        "per_requirement": dict(sorted(st.items())),
    }
    with open(args.baseline, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("recorded %s: %d requirements, %d executed, %d skipped"
          % (args.baseline, len(st), ex, len(st) - ex))
    return 0


def check(args):
    report = load_report(args.report, args.run_started)
    base = load_json(args.baseline, "baseline")

    prov = stated_provenance()
    for key, env in PROVENANCE:
        pinned = base.get(key, "")
        if pinned != prov[key]:
            die("PROVENANCE: the baseline was recorded with %s=%r and this run states %s=%r "
                "(%s).\n\nA baseline of a different suite commit, control or time zone is not an "
                "expectation for this run; comparing the two would judge one peer against "
                "another's pin." % (key, pinned, env, prov[key], args.baseline))

    got = statuses(report)
    want = base.get("per_requirement")
    if not isinstance(want, dict) or not want:
        die("The baseline carries no `per_requirement` map: %s" % args.baseline)

    floor_total = int(base.get("floor_total", 0))
    floor_exec = int(base.get("floor_executed", 0))
    if floor_total < MIN_PLAUSIBLE_TOTAL or floor_exec < MIN_PLAUSIBLE_EXECUTED:
        die("The baseline's own floors are implausible (total=%d executed=%d; minimums "
            "%d/%d). A baseline recorded from a run that executed nothing would make this "
            "check vacuous, so it is refused rather than trusted."
            % (floor_total, floor_exec, MIN_PLAUSIBLE_TOTAL, MIN_PLAUSIBLE_EXECUTED))

    problems = []

    # (1) FLOORS. Checked before equality, because a collapsed run can still be
    #     "equal" to a collapsed baseline and that is exactly the false green.
    ex = executed_count(got)
    if len(got) < floor_total:
        problems.append(
            "DISCOVERY FLOOR: this run found %d requirements, the baseline found %d. "
            "Fewer requirements is a broken run, not a smaller spec." % (len(got), floor_total))
    if ex < floor_exec:
        problems.append(
            "EXECUTION FLOOR: this run EXECUTED %d requirements, the baseline executed %d "
            "(%d skipped here). A transport that reports 0/N skipped is the TCK's own way "
            "of saying it never ran; it is not a pass." % (ex, floor_exec, len(got) - ex))

    # (2) SET EQUALITY. Both directions. A requirement that vanished is as much a signal
    #     as one that appeared.
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    for req in missing:
        problems.append("REQUIREMENT VANISHED: %s (baseline had it at %s, this run does not "
                        "report it at all)" % (req, want[req]))
    for req in extra:
        problems.append("REQUIREMENT APPEARED: %s = %s (the baseline does not know it). Either "
                        "the TCK gained a requirement or the pin moved." % (req, got[req]))

    # (3) PER-REQUIREMENT STATUS. Movement in EITHER direction is reported. A newly
    #     passing requirement is good news that still invalidates the pin.
    for req in sorted(set(want) & set(got)):
        if want[req] != got[req]:
            problems.append("STATUS MOVED: %s baseline=%s now=%s" % (req, want[req], got[req]))

    label = base.get("label", args.baseline)
    if problems:
        sys.stderr.write("\n" + "=" * 78 + "\n")
        sys.stderr.write("A2A TCK CONTROL BASELINE MISMATCH -- %s\n" % label)
        sys.stderr.write("=" * 78 + "\n")
        sys.stderr.write(
            "The control is a THIRD-PARTY reference pinned to an exact version, run against a\n"
            "TCK pinned to an exact commit. If its verdict moved, either the TCK changed, the\n"
            "control changed, or this wrapper changed. All three need a human before any\n"
            "subject result from this suite can be believed.\n\n")
        for p in problems:
            sys.stderr.write("  %s\n" % p)
        sys.stderr.write("\nTo re-pin deliberately, read the diff first, then re-record from a fresh "
                         "run (a recording is refused from any report but its own run's):\n")
        sys.stderr.write("  testing/a2a-tck/run-tck.sh record-baselines\n")
        sys.stderr.write("=" * 78 + "\n\n")
        return 1

    print("A2A TCK CONTROL BASELINE MATCHED -- %s" % label)
    print("  %d requirements, %d executed, %d skipped; every status identical to the pin."
          % (len(got), ex, len(got) - ex))
    return 0


def report_only(args):
    """A leg that is reported and never pinned still has to have produced a report."""
    report = load_report(args.report, args.run_started)
    st = statuses(report)
    ex = executed_count(st)
    if len(st) < MIN_PLAUSIBLE_TOTAL or ex < MIN_PLAUSIBLE_EXECUTED:
        die("The report discovered %d requirements and EXECUTED %d (minimums %d/%d): %s\n\n"
            "That is a run that measured next to nothing, and a number read off it means nothing."
            % (len(st), ex, MIN_PLAUSIBLE_TOTAL, MIN_PLAUSIBLE_EXECUTED, args.report))
    print("A2A TCK REPORT PRESENT -- %s" % args.report)
    print("  %d requirements, %d executed, %d skipped; reported, not compared."
          % (len(st), ex, len(st) - ex))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="check-baseline.py")
    ap.add_argument("--report", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--label", default="")
    ap.add_argument("--run-started", type=int, required=True,
                    help="the moment the run began, in epoch seconds; an older report is refused")
    args = ap.parse_args(argv)
    if args.report_only:
        if args.record or args.baseline:
            die("--report-only compares nothing and records nothing; it takes no --record and "
                "no --baseline.")
        return report_only(args)
    if not args.baseline:
        die("--baseline is required unless --report-only is given.")
    if args.record:
        if not args.label:
            die("--record needs a --label saying what the baseline is OF.")
        return record(args)
    return check(args)


if __name__ == "__main__":
    sys.exit(main())
