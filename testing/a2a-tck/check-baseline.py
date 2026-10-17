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

USAGE
    check-baseline.py --report <compatibility.json> --baseline <baseline.json>
    check-baseline.py --record --report <compatibility.json> --baseline <out.json> \
        --label "<what this baseline is of>"

EXIT
    0  identical to the baseline, and the floors held
    1  a difference, or a floor breached
    2  the comparison could not be made at all (missing/empty/malformed input)
"""

import argparse
import json
import os
import sys


# A baseline that recorded fewer executed requirements than this is not a baseline, it is a
# record of a broken run being blessed. Chosen well below the ~85 the pinned control actually
# executes, so it fails on a collapse rather than on ordinary movement.
MIN_PLAUSIBLE_EXECUTED = 40

# Likewise for the total discovered requirement set. The TCK declares ~129 requirements; a report
# carrying a handful means discovery broke, not that the spec shrank.
MIN_PLAUSIBLE_TOTAL = 100

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
    report = load_json(args.report, "report")
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
        "tck_ref": os.environ.get("A2A_TCK_REF", ""),
        "control": os.environ.get("A2A_TCK_CONTROL", ""),
        "tz": os.environ.get("TZ", ""),
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
    report = load_json(args.report, "report")
    base = load_json(args.baseline, "baseline")

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
        sys.stderr.write("\nTo re-pin deliberately, read the diff first, then:\n")
        sys.stderr.write("  check-baseline.py --record --report %s --baseline %s --label '%s'\n"
                         % (args.report, args.baseline, label))
        sys.stderr.write("=" * 78 + "\n\n")
        return 1

    print("A2A TCK CONTROL BASELINE MATCHED -- %s" % label)
    print("  %d requirements, %d executed, %d skipped; every status identical to the pin."
          % (len(got), ex, len(got) - ex))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="check-baseline.py")
    ap.add_argument("--report", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--label", default="")
    args = ap.parse_args(argv)
    if args.record:
        if not args.label:
            die("--record needs a --label saying what the baseline is OF.")
        return record(args)
    return check(args)


if __name__ == "__main__":
    sys.exit(main())
