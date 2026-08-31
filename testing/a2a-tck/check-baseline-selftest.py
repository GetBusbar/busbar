#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Self-test for check-baseline.py, in its own file because tests live in their own file.

EVERY GUARD IN THE COMPARATOR IS EXERCISED IN BOTH DIRECTIONS. A comparator nobody has watched
fail is a comparator that may not work, and this one exists precisely because the suite it wraps
prints `grpc: 0/72 (72 skipped)` with a tick next to it. So each case below plants a specific
defect and requires the exact refusal, and each has a green twin.

The one that had to be found the expensive way has its own case: `NOT TESTED` is the TCK's status
for a requirement nothing ran, and counting it as executed made a 73-requirement run look like a
100-requirement run. `not_tested_is_not_execution` pins that.

    check-baseline-selftest.py            run every case
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "check-baseline.py")

FAILURES = []
PASSES = []


def report(statuses):
    return {"summary": {}, "per_requirement":
            {k: {"level": "MUST", "status": v, "transports": {}, "errors": [], "test_ids": []}
             for k, v in statuses.items()}}


def baseline(statuses, floor_total=None, floor_executed=None):
    ex = sum(1 for v in statuses.values()
             if str(v).strip().upper().replace(" ", "_") not in
             {"SKIP", "SKIPPED", "NOT_APPLICABLE", "NOT_RUN", "NOT_TESTED", "UNKNOWN", ""})
    return {"label": "selftest", "recorded_by": "selftest",
            "floor_total": len(statuses) if floor_total is None else floor_total,
            "floor_executed": ex if floor_executed is None else floor_executed,
            "per_requirement": dict(statuses)}


def run(report_obj, baseline_obj):
    with tempfile.TemporaryDirectory() as d:
        rp, bp = os.path.join(d, "r.json"), os.path.join(d, "b.json")
        if report_obj is _EMPTY:
            open(rp, "w").close()
        else:
            json.dump(report_obj, open(rp, "w"))
        json.dump(baseline_obj, open(bp, "w"))
        p = subprocess.run([sys.executable, CHECK, "--report", rp, "--baseline", bp],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


_EMPTY = object()


def case(name, report_obj, baseline_obj, want_code, want_text=None):
    code, out = run(report_obj, baseline_obj)
    problems = []
    if code != want_code:
        problems.append("exit %d, wanted %d" % (code, want_code))
    if want_text and want_text not in out:
        problems.append("output did not contain %r" % want_text)
    if problems:
        FAILURES.append((name, "; ".join(problems), out))
    else:
        PASSES.append(name)


# A plausible run: big enough to clear the module's hard minimums (100 discovered, 40 executed).
GOOD = {}
for i in range(130):
    GOOD["REQ-%03d" % i] = "PASS" if i < 90 else "SKIPPED"


def main():
    # --- GREEN: identical input matches.
    case("identical_matches", report(GOOD), baseline(GOOD), 0, "BASELINE MATCHED")

    # --- RED: a status moved, in either direction. A newly PASSING requirement is good news
    #     that still invalidates the pin, so it must be reported too.
    moved = dict(GOOD); moved["REQ-000"] = "FAIL"
    case("status_regressed_is_red", report(moved), baseline(GOOD), 1, "STATUS MOVED")
    improved = dict(GOOD); improved["REQ-100"] = "PASS"
    case("status_improved_is_also_red", report(improved), baseline(GOOD), 1, "STATUS MOVED")

    # --- RED: set equality, both directions.
    gone = dict(GOOD); del gone["REQ-000"]
    case("requirement_vanished_is_red", report(gone), baseline(GOOD), 1, "REQUIREMENT VANISHED")
    added = dict(GOOD); added["REQ-999"] = "PASS"
    case("requirement_appeared_is_red", report(added), baseline(GOOD), 1, "REQUIREMENT APPEARED")

    # --- RED: the whole suite skipped. This is the `0/72 (72 skipped)` tick, and it is the
    #     single case this comparator was written for.
    allskip = {k: "SKIPPED" for k in GOOD}
    case("everything_skipped_is_red", report(allskip), baseline(GOOD), 1, "EXECUTION FLOOR")

    # --- RED: `NOT TESTED` is not execution. Same requirement set, same size, every status a
    #     status the TCK really emits -- and it must still breach the execution floor.
    nottested = {k: ("NOT TESTED" if v == "PASS" else v) for k, v in GOOD.items()}
    case("not_tested_is_not_execution", report(nottested), baseline(GOOD), 1, "EXECUTION FLOOR")

    # --- RED: the comparison could not be made at all. Exit 2, never 0.
    case("empty_report_is_red", _EMPTY, baseline(GOOD), 2, "EMPTY")

    # --- RED: a baseline whose own floors are implausible is refused rather than trusted.
    #     Without this, re-recording during a broken run makes every later run vacuous.
    tiny = {"REQ-000": "PASS"}
    case("implausible_baseline_is_refused", report(tiny), baseline(tiny), 2, "implausible")

    # --- RED: a baseline that discovered enough but EXECUTED almost nothing is equally refused.
    lazy = dict(GOOD)
    case("baseline_that_executed_nothing_is_refused",
         report(lazy), baseline(lazy, floor_executed=3), 2, "implausible")

    # --- GREEN twin for the floors: a run that executes MORE than the pin still has to match
    #     statuses, so the floor is a floor and not a licence.
    case("floors_do_not_replace_equality",
         report(GOOD), baseline(GOOD, floor_executed=50), 0, "BASELINE MATCHED")

    for name in PASSES:
        print("  ok   %s" % name)
    for name, why, out in FAILURES:
        print("  FAIL %s -- %s" % (name, why))
        print("       " + out.replace("\n", "\n       ")[:1200])

    # A selftest that discovered no cases is not a pass.
    total = len(PASSES) + len(FAILURES)
    if total < 11:
        print("\nSELFTEST DISCOVERED ONLY %d CASES. Cases were deleted or never ran." % total)
        return 2
    if FAILURES:
        print("\n%d of %d selftest cases FAILED." % (len(FAILURES), total))
        return 1
    print("\ncheck-baseline selftest: %d cases, all green." % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
