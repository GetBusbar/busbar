#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""PROVE THE SUPPLEMENT'S OWN EXIT-CODE FLOORS BITE, by making report() fail on purpose.

`report()` used to end `return 1 if bad else 0`, where `bad` is FAIL|ERROR only. Two runs that
established NOTHING were therefore green:

    * a requirement silently dropped from `run()`'s plan left the denominator instead of failing,
      so "21 of 21" quietly became "20 of 20" with nothing going red; and
    * a subject that answered every probe with UNTESTABLE/PARTIAL/NOT_APPLICABLE demonstrated ZERO
      MUST requirements and still exited 0, because none of those verdicts is `bad`.

Both are the absence of evidence, not a pass. This selftest drives the real `report()` against
results shaped exactly like each of those two runs and FAILS if the exit code is 0.

    python3 selftest.py   (run it the way run-supplement.sh runs the suite — it imports the a2asup
                           package, which pulls in the pinned TCK interpreter's deps)
"""

from __future__ import annotations

import contextlib
import io
import sys

from a2asup.model import Result, Verdict
from a2asup.runner import report
from a2asup.spec import REQUIREMENTS
from a2asup.target import Interface, Target

FAILURES: list[str] = []
# How many expectations HELD. Counted rather than inferred, so `main`'s floor can tell a green run
# from a run in which the cases were deleted -- a selftest that discovered nothing is not a pass.
PASSES_SEEN = [0]


def expect_code(label: str, got: int, want: int, why: str) -> None:
    ok = got == want
    print(f"  {'ok ' if ok else 'MISS'}  {label}")
    print(f"        -> exit {got} (wanted {want})")
    if ok:
        PASSES_SEEN[0] += 1
    else:
        FAILURES.append(f"{label}: report() exited {got}, wanted {want}. {why}")


def runner_floor_mutations() -> None:
    """The two ways a run can establish NOTHING and still exit 0, made to fail."""
    target = Target(label="selftest", card_url="http://selftest.invalid/card")
    target.card = {}
    target.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]

    def run_report(results) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return report(target, results, None)

    all_ids = sorted(REQUIREMENTS)

    print("\nRUNNER -- every declared requirement decided, at least one DEMONSTRATED")
    full_pass = [Result(i, Verdict.PASS, "selftest") for i in all_ids]
    expect_code(
        "POSITIVE CONTROL: a complete run with passes must exit 0",
        run_report(full_pass),
        0,
        "None of the floors may refuse a run that actually decided everything.",
    )

    print("\nRUNNER -- a requirement silently dropped from the plan")
    short = [Result(i, Verdict.PASS, "selftest") for i in all_ids[1:]]
    expect_code(
        f"a run that never ran {all_ids[0]} must NOT exit 0",
        run_report(short),
        1,
        "A requirement that leaves the denominator instead of failing turns '21 of 21' into "
        "'20 of 20' with nothing anywhere going red.",
    )

    print("\nRUNNER -- nothing demonstrated, and nothing failed either")
    nothing = [Result(i, Verdict.UNTESTABLE, "selftest") for i in all_ids]
    expect_code(
        "a run demonstrating ZERO MUSTs must NOT exit 0",
        run_report(nothing),
        1,
        "UNTESTABLE, PARTIAL and NOT_APPLICABLE are not passes and are not `bad`, so '0 of 21 "
        "DEMONSTRATED' exited 0 and read as a clean run.",
    )

    print("\nRUNNER -- a real failure is still a failure (the floors did not replace it)")
    one_bad = [Result(i, Verdict.PASS, "selftest") for i in all_ids[1:]]
    one_bad.append(Result(all_ids[0], Verdict.FAIL, "selftest"))
    expect_code(
        "a FAIL must still exit 1",
        run_report(one_bad),
        1,
        "The floors are added to the FAIL/ERROR rule, never in place of it.",
    )


def main() -> int:
    print("a2a-supplement SELFTEST -- the report() exit-code floors are made to fail on purpose")
    print("A floor that does not bite here is a suite that reports green over nothing.")
    runner_floor_mutations()
    print()
    # A SELFTEST THAT DISCOVERED NO CASES IS NOT A PASS. Without a floor, deleting a mutation leaves
    # this file printing SELFTEST PASSED over the checks it stopped exercising.
    total = len(FAILURES) + PASSES_SEEN[0]
    if total < 4:
        print(f"SELFTEST DISCOVERED ONLY {total} CASES. Mutations were deleted or never ran.")
        return 2
    if FAILURES:
        print(f"SELFTEST FAILED: {len(FAILURES)} floor(s) did not bite")
        for line in FAILURES:
            print(f"  - {line}")
        return 1
    print("SELFTEST PASSED: both exit-code floors bit, and neither the positive control nor a real "
          "FAIL was misjudged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
