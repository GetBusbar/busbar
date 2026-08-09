#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""The A2A conformance verdict must depend on EVERY leg, and must judge every leg it depends on.

WHY THIS EXISTS. `a2a-conformance.yml` ends in an aggregator job that asserts, per leg, that the
leg reached `success` -- because ten green ticks mean nothing if one of them is green because it
never ran. That aggregator is only as good as its `needs:` list, and a `needs:` list is exactly the
kind of hand-maintained enumeration that silently stops covering the thing added after it. A new
job that nobody adds to `needs:` is invisible to the verdict, and the verdict goes green over it.

So this is SET EQUALITY in both directions, not a floor and not a subset check:

  * every job in the workflow except the verdict itself must appear in the verdict's `needs:`
  * every name in `needs:` must be a real job
  * every leg the verdict depends on must actually be READ by the verdict's script, so a leg
    cannot be added to `needs:` and then never judged

Plus a floor, because a workflow that parsed to two jobs would satisfy every equality above.
"""

import os
import re
import sys

WORKFLOW = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", ".github", "workflows", "a2a-conformance.yml")
VERDICT = "verdict"
MIN_LEGS = 8


def load(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required to lint the workflow. `pip install pyyaml`.")
    with open(path) as fh:
        return yaml.safe_load(fh)


def main():
    path = os.path.normpath(WORKFLOW)
    if not os.path.exists(path):
        sys.exit("the A2A conformance workflow is missing: %s\n"
                 "Nothing was linted. That is red, not clean." % path)
    doc = load(path)
    jobs = doc.get("jobs") or {}
    if VERDICT not in jobs:
        sys.exit("the workflow has no `%s` job. Without the aggregator, a leg that never ran "
                 "looks identical to a leg that passed." % VERDICT)

    legs = set(jobs) - {VERDICT}
    needs = jobs[VERDICT].get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs = set(needs)

    problems = []

    if len(legs) < MIN_LEGS:
        problems.append(
            "FLOOR: the workflow declares only %d legs (minimum %d). Every equality below would "
            "hold for a workflow that had been gutted, so the count is checked first."
            % (len(legs), MIN_LEGS))

    for missing in sorted(legs - needs):
        problems.append(
            "UNJUDGED LEG: job `%s` exists but is not in `%s.needs`. It can fail, or never run, "
            "and the verdict will still be green." % (missing, VERDICT))

    for ghost in sorted(needs - legs):
        problems.append(
            "GHOST DEPENDENCY: `%s.needs` names `%s`, which is not a job in this workflow."
            % (VERDICT, ghost))

    # Depending on a leg is not the same as judging it. The verdict's script must mention each
    # leg by name, or the dependency is decorative.
    script = ""
    for step in jobs[VERDICT].get("steps") or []:
        script += (step.get("run") or "")
        for v in (step.get("env") or {}).values():
            script += "\n%s" % v
    for leg in sorted(legs & needs):
        if not re.search(r"\b%s\b" % re.escape(leg), script):
            problems.append(
                "DEPENDED ON BUT NOT READ: `%s` is in `needs` but its name never appears in the "
                "verdict's script or env, so its result is not being checked." % leg)

    if problems:
        sys.stderr.write("\nA2A CONFORMANCE VERDICT COVERAGE FAILED\n")
        for p in problems:
            sys.stderr.write("  %s\n" % p)
        sys.stderr.write("\n")
        return 1

    print("verdict coverage: %d legs, every one depended on and every one read." % len(legs))
    for leg in sorted(legs):
        print("  %s" % leg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
