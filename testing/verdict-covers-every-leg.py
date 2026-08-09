#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""A conformance verdict must depend on EVERY leg, and must judge every leg it depends on.

WHY THIS EXISTS. Each `*-conformance.yml` ends in an aggregator job that asserts, per leg, that the
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

THE WORKFLOWS ARE DISCOVERED, NOT ENUMERATED, and that is the same rule one level up. This file
began life hard-coded to `a2a-conformance.yml`. The MCP conformance workflow then arrived with the
identical defect this file exists to catch -- an aggregator that did not exist at all -- and a
hard-coded path would have sailed straight past it, which is precisely the "enumeration that
stopped covering what came after it" failure the docstring above is about. So the glob is the
source of truth and a FLOOR on the number of workflows found stops the glob silently matching
nothing.

USAGE
    verdict-covers-every-leg.py                 lint every .github/workflows/*conformance*.yml
    verdict-covers-every-leg.py PATH [PATH...]  lint exactly these
    verdict-covers-every-leg.py --selftest      prove the checks bite, before believing a green
"""

import glob
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PATTERN = os.path.join(ROOT, ".github", "workflows", "*conformance*.yml")
VERDICT = "verdict"
MIN_LEGS = 5

# At least one conformance workflow must exist on any branch this runs on. Zero means the glob is
# wrong or the workflows were deleted, and "nothing to lint" must never render as "clean".
MIN_WORKFLOWS = 1


def load(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required to lint the workflow. `pip install pyyaml`.")
    with open(path) as fh:
        return yaml.safe_load(fh)


def lint_doc(doc, label):
    """Return a list of problem strings for one parsed workflow document."""
    problems = []
    jobs = doc.get("jobs") or {}
    if VERDICT not in jobs:
        return ["%s: the workflow has no `%s` job. Without the aggregator, a leg that never ran "
                "looks identical to a leg that passed." % (label, VERDICT)]

    legs = set(jobs) - {VERDICT}
    needs = jobs[VERDICT].get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs = set(needs)

    if len(legs) < MIN_LEGS:
        problems.append(
            "%s: FLOOR: the workflow declares only %d legs (minimum %d). Every equality below "
            "would hold for a workflow that had been gutted, so the count is checked first."
            % (label, len(legs), MIN_LEGS))

    for missing in sorted(legs - needs):
        problems.append(
            "%s: UNJUDGED LEG: job `%s` exists but is not in `%s.needs`. It can fail, or never "
            "run, and the verdict will still be green." % (label, missing, VERDICT))

    for ghost in sorted(needs - legs):
        problems.append(
            "%s: GHOST DEPENDENCY: `%s.needs` names `%s`, which is not a job in this workflow."
            % (label, VERDICT, ghost))

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
                "%s: DEPENDED ON BUT NOT READ: `%s` is in `needs` but its name never appears in "
                "the verdict's script or env, so its result is not being checked."
                % (label, leg))

    return problems


def selftest():
    """Prove each check FAILS on a fixture built to break it, and passes on one built not to.

    Without this, every rule above could be silently broken and every workflow would lint clean --
    which is the same disease, one level in, as the vacuous green the rules are about.
    """
    ok = {
        "jobs": {
            "a": {}, "b": {}, "c": {}, "d": {}, "e": {},
            "verdict": {
                "needs": ["a", "b", "c", "d", "e"],
                "steps": [{"run": "check a b c d e"}],
            },
        }
    }
    fixtures = [
        ("a complete workflow", ok, 0),
        ("no verdict job at all",
         {"jobs": {"a": {}, "b": {}, "c": {}, "d": {}, "e": {}}}, 1),
        ("a leg missing from needs",
         {"jobs": dict(ok["jobs"], f={},)}, 1),
        ("a ghost dependency",
         {"jobs": {"a": {}, "b": {}, "c": {}, "d": {}, "e": {},
                   "verdict": {"needs": ["a", "b", "c", "d", "e", "ghost"],
                               "steps": [{"run": "check a b c d e ghost"}]}}}, 1),
        ("a leg depended on but never read",
         {"jobs": {"a": {}, "b": {}, "c": {}, "d": {}, "e": {},
                   "verdict": {"needs": ["a", "b", "c", "d", "e"],
                               "steps": [{"run": "check a b c d"}]}}}, 1),
        ("a gutted workflow below the leg floor",
         {"jobs": {"a": {}, "verdict": {"needs": ["a"], "steps": [{"run": "check a"}]}}}, 1),
    ]
    failures = 0
    for name, doc, want_problems in fixtures:
        got = lint_doc(doc, "selftest")
        if want_problems and not got:
            print("  MISS: %s was accepted" % name)
            failures += 1
        elif not want_problems and got:
            print("  MISS: %s was refused (%s)" % (name, got[0]))
            failures += 1
        else:
            print("  ok: %s -> %s" % (name, "refused" if got else "accepted"))
    if failures:
        sys.stderr.write("\n%d selftest fixture(s) did not behave as declared\n" % failures)
        return 1
    print("selftest: %d fixture(s) passed" % len(fixtures))
    return 0


def main(argv):
    if argv and argv[0] == "--selftest":
        return selftest()

    paths = [os.path.abspath(p) for p in argv] or sorted(glob.glob(PATTERN))
    if len(paths) < MIN_WORKFLOWS:
        sys.exit("no conformance workflow matched %s.\nNothing was linted. That is red, not "
                 "clean." % PATTERN)

    problems = []
    for path in paths:
        if not os.path.exists(path):
            problems.append("%s does not exist. Nothing was linted for it." % path)
            continue
        problems += lint_doc(load(path), os.path.basename(path))

    if problems:
        sys.stderr.write("\nCONFORMANCE VERDICT COVERAGE FAILED\n")
        for p in problems:
            sys.stderr.write("  %s\n" % p)
        sys.stderr.write("\n")
        return 1

    for path in paths:
        doc = load(path)
        legs = sorted(set(doc.get("jobs") or {}) - {VERDICT})
        print("%s: %d legs, every one depended on and every one read."
              % (os.path.basename(path), len(legs)))
        for leg in legs:
            print("  %s" % leg)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
