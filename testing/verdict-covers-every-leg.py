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

THE FLOOR IS A BATTERY'S, NOT A REUSABLE WORKFLOW'S. A workflow whose ONLY trigger is
`workflow_call` is not a battery: its status bubbles up into the CALLER's job, which is the
aggregation point (.github/required-status-checks.md, "Reusable workflows"). plugin-conformance.yml
is one: it runs the calling plugin repo's own `conformance` test target, which is one leg by
construction. Such a workflow keeps every equality and read check above and is excused from the
floor ONLY while a caller is found (a `uses:` reference under .github/, or plugin-ci.yml /
xtask/src/fleet.rs naming it). The exemption is structural, never by name: a battery cannot dodge
the floor by switching its trigger, because a callable nobody calls is floored like any battery.

THE DENOMINATOR IS LEGS, NOT JOBS. Every rule above is about JOBS, and a battery's legs are not
jobs: a battery that keeps its legs as `testing/<battery>/legs/<leg>.sh` files runs them through
`--leg <name>` invocations inside jobs. A leg file that NO job invokes is not a job, so it is not in
the job set, so set equality between the job set and `needs:` holds over it and the verdict goes
green over a leg that never ran -- structurally invisible to every check above. (The voice battery,
a dialect of the streaming plane, shipped its `tool-reply` leg exactly that way.) So, per battery:

  * the set of legs is DISCOVERED from the leg definitions (`testing/*/legs/*.sh`), never read off
    the workflow, which is the very enumeration under suspicion
  * every discovered leg must be run (`--leg NAME`, or `--leg "$v"` inside `for v in ...; do`, or
    `--leg ${{ matrix.K }}` over the job's matrix) by at least one job other than the verdict
  * at least one job that runs it must be in the verdict's `needs:` (and, by the rule above, read)
  * every `--leg NAME` a job invokes must be a real leg file, and a `--leg` argument this lint cannot
    resolve to names is itself a problem -- an invocation nobody can count is not coverage
  * every battery that has a `legs/` directory must be claimed (referenced as `testing/<battery>/`)
    by at least one conformance workflow, or its every leg is invisible one level further up

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


def discover_batteries(root=ROOT):
    """{battery: set(leg names)} from every `testing/<battery>/legs/*.sh` on disk."""
    out = {}
    for d in sorted(glob.glob(os.path.join(root, "testing", "*", "legs"))):
        if not os.path.isdir(d):
            continue
        battery = os.path.basename(os.path.dirname(d))
        out[battery] = {os.path.basename(f)[:-3] for f in glob.glob(os.path.join(d, "*.sh"))}
    return out


def claimed_batteries(text, batteries):
    """The batteries a workflow's text references as `testing/<battery>/`."""
    return {b for b in batteries if ("testing/%s/" % b) in text}


def triggers(doc):
    """The workflow's trigger names. PyYAML reads a bare `on:` key as the boolean True."""
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return set(on)
    return set()


def is_callable_only(doc):
    return triggers(doc) == {"workflow_call"}


# Where a reusable workflow's callers are named. `uses:` is the real call; plugin-ci.yml and
# fleet.rs are where the plugin fleet names the reusable workflows every plugin repo takes.
CALLER_NAMERS = (os.path.join(".github", "workflows", "plugin-ci.yml"),
                 os.path.join("xtask", "src", "fleet.rs"))


def callers_of(filename, root=ROOT):
    """The files that call (or, for the fleet's own files, name) the reusable workflow `filename`."""
    uses = re.compile(r"uses:\s*\S*\b%s\b" % re.escape(filename))
    found = []
    for path in sorted(glob.glob(os.path.join(root, ".github", "**", "*.yml"), recursive=True)):
        if os.path.basename(path) == filename:
            continue
        with open(path) as fh:
            if uses.search(fh.read()):
                found.append(os.path.relpath(path, root))
    for rel in CALLER_NAMERS:
        path = os.path.join(root, rel)
        if rel not in found and os.path.basename(path) != filename and os.path.exists(path):
            with open(path) as fh:
                if filename in fh.read():
                    found.append(rel)
    return found


def _job_run_text(job):
    text = ""
    for step in job.get("steps") or []:
        text += "\n" + (step.get("run") or "")
    # A backslash-continued shell line is one line to the shell; make it one line here too.
    return re.sub(r"\\\n", " ", text)


def legs_invoked(job):
    """Return (set of leg names this job's steps run via `--leg`, list of unresolvable arguments)."""
    text = _job_run_text(job)
    loops = {}
    for m in re.finditer(r"\bfor\s+(\w+)\s+in\s+([^;\n]*?)\s*(?:;|\n)\s*do\b", text):
        loops.setdefault(m.group(1), set()).update(m.group(2).split())
    matrix = ((job.get("strategy") or {}).get("matrix") or {})
    names, unresolved = set(), []
    for m in re.finditer(r"--leg\s+(\$\{\{\s*matrix\.(\w+)\s*\}\}|\S+)", text):
        arg = m.group(1)
        if m.group(2):
            vals = matrix.get(m.group(2))
            if isinstance(vals, list) and vals:
                names.update(str(v) for v in vals)
            else:
                unresolved.append(arg)
            continue
        bare = arg.strip("\"'")
        var = re.fullmatch(r"\$\{?(\w+)\}?", bare)
        if var:
            if var.group(1) in loops:
                names.update(loops[var.group(1)])
            else:
                unresolved.append(arg)
        elif re.fullmatch(r"[A-Za-z0-9_.-]+", bare):
            names.add(bare)
        else:
            unresolved.append(arg)
    return names, unresolved


def lint_legs(doc, label, battery_legs):
    """The LEG-denominator checks. `battery_legs` is {battery: set(leg names)} for the batteries
    this workflow claims; it comes from the leg definitions on disk, never from the workflow."""
    problems = []
    jobs = doc.get("jobs") or {}
    if not battery_legs:
        return problems
    needs = (jobs.get(VERDICT) or {}).get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs = set(needs)

    runners = {}  # leg -> set(job names that run it)
    for name, job in jobs.items():
        if name == VERDICT or not isinstance(job, dict):
            continue
        invoked, unresolved = legs_invoked(job)
        for arg in unresolved:
            problems.append(
                "%s: UNCOUNTABLE LEG INVOCATION: job `%s` runs `--leg %s`, which this lint cannot "
                "resolve to leg names. An invocation nobody can count is not coverage."
                % (label, name, arg))
        for leg in invoked:
            runners.setdefault(leg, set()).add(name)

    all_legs = set()
    for battery in sorted(battery_legs):
        for leg in sorted(battery_legs[battery]):
            all_legs.add(leg)
            jobs_running = runners.get(leg, set())
            if not jobs_running:
                problems.append(
                    "%s: LEG RUN BY NO JOB: `testing/%s/legs/%s.sh` is a declared leg, but no job "
                    "in this workflow runs `--leg %s`. It never runs, and the verdict is green over "
                    "it." % (label, battery, leg, leg))
            elif not (jobs_running & needs):
                problems.append(
                    "%s: LEG NOT JUDGED: leg `%s` (testing/%s/legs) runs only in job(s) %s, none "
                    "of which is in `%s.needs`." % (label, leg, battery,
                                                    ", ".join(sorted(jobs_running)), VERDICT))

    for ghost in sorted(set(runners) - all_legs):
        problems.append(
            "%s: GHOST LEG: job(s) %s run `--leg %s`, but no claimed battery declares that leg."
            % (label, ", ".join(sorted(runners[ghost])), ghost))
    return problems


def lint_orphans(batteries, claimed):
    """Every battery with a `legs/` directory must be claimed by at least one workflow."""
    problems = []
    for battery in sorted(set(batteries) - claimed):
        problems.append(
            "ORPHAN BATTERY: testing/%s/legs declares %d leg(s) but no conformance workflow "
            "references testing/%s/, so none of them is run or judged."
            % (battery, len(batteries[battery]), battery))
    for battery in sorted(b for b in batteries if not batteries[b]):
        problems.append("EMPTY BATTERY: testing/%s/legs exists but declares no leg." % battery)
    return problems


def lint_doc(doc, label, battery_legs=None, callers=None):
    """Return a list of problem strings for one parsed workflow document. `callers` is the list of
    files found calling this workflow; it matters only for a `workflow_call`-only workflow."""
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

    callable_only = is_callable_only(doc)
    if len(legs) < MIN_LEGS and not (callable_only and callers):
        problems.append(
            "%s: FLOOR: the workflow declares only %d legs (minimum %d). Every equality below "
            "would hold for a workflow that had been gutted, so the count is checked first.%s"
            % (label, len(legs), MIN_LEGS,
               " It is workflow_call-only, but no caller was found, so it is floored like a "
               "battery." if callable_only else ""))

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

    problems += lint_legs(doc, label, battery_legs or {})
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
    # THE REUSABLE-WORKFLOW RULE. The floor is excused only for a workflow_call-only workflow that
    # somebody calls, and nothing else is excused with it.
    one_leg = {"a": {}, "verdict": {"needs": ["a"], "steps": [{"run": "check a"}]}}
    called = ["caller.yml"]
    reusable_cases = [
        ("(a) a called workflow_call-only workflow with one judged leg",
         {True: {"workflow_call": None}, "jobs": one_leg}, called, 0),
        ("(b) a called workflow_call-only workflow with an unjudged leg",
         {True: {"workflow_call": None}, "jobs": dict(one_leg, b={})}, called, "UNJUDGED LEG"),
        ("(c) a workflow_run battery with one leg, callers or not",
         {True: {"workflow_run": None}, "jobs": one_leg}, called, "FLOOR"),
        ("(d) a workflow_call-only workflow nobody calls",
         {True: {"workflow_call": None}, "jobs": one_leg}, [], "FLOOR"),
        ("(e) a callable that is also dispatchable is a battery",
         {True: {"workflow_call": None, "workflow_dispatch": None}, "jobs": one_leg}, called,
         "FLOOR"),
    ]
    # THE LEG DENOMINATOR. Each of these workflows is a clean, COMPLETE job set -- every check above
    # passes on it -- so the only thing that can refuse it is the leg-based rule. A lint whose
    # denominator is jobs accepts every one of them.
    def battery_wf(extra_jobs=None, runs=None, verdict_needs=None):
        runs = runs if runs is not None else {
            "a": "bash testing/bat/bat.sh --leg one",
            "b": "bash testing/bat/bat.sh --leg ${{ matrix.slice }}",
            "c": ("for leg in three \\\n    four; do\n"
                  "  bash testing/bat/bat.sh --leg \"$leg\"\ndone"),
            "d": "true", "e": "true"}
        jobs = {n: {"steps": [{"run": r}]} for n, r in runs.items()}
        jobs["b"]["strategy"] = {"matrix": {"slice": ["two"]}}
        jobs.update(extra_jobs or {})
        legs = sorted(jobs)
        jobs["verdict"] = {"needs": verdict_needs or legs,
                           "steps": [{"run": "check " + " ".join(legs)}]}
        return {"jobs": jobs}
    four = {"bat": {"one", "two", "three", "four"}}
    fixtures += [
        ("a battery whose every leg runs in a judged job", battery_wf(), 0, four),
        ("a LEG RUN BY NO JOB (the tool-reply shape: a leg file, no job, job set still complete)",
         battery_wf(), "LEG RUN BY NO JOB", {"bat": {"one", "two", "three", "four", "tool-reply"}}),
        ("a leg dropped from a for-loop", battery_wf(runs={
            "a": "bash testing/bat/bat.sh --leg one",
            "b": "bash testing/bat/bat.sh --leg ${{ matrix.slice }}",
            "c": "for leg in three; do bash testing/bat/bat.sh --leg \"$leg\"; done",
            "d": "true", "e": "true"}), "LEG RUN BY NO JOB", four),
        ("a leg whose only job is not in needs",
         battery_wf(extra_jobs={"f": {"steps": [{"run": "x --leg five"}]}},
                    verdict_needs=["a", "b", "c", "d", "e"]),
         "LEG NOT JUDGED", {"bat": four["bat"] | {"five"}}),
        ("a ghost --leg naming no leg file",
         battery_wf(extra_jobs={"f": {"steps": [{"run": "x --leg nosuch"}]}}), "GHOST LEG",
         four),
        ("an uncountable --leg argument",
         battery_wf(extra_jobs={"f": {"steps": [{"run": "x --leg \"$(pick)\""}]}}),
         "UNCOUNTABLE LEG INVOCATION", four),
    ]

    failures = 0
    for fx in fixtures:
        name, doc, want_problems = fx[:3]
        got = lint_doc(doc, "selftest", fx[3] if len(fx) > 3 else None)
        if want_problems and not got:
            print("  MISS: %s was accepted" % name)
            failures += 1
        elif isinstance(want_problems, str) and not any(want_problems in g for g in got):
            # Refused, but not by the rule this case plants for -- so that rule is unproven.
            print("  MISS: %s was refused, but not as %s (%s)" % (name, want_problems, got[0]))
            failures += 1
        elif not want_problems and got:
            print("  MISS: %s was refused (%s)" % (name, got[0]))
            failures += 1
        else:
            print("  ok: %s -> %s" % (name, "refused" if got else "accepted"))
    for name, doc, callers, want_problems in reusable_cases:
        got = lint_doc(doc, "selftest", None, callers)
        if want_problems and not got:
            print("  MISS: %s was accepted" % name)
            failures += 1
        elif isinstance(want_problems, str) and not any(want_problems in g for g in got):
            print("  MISS: %s was refused, but not as %s (%s)" % (name, want_problems, got[0]))
            failures += 1
        elif not want_problems and got:
            print("  MISS: %s was refused (%s)" % (name, got[0]))
            failures += 1
        else:
            print("  ok: %s -> %s" % (name, "refused" if got else "accepted"))
    # The caller detector reads a real `uses:` line and ignores a workflow naming itself.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        wf = os.path.join(tmp, ".github", "workflows")
        os.makedirs(wf)
        with open(os.path.join(wf, "reuse.yml"), "w") as fh:
            fh.write("# reuse.yml calls nothing\non: workflow_call\n")
        with open(os.path.join(wf, "other.yml"), "w") as fh:
            fh.write("jobs:\n  x:\n    uses: ./.github/workflows/other-thing.yml\n")
        if callers_of("reuse.yml", tmp):
            print("  MISS: callers_of found a caller where there is none")
            failures += 1
        with open(os.path.join(wf, "caller.yml"), "w") as fh:
            fh.write("jobs:\n  x:\n    uses: GetBusbar/busbar/.github/workflows/reuse.yml@abc\n")
        if callers_of("reuse.yml", tmp) != [os.path.join(".github", "workflows", "caller.yml")]:
            print("  MISS: callers_of did not see a `uses:` caller")
            failures += 1
    # The battery-level rule: a legs/ directory no workflow claims is refused; one claimed is not.
    for name, batteries, claimed, want in [
        ("an orphan battery no workflow claims", four, set(), 1),
        ("a claimed battery", four, {"bat"}, 0),
        ("an empty legs/ directory", {"bat": set()}, {"bat"}, 1),
    ]:
        got = lint_orphans(batteries, claimed)
        if bool(got) != bool(want):
            print("  MISS: %s was %s" % (name, "refused" if got else "accepted"))
            failures += 1
        else:
            print("  ok: %s -> %s" % (name, "refused" if got else "accepted"))
    # And the claim detector reads the path a workflow actually uses.
    if claimed_batteries("run: bash testing/bat/bat.sh --leg one", four) != {"bat"}:
        print("  MISS: claimed_batteries did not see testing/bat/")
        failures += 1

    if failures:
        sys.stderr.write("\n%d selftest fixture(s) did not behave as declared\n" % failures)
        return 1
    print("selftest: %d fixture(s) passed" % (len(fixtures) + len(reusable_cases) + 5))
    return 0


def main(argv):
    if argv and argv[0] == "--selftest":
        return selftest()

    explicit = bool(argv)
    paths = [os.path.abspath(p) for p in argv] or sorted(glob.glob(PATTERN))
    if len(paths) < MIN_WORKFLOWS:
        sys.exit("no conformance workflow matched %s.\nNothing was linted. That is red, not "
                 "clean." % PATTERN)

    batteries = discover_batteries()
    problems = []
    claimed = set()
    for path in paths:
        if not os.path.exists(path):
            problems.append("%s does not exist. Nothing was linted for it." % path)
            continue
        with open(path) as fh:
            mine = claimed_batteries(fh.read(), batteries)
        claimed |= mine
        doc = load(path)
        callers = callers_of(os.path.basename(path)) if is_callable_only(doc) else None
        problems += lint_doc(doc, os.path.basename(path),
                             {b: batteries[b] for b in mine}, callers)
    # Only the full discovered set can say a battery is claimed by NO workflow; a hand-picked
    # subset of paths legitimately leaves the others' batteries unclaimed.
    if not explicit:
        problems += lint_orphans(batteries, claimed)

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
        if is_callable_only(doc) and len(legs) < MIN_LEGS:
            print("  reusable (workflow_call only), below the floor, aggregated by its caller(s): %s"
                  % ", ".join(callers_of(os.path.basename(path))))
        for leg in legs:
            print("  %s" % leg)
        with open(path) as fh:
            for b in sorted(claimed_batteries(fh.read(), batteries)):
                print("  battery testing/%s/legs: %d leg file(s), every one run by a judged job."
                      % (b, len(batteries[b])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
