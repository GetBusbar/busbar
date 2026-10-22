#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Self-test for check-baseline.py and for the runner's report handling, in its own file because
tests live in their own file.

EVERY REFUSAL THE COMPARATOR CAN MAKE IS PLANTED HERE AND MUST FIRE WITH ITS OWN MESSAGE, and every
mode has a green case that is the same input without the planted defect. A comparator nobody has
watched fail is a comparator that may not work, and this one exists precisely because the suite it
wraps prints `grpc: 0/72 (72 skipped)` with a tick next to it. The refusals, and the case for each:

    report missing / empty / not JSON          missing_report_is_red, empty_report_is_red,
                                               invalid_json_report_is_red
    baseline missing, or not given             missing_baseline_is_red, check_needs_a_baseline
    the run's start not given                  run_start_is_required
    report shape changed                       report_without_per_requirement_is_red,
                                               requirement_without_status_is_red
    report older than the run                  stale_report_is_red (and in --record, --report-only)
    provenance unstated or not the baseline's  provenance_unstated_is_red, suite_commit_moved_is_red,
                                               control_moved_is_red, time_zone_moved_is_red
    baseline carries no verdicts               baseline_without_per_requirement_is_red
    baseline floors implausible                implausible_baseline_is_refused,
                                               baseline_that_executed_nothing_is_refused
    discovery floor                            discovery_floor_alone_is_red
    execution floor                            everything_skipped_is_red, not_tested_is_not_execution
    requirement vanished / appeared            requirement_vanished_is_red, requirement_appeared_is_red
    status moved, either direction             status_regressed_is_red, status_improved_is_also_red,
                                               more_execution_does_not_excuse_a_moved_status
    --record: floors, label, provenance, age   record_* cases
    --report-only: absent, stale, collapsed,   report_only_* cases
                   given a baseline
    the runner and scenario-agent/serve.sh     runner_selftest_plants_every_refusal

`runner_selftest_plants_every_refusal` runs `run-tck.sh selftest`, which plants EVERY refusal
`run-tck.sh` and `scenario-agent/serve.sh` can make against the real functions, with stand-ins for
the suite, the control binary, `go`, `git`, `python3`, `rm`, the harness pin file and the scenario
agent. Every step either script runs that can fail is guarded; the only unguarded steps are the
ones that cannot fail on a checkout (`cd` into the script's own directory, `mkdir -p` of the
tracked `baselines/` directory, and serve.sh's final `exec` of the interpreter it has just run).
A leg passes only with its wanted text on the command's LAST line, so each refusal is also shown
to stop the run; legs about a half-made checkout or virtualenv also check the disk afterwards.
Each refusal has a green twin except two whose green side needs the network: the checkout pin
(run by every control leg the conformance recorder runs) and the subject endpoint (run by
`boot.sh --tck`). It prints its own leg list.

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
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "check-baseline.py")
RUNNER = os.path.join(HERE, "run-tck.sh")

FAILURES = []
PASSES = []

# The provenance every selftest run states and every selftest baseline records, unless a case
# moves one part of it on purpose.
PROV = {"tck_ref": "selftest-suite-commit", "control": "selftest-control", "tz": "America/New_York"}
PROV_ENV = {"tck_ref": "A2A_TCK_REF", "control": "A2A_TCK_CONTROL", "tz": "TZ"}


def report(statuses):
    return {"summary": {}, "per_requirement":
            {k: {"level": "MUST", "status": v, "transports": {}, "errors": [], "test_ids": []}
             for k, v in statuses.items()}}


def baseline(statuses, floor_total=None, floor_executed=None, **prov):
    ex = sum(1 for v in statuses.values()
             if str(v).strip().upper().replace(" ", "_") not in
             {"SKIP", "SKIPPED", "NOT_APPLICABLE", "NOT_RUN", "NOT_TESTED", "UNKNOWN", ""})
    out = {"label": "selftest", "recorded_by": "selftest",
           "floor_total": len(statuses) if floor_total is None else floor_total,
           "floor_executed": ex if floor_executed is None else floor_executed,
           "per_requirement": dict(statuses)}
    out.update(PROV)
    out.update(prov)
    return out


_EMPTY = object()      # a zero-byte report
_ABSENT = object()     # no report file at all
_NOT_JSON = object()   # a report that is not JSON


def _write(path, obj):
    if obj is _ABSENT:
        return
    with open(path, "w") as fh:
        if obj is _EMPTY:
            pass
        elif obj is _NOT_JSON:
            fh.write("{ this is not json")
        else:
            json.dump(obj, fh)


def run(report_obj, baseline_obj=None, mode=(), stale=False, env_prov=None, read_back=False,
        pass_baseline=True):
    """Run check-baseline.py once in a scratch directory; `(exit code, output)`.

    `stale` back-dates the report to an hour before the run started. `env_prov` replaces the
    stated provenance (a value of None unsets that variable). `read_back` appends the baseline
    file as written, for the --record cases. `pass_baseline=False` leaves `--baseline` off the
    command line altogether.
    """
    with tempfile.TemporaryDirectory() as d:
        rp, bp = os.path.join(d, "r.json"), os.path.join(d, "b.json")
        started = int(time.time())
        _write(rp, report_obj)
        if stale and os.path.exists(rp):
            os.utime(rp, (started - 3600, started - 3600))
        argv = [sys.executable, CHECK, "--report", rp, "--run-started", str(started)]
        argv += list(mode)
        if baseline_obj is not None:
            _write(bp, baseline_obj)
        if pass_baseline and "--report-only" not in mode:
            argv += ["--baseline", bp]
        env = dict(os.environ)
        for key, var in PROV_ENV.items():
            env[var] = PROV[key]
        for key, val in (env_prov or {}).items():
            if val is None:
                env.pop(PROV_ENV[key], None)
            else:
                env[PROV_ENV[key]] = val
        p = subprocess.run(argv, capture_output=True, text=True, env=env)
        out = p.stdout + p.stderr
        if read_back and os.path.exists(bp):
            with open(bp) as fh:
                out += "\n--- baseline as written ---\n" + fh.read()
        return p.returncode, out


def judge(name, code, out, want_code, want_text=None, not_text=None):
    problems = []
    if code != want_code:
        problems.append("exit %d, wanted %d" % (code, want_code))
    if want_text and want_text not in out:
        problems.append("output did not contain %r" % want_text)
    if not_text and not_text in out:
        problems.append("output contained %r" % not_text)
    if problems:
        FAILURES.append((name, "; ".join(problems), out))
    else:
        PASSES.append(name)


def case(name, report_obj, baseline_obj, want_code, want_text=None, not_text=None, **kw):
    code, out = run(report_obj, baseline_obj, **kw)
    judge(name, code, out, want_code, want_text, not_text)


# A plausible run: big enough to clear the module's hard minimums (100 discovered, 40 executed).
GOOD = {}
for i in range(130):
    GOOD["REQ-%03d" % i] = "PASS" if i < 90 else "SKIPPED"


def main():
    # --- GREEN: identical input, this run's report, this run's provenance, matches.
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

    # --- RED: the discovery floor on its own. The requirement sets are identical, so nothing
    #     vanished; only the baseline's recorded discovery count is above this run's.
    case("discovery_floor_alone_is_red", report(GOOD), baseline(GOOD, floor_total=131), 1,
         "DISCOVERY FLOOR", not_text="VANISHED")

    # --- The floors are floors, not a licence. A run that executes MORE than the pin with every
    #     status identical matches; the same run with one status moved is still RED.
    case("more_execution_with_identical_statuses_matches",
         report(GOOD), baseline(GOOD, floor_executed=50), 0, "BASELINE MATCHED")
    case("more_execution_does_not_excuse_a_moved_status",
         report(moved), baseline(GOOD, floor_executed=50), 1, "STATUS MOVED")

    # --- RED: the comparison could not be made at all. Exit 2, never 0.
    case("missing_report_is_red", _ABSENT, baseline(GOOD), 2, "does not exist")
    case("empty_report_is_red", _EMPTY, baseline(GOOD), 2, "EMPTY")
    case("invalid_json_report_is_red", _NOT_JSON, baseline(GOOD), 2, "not valid JSON")
    case("report_without_per_requirement_is_red", {"summary": {}}, baseline(GOOD), 2,
         "no `per_requirement`")
    shapeless = report(GOOD); del shapeless["per_requirement"]["REQ-000"]["status"]
    case("requirement_without_status_is_red", shapeless, baseline(GOOD), 2, "has no `status`")
    nomap = baseline(GOOD); nomap["per_requirement"] = {}
    case("baseline_without_per_requirement_is_red", report(GOOD), nomap, 2,
         "carries no `per_requirement`")

    # --- RED: an earlier run's report. Identical verdicts, so only its age can refuse it -- which
    #     is exactly the report a crashed run leaves behind in the runner's persistent cache.
    case("stale_report_is_red", report(GOOD), baseline(GOOD), 2, "PREDATES", stale=True)

    # --- RED: a baseline of something other than this run. Each part of the provenance moved on
    #     its own, and the run stating none at all.
    case("provenance_unstated_is_red", report(GOOD), baseline(GOOD), 2, "A2A_TCK_REF is not set",
         env_prov={"tck_ref": None})
    case("suite_commit_moved_is_red", report(GOOD), baseline(GOOD), 2, "PROVENANCE",
         env_prov={"tck_ref": "another-suite-commit"})
    case("control_moved_is_red", report(GOOD), baseline(GOOD), 2, "PROVENANCE",
         env_prov={"control": "another-control"})
    case("time_zone_moved_is_red", report(GOOD), baseline(GOOD), 2, "PROVENANCE",
         env_prov={"tz": "UTC"})

    # --- RED: a baseline whose own floors are implausible is refused rather than trusted.
    #     Without this, re-recording during a broken run makes every run after it vacuous.
    tiny = {"REQ-000": "PASS"}
    case("implausible_baseline_is_refused", report(tiny), baseline(tiny), 2, "implausible")

    # --- RED: a baseline that discovered enough but EXECUTED almost nothing is equally refused.
    case("baseline_that_executed_nothing_is_refused",
         report(GOOD), baseline(GOOD, floor_executed=3), 2, "implausible")

    # --- --record. GREEN: a plausible run of this run is recorded, with this run's provenance.
    #     RED: each refusal that stops a broken or foreign run being blessed as the expectation.
    rec = ("--record", "--label", "selftest")
    case("record_writes_this_runs_provenance", report(GOOD), None, 0,
         '"tck_ref": "selftest-suite-commit"', mode=rec, read_back=True)
    case("record_refuses_too_few_discovered", report(tiny), None, 2, "discovered only", mode=rec)
    case("record_refuses_too_few_executed", report(allskip), None, 2, "EXECUTED only", mode=rec)
    case("record_refuses_a_stale_report", report(GOOD), None, 2, "PREDATES", mode=rec,
         stale=True)
    case("record_refuses_unstated_provenance", report(GOOD), None, 2, "TZ is not set", mode=rec,
         env_prov={"tz": None})
    case("record_refuses_no_label", report(GOOD), None, 2, "needs a --label", mode=("--record",))

    # --- --report-only, the ceiling leg. GREEN: this run's plausible report. RED: no report, an
    #     earlier run's report, a collapsed run's report, and a misuse of the mode.
    ro = ("--report-only",)
    case("report_only_accepts_this_runs_report", report(GOOD), None, 0, "REPORT PRESENT", mode=ro)
    case("report_only_refuses_no_report", _ABSENT, None, 2, "does not exist", mode=ro)
    case("report_only_refuses_a_stale_report", report(GOOD), None, 2, "PREDATES", mode=ro,
         stale=True)
    case("report_only_refuses_a_collapsed_run", report(allskip), None, 2, "measured next to nothing",
         mode=ro)
    case("report_only_takes_no_baseline", report(GOOD), None, 2, "takes no --record",
         mode=ro + ("--record",))
    case("check_needs_a_baseline", report(GOOD), None, 2, "--baseline is required",
         pass_baseline=False)
    case("missing_baseline_is_red", report(GOOD), None, 2, "The baseline does not exist")

    # --- RED: no --run-started. Without it no report could be refused for its age.
    with tempfile.TemporaryDirectory() as d:
        rp = os.path.join(d, "r.json")
        _write(rp, report(GOOD))
        p = subprocess.run([sys.executable, CHECK, "--report", rp, "--report-only"],
                           capture_output=True, text=True)
        judge("run_start_is_required", p.returncode, p.stdout + p.stderr, 2, "--run-started")

    # --- The runner. `run-tck.sh selftest` plants every refusal the runner and serve.sh can make
    #     (see the docstring); the leg count is pinned so a deleted leg is not a quiet pass.
    p = subprocess.run(["bash", RUNNER, "selftest"], capture_output=True, text=True)
    judge("runner_selftest_plants_every_refusal", p.returncode, p.stdout + p.stderr, 0,
          "runner selftest: 48 legs, all green")

    for name in PASSES:
        print("  ok   %s" % name)
    for name, why, out in FAILURES:
        print("  FAIL %s -- %s" % (name, why))
        print("       " + out.replace("\n", "\n       ")[:1200])

    # A selftest that discovered no cases is not a pass.
    total = len(PASSES) + len(FAILURES)
    if total < 38:
        print("\nSELFTEST DISCOVERED ONLY %d CASES. Cases were deleted or never ran." % total)
        return 2
    if FAILURES:
        print("\n%d of %d selftest cases FAILED." % (len(FAILURES), total))
        return 1
    print("\ncheck-baseline selftest: %d cases, all green." % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
