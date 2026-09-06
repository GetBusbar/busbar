#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Does the battery's own machinery still work? Run before believing any verdict it produces.

This is not a conformance run and it needs no network, no control and no subject. It checks the
four properties the battery's trustworthiness rests on, and it checks them by MAKING THEM FAIL:

  1. THE MODULE ENUMERATION IS A DIRECTORY LISTING, NOT A HARDCODED LIST. A hardcoded list is a
     blind spot with a delay fuse -- the next `tests_*.py` anybody adds is silently never
     imported. Proven by planting a new module and requiring the count to move.
  2. THE FLOOR REFUSES A SHRUNKEN BATTERY. A count that only ever goes up is not a safeguard.
  3. THE GOVERNANCE WALL HOLDS. Registering a governance test inside the conformance harness must
     RAISE, not be quietly filtered. A perfectly conformant agent that ignores every budget and
     never quarantines anything scores 100% on conformance; letting the two verdicts mix is how
     that becomes invisible.
  4. THE GOVERNANCE TIER IS A SEPARATE TOOL THAT STILL WORKS. `a2agov` must discover its own
     tests, and a default conformance selection must contain exactly ZERO of them.

Every check has a green half and a red half. A check nobody has watched fail is not known to work.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.abspath(os.path.join(HERE, ".."))
GOVERNANCE = os.path.abspath(os.path.join(HARNESS, "..", "a2a-governance"))

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("  %s  %s%s" % ("ok  " if ok else "FAIL", name,
                          "" if ok else " -- " + detail))


def py(code, cwd=HARNESS, extra_path=None):
    env = dict(os.environ)
    path = [cwd] + ([extra_path] if extra_path else [])
    env["PYTHONPATH"] = os.pathsep.join(path + [env.get("PYTHONPATH", "")])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, "-c", code], cwd=cwd, env=env,
                          capture_output=True, text=True)


COUNT = ("from a2aht import runner\n"
         "print('COUNT=%d' % len(runner.load_tests()))\n")


def count_from(proc):
    for line in proc.stdout.splitlines():
        if line.startswith("COUNT="):
            return int(line.split("=", 1)[1])
    return None


def main():
    print("A2A harness selftest")

    # ---- 1a. GREEN: the battery loads, and its size is reported rather than assumed.
    p = py(COUNT)
    base = count_from(p)
    check("battery_loads", p.returncode == 0 and base is not None,
          (p.stdout + p.stderr)[-800:])
    if base is None:
        return 2
    print("       (%d tests registered)" % base)

    # ---- 1b. RED-then-GREEN: a NEW tests_*.py module must be picked up with no edit anywhere.
    #      This is the exact defect that once made a reuse ratchet stop covering two new files.
    planted = os.path.join(HARNESS, "a2aht", "tests_zz_selftest_plant.py")
    try:
        with open(planted, "w") as fh:
            fh.write(
                "from .model import a2a_test, ROLE_SERVER, EVERY_COMMIT, NEEDS_FAKE_PEER\n"
                "@a2a_test(id='selftest.planted', role=ROLE_SERVER, tier=EVERY_COMMIT,\n"
                "          needs=NEEDS_FAKE_PEER, clause='SELFTEST',\n"
                "          defect='A module added to the package is never imported, so the "
                "battery silently tests less than it claims.')\n"
                "def planted(ctx):\n"
                "    pass\n")
        p2 = py(COUNT)
        grown = count_from(p2)
        check("new_module_is_discovered_without_an_edit",
              grown is not None and grown == base + 1,
              "count went %s -> %s (wanted %d); the module list is not a directory listing"
              % (base, grown, base + 1))
    finally:
        if os.path.exists(planted):
            os.remove(planted)

    # ---- 1c. GREEN twin: removing it puts the count back. Otherwise 1b could pass on leakage.
    p3 = py(COUNT)
    check("count_returns_after_the_plant_is_removed", count_from(p3) == base,
          "count is %s, was %s" % (count_from(p3), base))

    # ---- 2. RED: the floor refuses a battery that shrank.
    p4 = py("from a2aht import runner\n"
            "runner.MIN_EXPECTED_TESTS = 10**6\n"
            "try:\n"
            "    runner.load_tests()\n"
            "except RuntimeError as e:\n"
            "    print('REFUSED'); print(e)\n"
            "else:\n"
            "    print('ACCEPTED')\n")
    check("floor_refuses_a_shrunken_battery", "REFUSED" in p4.stdout,
          (p4.stdout + p4.stderr)[-800:])

    # ---- 3. RED: a governance test registered INSIDE the conformance harness must RAISE.
    p5 = py("from a2aht import runner, model\n"
            "@model.a2a_test(id='selftest.gov_leak', role=model.ROLE_GOVERNANCE,\n"
            "                tier=model.EVERY_COMMIT, needs=model.NEEDS_FAKE_PEER,\n"
            "                clause='SELFTEST',\n"
            "                defect='Product policy leaks into a clean-room conformance "
            "verdict, so a conformance pass reads as a governance pass.')\n"
            "def leak(ctx):\n"
            "    pass\n"
            "try:\n"
            "    runner.load_tests()\n"
            "except Exception as e:\n"
            "    print('RAISED'); print(type(e).__name__, e)\n"
            "else:\n"
            "    print('ACCEPTED')\n")
    check("governance_inside_conformance_raises",
          "RAISED" in p5.stdout and "governance" in p5.stdout.lower(),
          (p5.stdout + p5.stderr)[-800:])

    # ---- 3b. GREEN twin: without the plant, the same load is clean. Otherwise 3 could pass
    #      because load_tests raises for an unrelated reason.
    check("conformance_load_is_clean_without_the_plant", p.returncode == 0,
          (p.stdout + p.stderr)[-400:])

    # ---- 4a. The governance tier is a separate tool and still discovers its own tests.
    p6 = py("import a2agov.tests_governance\n"
            "from a2aht import model\n"
            "g = [t for t in model.all_tests() if t.role == model.ROLE_GOVERNANCE]\n"
            "print('GOV=%d' % len(g))\n",
            cwd=GOVERNANCE, extra_path=HARNESS)
    gov = None
    for line in p6.stdout.splitlines():
        if line.startswith("GOV="):
            gov = int(line.split("=", 1)[1])
    check("governance_tier_discovers_its_own_tests", gov is not None and gov >= 3,
          "GOV=%s; %s" % (gov, (p6.stdout + p6.stderr)[-600:]))

    # ---- 4b. A default conformance selection contains EXACTLY ZERO governance tests.
    p7 = py("from a2aht import runner, model\n"
            "sel = runner.select(runner.load_tests())\n"
            "n = sum(1 for t in sel if t.role == model.ROLE_GOVERNANCE)\n"
            "print('SELECTED=%d GOV_IN_SELECTION=%d' % (len(sel), n))\n")
    ok = "GOV_IN_SELECTION=0" in p7.stdout and "SELECTED=0" not in p7.stdout
    check("conformance_selection_contains_no_governance", ok,
          (p7.stdout + p7.stderr)[-600:])

    # ---- 5. THE REQUIRED PROFILE: an INAPPLICABLE on a row every A2A server owes is RED.
    #      RED half and GREEN half, because a rule that reddens everything proves as little as one
    #      that reddens nothing. The synthetic report below is the shape a "no-lifecycle" agent
    #      produces: it answers every request with a Message, so the whole task lifecycle reports
    #      INAPPLICABLE and the run used to print BATTERY GREEN.
    p8 = py("import io\n"
            "from a2aht import runner\n"
            "req = sorted(runner.REQUIRED_PROFILE)\n"
            "def row(i, outcome, assertions=1):\n"
            "    return {'id': i, 'outcome': outcome, 'role': 'server', 'defect': 'd',\n"
            "            'detail': 'agent answered with a Message', 'clause': '', 'notes': [],\n"
            "            'observations': {}, 'assertions': assertions}\n"
            "holes = [row(i, 'INAPPLICABLE') for i in req]\n"
            "filler = [row('filler.%d' % n, 'PASS') for n in range(40)]\n"
            "rep = {'harness_version': '0', 'spec': {'repo': 'r', 'tag': 't'},\n"
            "       'target': 't', 'generated_at': 'now', 'meta': {},\n"
            "       'counts': {}, 'results': holes + filler}\n"
            "for r in rep['results']:\n"
            "    rep['counts'][r['outcome']] = rep['counts'].get(r['outcome'], 0) + 1\n"
            "print('BAD_WITH_HOLES=%d' % runner.print_human(rep, io.StringIO()))\n"
            "rep2 = {**rep, 'results': [row(i, 'PASS') for i in req] + filler}\n"
            "print('BAD_WITHOUT_HOLES=%d' % runner.print_human(rep2, io.StringIO()))\n")
    with_holes = None
    for line in p8.stdout.splitlines():
        if line.startswith("BAD_WITH_HOLES="):
            with_holes = int(line.split("=", 1)[1])
    check("inapplicable_on_a_required_row_is_red",
          with_holes is not None and with_holes > 0,
          (p8.stdout + p8.stderr)[-800:])
    check("a_run_without_holes_is_green",
          "BAD_WITHOUT_HOLES=0" in p8.stdout,
          (p8.stdout + p8.stderr)[-800:])

    # ---- 6. THE ASSERTED-ROW FLOOR: a run made of rows that asserted nothing is not a pass.
    p9 = py("from a2aht import runner\n"
            "def row(i, assertions):\n"
            "    return {'id': i, 'outcome': 'PASS', 'assertions': assertions}\n"
            "thin = [row('t.%d' % n, 0) for n in range(50)] + [row('a.%d' % n, 1)\n"
            "                                                  for n in range(3)]\n"
            "fat = [row('a.%d' % n, 1) for n in range(50)]\n"
            "print('THIN=%r' % (runner.asserted_row_shortfall(thin) is not None))\n"
            "print('FAT=%r' % (runner.asserted_row_shortfall(fat) is not None))\n"
            "print('EMPTY=%r' % (runner.asserted_row_shortfall([]) is not None))\n")
    check("asserted_row_floor_refuses_a_run_that_asserted_almost_nothing",
          "THIN=True" in p9.stdout and "EMPTY=True" in p9.stdout,
          (p9.stdout + p9.stderr)[-800:])
    check("asserted_row_floor_accepts_a_real_run", "FAT=False" in p9.stdout,
          (p9.stdout + p9.stderr)[-800:])

    # ---- 7. A DEVIATION RECORD MAY NOT ABSORB A DIFFERENT FAILURE.
    #      The RED half is the one that matters: same test, same recorded fragment still present in
    #      the message, but a DIFFERENT assertion cited. That used to fold to BASELINED (green).
    p10 = py("from a2aht import deviations as d\n"
             "doc = {'deviations': [{'test': 't.one', 'clause': \"SPEC 5.6.1 Timestamps: 'Z'\",\n"
             "                       'evidence': 'which does not end in Z',\n"
             "                       'judgement': 'j', 'verdict': 'real-defect-in-control'}]}\n"
             "def rep(clause):\n"
             "    return {'results': [{'id': 't.one', 'outcome': 'FAIL', 'clause': clause,\n"
             "                         'detail': 'a value which does not end in Z was returned'}]}\n"
             "same, _ = d.apply(rep(\"SPEC 5.6.1: 'Timezone: UTC'\"), doc)\n"
             "print('SAME_CLAUSE=%s' % same['results'][0]['outcome'])\n"
             "other, _ = d.apply(rep(\"SPEC 9.5: '-32603 InternalError'\"), doc)\n"
             "print('OTHER_CLAUSE=%s' % other['results'][0]['outcome'])\n")
    check("a_failure_citing_a_different_clause_is_not_baselined",
          "OTHER_CLAUSE=DEVIATION_CHANGED" in p10.stdout,
          (p10.stdout + p10.stderr)[-800:])
    check("the_recorded_failure_itself_still_baselines",
          "SAME_CLAUSE=BASELINED" in p10.stdout,
          (p10.stdout + p10.stderr)[-800:])

    # ---- 8. BOILERPLATE EVIDENCE IS REFUSED AT LOAD, and a real record still loads.
    p11 = py("import json, tempfile, os\n"
             "from a2aht import deviations as d\n"
             "def write(ev):\n"
             "    fh = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)\n"
             "    json.dump({'deviations': [{'test': 't', 'clause': 'SPEC 1.2',\n"
             "                               'evidence': ev, 'judgement': 'j',\n"
             "                               'verdict': 'real-defect-in-control'}]}, fh)\n"
             "    fh.close(); return fh.name\n"
             "for label, ev in (('BOILERPLATE', 'error'),\n"
             "                  ('SPECIFIC', 'without includeArtifacts=true')):\n"
             "    path = write(ev)\n"
             "    try:\n"
             "        d.load(path); print('%s=ACCEPTED' % label)\n"
             "    except d.DeviationFileError:\n"
             "        print('%s=REFUSED' % label)\n"
             "    finally:\n"
             "        os.unlink(path)\n")
    check("boilerplate_evidence_is_refused", "BOILERPLATE=REFUSED" in p11.stdout,
          (p11.stdout + p11.stderr)[-800:])
    check("specific_evidence_is_accepted", "SPECIFIC=ACCEPTED" in p11.stdout,
          (p11.stdout + p11.stderr)[-800:])

    # ---- 9. RED: a deviation recorded for a test that DID NOT RUN must make the run red.
    #      `deviations.print_summary` prints these under `DEVIATION RECORD PROBLEMS (these are
    #      RED)`, and until `runner.exit_code` existed the process exited 0 over them: the record
    #      produces no result row, so it contributes to no outcome count. Drop a test from the
    #      registry, or narrow `--role` past it, and its deviation stops being checked silently.
    p12 = py("from a2aht import runner\n"
             "rep = {'counts': {'PASS': 3},\n"
             "       'known_deviations': {'recorded': 1, 'baselined': 0, 'source': 'selftest',\n"
             "                            'problems': [{'id': 'gone.test',\n"
             "                                          'kind': 'DEVIATION_NOT_RUN',\n"
             "                                          'why': 'selftest'}]}}\n"
             "print('NOT_RUN_EXIT=%d' % runner.exit_code(rep))\n"
             "print('OLD_RULE_EXIT=%d' % (1 if sum(rep['counts'].get(o, 0)\n"
             "                                     for o in runner.BAD_OUTCOMES) else 0))\n")
    check("unrun_deviation_record_is_red",
          "NOT_RUN_EXIT=1" in p12.stdout and "OLD_RULE_EXIT=0" in p12.stdout,
          (p12.stdout + p12.stderr)[-800:])

    # ---- 9b. GREEN twin: a clean report with no deviation problems still exits 0, so 9 is not a
    #      rule that reddens everything.
    p13 = py("from a2aht import runner\n"
             "print('CLEAN_EXIT=%d' % runner.exit_code({'counts': {'PASS': 3, 'OBSERVED': 1}}))\n"
             "print('ALLOW_RED_EXIT=%d'\n"
             "      % runner.exit_code({'counts': {'FAIL': 2}}, allow_red=True))\n")
    check("clean_report_and_allow_red_still_exit_zero",
          "CLEAN_EXIT=0" in p13.stdout and "ALLOW_RED_EXIT=0" in p13.stdout,
          (p13.stdout + p13.stderr)[-800:])

    # A selftest that ran no checks is not a pass.
    if len(RESULTS) < 10:
        print("\nSELFTEST RAN ONLY %d CHECKS. Checks were deleted or never reached." % len(RESULTS))
        return 2
    bad = [n for n, ok, _ in RESULTS if not ok]
    if bad:
        print("\n%d of %d harness selftest checks FAILED: %s"
              % (len(bad), len(RESULTS), ", ".join(bad)))
        return 1
    print("\nharness selftest: %d checks, all green (battery = %d tests, governance = %d)."
          % (len(RESULTS), base, gov))
    return 0


if __name__ == "__main__":
    sys.exit(main())
