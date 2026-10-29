#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Parse h2spec's JUnit report (`h2spec -j`) into a per-case verdict.
#
#   parse-h2spec-junit.py --report R.xml --role control|negative|subject [--baseline B.json] --out O.json
#   parse-h2spec-junit.py --selftest
#
# A case is a <testcase>, named `<package>: <title>` (e.g. `http2/5.1.1: Sends stream ...`). It PASSED
# when it carries no <failure>, <error> or <skipped>. The roles judge the same counts differently:
#
#   subject    green only when EVERY case passed: no failure, no error, no skip, and at least
#              MIN_CASES cases (an empty or truncated report is never green).
#   control    the known-good third-party peer: green only when its failing set EQUALS the committed
#              baseline (the peer's own known results, `baselines/*.json`), no case skipped, and at
#              least MIN_CASES cases. A case that newly fails AND a baseline case that newly passes
#              are both a mismatch: the baseline is the peer's measured truth, not a waiver.
#   negative   the deliberately broken peer: green ("it bit") only when the SUBJECT rule grades it
#              RED and at least MIN_RED cases failed, so a parser that grades everything green, or a
#              broken peer that only trips one case, cannot pass.
#
# Exit 0 when the role's expectation held, 1 otherwise; the result JSON is written either way.
import json
import sys
import xml.etree.ElementTree as ET

# h2spec v2.6.0 runs 146 cases with -t (generic 23 + http2 + hpack 14).
MIN_CASES = 146
MIN_RED = 10


def load(path):
    root = ET.parse(path).getroot()
    cases = []
    for tc in root.iter("testcase"):
        name = "%s: %s" % (tc.get("package", "?"), tc.get("classname", "?"))
        if tc.find("failure") is not None or tc.find("error") is not None:
            state = "failed"
        elif tc.find("skipped") is not None:
            state = "skipped"
        else:
            state = "passed"
        cases.append((name, state))
    return cases


def summarize(cases):
    by = {"passed": [], "failed": [], "skipped": []}
    for name, state in cases:
        by[state].append(name)
    return {
        "total": len(cases),
        "passed": len(by["passed"]),
        "failed": len(by["failed"]),
        "skipped": len(by["skipped"]),
        "failing": sorted(by["failed"]),
        "skipping": sorted(by["skipped"]),
    }


def judge(role, s, baseline):
    """Return (ok, reason): ok means the role's expectation held."""
    short = s["total"] < MIN_CASES
    if role == "subject":
        if short:
            return False, "only %d cases ran, h2spec runs %d" % (s["total"], MIN_CASES)
        if s["failed"] or s["skipped"]:
            return False, "%d failed, %d skipped of %d: %s" % (
                s["failed"], s["skipped"], s["total"], "; ".join(s["failing"] + s["skipping"])[:600])
        return True, "all %d cases passed" % s["total"]
    if role == "control":
        if short:
            return False, "only %d cases ran, h2spec runs %d" % (s["total"], MIN_CASES)
        if s["skipped"]:
            return False, "control skipped: " + "; ".join(s["skipping"])
        want = sorted(baseline.get("failing", []))
        if s["failing"] != want:
            return False, "control failing set differs from baseline: got %r, baseline %r" % (s["failing"], want)
        return True, "control matches its baseline (%d known failing of %d)" % (len(want), s["total"])
    if role == "negative":
        sub_ok, _ = judge("subject", s, baseline)
        if sub_ok:
            return False, "the broken peer graded GREEN"
        if s["failed"] < MIN_RED:
            return False, "the broken peer failed only %d cases (< %d)" % (s["failed"], MIN_RED)
        return True, "the broken peer graded red (%d failed)" % s["failed"]
    return False, "unknown role %r" % role


def _xml(cases):
    body = []
    for pkg, title, kind in cases:
        inner = {"p": "", "f": "<failure>x</failure>", "e": "<error>x</error>", "s": "<skipped></skipped>"}[kind]
        body.append('<testcase package="%s" classname="%s">%s</testcase>' % (pkg, title, inner))
    return "<testsuites><testsuite>%s</testsuite></testsuites>" % "".join(body)


def selftest():
    import os
    import tempfile
    base = [("http2/1.%d" % i, "case %d" % i, "p") for i in range(MIN_CASES)]

    def run(role, cases, baseline=None):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(_xml(cases))
        try:
            return judge(role, summarize(load(f.name)), baseline or {})[0]
        finally:
            os.unlink(f.name)

    one_fail = [("http2/1.0", "case 0", "e")] + base[1:]
    one_skip = [("http2/1.0", "case 0", "s")] + base[1:]
    many_red = [(p, t, "f") for p, t, _ in base[:20]] + base[20:]
    checks = [
        ("subject: all pass is green", run("subject", base) is True),
        ("subject: one <error> is red", run("subject", one_fail) is False),
        ("subject: one <failure> is red", run("subject", [("http2/1.0", "case 0", "f")] + base[1:]) is False),
        ("subject: one skip is red", run("subject", one_skip) is False),
        ("subject: a truncated report is red", run("subject", base[:50]) is False),
        ("subject: an empty report is red", run("subject", []) is False),
        ("control: failing set == baseline is green", run("control", one_fail, {"failing": ["http2/1.0: case 0"]}) is True),
        ("control: a new failure is red", run("control", one_fail, {"failing": []}) is False),
        ("control: a baseline case that now passes is red", run("control", base, {"failing": ["http2/1.0: case 0"]}) is False),
        ("control: a skip is red", run("control", one_skip, {"failing": []}) is False),
        ("negative: many failures is green (it bit)", run("negative", many_red) is True),
        ("negative: all pass is red (it did not bite)", run("negative", base) is False),
        ("negative: one failure is red (too weak a peer)", run("negative", one_fail) is False),
    ]
    bad = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print("  %s: %s" % ("ok" if ok else "FAIL", n))
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    args = dict(zip(argv[1::2], argv[2::2]))
    for k in ("--report", "--role", "--out"):
        if k not in args:
            print("usage: parse-h2spec-junit.py --report R --role control|negative|subject [--baseline B] --out O", file=sys.stderr)
            return 2
    baseline = {}
    if "--baseline" in args:
        with open(args["--baseline"]) as f:
            baseline = json.load(f)
    try:
        s = summarize(load(args["--report"]))
        ok, reason = judge(args["--role"], s, baseline)
    except (OSError, ET.ParseError) as e:
        s = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "failing": [], "skipping": []}
        ok, reason = False, "no readable h2spec report: %s" % e
    out = dict(s, role=args["--role"], ok=ok, reason=reason)
    with open(args["--out"], "w") as f:
        json.dump(out, f, indent=2)
    print("%s: %s (%s)" % (args["--role"], "ok" if ok else "NOT OK", reason))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
