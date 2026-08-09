"""Known control deviations: enumerated, evidenced, and machine-checked.

The problem this solves. The control violates the spec in a small number of
places. There are two bad ways to cope with that and one good one:

  BAD   Weaken the test until the control passes. Now the test no longer
        asserts the thing, and the same defect in a subject sails through.

  BAD   Leave the run red and tell everyone to ignore those three lines. A
        standing red trains people to read red as normal, and the first real
        failure looks exactly like the expected one.

  GOOD  Keep the test at full strength, and record each deviation as an
        explicit, evidenced fact about the control. The run is green overall
        because every failure is accounted for, and the test still fires.

A deviation record is not a mute button. It is an assertion in its own right,
and it is checked in BOTH directions:

  - a FAIL that matches a recorded deviation becomes BASELINED (green)
  - a FAIL that does NOT match any record stays FAIL (red). A second deviation
    breaks the green, which is the entire point.
  - a FAIL whose evidence no longer matches the record stays FAIL (red). The
    deviation CHANGED, and a changed deviation is new information.
  - a recorded deviation that no longer occurs is DEVIATION_FIXED (red). It
    silently started passing, the record is now a lie, and it must be removed
    deliberately rather than rotting in the file forever.

Every record must carry the governing spec clause, the observed evidence, and
a human judgement. A record without those is refused at load time, because an
un-evidenced entry is indistinguishable from a mute button.
"""

import json

from .model import FAIL, ERROR

BASELINED = "BASELINED"
DEVIATION_FIXED = "DEVIATION_FIXED"
DEVIATION_CHANGED = "DEVIATION_CHANGED"

REQUIRED_KEYS = ("test", "clause", "evidence", "judgement", "verdict")

# A deviation must be classified. "real-defect-in-control" means the control
# is wrong and we have checked. "spec-ambiguity" means the spec permits it and
# the test is stricter than the spec allows, which is a bug in the test and
# must be fixed rather than baselined.
VALID_VERDICTS = (
    "real-defect-in-control",
    "control-policy-choice",
)


class DeviationFileError(Exception):
    pass


def load(path):
    with open(path) as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "deviations" not in doc:
        raise DeviationFileError(
            "%s: expected an object with a 'deviations' array" % path)
    records = doc["deviations"]
    seen = set()
    for i, rec in enumerate(records):
        missing = [k for k in REQUIRED_KEYS if not rec.get(k)]
        if missing:
            raise DeviationFileError(
                "%s: deviation %d is missing %s. Every record MUST carry the "
                "governing clause, the observed evidence and a human "
                "judgement; an un-evidenced record is just a mute button."
                % (path, i, missing))
        if rec["verdict"] not in VALID_VERDICTS:
            raise DeviationFileError(
                "%s: deviation %d has verdict %r, expected one of %s. If the "
                "spec actually permits the behaviour then the TEST is wrong "
                "and must be fixed, not baselined."
                % (path, i, rec["verdict"], list(VALID_VERDICTS)))
        if rec["test"] in seen:
            raise DeviationFileError(
                "%s: duplicate deviation for test %r" % (path, rec["test"]))
        seen.add(rec["test"])
    return doc


def apply(report, doc):
    """Fold recorded deviations into a report. Returns (report, problems)."""
    records = {r["test"]: r for r in doc["deviations"]}
    problems = []
    matched = set()

    for result in report["results"]:
        rec = records.get(result["id"])
        if rec is None:
            continue
        if result["outcome"] in (FAIL, ERROR):
            evidence = rec["evidence"]
            if evidence in (result["detail"] or ""):
                matched.add(result["id"])
                result["outcome"] = BASELINED
                result["baselined"] = {
                    "clause": rec["clause"],
                    "verdict": rec["verdict"],
                    "judgement": rec["judgement"],
                    "evidence": evidence,
                }
            else:
                matched.add(result["id"])
                result["outcome"] = DEVIATION_CHANGED
                problems.append({
                    "id": result["id"],
                    "kind": DEVIATION_CHANGED,
                    "why": "this test still fails, but not in the recorded "
                           "way. The deviation CHANGED, which is new "
                           "information and must be re-examined.",
                    "expected_evidence": evidence,
                    "actual_detail": (result["detail"] or "")[:600],
                })
        else:
            matched.add(result["id"])
            result["outcome"] = DEVIATION_FIXED
            problems.append({
                "id": result["id"],
                "kind": DEVIATION_FIXED,
                "why": "a recorded control deviation NO LONGER OCCURS "
                       "(outcome is now %s). The record is stale and must be "
                       "removed deliberately. Deviations are not allowed to "
                       "rot in the file." % result["outcome"],
                "expected_evidence": evidence_of(rec),
            })

    for test_id in sorted(set(records) - matched):
        problems.append({
            "id": test_id,
            "kind": "DEVIATION_NOT_RUN",
            "why": "a deviation is recorded for this test but the test did "
                   "not run in this battery. Either the selection is wrong or "
                   "the record is stale.",
            "expected_evidence": evidence_of(records[test_id]),
        })

    counts = {}
    for r in report["results"]:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    report["counts"] = counts
    report["known_deviations"] = {
        "source": doc.get("control", "unknown"),
        "recorded": len(records),
        "baselined": counts.get(BASELINED, 0),
        "problems": problems,
    }
    return report, problems


def evidence_of(rec):
    return rec.get("evidence", "")


def print_summary(report, stream):
    kd = report.get("known_deviations")
    if not kd:
        return
    w = stream.write
    w("\n")
    w("KNOWN CONTROL DEVIATIONS (%d recorded, %d baselined)\n"
      % (kd["recorded"], kd["baselined"]))
    for result in report["results"]:
        if result["outcome"] != BASELINED:
            continue
        b = result["baselined"]
        w("  BASELINED  %s\n" % result["id"])
        w("      verdict   %s\n" % b["verdict"])
        w("      clause    %s\n" % _wrap(b["clause"]))
        w("      evidence  %s\n" % _wrap(b["evidence"]))
        w("      judgement %s\n" % _wrap(b["judgement"]))
    if kd["problems"]:
        w("\n  DEVIATION RECORD PROBLEMS (these are RED)\n")
        for p in kd["problems"]:
            w("    [%s] %s\n" % (p["kind"], p["id"]))
            w("        %s\n" % _wrap(p["why"], 8))
    w("\n")


def _wrap(text, indent=16, width=96):
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    out, line = [], ""
    for word in text.split(" "):
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = " " * indent + word
        else:
            line = (line + " " + word) if line else word
    out.append(line)
    return "\n".join(out)
