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
import re

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

# WHAT COUNTS AS EVIDENCE, and why the bar is here rather than in a reviewer's head.
#
# THE DEFECT THIS CLOSES. `apply` folds a FAIL to BASELINED when the record's `evidence` string
# appears ANYWHERE in the failure detail. Evidence like "error" or "not found" appears in almost
# every failure message a test can produce, so a record written for one deviation silently absorbed
# a DIFFERENT and WORSE failure of the same test — the run stayed green and the regression was
# reported as an accounted-for fact about the control. That is precisely the mute button this file's
# own header says a deviation record must never be.
#
# Two independent bars now stand between a failure and a green row, and BOTH must clear:
#
#   1. THE RECORD MUST BE SPECIFIC (checked at load, below). A fragment that is a bare generic
#      phrase, or too short, or too few words to name anything observed, is refused outright: an
#      un-specific record cannot be told apart from a mute button, so it is not accepted as one.
#   2. THE FAILURE MUST BE THE SAME ASSERTION (checked in `apply`). The clause the failing result
#      CITES must share a spec reference with the clause the record was written against. A worse
#      regression trips a different assert_must with a different citation, and a different citation
#      can no longer be folded away by a fragment that happens to still appear in the text.
MIN_EVIDENCE_CHARS = 12
# Two, not three: the shortest legitimate record in the baselines quotes a two-word condition
# ("without includeArtifacts=true") that names exactly one observed thing. The word count is only
# here to refuse one-word phrases; the character floor and the blacklist do the rest, and the
# clause-reference rule in `apply` is what actually stops a different failure being folded away.
MIN_EVIDENCE_WORDS = 2

# Bare phrases that appear in failure text regardless of WHICH failure it is. A record whose whole
# evidence is one of these names nothing that was observed.
BOILERPLATE_EVIDENCE = frozenset([
    "error", "an error", "failed", "failure", "invalid", "not found",
    "internal error", "timeout", "timed out", "mismatch", "unexpected",
    "bad request", "no response", "none", "null", "empty", "missing",
    "does not match", "is wrong", "was rejected", "not supported",
])

_SPEC_REF = re.compile(r"\b(?:SPEC|PROTO)\s+[A-Za-z0-9][A-Za-z0-9._]*")


def clause_refs(text):
    """The spec references named in a clause string, e.g. {'SPEC 3.3.2', 'SPEC 9.5'}.

    Compared as SETS rather than as whole strings on purpose: a record quotes the clause in prose
    ("SPEC 5.6.1 Timestamps: '...'") while the assertion cites it in its own wording ("SPEC 5.6.1:
    '...'"). The REFERENCE is the stable part of both, and it is the part that identifies WHICH
    rule was broken.
    """
    return {m.group(0).rstrip(".").upper() for m in _SPEC_REF.finditer(text or "")}


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
        evidence = " ".join(str(rec["evidence"]).split())
        low = evidence.lower().strip(" .'\"")
        if (len(evidence) < MIN_EVIDENCE_CHARS
                or len(evidence.split()) < MIN_EVIDENCE_WORDS
                or low in BOILERPLATE_EVIDENCE):
            raise DeviationFileError(
                "%s: deviation %d for %r has evidence %r, which is not "
                "specific enough to identify one failure. A fragment this "
                "generic appears in failure text whatever the failure is, so "
                "it would fold a DIFFERENT and possibly WORSE failure of the "
                "same test into a green BASELINED row. Quote the observed "
                "message: at least %d characters and %d words naming what "
                "this control actually did."
                % (path, i, rec["test"], rec["evidence"],
                   MIN_EVIDENCE_CHARS, MIN_EVIDENCE_WORDS))
        if not clause_refs(rec["clause"]):
            raise DeviationFileError(
                "%s: deviation %d for %r cites clause %r, which names no SPEC "
                "or PROTO reference. The reference is what ties the record to "
                "ONE assertion; without it the record can absorb any failure "
                "of the test."
                % (path, i, rec["test"], rec["clause"]))
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
            # BOTH BARS. The fragment must still be there AND the failure must cite a clause the
            # record was written against. A regression that trips a different assertion inside the
            # same test now stays RED even when the recorded fragment happens to survive in its
            # message, which is the fold this file used to perform silently.
            recorded_refs = clause_refs(rec["clause"])
            actual_refs = clause_refs(result.get("clause") or "")
            same_assertion = bool(recorded_refs & actual_refs) if actual_refs else False
            if evidence in (result["detail"] or "") and same_assertion:
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
                           "information and must be re-examined."
                           + ("" if evidence in (result["detail"] or "") else
                              " The recorded evidence is not in the failure "
                              "detail.")
                           + ("" if same_assertion else
                              " The failure cites %s, and this record was "
                              "written against %s: a DIFFERENT assertion "
                              "inside the same test, which a record may never "
                              "absorb."
                              % (sorted(actual_refs) or "no clause",
                                 sorted(recorded_refs))),
                    "expected_evidence": evidence,
                    "expected_clause_refs": sorted(recorded_refs),
                    "actual_clause_refs": sorted(actual_refs),
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
