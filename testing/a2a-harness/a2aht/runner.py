"""Battery runner, report writer, and differential comparison."""

import json
import platform
import sys
import time

from . import model
from .model import (PASS, OBSERVED, INAPPLICABLE, NOT_CONFIGURED, FAIL, ERROR,
                    EVERY_COMMIT, PULL_REQUEST, PRE_RELEASE)

TIER_ORDER = {EVERY_COMMIT: 0, PULL_REQUEST: 1, PRE_RELEASE: 2}

# Outcomes that make a run red.
#
# BASELINED is deliberately NOT here: a baselined deviation is an accounted-for
# fact about the control, still asserted, and it does not make the run red.
# DEVIATION_FIXED and DEVIATION_CHANGED ARE here, because a record that no
# longer matches reality is new information.
BAD_OUTCOMES = (FAIL, ERROR, NOT_CONFIGURED, "DEVIATION_FIXED",
                "DEVIATION_CHANGED")

# THE REQUIRED PROFILE: rows where INAPPLICABLE is a HOLE, not a legal absence.
#
# INAPPLICABLE exists for capabilities the spec makes optional -- an unsigned card (SPEC 8.4 makes
# signing a MAY), a card with no skills, a binding this run did not select. Those absences are
# honest and they are not red.
#
# THE DEFECT THIS CLOSES. INAPPLICABLE was not in BAD_OUTCOMES for ANY row, and a large part of the
# battery reaches its Inapplicable branch through ONE condition: "the agent answered with a Message,
# so there is no task". An agent that answers every request with a Message therefore turned the
# whole task lifecycle -- get, cancel, terminal-state refusal, context stability, history -- into a
# row of quiet INAPPLICABLEs and scored BATTERY GREEN, having proven nothing about the half of A2A
# that carries work. A green tick over a lifecycle nobody exercised is the same false green as an
# unarmed leg.
#
# So these rows are REQUIRED: the spec obliges every A2A server to serve a card and to run the task
# lifecycle, and a run that could not reach them has not judged the agent, whatever the reason. It
# is deliberately a SPINE and not "everything": each id below is a row whose INAPPLICABLE means the
# harness never got to the mandatory surface, never a row that is INAPPLICABLE because an OPTIONAL
# capability was legally not declared. The pinned controls report INAPPLICABLE on none of them.
REQUIRED_PROFILE = frozenset([
    "card.served",
    "card.required_fields",
    "core.send_message_returns_task_or_message",
    "core.task_state_is_defined_enum",
    "core.blocking_send_reaches_settled_state",
    "core.get_task_roundtrip",
    "core.unknown_task_is_task_not_found",
    "core.context_id_present_and_stable",
    "core.terminal_task_refuses_new_messages",
    "core.cancel_semantics",
])

# THE ASSERTED-ROW FLOOR.
#
# A row is ASSERTED when at least one assert_must ran inside it. OBSERVED rows assert nothing by
# construction, INAPPLICABLE rows never reached their assertions, and a PASS with zero assertions is
# a scenario that looked at the target and judged nothing. A run made mostly of those is a report
# about a target nobody tested, and it prints BATTERY GREEN. The floor is a FRACTION of the rows the
# run selected rather than a fixed count, because the count legitimately moves with --tier, --role
# and --only; the pinned controls sit between 58% and 74%.
MIN_ASSERTED_FRACTION = 0.40
MIN_ASSERTED_ROWS = 10


def is_bad(result):
    """Is this row red? A dict as written into the report."""
    if result["outcome"] in BAD_OUTCOMES:
        return True
    return (result["outcome"] == INAPPLICABLE
            and result["id"] in REQUIRED_PROFILE)


def asserted_row_shortfall(results):
    """None if the run asserted enough, else a human-readable refusal.

    Kept separate from the per-row verdicts because it is a property of the RUN: no individual row
    is wrong, and the run as a whole still proves nothing.
    """
    if not results:
        return ("the run produced NO rows at all, so it judged nothing.")
    asserted = [r for r in results if r.get("assertions")]
    floor = max(MIN_ASSERTED_ROWS, int(len(results) * MIN_ASSERTED_FRACTION))
    if len(asserted) >= floor:
        return None
    return (
        "ASSERTED-ROW FLOOR: only %d of %d rows in this run actually ran a "
        "spec assertion against the target (floor %d). The rest observed, were "
        "inapplicable, or asserted nothing, so this number is a report about a "
        "target that was barely tested. A run this thin must not print GREEN."
        % (len(asserted), len(results), floor))


# If the battery ever shrinks below this, something has stopped being
# registered and the suite is quietly testing less than it claims. A count
# that only ever goes up is not a safeguard; a floor that refuses to run is.
MIN_EXPECTED_TESTS = 85


def load_tests():
    """Import every test module so the registry is populated.

    Modules are ENUMERATED FROM THE DIRECTORY, never listed by hand. A
    hardcoded list is a blind spot with a delay fuse: the next tests_*.py
    anyone adds is silently never imported, never registered, and never run,
    and the suite goes green having skipped it. The floor check below is the
    backstop for the same failure by any other route.
    """
    import importlib
    import pathlib
    import re

    here = pathlib.Path(__file__).parent
    modules = sorted(p.stem for p in here.glob("tests_*.py"))
    if not modules:
        raise RuntimeError(
            "no tests_*.py modules found in %s. The battery is empty and "
            "refuses to report a vacuous result." % here)
    for name in modules:
        importlib.import_module("%s.%s" % (__package__, name))

    tests = model.all_tests()
    if len(tests) < MIN_EXPECTED_TESTS:
        raise RuntimeError(
            "only %d tests registered from modules %s, below the floor of "
            "%d. Tests have stopped being registered, so this run would "
            "under-report coverage while looking green. Refusing to run.\n"
            "If the battery was legitimately reduced, lower "
            "MIN_EXPECTED_TESTS deliberately in a commit that says why."
            % (len(tests), modules, MIN_EXPECTED_TESTS))

    stray = [t.id for t in tests if t.role == "governance"]
    if stray:
        raise RuntimeError(
            "governance tests found INSIDE the conformance harness: %s.\n"
            "The conformance harness derives its value from containing zero "
            "product knowledge. Governance is product policy, not protocol, "
            "and a green conformance tick must never be readable as a "
            "governance pass. Governance lives in testing/a2a-governance."
            % stray)

    ids = [t.id for t in tests]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise RuntimeError(
            "duplicate test ids %s. Ids key the differential and the "
            "deviation records, so a duplicate silently overwrites a result."
            % dupes)
    return tests


def select(tests, tier=PRE_RELEASE, role=None, only=None, needs=None,
           include_governance=False):
    """Select tests to run.

    Governance tests are EXCLUDED unless asked for explicitly. A conformance
    verdict must never silently include them, and a governance verdict must
    never be mistaken for a conformance one.
    """
    ceiling = TIER_ORDER[tier]
    out = []
    for test in tests:
        if test.role == "governance" and not (include_governance
                                              or role == "governance"):
            continue
        if TIER_ORDER[test.tier] > ceiling:
            continue
        if role and test.role != role:
            continue
        if needs and test.needs not in needs:
            continue
        if only and not any(token in test.id for token in only):
            continue
        out.append(test)
    return out


def role_audit(all_registered, selected, tier=PRE_RELEASE):
    """Which DIRECTIONS this run measured, and which it did not, with counts.

    A conformance count with no role beside it is how a one-directional number
    comes to be read as a two-directional claim. The sibling MCP battery had
    exactly that defect: its fourteen client-role scenarios left the
    denominator when the role was unarmed and `50 pass, 0 fail` printed as
    total coverage.

    Here the deselection is done by `--role`, not by an unset launch command --
    an unsupplied `--client-drive` is already NOT_CONFIGURED and RED, which is
    correct -- so this function does not refuse anything. It makes the
    narrowing IMPOSSIBLE TO QUOTE WITHOUT: every role in the registry that this
    run did not select is named in the report and on the summary line, with the
    number of scenarios that went unmeasured.
    """
    ceiling = TIER_ORDER[tier]
    registered = {}
    for t in all_registered:
        if t.role == "governance":
            continue
        if TIER_ORDER[t.tier] > ceiling:
            continue
        registered[t.role] = registered.get(t.role, 0) + 1
    ran = {}
    for t in selected:
        ran[t.role] = ran.get(t.role, 0) + 1
    return {
        "roles_run": sorted(ran),
        "roles_not_run": sorted(r for r in registered if r not in ran),
        "scenarios_by_role": registered,
        "scenarios_run_by_role": ran,
    }


def run_battery(target, config, tests):
    results = []
    for test in tests:
        results.append(test.run(target, config))
    return results


def report(results, target_label, meta=None):
    counts = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    return {
        "harness": "a2aht",
        "harness_version": HARNESS_VERSION,
        "spec": {"repo": "https://github.com/a2aproject/A2A", "tag": "v1.0.1"},
        "target": target_label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "counts": counts,
        "results": [r.to_dict() for r in results],
        "meta": meta or {},
    }


HARNESS_VERSION = "1.0.0"


def print_human(rep, stream=sys.stdout, verbose=False):
    w = stream.write
    w("\n")
    w("A2A independent conformance battery\n")
    w("  harness      a2aht %s\n" % rep["harness_version"])
    w("  spec         %s @ %s\n" % (rep["spec"]["repo"], rep["spec"]["tag"]))
    w("  target       %s\n" % rep["target"])
    w("  generated    %s\n" % rep["generated_at"])
    w("\n")
    order = {FAIL: 0, ERROR: 1, NOT_CONFIGURED: 2, "DEVIATION_CHANGED": 3,
             "DEVIATION_FIXED": 4, "BASELINED": 5, OBSERVED: 6, PASS: 7,
             INAPPLICABLE: 8}
    for res in sorted(rep["results"], key=lambda r: (order.get(r["outcome"], 9),
                                                     r["id"])):
        w("  %-14s %-46s %s%s\n" % (res["outcome"], res["id"], res["role"],
                                    "  <-- REQUIRED BY THE PROFILE"
                                    if (res["outcome"] == INAPPLICABLE
                                        and res["id"] in REQUIRED_PROFILE)
                                    else ""))
        if is_bad(res):
            w("      defect  %s\n" % _wrap(res["defect"], 14))
            if res["detail"]:
                w("      detail  %s\n" % _wrap(res["detail"].strip(), 14))
            if res["clause"]:
                w("      clause  %s\n" % _wrap(res["clause"], 14))
        elif verbose and res["observations"]:
            for k, v in sorted(res["observations"].items()):
                if k.startswith("_"):
                    continue
                w("      %-20s %s\n" % (k, _short(v)))
        for note in res["notes"]:
            w("      NOTE    %s\n" % _wrap(note, 14))
    w("\n")
    gaps = [r for r in rep["results"] if r["outcome"] == INAPPLICABLE]
    if gaps:
        w("GAPS: tests that did not exercise the target, and why\n")
        w("  A gap is a hole shaped exactly like the boundary the test was\n")
        w("  written to defend. None of these prove anything.\n\n")
        for r in sorted(gaps, key=lambda x: x["id"]):
            w("  %-46s %s\n" % (r["id"], _wrap(r["detail"] or "no reason "
                                                 "recorded", 48)))
        w("\n")

    # THE ROLES THIS NUMBER MEASURED, printed immediately above the number so the
    # two cannot be separated when somebody quotes it.
    audit = (rep.get("meta") or {}).get("role_audit")
    if audit:
        w("  roles run     %s\n" % (", ".join(
            "%s (%d)" % (r, audit["scenarios_run_by_role"].get(r, 0))
            for r in audit["roles_run"]) or "<none>"))
        for r in audit["roles_not_run"]:
            w("  ROLE NOT RUN  %s -- %d scenario(s) in this tier were NOT "
              "selected, so this number says NOTHING about that direction\n"
              % (r, audit["scenarios_by_role"].get(r, 0)))

    counts = rep["counts"]
    w("  " + "  ".join("%s=%d" % (k, counts[k]) for k in sorted(counts))
      + ("   [roles: %s]" % ",".join(audit["roles_run"]) if audit else "")
      + "\n")
    bad = sum(1 for r in rep["results"] if is_bad(r))

    # THE PROFILE HOLES, NAMED. A required row that could not be reached is not a smaller battery,
    # it is an unjudged obligation, and the reader must see which one.
    holes = [r for r in rep["results"]
             if r["outcome"] == INAPPLICABLE and r["id"] in REQUIRED_PROFILE]
    if holes:
        w("\n  REQUIRED ROWS THAT NEVER RAN (%d). Every A2A server owes these; an\n"
          "  INAPPLICABLE here is a hole in the verdict, not a legal absence:\n" % len(holes))
        for r in sorted(holes, key=lambda x: x["id"]):
            w("    %-46s %s\n" % (r["id"], _wrap(r["detail"] or "no reason recorded", 48)))

    # The floor is a property of a CONFORMANCE verdict. The governance probe asserts nothing by
    # construction — it observes policy and says so, and it gates on nothing — so applying a floor
    # meant for conformance would print a red banner over a tool that is working exactly as designed.
    is_conformance = not (rep.get("meta") or {}).get("not_a_conformance_result")
    shortfall = asserted_row_shortfall(rep["results"]) if is_conformance else None
    if shortfall:
        bad += 1
        w("\n  %s\n" % _wrap(shortfall, 2))

    w("  %s\n" % ("BATTERY GREEN" if bad == 0
                  else "BATTERY RED: %d test(s) need attention" % bad))
    w("\n")
    return bad


def exit_code(rep, allow_red=False):
    """The run's verdict, from the report alone. ONE place, so nothing decides it twice.

    `print_human` returns the number of BAD_OUTCOMES it printed, and for a long time that was the
    whole verdict. It misses one thing, and the miss is silent: a deviation recorded for a test that
    DID NOT RUN produces no result row at all, so it contributes to no outcome count.
    `deviations.print_summary` prints it under a heading that reads `DEVIATION RECORD PROBLEMS
    (these are RED)` -- and then the run exited 0 anyway. That is the shape of a record going stale
    while the gate that is supposed to notice keeps ticking: drop a test from the registry, or
    narrow the selection past it, and its deviation record stops being checked with nothing
    anywhere going red.
    """
    counts = rep.get("counts") or {}
    bad = sum(counts.get(o, 0) for o in BAD_OUTCOMES)
    bad += unrun_deviations(rep)
    if allow_red:
        return 0
    return 1 if bad else 0


def unrun_deviations(rep):
    """How many recorded deviations name a test this run never executed."""
    problems = ((rep.get("known_deviations") or {}).get("problems")) or []
    return sum(1 for p in problems if p.get("kind") == "DEVIATION_NOT_RUN")


def _short(value):
    text = json.dumps(value, default=str)
    return text if len(text) <= 100 else text[:97] + "..."


def _wrap(text, indent, width=100):
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    out = []
    line = ""
    for word in text.split(" "):
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = " " * (indent + 8) + word
        else:
            line = (line + " " + word) if line else word
    out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Differential comparison
# ---------------------------------------------------------------------------

def differential(control_report, subject_report):
    """Compare a subject run against a control run.

    The comparison has two halves, and the split is the whole point:

      DEFECTS      the subject violated a spec MUST. This is a defect in the
                   subject whatever the control did. The control's behaviour
                   is irrelevant here and is never used to excuse a failure.

      DIVERGENCES  the subject and the control differ somewhere the spec
                   permits variation. This is NOT a failure. It is a report
                   for a human, naming the input, both values, and the clause
                   that makes the variation legal, if there is one.
    """
    control = {r["id"]: r for r in control_report["results"]}
    subject = {r["id"]: r for r in subject_report["results"]}

    defects = []
    divergences = []
    outcome_shifts = []
    missing = []

    for test_id, sub in sorted(subject.items()):
        ctl = control.get(test_id)
        if ctl is None:
            missing.append({"id": test_id,
                            "why": "not present in the control report"})
            continue

        if sub["outcome"] in (FAIL, ERROR):
            defects.append({
                "id": test_id,
                "defect_caught": sub["defect"],
                "clause": sub["clause"] or ctl["clause"],
                "subject_outcome": sub["outcome"],
                "subject_detail": sub["detail"],
                "control_outcome": ctl["outcome"],
                "control_detail": ctl["detail"],
                "also_fails_on_control": ctl["outcome"] in (FAIL, ERROR),
            })
        elif sub["outcome"] != ctl["outcome"]:
            outcome_shifts.append({
                "id": test_id,
                "control_outcome": ctl["outcome"],
                "subject_outcome": sub["outcome"],
                "control_detail": ctl["detail"],
                "subject_detail": sub["detail"],
                "note": "Different outcome without a MUST violation. Usually "
                        "an optional capability one side declares and the "
                        "other does not.",
            })

        clauses = (ctl.get("observations") or {}).get("_clauses", {})
        for key in sorted(set(ctl["observations"]) | set(sub["observations"])):
            if key.startswith("_"):
                continue
            cval = ctl["observations"].get(key, "<absent>")
            sval = sub["observations"].get(key, "<absent>")
            if cval != sval:
                divergences.append({
                    "id": test_id,
                    "observation": key,
                    "input": test_id,
                    "control_returned": cval,
                    "subject_returned": sval,
                    "governing_clause": clauses.get(key)
                        or (sub["observations"].get("_clauses", {}) or {}).get(key)
                        or "NONE. The spec does not constrain this, so the "
                           "two implementations may legally differ.",
                })

    for test_id in sorted(set(control) - set(subject)):
        missing.append({"id": test_id,
                        "why": "the subject run did not execute this test"})

    return {
        "control": control_report["target"],
        "subject": subject_report["target"],
        "spec_tag": control_report["spec"]["tag"],
        "defects": defects,
        "divergences": divergences,
        "outcome_shifts": outcome_shifts,
        "missing": missing,
        "summary": {
            "defects": len(defects),
            "divergences": len(divergences),
            "outcome_shifts": len(outcome_shifts),
            "missing": len(missing),
        },
    }


def print_differential(diff, stream=sys.stdout):
    w = stream.write
    w("\n")
    w("A2A DIFFERENTIAL REPORT\n")
    w("  control  %s\n" % diff["control"])
    w("  subject  %s\n" % diff["subject"])
    w("  spec     %s\n" % diff["spec_tag"])
    w("\n")

    w("DEFECTS (subject violated a spec MUST; these are failures)\n")
    if not diff["defects"]:
        w("  none\n")
    for d in diff["defects"]:
        w("  [%s] %s\n" % (d["subject_outcome"], d["id"]))
        w("      catches  %s\n" % _wrap(d["defect_caught"], 14))
        w("      detail   %s\n" % _wrap(d["subject_detail"].strip(), 14))
        w("      clause   %s\n" % _wrap(d["clause"], 14))
        if d["also_fails_on_control"]:
            w("      WARNING  the control fails this test too, so suspect "
              "the TEST before the subject\n")
    w("\n")

    w("DIVERGENCES (spec permits both; for a human to judge, not failures)\n")
    if not diff["divergences"]:
        w("  none\n")
    for d in diff["divergences"]:
        w("  %s :: %s\n" % (d["id"], d["observation"]))
        w("      control  %s\n" % _short(d["control_returned"]))
        w("      subject  %s\n" % _short(d["subject_returned"]))
        w("      clause   %s\n" % _wrap(d["governing_clause"], 14))
    w("\n")

    if diff["outcome_shifts"]:
        w("OUTCOME SHIFTS (no MUST violated, but the two ran differently)\n")
        for d in diff["outcome_shifts"]:
            w("  %s  control=%s subject=%s\n"
              % (d["id"], d["control_outcome"], d["subject_outcome"]))
            if d["subject_detail"]:
                w("      %s\n" % _wrap(d["subject_detail"].strip(), 6))
        w("\n")

    if diff["missing"]:
        w("NOT COMPARED\n")
        for d in diff["missing"]:
            w("  %s  %s\n" % (d["id"], d["why"]))
        w("\n")

    s = diff["summary"]
    w("  defects=%d divergences=%d outcome_shifts=%d not_compared=%d\n"
      % (s["defects"], s["divergences"], s["outcome_shifts"], s["missing"]))
    w("  %s\n" % ("NO DEFECTS" if s["defects"] == 0
                  else "%d DEFECT(S) FOUND" % s["defects"]))
    w("\n")
    return s["defects"]


# ---------------------------------------------------------------------------
# Baseline comparison, used by the control CI job.
# ---------------------------------------------------------------------------

def compare_to_baseline(report_now, baseline):
    """Assert the control still behaves exactly as recorded.

    The control job does NOT assert "everything passed". It asserts "the
    result is identical to the pinned baseline", which additionally catches:
      - a control upgrade quietly changing what conformant means
      - a harness edit that turns a test green or red by accident
    """
    now = {r["id"]: r["outcome"] for r in report_now["results"]}
    was = {r["id"]: r["outcome"] for r in baseline["results"]}
    changes = []
    for test_id in sorted(set(now) | set(was)):
        if now.get(test_id) != was.get(test_id):
            changes.append({
                "id": test_id,
                "baseline": was.get(test_id, "<not in baseline>"),
                "now": now.get(test_id, "<not run>"),
            })
    return changes
