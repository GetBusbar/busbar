#!/usr/bin/env python3
"""ci-umbrella-lint -- every job in ci.yml is either GATED by the umbrella or declared non-gating.

WHY THIS EXISTS. `ci-umbrella` is the single required check: it is the job branch protection points
at, and its `needs:` list is the whole of what "CI is green" means. That list is maintained BY HAND,
one entry per job, in a file where jobs are added by people who are thinking about the new job and
not about the umbrella. The failure mode is silent and total: add an enforcement job, forget the
`needs:` line, and the umbrella reports GREEN on a run in which that job failed. Nothing anywhere
notices, because a job that is not in `needs` is not a job the umbrella has ever heard of.

That is not hypothetical. `deletion-test-matrix` -- the enforcement gate that proves the neutral
crates still compile with a plane removed, running on every pull request -- sat outside `needs` for
its whole life. Its red would not have reddened the umbrella.

So membership is now DERIVED and ASSERTED rather than remembered:

  * every job in the file is in `ci-umbrella.needs`, UNLESS a `# non-gating:` line names it WITH a
    reason. Omission is impossible; deliberate exclusion is possible, in writing, and reviewable.
  * every job in `needs` is scored in the umbrella's RESULTS ledger, UNLESS a `# report-only:` line
    names it with a reason (that is the construction gate's status today: waited for, printed, not
    counted).
  * RESULTS rows name real jobs, carry a real tier, and every one of them is in `needs` -- a row
    reading `${{ needs.X.result }}` for an X that is not a dependency evaluates to the empty string,
    which is neither "success" nor a recognised skip, so it would red every run. Asserted so the
    ledger cannot silently name a job the umbrella does not wait for.
  * FLOORS. A parser that matched nothing would report a clean file. Under the floors it cannot.

DECLARATION SYNTAX, anywhere in ci.yml, as a comment:

    # non-gating: <job-key> -- <reason, at least 30 characters>
    # report-only: <job-key> -- <reason, at least 30 characters>

`qa-gate.yml` HAS THE SAME SHAPE AND THE SAME HAZARD, and it was not covered. Its `umbrella` job is
the second required check (branch protection requires `ci umbrella` on dev, and `ci umbrella` +
`qa-gate umbrella` on qa and main), its `needs:` is likewise hand-maintained, and its scoring ledger
is a run of `check <job> "${{ needs[...].result }}"` lines rather than an env table. The hazard is
identical: add the `done-oracle` job -- the one that runs `scripts/verify-1.6.0-done.sh` in full,
including the `--plane all` replay -- forget the `needs:` line, and a red done-oracle reports GREEN
on the check that gates qa->main. So this lint reads BOTH files, in each one's own dialect, and
`qa-gate.yml` additionally carries a NAMED, REQUIRED member: `done-oracle` must be in the umbrella's
needs, by name. A floor catches a needs list that shrank; a named requirement catches the one
deletion that matters most and would still clear any floor.

Usage:
    python3 scripts/ci-umbrella-lint.py [--root .] [--workflow ci|qa-gate|both]
    python3 scripts/ci-umbrella-lint.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

WORKFLOW = ".github/workflows/ci.yml"
UMBRELLA = "ci-umbrella"

# Floors. Each is well below today's real count; they exist to make a parser that matched nothing
# fail loudly rather than pass vacuously.
MIN_JOBS = 20
MIN_NEEDS = 15
MIN_RESULTS = 15
MIN_REASON = 30

# ── qa-gate.yml, the OTHER required umbrella ─────────────────────────────────────────────────────
QA_WORKFLOW = ".github/workflows/qa-gate.yml"
QA_UMBRELLA = "umbrella"
# Floors, same purpose as above: well below today's six jobs, there so a parser that matched nothing
# fails loudly instead of reporting a clean file.
MIN_QA_JOBS = 5
MIN_QA_NEEDS = 4
# NAMED, REQUIRED MEMBERS. A floor only notices a needs list that got SHORTER than some number; it
# cannot notice that the one job which actually spends the two hours has been swapped out for a
# cheap one. Each entry is a job that must be in the umbrella's `needs` BY NAME, with the sentence
# that says what goes unmeasured without it.
QA_REQUIRED_NEEDS = {
    "done-oracle": (
        "it is the only thing anywhere that runs scripts/verify-1.6.0-done.sh in FULL -- the "
        "PARITY group's `--plane all` replay against the pinned 1.5.5 golden, the AUDIT-LEDGER "
        "check, STORE-QA, DESIGN and the full-gate battery. Outside the umbrella's needs, its red "
        "reports GREEN on the check that gates qa->main."
    ),
}
# The qa-gate umbrella scores its dependencies with shell, not with an env table: one
# `check <job> "${{ needs.<job>.result }}"` line each. Both spellings of the context reference are
# accepted (`needs.x.result` and `needs['x'].result`) because a hyphenated job key REQUIRES the
# index form -- `-` inside a property path is parsed as subtraction.
QA_CHECK_RE = re.compile(
    r"^\s*check\s+([A-Za-z0-9_.-]+)\s+\"\$\{\{\s*needs(?:\.([A-Za-z0-9_.-]+)|\[\s*'([^']+)'\s*\])\.result\s*\}\}\""
)

DECL_RE = re.compile(
    r"^\s*#\s*(non-gating|report-only)\s*:\s*([A-Za-z0-9_.-]+)\s*(?:--|—|-|:)\s*(.+?)\s*$"
)
RESULT_ROW_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\|(fast|full)\|\$\{\{\s*needs\.([A-Za-z0-9_.-]+)\.result\s*\}\}\s*$")


def declarations(text: str) -> dict[str, list[tuple[str, str]]]:
    """`{kind: [(job, reason), ...]}` for every `# non-gating:` / `# report-only:` comment."""
    out: dict[str, list[tuple[str, str]]] = {"non-gating": [], "report-only": []}
    for line in text.splitlines():
        m = DECL_RE.match(line)
        if m:
            out[m.group(1)].append((m.group(2), m.group(3)))
    return out


def results_rows(umbrella: dict) -> list[tuple[str, str, str]]:
    """The umbrella's `RESULTS` ledger as `(jobkey, tier, referenced-job)` triples."""
    raw = ((umbrella.get("env") or {}).get("RESULTS") or "")
    rows = []
    for line in str(raw).splitlines():
        if not line.strip():
            continue
        m = RESULT_ROW_RE.match(line)
        rows.append((line.strip(), "", "") if not m else (m.group(1), m.group(2), m.group(3)))
    return rows


def check_text(text: str) -> list[str]:
    """Every problem with this workflow's umbrella wiring. Empty list == the wiring holds."""
    problems: list[str] = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover -- a malformed ci.yml is caught by actionlint
        return [f"ci.yml does not parse as YAML: {exc}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return ["ci.yml has no `jobs:` mapping -- refusing to report a clean file from an unread one"]

    jobs = doc["jobs"]
    if len(jobs) < MIN_JOBS:
        problems.append(
            f"only {len(jobs)} job(s) parsed (floor {MIN_JOBS}). A reader that sees almost no jobs "
            f"reports almost no omissions; that is not a pass."
        )
    if UMBRELLA not in jobs:
        return problems + [f"there is no `{UMBRELLA}` job -- the single required check is gone"]

    umbrella = jobs[UMBRELLA] or {}
    needs = umbrella.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs_set = set(needs)
    if len(needs_set) < MIN_NEEDS:
        problems.append(
            f"`{UMBRELLA}.needs` lists {len(needs_set)} job(s) (floor {MIN_NEEDS}). "
            f"A short needs list is how a required check stops requiring things."
        )

    decls = declarations(text)
    non_gating = {job: reason for job, reason in decls["non-gating"]}
    report_only = {job: reason for job, reason in decls["report-only"]}

    for kind, table in (("non-gating", non_gating), ("report-only", report_only)):
        for job, reason in table.items():
            if job not in jobs:
                problems.append(
                    f"`# {kind}: {job}` names a job that does not exist in ci.yml -- a stale "
                    f"exemption outlives the job it excused and silently excuses the next one."
                )
            if len(reason) < MIN_REASON:
                problems.append(
                    f"`# {kind}: {job}` carries a {len(reason)}-character reason (floor "
                    f"{MIN_REASON}). An exemption without a reason becomes permanent by accident."
                )

    # RULE 1 -- omission is impossible.
    for job in jobs:
        if job == UMBRELLA or job in needs_set:
            continue
        if job in non_gating:
            continue
        problems.append(
            f"job `{job}` is not in `{UMBRELLA}.needs` and is not declared non-gating. "
            f"The umbrella does not wait for it and cannot see it fail, so a red in `{job}` "
            f"reports GREEN on the required check. Add it to `needs` (and to RESULTS), or write "
            f"`# non-gating: {job} -- <why it must not gate>` in ci.yml."
        )

    rows = results_rows(umbrella)
    if len(rows) < MIN_RESULTS:
        problems.append(
            f"the umbrella's RESULTS ledger has {len(rows)} row(s) (floor {MIN_RESULTS}) -- "
            f"an unread ledger scores nothing and prints GREEN."
        )
    scored = set()
    for jobkey, tier, ref in rows:
        if not tier:
            problems.append(f"RESULTS row is not `jobkey|tier|${{{{ needs.<job>.result }}}}`: {jobkey!r}")
            continue
        scored.add(jobkey)
        if jobkey != ref:
            problems.append(
                f"RESULTS row `{jobkey}` reads `needs.{ref}.result` -- the label and the job "
                f"it scores disagree, so the printed name is not the measured one."
            )
        if ref not in jobs:
            problems.append(f"RESULTS row `{jobkey}` scores `{ref}`, which is not a job in ci.yml.")
        elif ref not in needs_set:
            problems.append(
                f"RESULTS row `{jobkey}` scores `{ref}`, which is NOT in `{UMBRELLA}.needs`. "
                f"`needs.{ref}.result` is the empty string there, not a verdict."
            )

    # RULE 2 -- a job waited for is a job scored, unless it is declared report-only.
    for job in sorted(needs_set):
        if job in scored or job in report_only:
            continue
        problems.append(
            f"job `{job}` is in `{UMBRELLA}.needs` but has no RESULTS row: the umbrella waits for "
            f"it and then does not score it. Add the row, or write "
            f"`# report-only: {job} -- <why it is printed and not counted>`."
        )
    return problems


def check_qa_text(text: str) -> list[str]:
    """Every problem with qa-gate.yml's umbrella wiring. Empty list == the wiring holds."""
    problems: list[str] = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"qa-gate.yml does not parse as YAML: {exc}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return ["qa-gate.yml has no `jobs:` mapping -- refusing to report a clean file from an unread one"]

    jobs = doc["jobs"]
    if len(jobs) < MIN_QA_JOBS:
        problems.append(
            f"only {len(jobs)} job(s) parsed in qa-gate.yml (floor {MIN_QA_JOBS}). A reader that "
            f"sees almost no jobs reports almost no omissions; that is not a pass."
        )
    if QA_UMBRELLA not in jobs:
        return problems + [
            f"there is no `{QA_UMBRELLA}` job in qa-gate.yml -- `qa-gate umbrella` is a required "
            f"check on qa and main, and it is gone"
        ]

    umbrella = jobs[QA_UMBRELLA] or {}
    needs = umbrella.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs_set = set(needs)
    if len(needs_set) < MIN_QA_NEEDS:
        problems.append(
            f"`{QA_UMBRELLA}.needs` in qa-gate.yml lists {len(needs_set)} job(s) (floor "
            f"{MIN_QA_NEEDS}). A short needs list is how a required check stops requiring things."
        )

    # THE NAMED REQUIREMENT. This is the rule a floor cannot express.
    for job, why in QA_REQUIRED_NEEDS.items():
        if job not in jobs:
            problems.append(
                f"qa-gate.yml has no `{job}` job at all. It is a REQUIRED member of the umbrella "
                f"because {why}"
            )
        elif job not in needs_set:
            problems.append(
                f"job `{job}` is not in `{QA_UMBRELLA}.needs` in qa-gate.yml. It is a REQUIRED "
                f"member because {why}"
            )

    decls = declarations(text)
    non_gating = {job: reason for job, reason in decls["non-gating"]}
    report_only = {job: reason for job, reason in decls["report-only"]}
    for kind, table in (("non-gating", non_gating), ("report-only", report_only)):
        for job, reason in table.items():
            if job not in jobs:
                continue  # the declaration belongs to the other workflow; its own pass judges it
            if len(reason) < MIN_REASON:
                problems.append(
                    f"`# {kind}: {job}` in qa-gate.yml carries a {len(reason)}-character reason "
                    f"(floor {MIN_REASON}). An exemption without a reason becomes permanent."
                )
            if job in QA_REQUIRED_NEEDS:
                problems.append(
                    f"`# {kind}: {job}` tries to exempt a REQUIRED umbrella member. That is not an "
                    f"exemption anyone may write: {QA_REQUIRED_NEEDS[job]}"
                )

    # RULE 1 -- omission is impossible.
    for job in jobs:
        if job == QA_UMBRELLA or job in needs_set or job in non_gating:
            continue
        problems.append(
            f"job `{job}` is not in `{QA_UMBRELLA}.needs` in qa-gate.yml and is not declared "
            f"non-gating. The umbrella does not wait for it and cannot see it fail, so a red in "
            f"`{job}` reports GREEN on the required check that gates qa->main."
        )

    # RULE 2 -- a job waited for is a job SCORED. qa-gate's ledger is the `check <job> "..."` lines
    # in the umbrella's own run script, so it is read from there rather than from an env table.
    scored: dict[str, str] = {}
    for step in umbrella.get("steps") or []:
        for line in str((step or {}).get("run") or "").splitlines():
            m = QA_CHECK_RE.match(line)
            if m:
                scored[m.group(1)] = m.group(2) or m.group(3)
    for label, ref in scored.items():
        if label != ref:
            problems.append(
                f"qa-gate umbrella scores `check {label}` from `needs.{ref}.result` -- the printed "
                f"name and the measured job disagree."
            )
        if ref not in jobs:
            problems.append(f"qa-gate umbrella scores `{ref}`, which is not a job in qa-gate.yml.")
        elif ref not in needs_set:
            problems.append(
                f"qa-gate umbrella scores `{ref}`, which is NOT in `{QA_UMBRELLA}.needs`. "
                f"`needs.{ref}.result` is the empty string there, not a verdict."
            )
    for job in sorted(needs_set):
        if job in scored or job in report_only:
            continue
        problems.append(
            f"job `{job}` is in qa-gate's `{QA_UMBRELLA}.needs` but the umbrella never scores it: "
            f"it waits for the job and then does not read its result. Add a "
            f"`check {job} \"${{{{ needs['{job}'].result }}}}\"` line, or write "
            f"`# report-only: {job} -- <why it is printed and not counted>`."
        )
    return problems


PASSES = (
    (WORKFLOW, lambda text: check_text(text),
     "every job is gated by the umbrella or declared non-gating, with a reason"),
    (QA_WORKFLOW, lambda text: check_qa_text(text),
     "every job is inside the umbrella's needs and scored, and done-oracle is in it by name"),
)


def check(root: Path, which: str = "both") -> int:
    """Judge one or both umbrellas. Unreadable is exit 2 -- unknown is never green."""
    rc = 0
    for path_rel, fn, ok_line in PASSES:
        if which == "ci" and path_rel != WORKFLOW:
            continue
        if which == "qa-gate" and path_rel != QA_WORKFLOW:
            continue
        path = root / path_rel
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ci-umbrella-lint: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        problems = fn(text)
        if problems:
            print(f"::error::ci-umbrella-lint: {len(problems)} problem(s) in {path_rel}", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            rc = 1
        else:
            print(f"ci-umbrella-lint: {path_rel}: {ok_line}")
    return rc


BASE = """
name: CI
on: [push]
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      - run: echo alpha
  bravo:
    runs-on: ubuntu-latest
    steps:
      - run: echo bravo
  charlie:
    runs-on: ubuntu-latest
    steps:
      - run: echo charlie
  ci-umbrella:
    # non-gating: charlie -- reporting only; it uploads coverage and asserts nothing at all.
    needs:
      - alpha
      - bravo
    runs-on: ubuntu-latest
    env:
      RESULTS: |
        alpha|fast|${{ needs.alpha.result }}
        bravo|full|${{ needs.bravo.result }}
    steps:
      - run: echo umbrella
"""


def selftest(root: Path) -> int:
    """Prove the lint discriminates: every rule constructed RED, and the clean base GREEN.

    The floors are the reason this cannot just run `check_text` on the real file and call it proven
    -- so the synthetic cases below run against a relaxed set of floors, and the LAST case is the
    real ci.yml with the real historical defect re-planted in it.
    """
    global MIN_JOBS, MIN_NEEDS, MIN_RESULTS
    saved = (MIN_JOBS, MIN_NEEDS, MIN_RESULTS)
    MIN_JOBS, MIN_NEEDS, MIN_RESULTS = 3, 2, 2

    cases: list[tuple[str, str, int, str]] = [
        ("clean base", BASE, 0, "a correctly wired umbrella must pass"),
        (
            "a job outside needs, undeclared",
            BASE.replace(
                "    # non-gating: charlie -- reporting only; it uploads coverage and asserts nothing at all.\n",
                "",
            ),
            1,
            "THE DEFECT: a job the umbrella never waits for must be refused",
        ),
        (
            "a needs entry with no RESULTS row",
            BASE.replace("        bravo|full|${{ needs.bravo.result }}\n", ""),
            1,
            "a job waited for but not scored must be refused",
        ),
        (
            "a RESULTS row for a job not in needs",
            BASE.replace(
                "        bravo|full|${{ needs.bravo.result }}",
                "        bravo|full|${{ needs.bravo.result }}\n        charlie|full|${{ needs.charlie.result }}",
            ),
            1,
            "scoring a non-dependency reads the empty string, never a verdict",
        ),
        (
            "a label that scores a different job",
            BASE.replace("alpha|fast|${{ needs.alpha.result }}", "alpha|fast|${{ needs.bravo.result }}"),
            1,
            "a printed name that is not the measured job must be refused",
        ),
        (
            "an exemption with no reason",
            BASE.replace("charlie -- reporting only; it uploads coverage and asserts nothing at all.", "charlie -- meh"),
            1,
            "an unreasoned exemption becomes permanent by accident",
        ),
        (
            "an exemption for a job that no longer exists",
            BASE.replace("  charlie:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo charlie\n", ""),
            1,
            "a stale exemption silently excuses the next job to take the name",
        ),
        (
            "the umbrella job deleted",
            BASE.replace("  ci-umbrella:", "  not-the-umbrella:"),
            1,
            "no umbrella is not a pass",
        ),
        ("an empty file", "", 1, "an unreadable workflow must never read as clean"),
    ]

    failures = 0
    for name, text, want, why in cases:
        got = 1 if check_text(text) else 0
        ok = got == want
        failures += 0 if ok else 1
        print(
            f"  [{'ok' if ok else 'FAILED'}] {name:<42} -> {'RED' if got else 'green'} "
            f"(expected {'RED' if want else 'green'})\n           {why}"
        )

    MIN_JOBS, MIN_NEEDS, MIN_RESULTS = saved

    # THE FLOORS BITE. Under the real floors, the tiny synthetic base must be REFUSED.
    if check_text(BASE):
        print("  [ok]     under the real floors a 3-job stub is REFUSED (a parser that sees little proves little)")
    else:
        print("  [FAILED] the job/needs/RESULTS floors do not bite")
        failures += 1

    # RED BEFORE GREEN, ON THE REAL FILE. Re-plant the historical defect (`deletion-test-matrix`
    # absent from `needs`) in the tree's own ci.yml and require a RED; then require the tree GREEN.
    real = (root / WORKFLOW).read_text(encoding="utf-8")
    planted = re.sub(r"\n +- deletion-test-matrix(?=\n)", "", real, count=1)
    if planted == real:
        print("  [FAILED] could not plant the historical defect: `- deletion-test-matrix` is not in ci.yml's needs")
        failures += 1
    elif check_text(planted):
        print("  [ok]     the real ci.yml with `deletion-test-matrix` removed from needs is REFUSED (red before green)")
    else:
        print("  [FAILED] removing an enforcement gate from the real umbrella's needs was ACCEPTED")
        failures += 1

    real_problems = check_text(real)
    if real_problems:
        print(f"  [FAILED] the tree's own ci.yml does not pass: {real_problems[0]}")
        failures += 1
    else:
        print("  [ok]     the tree's own ci.yml passes")

    # ── THE qa-gate UMBRELLA: EVERY MUTATION REFUSED, THEN THE REAL FILE ACCEPTED ────────────────
    # Three mutations, each of which is a way the done-oracle job stops gating without anybody
    # editing the job itself: dropped from `needs`, dropped from the umbrella's scoring, or deleted
    # outright. All three must be REFUSED, and then the tree's own file must pass.
    qa_real = (root / QA_WORKFLOW).read_text(encoding="utf-8")
    qa_cases: list[tuple[str, str, str]] = []

    dropped_needs = re.sub(r"\n( +)- done-oracle(?=\n)", "", qa_real, count=1)
    if dropped_needs == qa_real:
        dropped_needs = qa_real.replace(
            "needs: [build, fast, slow, loader, done-oracle]", "needs: [build, fast, slow, loader]", 1
        )
    qa_cases.append((
        "done-oracle removed from the umbrella's needs",
        dropped_needs,
        "THE DEFECT: the umbrella would not wait for the full done-oracle, so its red reports GREEN",
    ))

    unscored = re.sub(r"\n *check done-oracle [^\n]*", "", qa_real, count=1)
    qa_cases.append((
        "done-oracle waited for but never scored",
        unscored,
        "a job the umbrella waits for and does not read is a job it cannot fail on",
    ))

    deleted = qa_real.replace("\n  done-oracle:\n", "\n  done-oracle-renamed:\n", 1)
    qa_cases.append((
        "the done-oracle job renamed out from under needs",
        deleted,
        "a required member that no longer exists is not an excused member",
    ))

    for name, text, why in qa_cases:
        if text == qa_real:
            print(f"  [FAILED] could not plant the qa-gate mutation: {name}")
            failures += 1
            continue
        if check_qa_text(text):
            print(f"  [ok]     qa-gate.yml with '{name}' is REFUSED\n           {why}")
        else:
            print(f"  [FAILED] qa-gate.yml with '{name}' was ACCEPTED\n           {why}")
            failures += 1

    qa_problems = check_qa_text(qa_real)
    if qa_problems:
        print(f"  [FAILED] the tree's own qa-gate.yml does not pass: {qa_problems[0]}")
        failures += 1
    else:
        print("  [ok]     the tree's own qa-gate.yml passes")

    # The qa floors must BITE too: the tiny CI stub has no `umbrella` job and far too few jobs.
    if check_qa_text(BASE):
        print("  [ok]     under the qa floors a 3-job stub is REFUSED")
    else:
        print("  [FAILED] the qa job/needs floors do not bite")
        failures += 1

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} check(s) did not hold", file=sys.stderr)
        return 1
    print(f"\nself-test: {len(cases) + 3 + len(qa_cases) + 2} checks, all hold")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="assert every ci.yml and qa-gate.yml job is gated or declared non-gating"
    )
    ap.add_argument("--selftest", action="store_true", help="prove the lint discriminates, then exit")
    ap.add_argument("--root", default=".", help="repository root to check")
    ap.add_argument(
        "--workflow", default="both", choices=("ci", "qa-gate", "both"),
        help="which umbrella to judge (default: both -- there are two required checks)",
    )
    args = ap.parse_args()
    root = Path(args.root)
    return selftest(root) if args.selftest else check(root, args.workflow)


if __name__ == "__main__":
    sys.exit(main())
