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

Usage:
    python3 scripts/ci-umbrella-lint.py [--root .]
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


def check(root: Path) -> int:
    path = root / WORKFLOW
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ci-umbrella-lint: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    problems = check_text(text)
    if problems:
        print(f"::error::ci-umbrella-lint: {len(problems)} problem(s) in {WORKFLOW}", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("ci-umbrella-lint: every job is gated by the umbrella or declared non-gating, with a reason")
    return 0


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

    # THE FLOORS BITE, ONE AT A TIME. Refusing the 3-job stub under all three real floors proves
    # only that AT LEAST ONE of them fired -- and MIN_JOBS alone does that, so MIN_NEEDS and
    # MIN_RESULTS were carried by it. Planted at MIN_NEEDS=0 the suite stayed green. Each floor is
    # now driven alone, against the real ci.yml with that one dimension shrunk to just under it, so
    # a floor that stopped biting is named rather than covered for by its neighbour.
    if check_text(BASE):
        print("  [ok]     under the real floors a 3-job stub is REFUSED (a parser that sees little proves little)")
    else:
        print("  [FAILED] the job/needs/RESULTS floors do not bite")
        failures += 1

    real_text = (root / WORKFLOW).read_text(encoding="utf-8")

    def floor_case(name, want, mutate):
        """`mutate(doc)` shrinks one dimension of the real ci.yml; the named floor must be the
        thing that fires. Checked by its own message, so another rule reddening does not count."""
        nonlocal failures
        doc = yaml.safe_load(real_text)
        mutate(doc)
        # safe_dump drops comments, and the `# non-gating:`/`# report-only:` declarations ARE
        # comments, so they are carried over verbatim; otherwise every exempted job would also
        # fire rule 1 and the case could pass on the wrong problem.
        decls = "\n".join(ln for ln in real_text.splitlines() if DECL_RE.match(ln))
        problems = check_text(yaml.safe_dump(doc, sort_keys=False) + "\n" + decls + "\n")
        if any(want in p for p in problems):
            print(f"  [ok]     {name}")
        else:
            print(f"  [FAILED] {name} -- nothing said {want!r}; got {problems[:2] or 'nothing'}")
            failures += 1

    def shrink_needs(doc):
        u = doc["jobs"][UMBRELLA]
        u["needs"] = list(u["needs"])[: MIN_NEEDS - 1]

    def shrink_results(doc):
        u = doc["jobs"][UMBRELLA]
        rows = [r for r in str(u["env"]["RESULTS"]).splitlines() if r.strip()]
        u["env"]["RESULTS"] = "\n".join(rows[: MIN_RESULTS - 1]) + "\n"

    def shrink_jobs(doc):
        keep = [UMBRELLA] + [j for j in doc["jobs"] if j != UMBRELLA][: MIN_JOBS - 2]
        doc["jobs"] = {k: doc["jobs"][k] for k in keep}

    floor_case(
        f"the NEEDS floor bites on its own at {MIN_NEEDS - 1} dependencies "
        f"(a short needs list is how a required check stops requiring things)",
        f"job(s) (floor {MIN_NEEDS})", shrink_needs)
    floor_case(
        f"the RESULTS floor bites on its own at {MIN_RESULTS - 1} rows "
        f"(an unread ledger scores nothing and prints GREEN)",
        f"row(s) (floor {MIN_RESULTS})", shrink_results)
    floor_case(
        f"the JOBS floor bites on its own at {MIN_JOBS - 1} jobs "
        f"(a reader that sees almost no jobs reports almost no omissions)",
        f"job(s) parsed (floor {MIN_JOBS})", shrink_jobs)

    # BOTH VERDICTS, ON THE REAL FILE. Re-plant the historical defect (`deletion-test-matrix`
    # absent from `needs`) in the tree's own ci.yml and require a RED; then require the tree GREEN.
    # ON THE REAL FILE: re-plant the historical defect (`deletion-test-matrix` absent from `needs`)
    # in the tree's own ci.yml and require the lint to refuse it; then require the untouched tree
    # to pass.
    real = (root / WORKFLOW).read_text(encoding="utf-8")
    planted = re.sub(r"\n +- deletion-test-matrix(?=\n)", "", real, count=1)
    if planted == real:
        print("  [FAILED] could not plant the historical defect: `- deletion-test-matrix` is not in ci.yml's needs")
        failures += 1
    elif check_text(planted):
        print("  [ok]     the real ci.yml with `deletion-test-matrix` removed from needs is REFUSED")
    else:
        print("  [FAILED] removing an enforcement gate from the real umbrella's needs was ACCEPTED")
        failures += 1

    real_problems = check_text(real)
    if real_problems:
        print(f"  [FAILED] the tree's own ci.yml does not pass: {real_problems[0]}")
        failures += 1
    else:
        print("  [ok]     the tree's own ci.yml passes")

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} check(s) did not hold", file=sys.stderr)
        return 1
    print(f"\nself-test: {len(cases) + 3} checks, all hold")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="assert every ci.yml job is gated or declared non-gating")
    ap.add_argument("--selftest", action="store_true", help="prove the lint discriminates, then exit")
    ap.add_argument("--root", default=".", help="repository root to check")
    args = ap.parse_args()
    root = Path(args.root)
    return selftest(root) if args.selftest else check(root)


if __name__ == "__main__":
    sys.exit(main())
