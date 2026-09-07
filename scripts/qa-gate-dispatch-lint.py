#!/usr/bin/env python3
"""Fail when the qa-gate DISPATCHER on the default branch has drifted from this commit's.

WHY THIS EXISTS
---------------
`workflow_run` ALWAYS loads the workflow file from the DEFAULT branch. Whatever
`.github/workflows/qa-gate.yml` looks like on `main` is what auto-fires after a push to `qa`,
regardless of what the promoted commit carries. That has already cost us once: measured on qa
c736177, the auto-fired gate ran ONE job while the whole segmentation umbrella sat unused on `qa`.
It failed SILENTLY — the run went green, it had simply done far less than anyone believed.

The dispatcher design already solves most of this: `qa-gate.yml` checks out the TRIGGERING SHA and
invokes `scripts/qa-gate-run.sh` from that checkout, so gate LOGIC rides the commit it gates. What
cannot ride the commit is everything GitHub must read before a checkout exists — `on:`,
`concurrency`, `permissions`, `env`, `runs-on`, `timeout-minutes`, the `needs`/`if` graph, and the
`strategy.matrix` expression. Those come from `main`, always. Change one of them on `dev` and the
auto-fired gate keeps running the old graph until someone remembers to promote the file.

Nobody remembers. It re-diverged within a day of the last sync.

WHAT THIS CHECKS, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
It compares the PARSED YAML — the structure GitHub actually executes — not the bytes. Comments and
formatting are dropped by the parser and may drift freely.

That distinction is the whole reason this lint can exist at all. A byte-identical requirement would
deadlock: `main` only moves at a release, so any qa-gate edit on `dev` would be red until the next
release, which is the release the edit is meant to gate. Requiring only STRUCTURAL identity means a
prose change costs nothing while a change to the run graph fails immediately — which is exactly the
split between what rides the commit and what does not.

WHICH QUESTION, AND WHERE — THE PREMISE THIS GATE GOT WRONG
-----------------------------------------------------------
Structural identity fixed the prose deadlock and left a bigger one standing. The comparison was
against `origin/main` on EVERY branch, and on a branch that is not `qa` or `main` the only way to
satisfy it is to push the workflow to the default branch — a release-path action. An integration
branch carrying a legitimate dispatcher change is therefore red for its entire life, by
construction, with a remedy no one on that branch is allowed to take. That is the same failure as
the byte-identical version, one level up: a gate that cannot be satisfied from where it runs stops
being read, and a gate nobody reads is not a gate.

So the question is asked where it can be answered:

  * EVERY branch — does `qa-gate.yml` match the shape this branch DECLARES, the committed
    projection at `.github/workflows/qa-gate.dispatcher.json` that is promoted along with it? Any
    change to the run graph is still caught immediately, at the commit that makes it, with the
    declared file in the diff for a reviewer to see.
  * `qa` and `main` ADDITIONALLY — does the copy on the default branch, the one `workflow_run`
    actually loads, match? This is the original question, kept whole and unrelaxed, asked at the
    two branches where the promotion is the point and where the answer decides whether a release
    is gated by the graph anyone believes.

Nothing is dropped and nothing is weakened. What changed is that a development branch is measured
against something it controls.

FAILS CLOSED
------------
If the default branch's copy cannot be read, that is a FAILURE, not a skip. Unknown is not green:
a lint that passes when it cannot see is worse than no lint, because it is consulted and wrong.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is not installed, so this lint cannot parse the workflow.", file=sys.stderr)
    print("      Unknown is not green — install it rather than skipping this check.", file=sys.stderr)
    sys.exit(2)

WORKFLOW = ".github/workflows/qa-gate.yml"
DEFAULT_BRANCH_REF = "origin/main"

# The shape THIS BRANCH declares — the dispatcher that will be promoted along with it.
DECLARED = ".github/workflows/qa-gate.dispatcher.json"

# The branches on which the dispatcher that fires IS the one on the default branch, so the
# comparison against `origin/main` is the question actually being asked.
PROMOTION_BRANCHES = ("qa", "main")

# What the diff paths call the other side. Set per comparison; the two arms compare against
# different things and a message naming the wrong one sends the reader to the wrong file.
OTHER = "the default branch"


def read_ref(ref: str, path: str) -> str | None:
    """Return a file's contents at a git ref, or None if it cannot be read."""
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout
    except subprocess.CalledProcessError:
        return None


def structure(text: str, label: str) -> object:
    """Parse to the structure GitHub executes, discarding comments and formatting."""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        print(f"FAIL: {label} is not parseable YAML: {exc}", file=sys.stderr)
        sys.exit(2)


def diff_paths(a: object, b: object, path: str = "") -> list[str]:
    """Every path at which two parsed structures disagree, as dotted keys.

    Reported as paths rather than as a text diff because the useful question is WHICH part of the
    run graph moved — `on.workflow_run.workflows` and a `needs:` edge are very different problems,
    and a unified diff of re-serialised YAML buries that under formatting noise.
    """
    if type(a) is not type(b):
        return [f"{path or '(root)'}: type {type(a).__name__} vs {type(b).__name__}"]

    if isinstance(a, dict):
        out: list[str] = []
        # Sorted by str(), not by the key itself, because a GitHub workflow's top-level `on:` parses
        # as the BOOLEAN True under YAML 1.1 — the same quirk that turns `no` into False and NO into
        # the Norway problem. So the key set is genuinely mixed-type and `sorted()` on the raw keys
        # raises TypeError comparing bool to str. Sorting is only for stable output ordering, so
        # coercing to str costs nothing and makes the mixed set well-ordered.
        for key in sorted(set(a) | set(b), key=str):
            here = f"{path}.{key}" if path else str(key)
            if key not in a:
                out.append(f"{here}: missing on this commit, present in {OTHER}")
            elif key not in b:
                out.append(f"{here}: present on this commit, missing in {OTHER}")
            else:
                out.extend(diff_paths(a[key], b[key], here))
        return out

    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{path}: {len(a)} entries here vs {len(b)} in {OTHER}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(diff_paths(x, y, f"{path}[{i}]"))
        return out

    return [] if a == b else [f"{path}: {a!r} here vs {b!r} in {OTHER}"]


def current_branch() -> str:
    """The branch this run is on, as CI knows it, falling back to the working tree.

    `GITHUB_REF_NAME` is what the workflow is actually running as and is exact. An unknown branch is
    treated as a development branch, which is the SAFE direction: the development arm is the one
    that is always answerable, and the promotion arm cannot be asked without knowing you are
    promoting.
    """
    env = os.environ.get("GITHUB_REF_NAME")
    if env:
        return env
    try:
        out = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except subprocess.CalledProcessError:
        return "(unknown)"


def canonical(shape: object) -> str:
    """The declared shape's on-disk form: sorted, indented JSON, one trailing newline.

    JSON rather than YAML because this is a DERIVED artifact nobody should hand-edit: `--write`
    produces it and the lint compares against it, the same regen-drift shape the openapi,
    config-schema and design-bindings artifacts already use. Keys are coerced to strings because a
    workflow's top-level `on:` parses as the boolean True under YAML 1.1 - the Norway problem's
    cousin - and JSON has no boolean key at all, so it is spelled back out as the word the workflow
    file actually says. Both sides of the comparison go through this function, so the spelling is
    the same on each and a reader of the declared file sees `"on"`, not `"True"`.
    """
    def keys_to_text(node: object) -> object:
        if isinstance(node, dict):
            return {("on" if k is True else str(k)): keys_to_text(v) for k, v in node.items()}
        if isinstance(node, list):
            return [keys_to_text(v) for v in node]
        return node

    return json.dumps(keys_to_text(shape), indent=2, sort_keys=True, default=str) + "\n"


def check(root: Path, branch: str | None = None, remote_text: str | None = None) -> int:
    """Two arms, and which one is asked depends on where the run is.

    THE PREMISE THIS FIXES. The lint used to ask ONE question everywhere: does this commit's
    dispatcher match `origin/main`'s? On `qa` and `main` that is exactly right — the file
    `workflow_run` loads IS the default branch's. On every other branch it is a question the branch
    cannot answer: the only way to go green is to push the workflow to `main`, a release-path action,
    so an integration branch is red for its whole life by construction. A gate that can only be
    satisfied by an action outside the branch is not measuring the branch, and one that is red for
    weeks stops being read.

    A development branch is therefore asked the question it CAN answer, and it is not a weaker one:
    does the dispatcher match the shape this branch DECLARES — the committed projection that will be
    promoted along with it? Any change to the run graph still fails immediately, at the commit that
    makes it, with the declared file in the diff for a reviewer to see. What it no longer does is
    demand the promotion have already happened before the change can land.

    On `qa` and `main` BOTH arms run: the declared shape must still be current AND the default
    branch's copy must match it, which is the moment that answer decides whether a release is gated
    by the graph anyone believes. Nothing is dropped; the second question is asked where it is
    answerable and where it matters.
    """
    global OTHER
    local_path = root / WORKFLOW
    if not local_path.is_file():
        print(f"FAIL: {WORKFLOW} does not exist in this checkout.", file=sys.stderr)
        return 2

    branch = branch or current_branch()
    here = structure(local_path.read_text(), "this commit's qa-gate.yml")

    # -- ARM 1: the declared shape. Every branch, including qa and main. ------------------------
    declared_path = root / DECLARED
    if not declared_path.is_file():
        print(
            f"FAIL: {DECLARED} does not exist. It is the shape this branch declares for the "
            f"dispatcher\n"
            f"      and the thing every branch is measured against. Write it with\n"
            f"      `python3 scripts/qa-gate-dispatch-lint.py --write` and commit it.",
            file=sys.stderr,
        )
        return 2
    try:
        declared = json.loads(declared_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"FAIL: {DECLARED} is not parseable JSON: {exc}", file=sys.stderr)
        print("      Unknown is not green. Regenerate it with --write.", file=sys.stderr)
        return 2

    OTHER = f"the declared shape ({DECLARED})"
    # Compared through the same canonicalisation the writer uses, so a YAML scalar with no JSON
    # spelling (a date, the boolean `on:` key) cannot read as drift on every run.
    drift = diff_paths(json.loads(canonical(here)), declared)
    if drift:
        print(
            f"FAIL: {WORKFLOW} does not match the shape this branch declares in {DECLARED}.\n",
            file=sys.stderr,
        )
        for d in drift:
            print(f"  {d}", file=sys.stderr)
        print(
            f"\n  The declared shape is what will be promoted with this branch, and it is what a\n"
            f"  reviewer reads to see that the run graph moved. Regenerate it in the same commit as\n"
            f"  the workflow change: `python3 scripts/qa-gate-dispatch-lint.py --write`.",
            file=sys.stderr,
        )
        return 1

    if branch not in PROMOTION_BRANCHES:
        print(
            f"qa-gate dispatcher: matches the shape this branch declares ({DECLARED}).\n"
            f"  Branch is {branch!r}. The comparison against {DEFAULT_BRANCH_REF} - the copy\n"
            f"  `workflow_run` actually loads - is asked on "
            f"{' and '.join(PROMOTION_BRANCHES)}, where it is\n"
            f"  answerable and where it decides whether a release is gated by the graph anyone\n"
            f"  believes."
        )
        return 0

    # -- ARM 2: the promoted copy. Only where the promotion is the point. -----------------------
    if remote_text is None:
        remote_text = read_ref(DEFAULT_BRANCH_REF, WORKFLOW)
    if remote_text is None:
        print(
            f"FAIL: could not read {WORKFLOW} from {DEFAULT_BRANCH_REF}, so it is UNKNOWN whether "
            f"the dispatcher that will actually fire matches this commit's.\n"
            f"      Unknown is not green. Fetch the default branch and re-run; do not skip this "
            f"check.",
            file=sys.stderr,
        )
        return 2

    OTHER = DEFAULT_BRANCH_REF
    there = structure(remote_text, f"{DEFAULT_BRANCH_REF}'s qa-gate.yml")
    differences = diff_paths(here, there)
    if not differences:
        print(
            f"qa-gate dispatcher: matches the declared shape AND {DEFAULT_BRANCH_REF} "
            f"(comments and formatting may differ, and that is fine)."
        )
        return 0

    print(
        "FAIL: the qa-gate DISPATCHER on this commit differs STRUCTURALLY from the one on "
        f"{DEFAULT_BRANCH_REF}.\n",
        file=sys.stderr,
    )
    for d in differences:
        print(f"  {d}", file=sys.stderr)
    print(
        f"\n  `workflow_run` always loads the workflow file from the DEFAULT branch, so the gate "
        f"that\n"
        f"  actually fires after a push to `qa` is the one on {DEFAULT_BRANCH_REF} - NOT the one in "
        f"this\n"
        f"  commit. Until these agree, a qa-gate improvement cannot gate the release that ships it, "
        f"and\n"
        f"  the run goes GREEN having done less than anyone thinks.\n\n"
        f"  This is branch {branch!r}, where the promotion IS the point: fix by promoting this file "
        f"to\n"
        f"  the default branch, not by relaxing this check. Gate LOGIC belongs in\n"
        f"  scripts/qa-gate-run.sh, which rides the commit and is exempt from this problem "
        f"entirely -\n"
        f"  if what you changed could live there, move it there instead.",
        file=sys.stderr,
    )
    return 1


def write_declared(root: Path) -> int:
    """Regenerate the declared shape from the workflow this branch carries."""
    local_path = root / WORKFLOW
    if not local_path.is_file():
        print(f"FAIL: {WORKFLOW} does not exist in this checkout.", file=sys.stderr)
        return 2
    shape = structure(local_path.read_text(), "this commit's qa-gate.yml")
    (root / DECLARED).write_text(canonical(shape))
    print(f"wrote {DECLARED} from {WORKFLOW}")
    return 0


def selftest() -> int:
    """Prove the lint discriminates, by constructing both answers rather than trusting one.

    A lint whose only evidence is a green run has proven nothing: it would look identical to one
    that parses nothing and returns 0. So this asserts BOTH arms — a structural change must be
    caught, and a comment-only change must NOT be, since the second property is what stops this
    lint deadlocking every prose edit until the next release.
    """
    base = """
name: qa-gate
on:
  workflow_run:
    workflows: ["CI"]
    branches: [qa]
    types: [completed]
concurrency:
  group: qa-gate-${{ github.event.workflow_run.head_sha }}
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - run: echo build
  slow:
    needs: [build, fast]
    runs-on: ubuntu-latest
    steps:
      - run: echo slow
"""
    cases = [
        (
            "identical",
            base,
            0,
            "byte-identical input must pass",
        ),
        (
            "comment-only change",
            "# a fresh comment that changes nothing GitHub executes\n" + base,
            0,
            "a prose edit must NOT fail, or every comment change deadlocks until the next release",
        ),
        (
            "a needs: edge removed",
            base.replace("needs: [build, fast]", "needs: [build]"),
            1,
            "a change to the run graph must be caught",
        ),
        (
            "trigger branch changed",
            base.replace("branches: [qa]", "branches: [dev]"),
            1,
            "a change to what fires the gate must be caught",
        ),
        (
            "a timeout removed",
            base.replace("    timeout-minutes: 90\n", ""),
            1,
            "a removed structural key must be caught",
        ),
        (
            "a whole job removed",
            base.split("  slow:")[0],
            1,
            "a removed job must be caught",
        ),
    ]

    failures = 0
    for name, text, want, why in cases:
        got_diff = diff_paths(structure(text, name), structure(base, "base"))
        got = 1 if got_diff else 0
        ok = got == want
        if not ok:
            failures += 1
        print(
            f"  [{'ok' if ok else 'FAILED'}] {name:<24} -> "
            f"{'differs' if got else 'identical'} (expected {'differs' if want else 'identical'})"
            f"\n           {why}"
        )

    # The unreadable-ref arm, proven rather than asserted: a ref that cannot exist must return None,
    # which check() turns into exit 2. This is the fails-closed guarantee.
    if read_ref("refs/heads/definitely-not-a-real-ref-for-selftest", WORKFLOW) is not None:
        print("  [FAILED] unreadable ref did not return None", file=sys.stderr)
        failures += 1
    else:
        print("  [ok] unreadable default branch -> None -> exit 2 (fails closed)")

    # -- BOTH ARMS OF THE BRANCH SPLIT, each proven end-to-end -----------------------------------
    #
    # The cases above prove the COMPARISON discriminates. They say nothing about WHICH comparison a
    # given branch gets, which is the thing this gate got wrong: it asked every branch a question
    # only `qa` and `main` can answer. So both arms are driven through `check()` itself, against a
    # throwaway tree, with the remote copy injected rather than fetched — a self-test that needed
    # the network could not prove the qa arm at all and would quietly stop covering it.
    graph_change = base.replace("needs: [build, fast]", "needs: [build]")
    arms = [
        # (branch, workflow on disk, declared shape source, remote copy, expected exit, why)
        ("integration/some-branch", graph_change, graph_change, base, 0,
         "a dev branch whose dispatcher matches its OWN declared shape is GREEN even though the "
         "default branch has not been promoted yet - the deadlock this fixes"),
        ("integration/some-branch", graph_change, base, base, 1,
         "a dev branch whose dispatcher does NOT match its declared shape is RED - a run-graph "
         "change still fails at the commit that makes it"),
        ("qa", graph_change, graph_change, base, 1,
         "on qa the promoted copy is compared too, so an unpromoted graph change is RED"),
        ("qa", base, base, base, 0,
         "on qa a dispatcher that matches BOTH the declared shape and the default branch is GREEN"),
        ("main", graph_change, graph_change, base, 1,
         "main is judged the same as qa - the copy that fires is the default branch's"),
    ]
    for branch, workflow_text, declared_src, remote, want, why in arms:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / WORKFLOW).write_text(workflow_text)
            (root / DECLARED).write_text(canonical(structure(declared_src, "declared")))
            got = check(root, branch=branch, remote_text=remote)
        ok = got == want
        if not ok:
            failures += 1
        print(
            f"  [{'ok' if ok else 'FAILED'}] {branch:<24} -> exit {got} (expected {want})"
            f"\n           {why}"
        )
    arm_cases = len(arms)

    # A missing declared shape is UNKNOWN, and unknown is not green - the same discipline the
    # unreadable-ref arm above holds the promotion side to.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / WORKFLOW).write_text(base)
        got = check(root, branch="integration/some-branch", remote_text=base)
    if got == 2:
        print("  [ok] a missing declared shape -> exit 2 (fails closed, never a skip)")
    else:
        print(f"  [FAILED] a missing declared shape returned {got}, not 2", file=sys.stderr)
        failures += 1
    arm_cases += 1

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} of {len(cases) + 1 + arm_cases} checks did not hold", file=sys.stderr)
        return 1
    print(f"\nself-test: {len(cases) + 1 + arm_cases} checks, all hold "
          f"(the comparison discriminates, and each branch gets the arm it can answer)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="prove the lint discriminates, then exit")
    ap.add_argument("--root", default=".", help="repository root to check")
    ap.add_argument("--write", action="store_true",
                    help="regenerate the declared dispatcher shape from this branch's qa-gate.yml")
    ap.add_argument("--branch", default=None,
                    help="the branch to judge as (default: GITHUB_REF_NAME, else the checked-out "
                         "branch). Only `qa` and `main` are additionally compared against "
                         "origin/main.")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.write:
        return write_declared(Path(args.root))
    return check(Path(args.root), branch=args.branch)


if __name__ == "__main__":
    sys.exit(main())
