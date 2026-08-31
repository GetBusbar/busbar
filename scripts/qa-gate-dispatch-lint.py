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

FAILS CLOSED
------------
If the default branch's copy cannot be read, that is a FAILURE, not a skip. Unknown is not green:
a lint that passes when it cannot see is worse than no lint, because it is consulted and wrong.
"""

from __future__ import annotations

import argparse
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
                out.append(f"{here}: missing on this commit, present on the default branch")
            elif key not in b:
                out.append(f"{here}: present on this commit, missing on the default branch")
            else:
                out.extend(diff_paths(a[key], b[key], here))
        return out

    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{path}: {len(a)} entries here vs {len(b)} on the default branch"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out.extend(diff_paths(x, y, f"{path}[{i}]"))
        return out

    return [] if a == b else [f"{path}: {a!r} here vs {b!r} on the default branch"]


def check(root: Path) -> int:
    local_path = root / WORKFLOW
    if not local_path.is_file():
        print(f"FAIL: {WORKFLOW} does not exist in this checkout.", file=sys.stderr)
        return 2

    remote_text = read_ref(DEFAULT_BRANCH_REF, WORKFLOW)
    if remote_text is None:
        print(
            f"FAIL: could not read {WORKFLOW} from {DEFAULT_BRANCH_REF}, so it is UNKNOWN whether "
            f"the dispatcher that will actually fire matches this commit's.\n"
            f"      Unknown is not green. Fetch the default branch and re-run "
            f"(`git fetch origin main`); do not skip this check.",
            file=sys.stderr,
        )
        return 2

    here = structure(local_path.read_text(), "this commit's qa-gate.yml")
    there = structure(remote_text, f"{DEFAULT_BRANCH_REF}'s qa-gate.yml")

    differences = diff_paths(here, there)
    if not differences:
        print(
            "qa-gate dispatcher: structurally identical to the default branch "
            "(comments and formatting may differ, and that is fine)."
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
        f"  actually fires after a push to `qa` is the one on {DEFAULT_BRANCH_REF} — NOT the one in "
        f"this\n"
        f"  commit. Until these agree, a qa-gate improvement cannot gate the release that ships it, "
        f"and\n"
        f"  the run goes GREEN having done less than anyone thinks.\n\n"
        f"  Fix by promoting this file to the default branch, not by relaxing this check. Gate "
        f"LOGIC\n"
        f"  belongs in scripts/qa-gate-run.sh, which rides the commit and is exempt from this "
        f"problem\n"
        f"  entirely — if what you changed could live there, move it there instead.",
        file=sys.stderr,
    )
    return 1


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

    if failures:
        print(f"\nSELF-TEST FAILED: {failures} of {len(cases) + 1} checks did not hold", file=sys.stderr)
        return 1
    print(f"\nself-test: {len(cases) + 1} checks, all hold")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="prove the lint discriminates, then exit")
    ap.add_argument("--root", default=".", help="repository root to check")
    args = ap.parse_args()
    return selftest() if args.selftest else check(Path(args.root))


if __name__ == "__main__":
    sys.exit(main())
