#!/usr/bin/env python3
"""changelog-lint - the newest entry in CHANGELOG.md carries a version AND a date, always.

WHAT THIS GUARDS, AND WHY IT IS A GATE RATHER THAN A CONVENTION.

The top of CHANGELOG.md is the first thing a human reads and the only thing the marketing site
publishes. It has repeatedly gone out without a version number or without a date, and the request
to fix it has been made more than once - which is the definition of something that needs a gate
rather than another reminder. A fix somebody has to keep asking for is not a fix.

THE FAILURE THAT MOTIVATED THIS, precisely, because it was not what anyone assumed. The site's
sync step strips `## [Unreleased]` before publishing and rewrites `## [1.5.1], 2026-08-02` into a
version heading plus a styled date line. It did that with a regex terminated by `\\Z`, intending
"end of input". JavaScript has no `\\Z` anchor - it degrades to the literal letter `Z`, and under
the `/i` flag it matched a lowercase `z`. The strip therefore ended at the first `z` in the
Unreleased notes, cut mid-word, and left the remainder of the section on the published page as a
HEADLESS blob of prose sitting above the newest real release. No heading meant no version and no
date, and no rewriter ever looked at it. It only fired when `[Unreleased]` was non-empty, which is
why `main` (empty at release time) looked correct while `dev` was broken for weeks.

That specific bug lives in the site repo and is fixed there. This lint guards the OTHER half - the
source file's own shape - because the site can only publish what this file gives it, and every
downstream renderer in the project keys off the exact heading spelling below.

THE CANONICAL SHAPE, and there is exactly one:

    ## [1.5.1], 2026-08-02

`## [Unreleased]` is permitted as a staging area and must be the first heading if present. Nothing
else is. A heading that is nearly right is worse than one that is obviously wrong: the site's
rewriter has an OPTIONAL date group, so `## [1.6.0]` with no date publishes silently as a bare
version with no date rather than failing. Rule TOP-ENTRY-DATED exists because that degradation is
silent at every layer below this one.

WHY THE ORDERING AND FUTURE-DATE RULES ARE HERE TOO. They are nearly free once the headings are
parsed, and both have a real failure behind them: entries have been added in the wrong place when
a release branch merged back out of order, and a date typed a year ahead renders a release as
shipped in the future on a public page.

Every rule is proven RED against a synthetic violation and GREEN against a twin by `--selftest`,
which runs FIRST in CI. A guard nobody has watched fail is not a guard.

Usage:
    scripts/changelog-lint.py [--root .] [--file CHANGELOG.md]
    scripts/changelog-lint.py --selftest
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys

# The one accepted spelling of a released entry's heading.
CANONICAL = re.compile(r"^## \[(?P<ver>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\], (?P<date>\d{4}-\d{2}-\d{2})$")

# Any level-2 heading at all. Anything matching this and not CANONICAL must be an allowed
# non-release heading or it is a violation - so a malformed heading cannot be skipped by accident.
ANY_H2 = re.compile(r"^## .*$")

# Headings that are deliberately not releases.
UNRELEASED = "## [Unreleased]"
NON_RELEASE = {UNRELEASED, "## [Early development]"}


def semver_key(ver: str):
    """Sort key with correct pre-release ordering: 1.0.0-rc.7 sorts BELOW 1.0.0."""
    core, _, pre = ver.partition("-")
    nums = tuple(int(p) for p in core.split("."))
    if not pre:
        # No pre-release outranks any pre-release of the same core version.
        return (nums, (1,))
    parts = []
    for p in pre.split("."):
        # Numeric identifiers compare numerically and below alphanumeric ones.
        parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return (nums, (0, tuple(parts)))


def parse(text: str):
    """Return (headings, problems-from-parsing). headings: list of (lineno, raw, kind, ver, date)."""
    out = []
    for i, line in enumerate(text.split("\n"), start=1):
        if not ANY_H2.match(line):
            continue
        raw = line.rstrip()
        if raw in NON_RELEASE:
            out.append((i, raw, "non-release", None, None))
            continue
        m = CANONICAL.match(raw)
        if m:
            out.append((i, raw, "release", m.group("ver"), m.group("date")))
        else:
            out.append((i, raw, "malformed", None, None))
    return out


def check(text: str, today: _dt.date | None = None) -> list[str]:
    """Every rule. Returns a list of operator-readable failures; empty means green."""
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    problems: list[str] = []
    heads = parse(text)

    if not heads:
        return [
            "SHAPE: no `## ` version headings found at all. Either the file is empty or the "
            "parser is broken, and a broken parser reports a clean changelog."
        ]

    # -- CANONICAL-HEADING -----------------------------------------------------------------
    for lineno, raw, kind, _v, _d in heads:
        if kind == "malformed":
            problems.append(
                f"CANONICAL-HEADING: line {lineno}: {raw!r} is not a valid entry heading.\n"
                f"    Every released entry must read exactly:  ## [X.Y.Z], YYYY-MM-DD\n"
                f"    (for example: ## [1.5.1], 2026-08-02). The only other headings allowed are "
                f"`{UNRELEASED}` and `## [Early development]`."
            )

    releases = [(ln, raw, v, d) for ln, raw, k, v, d in heads if k == "release"]

    # -- UNRELEASED-FIRST ------------------------------------------------------------------
    for idx, (lineno, raw, kind, _v, _d) in enumerate(heads):
        if raw == UNRELEASED and idx != 0:
            problems.append(
                f"UNRELEASED-FIRST: line {lineno}: `{UNRELEASED}` appears below a released entry. "
                f"Staged notes belong at the very top of the file or nowhere; buried, they publish "
                f"in the middle of shipped history."
            )

    # -- TOP-ENTRY-DATED -------------------------------------------------------------------
    # The newest RELEASED entry is what the site publishes at the top of the page. It must carry
    # both a version and a date. A heading that got a version but no date is the silent case: the
    # site's rewriter has an optional date group and publishes a bare version rather than failing.
    first_release_idx = next((i for i, h in enumerate(heads) if h[2] == "release"), None)
    if first_release_idx is None:
        problems.append(
            "TOP-ENTRY-DATED: the file contains no released entry at all - every heading is "
            "`[Unreleased]` or `[Early development]`. The published changelog would have no "
            "version and no date anywhere on it."
        )
    else:
        # Anything malformed ABOVE the first good release is what a reader sees at the top.
        for lineno, raw, kind, _v, _d in heads[:first_release_idx]:
            if kind == "malformed":
                problems.append(
                    f"TOP-ENTRY-DATED: line {lineno}: the TOPMOST entry is {raw!r}, which carries "
                    f"no usable version and date. This is the heading the changelog page shows "
                    f"first. Stamp it as `## [X.Y.Z], YYYY-MM-DD` before release."
                )

    # -- NO-DUPLICATE-VERSION --------------------------------------------------------------
    seen: dict[str, int] = {}
    for lineno, _raw, v, _d in releases:
        if v in seen:
            problems.append(
                f"NO-DUPLICATE-VERSION: line {lineno}: version {v} was already used at line "
                f"{seen[v]}. Two entries with one version number make the release ambiguous."
            )
        else:
            seen[v] = lineno

    # -- DESCENDING ------------------------------------------------------------------------
    for (ln_a, _ra, va, da), (ln_b, _rb, vb, db) in zip(releases, releases[1:]):
        if semver_key(va) <= semver_key(vb):
            problems.append(
                f"DESCENDING: line {ln_b}: version {vb} is not older than {va} above it at line "
                f"{ln_a}. The changelog reads newest-first; an entry added in the wrong place "
                f"shows a superseded release as the current one."
            )
        if da < db:
            problems.append(
                f"DESCENDING: line {ln_b}: {vb} is dated {db}, which is AFTER {va} above it "
                f"({da}). Dates must not increase as you read down the file."
            )

    # -- NO-FUTURE-DATE --------------------------------------------------------------------
    for lineno, _raw, v, d in releases:
        if _dt.date.fromisoformat(d) > today:
            problems.append(
                f"NO-FUTURE-DATE: line {lineno}: {v} is dated {d}, which is in the future "
                f"(today is {today} UTC). A release cannot have shipped on a date that has not "
                f"happened; this renders as a future ship date on the public changelog."
            )

    return problems


# ------------------------------------------------------------------------------------------
# Self-test. Every rule proven RED against a synthetic violation, and GREEN against a twin that
# differs only in the thing the rule is about. A rule that cannot be shown to fire is not a rule.
# ------------------------------------------------------------------------------------------

GOOD = "\n".join(
    [
        "# Changelog",
        "",
        "## [Unreleased]",
        "",
        "### Added",
        "",
        "- Something staged.",
        "",
        "## [1.5.4], 2026-08-14",
        "",
        "- A shipped thing.",
        "",
        "## [1.5.3], 2026-08-08",
        "",
        "- An older shipped thing.",
        "",
    ]
)

CASES = [
    (
        "CANONICAL-HEADING",
        GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4] - 2026-08-14"),
        "a dash separator instead of the canonical comma",
    ),
    (
        "TOP-ENTRY-DATED",
        GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4]"),
        "the newest entry stamped with a version but NO date",
    ),
    (
        "TOP-ENTRY-DATED",
        GOOD.replace("## [1.5.4], 2026-08-14", "## [Next release]"),
        "the newest entry with neither a version nor a date",
    ),
    (
        "UNRELEASED-FIRST",
        GOOD.replace("## [Unreleased]\n", "").replace(
            "## [1.5.3], 2026-08-08", "## [Unreleased]\n\n## [1.5.3], 2026-08-08"
        ),
        "an Unreleased block buried below a shipped release",
    ),
    (
        "NO-DUPLICATE-VERSION",
        GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.4], 2026-08-08"),
        "one version number used by two entries",
    ),
    (
        "DESCENDING",
        GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.5], 2026-08-08"),
        "a newer version listed below an older one",
    ),
    (
        "DESCENDING",
        GOOD.replace("## [1.5.3], 2026-08-08", "## [1.5.3], 2026-08-20"),
        "a date that increases as you read down the file",
    ),
    (
        "NO-FUTURE-DATE",
        GOOD.replace("## [1.5.4], 2026-08-14", "## [1.5.4], 2099-01-01"),
        "a release dated in the future",
    ),
]


def selftest() -> int:
    today = _dt.date(2026, 8, 16)
    failures = 0

    green = check(GOOD, today=today)
    if green:
        print("  [FAIL]   the known-good fixture does not pass. The lint rejects a correct file:")
        for g in green:
            print("           " + g.splitlines()[0])
        failures += 1
    else:
        print("  [ok]     known-good fixture passes (no false positive)")

    for rule, broken, why in CASES:
        problems = check(broken, today=today)
        fired = [p for p in problems if p.startswith(rule + ":")]
        if fired:
            print(f"  [ok]     {rule:22} fires RED on {why}")
        else:
            print(f"  [FAIL]   {rule:22} did NOT fire on {why}")
            print(f"           (what did fire: {[p.split(':')[0] for p in problems] or 'nothing'})")
            failures += 1

    # A rule table that has stopped being reachable reads as green forever. Floor it.
    covered = {rule for rule, _, _ in CASES}
    expected = {
        "CANONICAL-HEADING",
        "TOP-ENTRY-DATED",
        "UNRELEASED-FIRST",
        "NO-DUPLICATE-VERSION",
        "DESCENDING",
        "NO-FUTURE-DATE",
    }
    missing = expected - covered
    if missing:
        print(f"  [FAIL]   rules with no RED case: {sorted(missing)}")
        failures += 1
    else:
        print(f"  [ok]     every one of the {len(expected)} rules has a proven RED case")

    print()
    if failures:
        print(f"changelog-lint --selftest: {failures} FAILED")
        return 1
    print(f"changelog-lint --selftest: all {len(CASES)} red cases + green twin pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--file", default="CHANGELOG.md", help="changelog path, relative to --root")
    ap.add_argument("--selftest", action="store_true", help="prove every rule RED, then exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    path = os.path.join(args.root, args.file)
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"changelog-lint: cannot read {path}: {exc}", file=sys.stderr)
        print("An unreadable changelog is not a clean one.", file=sys.stderr)
        return 1

    problems = check(text)
    if problems:
        print(f"changelog-lint: {len(problems)} problem(s) in {path}\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        print(
            "The newest entry in the changelog is what the public changelog page shows first.\n"
            "It must carry a version number and a release date.",
            file=sys.stderr,
        )
        return 1

    n = sum(1 for h in parse(text) if h[2] == "release")
    print(f"changelog-lint: ok - {n} released entries, canonical headings, newest first, top entry dated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
