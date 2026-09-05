#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# changelog-register-check.py -- every `breaking` entry in the accepted-differences register names
# its own CHANGELOG line, verbatim, so the release notes cannot silently fall out of sync with what
# the owner actually accepted as a break. This is the ONLY thing this script checks: it does not
# validate `improvement` entries (those have no `changelog` contract) and it does not judge whether
# the CHANGELOG's prose is otherwise truthful -- only that every register-declared break is NAMED.
#
#   PASS   every `breaking` entry has a non-empty `changelog` field and that exact string is a
#          substring of CHANGELOG.md
#   FAIL   a `breaking` entry has no `changelog` field, an empty one, or a `changelog` string that
#          is not found verbatim in CHANGELOG.md (the line drifted or was never written)
#
# Zero `breaking` entries is a PASS with zero rows (nothing owed) -- this is not the ship gate by
# itself, see docs/design/1.6.0-TRACKER.md group I; testing/shadow-oracle's own differ separately
# refuses any entry that accepts `status`/`effects.usage` without kind=breaking and a `changelog`
# field, so a malformed register is caught there, not here.
#
# python3 stdlib only.
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_REGISTER = REPO / "testing/shadow-oracle/accepted-differences.json"
DEFAULT_CHANGELOG = REPO / "CHANGELOG.md"

_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    """Collapse whitespace runs (incl. markdown line-wrap newlines) to a single space, so a
    `changelog` line that CHANGELOG.md happens to wrap across two source lines still matches. This
    is whitespace-only normalization: no word is added, removed or reordered."""
    return _WS.sub(" ", text).strip()


def check(register_path: Path, changelog_path: Path):
    """Return (rows, ok) where rows is a list of (id, status, detail) and ok is overall pass/fail."""
    rows = []
    try:
        register = json.loads(register_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [("<register>", "FAIL", f"could not read/parse {register_path}: {exc}")], False

    try:
        changelog_text = changelog_path.read_text()
    except OSError as exc:
        return [("<changelog>", "FAIL", f"could not read {changelog_path}: {exc}")], False

    ok = True
    entries = register.get("accepted", [])
    breaking = [e for e in entries if e.get("kind") == "breaking"]
    normalized_changelog = _normalize(changelog_text)
    for entry in breaking:
        entry_id = entry.get("id", "<unnamed>")
        line = entry.get("changelog")
        if not line:
            rows.append((entry_id, "FAIL", "kind=breaking but no (or empty) `changelog` field"))
            ok = False
        elif _normalize(line) not in normalized_changelog:
            rows.append(
                (
                    entry_id,
                    "FAIL",
                    f"changelog line not found verbatim in {changelog_path.name}: {line!r}",
                )
            )
            ok = False
        else:
            rows.append((entry_id, "PASS", "changelog line present verbatim"))
    return rows, ok


def selftest() -> int:
    import tempfile

    fails = 0
    cases = 0

    def say(passed, msg):
        nonlocal fails, cases
        cases += 1
        tag = "PASS" if passed else "FAIL"
        print(f"{tag}  {msg}")
        if not passed:
            fails += 1

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # (a) a breaking entry whose changelog line IS in the changelog -> PASS, overall ok
        good_register = tmp / "good.json"
        good_register.write_text(
            json.dumps(
                {
                    "accepted": [
                        {"id": "X-1", "kind": "improvement", "rationale": "no changelog needed"},
                        {"id": "X-2", "kind": "breaking", "changelog": "the sky is now green"},
                    ]
                }
            )
        )
        good_changelog = tmp / "good.md"
        good_changelog.write_text("## [1.6.0]\n\n- the sky is now green\n")
        rows, ok = check(good_register, good_changelog)
        say(
            ok and rows == [("X-2", "PASS", "changelog line present verbatim")],
            "breaking entry with its line present -> PASS, run green",
        )

        # (b) a breaking entry whose changelog line is ABSENT -> FAIL, overall not ok
        bad_changelog = tmp / "bad.md"
        bad_changelog.write_text("## [1.6.0]\n\n- nothing to see here\n")
        rows, ok = check(good_register, bad_changelog)
        say(
            (not ok) and rows[0][0] == "X-2" and rows[0][1] == "FAIL",
            "breaking entry whose line is missing from CHANGELOG -> FAIL, run red",
        )

        # (c) a breaking entry with NO changelog field at all -> FAIL
        no_field_register = tmp / "no_field.json"
        no_field_register.write_text(
            json.dumps({"accepted": [{"id": "X-3", "kind": "breaking"}]})
        )
        rows, ok = check(no_field_register, good_changelog)
        say(
            (not ok) and rows[0] == ("X-3", "FAIL", "kind=breaking but no (or empty) `changelog` field"),
            "breaking entry with no changelog field -> FAIL",
        )

        # (d) zero breaking entries -> PASS with zero rows (nothing owed)
        empty_register = tmp / "empty.json"
        empty_register.write_text(json.dumps({"accepted": [{"id": "X-4", "kind": "improvement"}]}))
        rows, ok = check(empty_register, good_changelog)
        say(ok and rows == [], "no breaking entries -> zero rows, PASS")

        # (e) missing register file -> FAIL, not a crash
        rows, ok = check(tmp / "does-not-exist.json", good_changelog)
        say(not ok and rows and rows[0][1] == "FAIL", "missing register file -> FAIL, not a crash")

        # (f) the changelog line is present but markdown-wrapped across two source lines -> still
        # PASS (whitespace-only normalization, not a text edit)
        wrapped_register = tmp / "wrapped.json"
        wrapped_register.write_text(
            json.dumps(
                {"accepted": [{"id": "X-5", "kind": "breaking", "changelog": "the sky is now a lovely green"}]}
            )
        )
        wrapped_changelog = tmp / "wrapped.md"
        wrapped_changelog.write_text("## [1.6.0]\n\n- the sky is now a lovely\n  green\n")
        rows, ok = check(wrapped_register, wrapped_changelog)
        say(ok and rows == [("X-5", "PASS", "changelog line present verbatim")], "line wrapped across two source lines -> still PASS")

    print()
    if fails == 0:
        print(f"changelog-register-check selftest: GREEN ({cases} cases)")
        return 0
    print(f"changelog-register-check selftest: RED ({fails}/{cases} cases failed)")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    rows, ok = check(args.register, args.changelog)
    if not rows:
        print("changelog-register-check: 0 `breaking` register entries -- nothing owed")
        return 0
    for entry_id, status, detail in rows:
        print(f"{status}  {entry_id}  {detail}")
    print()
    if ok:
        print(f"changelog-register-check: GREEN ({len(rows)} breaking entr{'y' if len(rows) == 1 else 'ies'} named)")
        return 0
    bad = sum(1 for _, status, _ in rows if status == "FAIL")
    print(f"changelog-register-check: RED ({bad}/{len(rows)} breaking entries not named in CHANGELOG.md)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
