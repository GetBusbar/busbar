#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# changelog-register-check.py -- EVERY entry in the accepted-differences register names its own
# CHANGELOG line, verbatim, so the release notes cannot silently fall out of sync with what the owner
# actually accepted. ARCHITECTURE.md's owner rule says a difference registered as `improvement` is
# accepted "(owner sign-off, named in the CHANGELOG)" exactly as a break is, so the contract is not
# `kind == "breaking"` -- it is every accepted difference. What this script does NOT do is judge
# whether the CHANGELOG's prose is otherwise truthful: only that every register-declared difference
# is NAMED, and that the name still exists in the file.
#
#   PASS    the entry has a non-empty `changelog` string and that exact string is a substring of
#           CHANGELOG.md (whitespace-normalized, so a markdown line-wrap still matches)
#   WAIVED  the entry carries an EXPLICIT `"changelog": null` together with a non-empty
#           `changelog_reason` saying why this difference is not user-visible. The waiver is a
#           written argument a reviewer can disagree with, never an omission -- which is the whole
#           difference between "we decided this needs no line" and "nobody wrote one".
#   FAIL    the entry has no `changelog` key at all, an empty/blank one, a `null` with no
#           `changelog_reason`, a `changelog` string not found verbatim in CHANGELOG.md (the line
#           drifted or was never written), or -- for a `breaking` entry -- a waiver at all, because
#           a break the owner accepted is user-visible by definition and always owes a line.
#
# Zero entries is a PASS with zero rows (nothing owed) -- this is not the ship gate by itself, see
# docs/design/1.6.0-TRACKER.md group I; testing/shadow-oracle's own differ separately refuses any
# entry that accepts `status`/`effects.usage` without kind=breaking and a `changelog` field, so a
# malformed register is caught there, not here.
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
    normalized_changelog = _normalize(changelog_text)
    for entry in entries:
        entry_id = entry.get("id", "<unnamed>")
        kind = entry.get("kind", "<no kind>")
        if "changelog" not in entry:
            rows.append(
                (
                    entry_id,
                    "FAIL",
                    f"kind={kind} but the entry carries no `changelog` key at all -- an accepted "
                    f"difference owes either a named line or an explicit waiver",
                )
            )
            ok = False
            continue
        line = entry["changelog"]
        if line is None:
            reason = (entry.get("changelog_reason") or "").strip()
            if kind == "breaking":
                rows.append(
                    (
                        entry_id,
                        "FAIL",
                        "kind=breaking may not waive its CHANGELOG line: an accepted break is "
                        "user-visible by definition",
                    )
                )
                ok = False
            elif not reason:
                rows.append(
                    (
                        entry_id,
                        "FAIL",
                        "`changelog` is null but no `changelog_reason` says why no line is owed",
                    )
                )
                ok = False
            else:
                rows.append((entry_id, "WAIVED", f"no line owed: {reason}"))
            continue
        if not isinstance(line, str) or not line.strip():
            rows.append((entry_id, "FAIL", f"`changelog` is empty or not a string: {line!r}"))
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

        # (a) a breaking entry AND an improvement entry, both with their lines present -> PASS.
        # The improvement row is the half ARCHITECTURE.md's owner rule owes and this gate used to
        # skip entirely: an improvement is accepted "named in the CHANGELOG" just as a break is.
        good_register = tmp / "good.json"
        good_register.write_text(
            json.dumps(
                {
                    "accepted": [
                        {"id": "X-1", "kind": "improvement", "changelog": "the grass is now greener"},
                        {"id": "X-2", "kind": "breaking", "changelog": "the sky is now green"},
                    ]
                }
            )
        )
        good_changelog = tmp / "good.md"
        good_changelog.write_text("## [1.6.0]\n\n- the grass is now greener\n- the sky is now green\n")
        rows, ok = check(good_register, good_changelog)
        say(
            ok
            and rows
            == [
                ("X-1", "PASS", "changelog line present verbatim"),
                ("X-2", "PASS", "changelog line present verbatim"),
            ],
            "improvement AND breaking entries with their lines present -> PASS, run green",
        )

        # (b) a breaking entry whose changelog line is ABSENT -> FAIL, overall not ok
        bad_changelog = tmp / "bad.md"
        bad_changelog.write_text("## [1.6.0]\n\n- the grass is now greener\n")
        rows, ok = check(good_register, bad_changelog)
        say(
            (not ok) and rows[1][0] == "X-2" and rows[1][1] == "FAIL",
            "breaking entry whose line is missing from CHANGELOG -> FAIL, run red",
        )

        # (b2) an IMPROVEMENT entry whose changelog line is absent -> FAIL too, on the same terms.
        improvement_only = tmp / "improvement_only.json"
        improvement_only.write_text(
            json.dumps({"accepted": [{"id": "X-6", "kind": "improvement", "changelog": "never written"}]})
        )
        rows, ok = check(improvement_only, good_changelog)
        say(
            (not ok) and rows[0][0] == "X-6" and rows[0][1] == "FAIL",
            "improvement entry whose line is missing from CHANGELOG -> FAIL, run red",
        )

        # (c) a breaking entry with NO changelog field at all -> FAIL
        no_field_register = tmp / "no_field.json"
        no_field_register.write_text(
            json.dumps({"accepted": [{"id": "X-3", "kind": "breaking"}]})
        )
        rows, ok = check(no_field_register, good_changelog)
        say(
            (not ok) and rows[0][0] == "X-3" and rows[0][1] == "FAIL",
            "breaking entry with no changelog field -> FAIL",
        )

        # (c2) an IMPROVEMENT with no changelog key at all -> FAIL. This is the exact shape the
        # register carried before this rule existed, so it is the red the change is measured by.
        no_field_improvement = tmp / "no_field_improvement.json"
        no_field_improvement.write_text(
            json.dumps({"accepted": [{"id": "X-7", "kind": "improvement", "rationale": "silent"}]})
        )
        rows, ok = check(no_field_improvement, good_changelog)
        say(
            (not ok) and rows[0][0] == "X-7" and rows[0][1] == "FAIL",
            "improvement entry with no changelog key -> FAIL (the pre-rule shape is red)",
        )

        # (d) an explicit waiver: `changelog: null` WITH a reason -> WAIVED, run still green.
        waived = tmp / "waived.json"
        waived.write_text(
            json.dumps(
                {
                    "accepted": [
                        {
                            "id": "X-4",
                            "kind": "improvement",
                            "changelog": None,
                            "changelog_reason": "internal-only; no user-observable byte changes",
                        }
                    ]
                }
            )
        )
        rows, ok = check(waived, good_changelog)
        say(
            ok and rows[0][0] == "X-4" and rows[0][1] == "WAIVED",
            "explicit `changelog: null` with a reason -> WAIVED, run green",
        )

        # (d2) the same waiver with NO reason -> FAIL: a null is a decision, not an omission.
        waived_no_reason = tmp / "waived_no_reason.json"
        waived_no_reason.write_text(
            json.dumps({"accepted": [{"id": "X-8", "kind": "improvement", "changelog": None}]})
        )
        rows, ok = check(waived_no_reason, good_changelog)
        say(
            (not ok) and rows[0][0] == "X-8" and rows[0][1] == "FAIL",
            "`changelog: null` with no reason -> FAIL",
        )

        # (d3) a BREAKING entry may not waive at all.
        waived_breaking = tmp / "waived_breaking.json"
        waived_breaking.write_text(
            json.dumps(
                {
                    "accepted": [
                        {
                            "id": "X-9",
                            "kind": "breaking",
                            "changelog": None,
                            "changelog_reason": "we would rather not say",
                        }
                    ]
                }
            )
        )
        rows, ok = check(waived_breaking, good_changelog)
        say(
            (not ok) and rows[0][0] == "X-9" and rows[0][1] == "FAIL",
            "a breaking entry trying to waive its line -> FAIL",
        )

        # (d4) zero entries -> PASS with zero rows (nothing owed)
        empty_register = tmp / "empty.json"
        empty_register.write_text(json.dumps({"accepted": []}))
        rows, ok = check(empty_register, good_changelog)
        say(ok and rows == [], "no register entries -> zero rows, PASS")

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
        print("changelog-register-check: 0 register entries -- nothing owed")
        return 0
    for entry_id, status, detail in rows:
        print(f"{status:<6}  {entry_id}  {detail}")
    print()
    named = sum(1 for _, status, _ in rows if status == "PASS")
    waived = sum(1 for _, status, _ in rows if status == "WAIVED")
    if ok:
        print(
            f"changelog-register-check: GREEN ({named} of {len(rows)} accepted difference(s) named "
            f"in CHANGELOG.md, {waived} explicitly waived)"
        )
        return 0
    bad = sum(1 for _, status, _ in rows if status == "FAIL")
    print(
        f"changelog-register-check: RED ({bad}/{len(rows)} accepted differences are neither named "
        f"in CHANGELOG.md nor explicitly waived)"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
