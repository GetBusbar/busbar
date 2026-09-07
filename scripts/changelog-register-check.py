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
# THE SEARCH IS SCOPED TO THE NEWEST `## [x.y.z]` SECTION, not to the whole file. CHANGELOG.md is an
# append-only history of every release, so an unanchored substring search over it can be satisfied by
# prose written for 1.5.0 -- and, the other way round, an entry could count as "named in the
# CHANGELOG" while the section this release actually ships says nothing about it. The rule is that an
# accepted difference is named in THIS release's notes; an older section cannot discharge it.
#
#   PASS    the entry has a non-empty `changelog` string and that exact string is a substring of the
#           NEWEST release section of CHANGELOG.md (whitespace-normalized, so a line-wrap matches)
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


_SECTION_RE = re.compile(r"^## \[(?P<ver>[0-9]+\.[0-9]+\.[0-9]+)\]", re.MULTILINE)


def newest_section(changelog_text: str):
    """(version, body) for the TOP `## [x.y.z]` section of CHANGELOG.md, or (None, None).

    THE SEARCH IS ANCHORED TO ONE SECTION, and it was not. The check asked whether an accepted
    difference's `changelog` line appeared ANYWHERE in the whole file, as an unanchored substring
    over every release that has ever shipped. CHANGELOG.md is an append-only history of a dozen
    versions, so the register was being satisfied by prose written for 1.5.0 that happens to contain
    the same words -- and, worse, an entry could be "named in the CHANGELOG" while the section this
    release actually publishes says nothing about it at all. The rule the owner wrote is that an
    accepted difference is named in the release notes THIS release ships; nothing about the 1.5.x
    history can discharge it, and a line deleted from the current section must go red even if an
    older section still carries the same sentence.
    """
    m = _SECTION_RE.search(changelog_text)
    if not m:
        return None, None
    nxt = _SECTION_RE.search(changelog_text, m.end())
    return m.group("ver"), changelog_text[m.start(): nxt.start() if nxt else len(changelog_text)]


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

    # THE OWED SET IS ONE JSON KEY, SO A MISSING KEY MUST BE RED, NOT EMPTY. `.get("accepted", [])`
    # made "the register has nothing to name" and "this gate is no longer reading the register"
    # indistinguishable: both produced zero rows, and main() calls zero rows a pass. The register is
    # testing/shadow-oracle/accepted-differences.json — a file this gate does not own. Rename its
    # `accepted` key in a differ refactor and this gate reports GREEN over every unnamed accepted
    # difference in it, `kind: breaking` ones included. An `accepted` key holding an empty list is
    # still an honest "nothing owed"; an ABSENT key is a gate that lost its input.
    if not isinstance(register, dict) or "accepted" not in register:
        keys = sorted(register) if isinstance(register, dict) else type(register).__name__
        return [(
            "<register>", "FAIL",
            f"{register_path} has no `accepted` key (top level: {keys}) — this gate reads the "
            f"register by that one key, so an absent key silently empties the owed set and would "
            f"report GREEN over every accepted difference in the file",
        )], False
    entries = register["accepted"]
    if not isinstance(entries, list):
        return [(
            "<register>", "FAIL",
            f"{register_path}: `accepted` is {type(entries).__name__}, not a list — nothing can be "
            f"enumerated from it",
        )], False
    ok = True
    section_version, section_text = newest_section(changelog_text)
    if section_text is None:
        return [(
            "<changelog>", "FAIL",
            f"{changelog_path.name} has no `## [x.y.z]` section heading -- there is no release "
            f"section to search, and an unanchored search over the whole file would be satisfied "
            f"by any older release's prose",
        )], False
    normalized_changelog = _normalize(section_text)
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
                    f"changelog line not found verbatim in the {section_version} section of "
                    f"{changelog_path.name}: {line!r}",
                )
            )
            ok = False
        else:
            rows.append((entry_id, "PASS",
                         f"changelog line present verbatim in the {section_version} section"))
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
                ("X-1", "PASS", "changelog line present verbatim in the 1.6.0 section"),
                ("X-2", "PASS", "changelog line present verbatim in the 1.6.0 section"),
            ],
            "improvement AND breaking entries with their lines present -> PASS, run green",
        )

        # (a2) THE ANCHOR. The same register, against a CHANGELOG whose CURRENT section says nothing
        # and whose OLD section carries both lines verbatim. Unanchored, this passed: the substring
        # search ran over the whole append-only history, so an entry accepted for this release could
        # be discharged by prose shipped a year ago, and deleting a line from the current section
        # changed nothing. It must be RED.
        stale_changelog = tmp / "stale.md"
        stale_changelog.write_text(
            "## [1.6.0], unreleased\n\n- an unrelated note\n\n"
            "## [1.5.0], 2026-08-01\n\n- the grass is now greener\n- the sky is now green\n"
        )
        rows, ok = check(good_register, stale_changelog)
        say(
            (not ok) and [r[1] for r in rows] == ["FAIL", "FAIL"],
            "lines present ONLY in an older release section -> FAIL (the search is anchored to the newest one)",
        )

        # (a3) and the anchor must not be a way to pass by having no sections at all.
        headless = tmp / "headless.md"
        headless.write_text("- the grass is now greener\n- the sky is now green\n")
        rows, ok = check(good_register, headless)
        say(
            (not ok) and rows[0][0] == "<changelog>",
            "a CHANGELOG with no `## [x.y.z]` heading -> FAIL, never a vacuous pass",
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

        # (d5) the OWED-SET KEY IS GONE -> FAIL, never "zero rows, nothing owed". (d4) above is the
        # honest empty case; this is the one that used to look identical to it. The register belongs
        # to the shadow-oracle differ, so its key can be renamed by someone who never reads this file.
        renamed_register = tmp / "renamed.json"
        renamed_register.write_text(
            json.dumps(
                {"differences": [{"id": "X-6", "kind": "breaking", "changelog": "nobody will ever check this"}]}
            )
        )
        rows, ok = check(renamed_register, good_changelog)
        say(
            (not ok) and rows and rows[0][1] == "FAIL" and "no `accepted` key" in rows[0][2],
            "register with the `accepted` key renamed -> FAIL, not a vacuous pass",
        )

        # (d6) `accepted` present but not a list -> FAIL rather than silently enumerating nothing
        scalar_register = tmp / "scalar.json"
        scalar_register.write_text(json.dumps({"accepted": {"X-7": {"kind": "breaking"}}}))
        rows, ok = check(scalar_register, good_changelog)
        say((not ok) and rows and rows[0][1] == "FAIL", "`accepted` that is not a list -> FAIL")

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
        say(
            ok and rows == [("X-5", "PASS", "changelog line present verbatim in the 1.6.0 section")],
            "line wrapped across two source lines -> still PASS",
        )

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
