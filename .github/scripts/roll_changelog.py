#!/usr/bin/env python3
"""Promote CHANGELOG [Unreleased] to a dated [version] section, add a fresh empty
[Unreleased] above it. Used by .github/workflows/cut-release.yml."""
import sys, re, datetime

def main(version: str, path: str) -> None:
    today = datetime.date.today().isoformat()
    s = open(path).read()
    m = re.search(r'^## \[Unreleased\]\s*\n(.*?)(?=^## \[)', s, re.S | re.M)
    if not m:
        sys.exit("roll_changelog: no [Unreleased] section found")
    # ALREADY CUT? Refuse, loudly. A release note can be written and dated by hand BEFORE the tag
    # (1.5.3 was). Rolling on top of that inserts a SECOND `## [<version>]` section, and because
    # `[Unreleased]` is empty by then the duplicate reads "Maintenance and dependency updates" and
    # sits ABOVE the real entry. The publish succeeds and the changelog is wrong, which is the
    # failure shape this project treats as worse than a hard stop.
    if re.search(rf'^## \[{re.escape(version)}\][,\s]', s, re.M):
        sys.exit(
            f"roll_changelog: CHANGELOG.md already has a [{version}] section, refusing to add a "
            f"second one. The notes were written by hand before the tag. Either drop the roll step "
            f"for this release, or delete the hand-written section first if you want it generated."
        )
    body = m.group(1).strip('\n')
    if not body.strip():
        body = "### Changed\n\n- Maintenance and dependency updates."
    new = f"## [Unreleased]\n\n## [{version}], {today}\n\n{body}\n\n"
    open(path, "w").write(s[:m.start()] + new + s[m.end():])
    print(f"rolled CHANGELOG: [Unreleased] -> [{version}] {today}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: roll_changelog.py <version> <CHANGELOG.md>")
    main(sys.argv[1], sys.argv[2])
