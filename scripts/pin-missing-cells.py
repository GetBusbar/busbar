#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Regenerate qa/method-coverage.missing -- the pinned MISSING work queue.

THIS IS A DEV SCRIPT, AND IT LIVES OUTSIDE THE GATE ON PURPOSE.

crates/busbar/tests/method_coverage.rs used to carry this regeneration itself, behind an
environment variable: set the variable and the gate rewrote the pinned file from whatever the tree
currently said, then returned green. A gate that its own caller can talk into agreeing with the
tree is not a gate -- the pinned queue stops recording what was OWED and starts recording what
happens to be built. So the write moved here, where a human runs it deliberately and reads the
diff, and the test now only ever compares.

The MISSING set is defined exactly as the gate defines it, and the gate is the authority: a cell of
qa/method-inventory.json is MISSING when it is

  * owed at all            -- `na_reason` is absent (an N/A cell is not owed an implementation),
  * not claimed            -- its id is absent from qa/method-coverage.status, and
  * not argued impossible  -- its id is absent from qa/WAIVERS.md.

If this script and the gate ever disagree, the gate goes RED in the direction of the disagreement
and this script is what is wrong. Never edit the test to agree with this file.

Usage:
    scripts/pin-missing-cells.py            # print the diff against the pinned file; exit 1 if any
    scripts/pin-missing-cells.py --write    # rewrite the pinned file, preserving its header
"""

import argparse
import difflib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY = os.path.join(ROOT, "qa", "method-inventory.json")
STATUS = os.path.join(ROOT, "qa", "method-coverage.status")
WAIVERS = os.path.join(ROOT, "qa", "WAIVERS.md")
PINNED = os.path.join(ROOT, "qa", "method-coverage.missing")


def claimed_ids():
    """Every cell id the status file claims, `implemented` or `waived`. The gate's parser validates
    the SHAPE of each line (a waiver needs a date and a reason); this only needs the id, and a
    malformed line is the gate's failure to report, not this script's."""
    ids = set()
    with open(STATUS, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            ids.add(line.split("=", 1)[0].strip())
    return ids


def impossible_ids():
    """Every cell id argued impossible in qa/WAIVERS.md: a row is ``- `<cell-id>` --- <argument>``."""
    ids = set()
    with open(WAIVERS, encoding="utf-8") as fh:
        for raw in fh:
            if not raw.startswith("- `"):
                continue
            rest = raw[3:]
            if "`" not in rest:
                continue
            ids.add(rest.split("`", 1)[0])
    return ids


def computed_missing():
    with open(INVENTORY, encoding="utf-8") as fh:
        doc = json.load(fh)
    claimed = claimed_ids()
    impossible = impossible_ids()
    out = [
        c["id"]
        for c in doc["cells"]
        if c.get("na_reason") is None
        and c["id"] not in claimed
        and c["id"] not in impossible
    ]
    return sorted(set(out))


def pinned_lines():
    with open(PINNED, encoding="utf-8") as fh:
        text = fh.read()
    body = [l.split("#", 1)[0].strip() for l in text.splitlines()]
    return text, sorted({l for l in body if l})


def header_of(text):
    """The pinned file's leading comment block -- the prose that says what the file is. It is
    preserved verbatim across a rewrite: it is a human's explanation, not generated content."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            out.append(line)
        else:
            break
    return "\n".join(out).rstrip("\n") + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--write",
        action="store_true",
        help="rewrite qa/method-coverage.missing (default: show the diff and exit non-zero)",
    )
    args = ap.parse_args()

    computed = computed_missing()
    text, pinned = pinned_lines()

    if computed == pinned:
        print("qa/method-coverage.missing is already exact: %d cells." % len(computed))
        return 0

    diff = list(
        difflib.unified_diff(
            pinned, computed, fromfile="pinned (on disk)", tofile="computed (from the tree)", lineterm=""
        )
    )
    print("\n".join(diff))
    print(
        "\n%d cell(s) newly MISSING, %d cell(s) now covered."
        % (len(set(computed) - set(pinned)), len(set(pinned) - set(computed)))
    )

    if not args.write:
        print("\nRe-run with --write to pin this. READ THE DIFF FIRST: every added line is a gap.")
        return 1

    with open(PINNED, "w", encoding="utf-8") as fh:
        fh.write(header_of(text))
        for cell in computed:
            fh.write(cell + "\n")
    print("\nwrote qa/method-coverage.missing (%d cells)." % len(computed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
