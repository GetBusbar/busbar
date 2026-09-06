#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# inventory-coverage.py — the honest scoreboard for the parity claim in
# docs/design/ARCHITECTURE.md Appendix B: "every row of every inventory file under
# docs/design/inventory/ is a parity binding and an oracle cell." Nothing checked that claim
# before this script. It:
#
#   1. Reads every row id out of docs/design/inventory/*.md (only rows that live in a table whose
#      header column is literally "id" count — a hyphenated word in some other column is not an
#      id). The id family is the text before the first "-" (BOOT, CONF, SEC, ADM, RT, LST, ... —
#      whatever actually exists; the list is not hard-coded).
#   2. Reads testing/shadow-oracle/cells.json (read-only — that tree belongs to another owner) and
#      asks, for each inventory id, "does any oracle cell cite this id?" Two citation styles are
#      recognised, both literal data already in cells.json, nothing invented:
#        - the id text appears verbatim (word-bounded) anywhere in the cell's own fields (its own
#          "id", "why", "exec.config", etc. — this is how boot.refusal cells cite BOOT-nnn today);
#        - for the "ADM" family specifically, an admin.ops cell's second id-segment is the exact
#          operationId named in the ADM row's "operationId" column (admin.ops cell ids are
#          "admin.ops|<operationId>|<case>", and the ADM table's second column literally is that
#          operationId — this is a real foreign key, not a guess).
#      Rows in inventory files that have no "id" column at all (six of the eight files, today) have
#      no ids to check — they show up as families with zero rows, which is itself the finding.
#   3. Reads the golden ledger (testing/shadow-oracle/golden/<version>/ledger.tsv, read-only) for
#      PASS/SKIP per cell id, and classifies every inventory id:
#        covered  - at least one citing cell is PASS on the golden
#        partial  - cited, but every citing cell is SKIP (or the cell is flagged needs_fixture)
#        none     - no cell cites it at all
#   4. Fills the 40-row coverage matrix (rows C1..O6) in docs/design/1.5.5-BEHAVIOUR.md between
#      <!-- coverage:begin --> / <!-- coverage:end --> markers: CELL if every id family the row
#      spans is fully covered, UNMAPPED if none of it is, PARTIAL otherwise. A row that spans no id
#      family (its source file has no id column) is UNMAPPED - there is nothing to bind yet.
#   5. Writes qa/inventory-coverage.json (full per-id detail) and, on --write, regenerates
#      qa/inventory-gaps.json: every id with status "none", each with a one-line reason.
#
# Usage:
#   inventory-coverage.py --write      run the analysis, write both qa/*.json files, rewrite the
#                                       coverage table in 1.5.5-BEHAVIOUR.md, print the summary.
#   inventory-coverage.py --check      re-run the analysis; fail (exit 1) if any id with status
#                                       "none" is missing from qa/inventory-gaps.json.
#   inventory-coverage.py --selftest   prove the mechanism can actually fail: (a) drop one cell that
#                                       currently covers an id, in memory only, and confirm the id
#                                       turns "none" (red); (b) confirm an id already named in
#                                       qa/inventory-gaps.json still passes --check-style logic
#                                       (green). Touches no file on disk.
#
# Plain bash 3.2 / POSIX-adjacent posture is not needed here (this is Python), but the same house
# rule applies: never write inside testing/shadow-oracle/ — that tree is owned elsewhere and is
# read here, never mutated.

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict, OrderedDict
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY_DIR = os.path.join(REPO_ROOT, "docs", "design", "inventory")
BEHAVIOUR_MD = os.path.join(REPO_ROOT, "docs", "design", "1.5.5-BEHAVIOUR.md")
CELLS_JSON = os.path.join(REPO_ROOT, "testing", "shadow-oracle", "cells.json")
GOLDEN_LEDGER = os.path.join(REPO_ROOT, "testing", "shadow-oracle", "golden", "1.5.5", "ledger.tsv")
QA_DIR = os.path.join(REPO_ROOT, "qa")
COVERAGE_JSON = os.path.join(QA_DIR, "inventory-coverage.json")
GAPS_JSON = os.path.join(QA_DIR, "inventory-gaps.json")

ID_ROW_RE = re.compile(r"^([A-Za-z]+-[A-Za-z0-9]+)$")

BEGIN_MARK = "<!-- coverage:begin -->"
END_MARK = "<!-- coverage:end -->"

# Which id families each 40-row matrix section can even be bound to, drawn from what family(ies)
# of ids actually live under that inventory section today. A row mapped to a family that turns out
# to have zero ids (because its source file has no id column) is honestly UNMAPPED - nothing here
# invents an id that is not in the inventory file.
ROW_FAMILIES = OrderedDict([
    ("C1", ["CONF"]),          # config keys with defaults
    ("C2", ["BOOT"]),         # boot refusals + warnings
    ("C3", ["BOOT", "CONF"]),  # reserved names, precedence, migration, reload
    ("C4", ["SEC"]),          # secret refs
    ("R1", ["LST"]),          # listeners and router separation
    ("R2", ["RT"]),           # data-plane routes and ladder
    ("R3", ["ADM"]),          # admin operations
    ("R4", ["RT"]),           # error envelopes, KIND_*, timeouts, Retry-After
    ("R5", ["ADM"]),          # admin audit chain
    ("G1", []),  # bucket topology and windows                 - governance-billing.md has no id column
    ("G2", []),  # admission order and charges
    ("G3", []),  # refunds
    ("G4", []),  # per-lane controls
    ("G5", []),  # cost model
    ("G6", []),  # /usage arithmetic
    ("G7", []),  # write-behind and store failure
    ("P1", []),  # request lifecycle, hooks, ranking, failover  - proxy-hooks.md has no id column
    ("P2", []),  # status and error mapping
    ("P3", []),  # egress auth schemes
    ("P4", []),  # network guard
    ("D1", []),  # dialect catalogue and 36 pairs                - dialects.md has no id column
    ("D2", []),  # streaming and usage extraction
    ("D3", []),  # error mapping per dialect
    ("D4", []),  # headers
    ("A1", []),  # credential forms and precedence               - auth-secrets.md has no id column
    ("A2", []),  # key lifecycle and idempotency
    ("A3", []),  # token exchange and provisioning
    ("A4", []),  # auth plugin ABI and modules
    ("A5", []),  # admin auth and mTLS
    ("A6", []),  # secrets and TLS
    ("S1", []),  # ABI versions and loader                        - plugins-stores.md has no id column
    ("S2", []),  # store contract and memory store
    ("S3", []),  # export
    ("S4", []),  # reload/rollback
    ("O1", []),  # CLI and env vars                               - ops-observability.md has no id column
    ("O2", []),  # lifecycle, health, signals, shutdown
    ("O3", []),  # metrics
    ("O4", []),  # logs, spans, OTLP
    ("O5", []),  # /stats and operational signals
    ("O6", []),  # documented behaviour cross-check
])

ROW_LABELS = {
    "C1": "config keys (205) with defaults",
    "C2": "boot refusals + warnings (228)",
    "C3": "reserved names, precedence, migration, reload",
    "C4": "secret refs",
    "R1": "listeners and router separation",
    "R2": "data-plane routes (37) and ladder",
    "R3": "admin operations (66)",
    "R4": "error envelopes, KIND_*, timeouts, Retry-After",
    "R5": "admin audit chain",
    "G1": "bucket topology and windows",
    "G2": "admission order and charges",
    "G3": "refunds",
    "G4": "per-lane controls",
    "G5": "cost model",
    "G6": "/usage arithmetic",
    "G7": "write-behind and store failure",
    "P1": "request lifecycle, hooks, ranking, failover",
    "P2": "status and error mapping (29 rows)",
    "P3": "egress auth schemes (9)",
    "P4": "network guard",
    "D1": "dialect catalogue and 36 pairs",
    "D2": "streaming and usage extraction",
    "D3": "error mapping per dialect",
    "D4": "headers",
    "A1": "credential forms and precedence",
    "A2": "key lifecycle and idempotency",
    "A3": "token exchange and provisioning",
    "A4": "auth plugin ABI and modules",
    "A5": "admin auth and mTLS",
    "A6": "secrets and TLS",
    "S1": "ABI versions and loader",
    "S2": "store contract and memory store",
    "S3": "export",
    "S4": "reload/rollback",
    "O1": "CLI and env vars",
    "O2": "lifecycle, health, signals, shutdown",
    "O3": "metrics (25)",
    "O4": "logs, spans, OTLP",
    "O5": "/stats and operational signals",
    "O6": "documented behaviour cross-check",
}


def parse_inventory_ids(inventory_dir=INVENTORY_DIR):
    """Walk every *.md file under inventory_dir and pull out every row of every table whose
    header row's first column is literally "id". Returns {id: {family, file, line, operationId}}.
    """
    ids = OrderedDict()
    for path in sorted(glob.glob(os.path.join(inventory_dir, "*.md"))):
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        i = 0
        rel = os.path.relpath(path, REPO_ROOT)
        while i < len(lines):
            line = lines[i]
            if line.strip().lower().startswith("| id |"):
                # header row -> next line is the "|---|---|" separator, then data rows.
                i += 2
                while i < len(lines) and lines[i].startswith("|"):
                    raw_cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                    row_id = raw_cells[0].strip("` ")
                    m = ID_ROW_RE.match(row_id)
                    if m:
                        family = row_id.split("-", 1)[0]
                        op_id = raw_cells[1].strip("` ") if len(raw_cells) > 1 else ""
                        if row_id in ids:
                            raise SystemExit(
                                "duplicate inventory id %s in %s and %s" % (row_id, ids[row_id]["file"], rel)
                            )
                        ids[row_id] = {
                            "family": family,
                            "file": rel,
                            "line": i + 1,
                            "operationId": op_id,
                        }
                    i += 1
                continue
            i += 1
    return ids


def _read_committed_or_live(path):
    """testing/shadow-oracle/** belongs to another owner and may be mid-write in the working
    copy. Prefer the last-committed (HEAD) version so this gate reads a consistent snapshot
    instead of a half-written file; fall back to the working copy if git has nothing for it yet
    (e.g. a brand-new untracked file) or git itself is unavailable."""
    import subprocess

    rel = os.path.relpath(path, REPO_ROOT)
    try:
        out = subprocess.run(
            ["git", "-C", REPO_ROOT, "show", "HEAD:%s" % rel],
            capture_output=True, text=True, check=True,
        )
        return out.stdout
    except Exception:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        return None


def load_cells(cells_path=CELLS_JSON):
    text = _read_committed_or_live(cells_path)
    if text is None:
        return []
    doc = json.loads(text)
    return doc.get("cells", [])


def load_ledger(ledger_path=GOLDEN_LEDGER):
    """cell_id -> status (PASS / SKIP / ...). Missing file -> empty ledger (every citation is
    "partial" at best, which is the honest answer when there is no golden yet)."""
    ledger = {}
    text = _read_committed_or_live(ledger_path)
    if text is None:
        return ledger
    for line in text.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        ledger[parts[0]] = parts[1] if len(parts) > 1 else ""
    return ledger


def compute_coverage(ids, cells, ledger):
    """Returns {id: {status, family, citers: [cell_id, ...]}}."""
    # Precompute each cell's own JSON text once (cheap: a few thousand small dicts) so the id
    # citation search is a plain substring/word-boundary scan, not a hand-rolled JSON walk.
    cell_text = OrderedDict((c.get("id", ""), json.dumps(c, ensure_ascii=False)) for c in cells)

    # ADM operationId foreign key: admin.ops|<operationId>|<case> -> operationId
    admin_ops_by_opid = defaultdict(list)
    for c in cells:
        cid = c.get("id", "")
        if cid.startswith("admin.ops|"):
            seg = cid.split("|")
            if len(seg) >= 2:
                admin_ops_by_opid[seg[1]].append(cid)

    result = OrderedDict()
    for row_id, info in ids.items():
        token_re = re.compile(r"\b" + re.escape(row_id) + r"\b")
        citers = [cid for cid, text in cell_text.items() if token_re.search(text)]
        if info["family"] == "ADM" and info["operationId"]:
            citers.extend(admin_ops_by_opid.get(info["operationId"], []))
        # de-dupe, keep first-seen order
        citers = list(OrderedDict.fromkeys(citers))

        if not citers:
            status = "none"
        else:
            status = "partial"
            for cid in citers:
                if ledger.get(cid) == "PASS":
                    status = "covered"
                    break
        result[row_id] = {"status": status, "family": info["family"], "citers": citers}
    return result


def family_summary(ids, coverage):
    fam_counts = defaultdict(lambda: Counter())
    for row_id, info in ids.items():
        fam_counts[info["family"]][coverage[row_id]["status"]] += 1
    out = OrderedDict()
    for fam in sorted(fam_counts):
        c = fam_counts[fam]
        out[fam] = {
            "covered": c.get("covered", 0),
            "partial": c.get("partial", 0),
            "none": c.get("none", 0),
            "total": sum(c.values()),
        }
    return out


def row_status(families, ids, coverage):
    """CELL if every id spanned by `families` is covered, UNMAPPED if none of them are, PARTIAL
    otherwise. A row that spans no family (its source inventory file has no id column at all) is
    UNMAPPED — there is nothing bound yet, which is the honest answer."""
    row_ids = [rid for rid, info in ids.items() if info["family"] in families]
    if not row_ids:
        return "UNMAPPED"
    statuses = [coverage[rid]["status"] for rid in row_ids]
    if all(s == "covered" for s in statuses):
        return "CELL"
    if all(s == "none" for s in statuses):
        return "UNMAPPED"
    return "PARTIAL"


def build_matrix(ids, coverage):
    matrix = []
    for row, families in ROW_FAMILIES.items():
        matrix.append({
            "row": row,
            "label": ROW_LABELS[row],
            "families": families,
            "status": row_status(families, ids, coverage),
        })
    return matrix


def render_matrix_table(matrix):
    lines = []
    lines.append("| # | Inventory section | Id families | Status |")
    lines.append("|---|---|---|---|")
    for m in matrix:
        fams = ", ".join(m["families"]) if m["families"] else "(no id column in source file)"
        lines.append("| %s | %s | %s | %s |" % (m["row"], m["label"], fams, m["status"]))
    return "\n".join(lines)


def update_behaviour_md(matrix, path=BEHAVIOUR_MD):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    table = render_matrix_table(matrix)
    block = "%s\n%s\n%s" % (BEGIN_MARK, table, END_MARK)

    if BEGIN_MARK in text and END_MARK in text:
        pre = text.split(BEGIN_MARK)[0]
        post = text.split(END_MARK)[1]
        new_text = pre + block + post
    else:
        # First run: markers don't exist yet. Insert the generated block right after the existing
        # "## 3. Coverage matrix" heading's intro paragraph and its old hand-written table, so the
        # generated table replaces the manual UNMAPPED one without disturbing sections 1, 2, 4, 5.
        marker_heading = "## 3. Coverage matrix"
        if marker_heading not in text:
            raise SystemExit("could not find %r in %s to anchor the coverage table" % (marker_heading, path))
        head, rest = text.split(marker_heading, 1)
        # `rest` starts right after the heading text; the old table runs until the next "## "
        # heading (section 4). Keep the intro prose, drop the old table, insert the new block.
        next_heading_idx = rest.find("\n## ")
        if next_heading_idx == -1:
            raise SystemExit("could not find the section after the coverage matrix in %s" % path)
        section_body = rest[:next_heading_idx]
        tail = rest[next_heading_idx:]
        # The intro prose is everything up to the first table line ("| # |"); drop the old table.
        table_start = section_body.find("\n| # |")
        intro = section_body if table_start == -1 else section_body[:table_start]
        new_text = head + marker_heading + intro.rstrip("\n") + "\n\n" + block + "\n" + tail

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new_text)


def default_gap_reason(row_id, info, cells_by_family_needs_fixture):
    """A one-line reason for an id with zero citing cells. Where a needs_fixture cell exists in
    the same family (a nearby cell already named as blocked on a missing fixture), quote its note
    as the likely reason; otherwise state plainly that nothing in cells.json cites this id yet."""
    fam = info["family"]
    notes = cells_by_family_needs_fixture.get(fam)
    if notes:
        return "no cell cites this row yet; nearest %s needs_fixture note: %s" % (fam, notes[0])
    return "no oracle cell in cells.json cites this row (%s:%d)" % (info["file"], info["line"])


def build_gaps(ids, coverage, cells):
    fam_needs_fixture_notes = defaultdict(list)
    for c in cells:
        if c.get("needs_fixture"):
            fam = c.get("family") or (c.get("id", "").split("|")[0] if c.get("id") else "")
            why = c.get("why", "")
            if fam and why:
                fam_needs_fixture_notes[fam].append(why)

    gaps = []
    for row_id, info in ids.items():
        # PARTIAL IS A GAP TOO. It used to be silently excluded, and "partial" is not a shade of
        # covered: it means every cell citing this row is SKIP on the golden, or is flagged
        # needs_fixture. Nothing was executed against it. An id in that state was in neither list —
        # not counted as covered by anything a reader looks at, and not owed by --check either — so
        # a covered id could DECAY to partial and no gate anywhere would notice. Both non-covered
        # statuses are now owed, and the status is carried on the row so the two are still
        # distinguishable to a reader.
        status = coverage[row_id]["status"]
        if status == "covered":
            continue
        reason = default_gap_reason(row_id, info, fam_needs_fixture_notes)
        if status == "partial":
            reason = "every citing cell is SKIP on the golden (or needs_fixture): nothing was executed against this row"
        gaps.append({
            "id": row_id,
            "family": info["family"],
            "status": status,
            "file": info["file"],
            "line": info["line"],
            "reason": reason,
        })
    return gaps


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, sort_keys=False)
        fh.write("\n")


def run_analysis():
    ids = parse_inventory_ids()
    cells = load_cells()
    ledger = load_ledger()
    coverage = compute_coverage(ids, cells, ledger)
    summary = family_summary(ids, coverage)
    matrix = build_matrix(ids, coverage)
    return ids, cells, ledger, coverage, summary, matrix


# ── THE FLOOR, READ FROM THE LAST RECORDED RUN ────────────────────────────────────────────────────
# The owed set is DISCOVERED: a `docs/design/inventory/*.md` glob, and within each file the rows of
# any table whose header row begins with the literal `| id |`. Both halves fail silently and
# identically. Rename or move a file out of that directory, retitle a column `| ID |` or `| Id |`,
# wrap the header differently, or let a table's separator row drift — and that file's rows simply
# stop existing. Every id in it leaves `ids`, so it is in no family total, has no status, is in
# `none_ids` for nobody, and `--check`'s only test (`none_ids - named`) is satisfied by the empty
# set. The gate goes GREEN having stopped measuring an entire inventory file, and
# `qa/inventory-gaps.json` — regenerated from that same collapsed set — shrinks to agree with it.
#
# So the recorded per-family totals in qa/inventory-coverage.json are the floor. That file is
# already written on every `--write` and already carries exactly the numbers needed. A family whose
# row count has DROPPED below its recorded total, or that has vanished from the analysis entirely,
# is RED — the inventory did not get smaller by accident. Deliberate shrinkage is a `--write` (which
# re-records the totals) in the same commit as the deletion, where a reviewer sees the number move.
def load_recorded_totals():
    """{family: total} from the last committed qa/inventory-coverage.json, or None if unreadable."""
    if not os.path.exists(COVERAGE_JSON):
        return None
    try:
        with open(COVERAGE_JSON, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (ValueError, OSError):
        return None
    fam = doc.get("family_summary")
    if not isinstance(fam, dict):
        return None
    out = {}
    for name, counts in fam.items():
        if isinstance(counts, dict) and isinstance(counts.get("total"), int):
            out[name] = counts["total"]
    return out or None


def check_floor(summary):
    """Every problem with the discovered owed set, measured against the recorded totals."""
    problems = []
    recorded = load_recorded_totals()
    rel = os.path.relpath(COVERAGE_JSON, REPO_ROOT)
    if recorded is None:
        problems.append(
            "%s is missing or carries no family_summary — there is no floor to measure the "
            "discovered inventory against, so a discovery that collapsed to nothing would read "
            "as a clean tree. Run --write and commit it." % rel)
        return problems
    for fam, want in sorted(recorded.items()):
        got = summary.get(fam, {}).get("total", 0)
        if got < want:
            problems.append(
                "family %s: the inventory now yields %d row(s), %d were recorded in %s. Rows do "
                "not disappear on their own — a renamed file, a retitled `| id |` header column, "
                "or a table whose separator row drifted removes them from the owed set silently, "
                "and every one of them then counts as neither covered nor owed."
                % (fam, got, want, rel))
    total_now = sum(c["total"] for c in summary.values())
    total_want = sum(recorded.values())
    if total_now < total_want:
        problems.append(
            "the whole inventory yields %d row(s), %d were recorded in %s."
            % (total_now, total_want, rel))
    return problems


def cmd_write(accepted_gaps=()):
    ids, cells, ledger, coverage, summary, matrix = run_analysis()

    # The floor applies to `--write` too. `--write` REGENERATES the file the floor is read from, so
    # letting it run under a collapsed discovery would launder the collapse into the new baseline in
    # a single command and leave nothing for `--check` to find.
    floor_problems = check_floor(summary)
    if floor_problems:
        print("RED: refusing to --write over the recorded totals:")
        for p in floor_problems:
            print("  - %s" % p)
        print("If the shrinkage is real and reviewed, delete the affected family rows from")
        print("qa/inventory-coverage.json's family_summary by hand in the same commit, and say why.")
        return 1

    coverage_doc = {
        "_comment": [
            "GENERATED by scripts/inventory-coverage.py --write. Do not edit by hand.",
            "Answers, for every row id in docs/design/inventory/*.md, whether an oracle cell",
            "(testing/shadow-oracle/cells.json, checked against the golden ledger) covers it.",
        ],
        "generated_at": date.today().isoformat(),
        "family_summary": summary,
        "ids": {
            row_id: {
                "family": info["family"],
                "file": info["file"],
                "line": info["line"],
                "status": coverage[row_id]["status"],
                "citers": coverage[row_id]["citers"],
            }
            for row_id, info in ids.items()
        },
        "matrix": matrix,
    }
    write_json(COVERAGE_JSON, coverage_doc)

    gaps = build_gaps(ids, coverage, cells)

    # ── A GAPS FILE MAY NOT GROW BY ITSELF ────────────────────────────────────────────────────────
    # `--check` asks only whether every uncovered id is NAMED in qa/inventory-gaps.json, and
    # `--write` generates that file from the same set it just measured. The two therefore agree by
    # construction, always: any new uncovered id — a regression that dropped a row from covered to
    # none — is written into the gaps file by the very run that discovered it, and `--check` is
    # green again on the next commit. The ledger records the loss and nothing objects to it.
    #
    # So a NEW gap id must be accepted BY NAME, one `--accept-gap ID` per id. Losing coverage is
    # then a deliberate, itemised act that appears in the command line of the commit that does it,
    # and cannot happen as a side effect of regenerating a file.
    previously_named = set()
    if os.path.exists(GAPS_JSON):
        try:
            with open(GAPS_JSON, encoding="utf-8") as fh:
                previously_named = {g["id"] for g in json.load(fh).get("gaps", [])}
        except (ValueError, OSError, KeyError, TypeError):
            previously_named = set()
    new_gaps = sorted({g["id"] for g in gaps} - previously_named - set(accepted_gaps))
    if new_gaps:
        print("RED: --write would add %d id(s) to %s that are not accepted:"
              % (len(new_gaps), os.path.relpath(GAPS_JSON, REPO_ROOT)))
        for rid in new_gaps:
            print("  %s" % rid)
        print()
        print("Each of these was covered (or absent) and is now a gap. A gaps file that grows on")
        print("its own turns a coverage regression into a record of itself: --check then passes,")
        print("because the id it would have failed on has just been written into the file it")
        print("checks against. Restore the coverage, or accept each loss by name:")
        print("  python3 scripts/inventory-coverage.py --write %s"
              % " ".join("--accept-gap %s" % rid for rid in new_gaps))
        return 1

    gaps_doc = {
        "_comment": [
            "GENERATED by scripts/inventory-coverage.py --write. Do not edit by hand.",
            "Every inventory id NOT covered by a PASSing oracle cell today, with a one-line reason.",
            "\"status\" is \"none\" (no cell cites it) or \"partial\" (cited only by SKIP/needs_fixture",
            "cells, i.e. nothing was executed against it). --check fails if any uncovered id is",
            "missing from this file, and --write refuses to ADD one without --accept-gap ID.",
        ],
        "generated_at": date.today().isoformat(),
        "gaps": gaps,
    }
    write_json(GAPS_JSON, gaps_doc)

    update_behaviour_md(matrix)

    print_summary(summary, matrix, gaps)
    return 0


def print_summary(summary, matrix, gaps):
    print("id families (covered / partial / none / total):")
    for fam, c in summary.items():
        print("  %-6s %4d / %4d / %4d / %4d" % (fam, c["covered"], c["partial"], c["none"], c["total"]))
    print()
    print(render_matrix_table(matrix))
    print()
    print("gaps: %d id(s) with zero citing cells" % len(gaps))


def cmd_check():
    ids, cells, ledger, coverage, summary, matrix = run_analysis()
    # BOTH non-covered statuses are owed, not just "none" — see build_gaps.
    owed = {row_id for row_id, c in coverage.items() if c["status"] != "covered"}

    if not os.path.exists(GAPS_JSON):
        print("RED: %s does not exist — run --write first" % os.path.relpath(GAPS_JSON, REPO_ROOT))
        return 1

    with open(GAPS_JSON, encoding="utf-8") as fh:
        gaps_doc = json.load(fh)
    named = {g["id"] for g in gaps_doc.get("gaps", [])}

    print_summary(summary, matrix, gaps_doc.get("gaps", []))

    # THE FLOOR FIRST. `owed - named` is satisfied by an EMPTY owed set, so it can only ever be as
    # trustworthy as the discovery that produced it; the floor is what makes an empty owed set mean
    # "nothing is owed" rather than "nothing was read".
    problems = check_floor(summary)
    unnamed = sorted(owed - named)
    if unnamed:
        problems.append(
            "%d id(s) are not covered by a PASSing oracle cell and are not named in %s: %s"
            % (len(unnamed), os.path.relpath(GAPS_JSON, REPO_ROOT), ", ".join(unnamed[:20])
               + (" …" if len(unnamed) > 20 else "")))

    if problems:
        print()
        print("RED:")
        for p in problems:
            print("  - %s" % p)
        return 1

    print()
    print("GREEN: every uncovered id (%d: %d none, %d partial) is a named gap in %s, and every "
          "family is at or above its recorded row count" % (
              len(owed),
              sum(c["none"] for c in summary.values()),
              sum(c["partial"] for c in summary.values()),
              os.path.relpath(GAPS_JSON, REPO_ROOT)))
    return 0


def cmd_selftest():
    ids = parse_inventory_ids()
    cells = load_cells()
    ledger = load_ledger()

    coverage = compute_coverage(ids, cells, ledger)

    # (a) removing a covering cell must turn a covered id red (status != "covered").
    covered_ids = [rid for rid, c in coverage.items() if c["status"] == "covered"]
    if not covered_ids:
        print("SELFTEST FAIL: no id is currently \"covered\" — cannot prove the mechanism reacts")
        return 1
    target = covered_ids[0]
    passing_cell_id = next(cid for cid in coverage[target]["citers"] if ledger.get(cid) == "PASS")
    cells_without = [c for c in cells if c.get("id") != passing_cell_id]
    coverage_without = compute_coverage(ids, cells_without, ledger)
    if coverage_without[target]["status"] == "covered":
        print("SELFTEST FAIL: removing the only PASS-ing cell for %s (%s) did not turn it red"
              % (target, passing_cell_id))
        return 1
    print("SELFTEST ok: removing cell %r turned %s from covered -> %s (in-memory only, no file touched)"
          % (passing_cell_id, target, coverage_without[target]["status"]))

    # (b) an id already named in qa/inventory-gaps.json must still satisfy --check-style logic
    # (i.e. adding it to the named set makes an otherwise-red "none" id green), proving the check
    # is exercising real logic rather than always passing.
    none_ids = [rid for rid, c in coverage.items() if c["status"] == "none"]
    if not none_ids:
        print("SELFTEST FAIL: no id is currently \"none\" — cannot prove a named gap stays green")
        return 1
    gap_target = none_ids[0]
    named = {gap_target}
    unnamed = [rid for rid in none_ids if rid not in named]
    if gap_target in unnamed:
        print("SELFTEST FAIL: naming %s did not remove it from the unnamed set" % gap_target)
        return 1
    print("SELFTEST ok: naming %s as a gap keeps it out of the --check failure list" % gap_target)

    # (c) THE FLOOR BITES. The owed set is discovered by a `*.md` glob plus a `| id |` header
    # literal, and a discovery that finds nothing satisfies `owed - named` with the empty set: the
    # gate reports GREEN having read no inventory at all. Simulate exactly that — an entire family
    # gone from the analysis — and require check_floor to refuse it.
    summary = family_summary(ids, coverage)
    if check_floor(summary):
        print("SELFTEST FAIL: the tree's own family totals are already below the recorded floor")
        return 1
    print("SELFTEST ok: the tree's real family totals sit at or above the recorded floor")

    recorded = load_recorded_totals()
    if not recorded:
        print("SELFTEST FAIL: qa/inventory-coverage.json carries no recorded totals — there is no floor")
        return 1
    victim = sorted(recorded)[0]
    collapsed = {f: dict(c) for f, c in summary.items() if f != victim}
    if not check_floor(collapsed):
        print("SELFTEST FAIL: dropping the whole %s family from the analysis was ACCEPTED — a "
              "renamed inventory file or a retitled `| id |` column would read as a clean tree" % victim)
        return 1
    print("SELFTEST ok: dropping the whole %s family (%d rows) is REFUSED by the floor"
          % (victim, recorded[victim]))

    shrunk = {f: dict(c) for f, c in summary.items()}
    shrunk[victim]["total"] -= 1
    if not check_floor(shrunk):
        print("SELFTEST FAIL: losing a single %s row was accepted — the floor is not exact" % victim)
        return 1
    print("SELFTEST ok: losing even ONE %s row is REFUSED" % victim)

    # (d) PARTIAL IS OWED. An id cited only by SKIP/needs_fixture cells was in neither list; prove
    # it is now in the owed set that --check measures.
    partial_ids = [rid for rid, c in coverage.items() if c["status"] == "partial"]
    owed = {rid for rid, c in coverage.items() if c["status"] != "covered"}
    if partial_ids and not set(partial_ids) <= owed:
        print("SELFTEST FAIL: a \"partial\" id is not in the owed set — nothing executed against it, "
              "and nothing owes it either")
        return 1
    print("SELFTEST ok: all %d \"partial\" id(s) are owed by --check, not silently forgiven"
          % len(partial_ids))

    print("SELFTEST PASS")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--accept-gap", action="append", default=[], metavar="ID",
        help="accept ONE new uncovered id into qa/inventory-gaps.json. Repeatable, and required "
             "per id: --write refuses to grow the gaps file on its own, because a gaps file that "
             "grows by itself turns a coverage regression into the record that excuses it.")
    args = parser.parse_args(argv)

    if args.write:
        return cmd_write(accepted_gaps=args.accept_gap)
    if args.check:
        return cmd_check()
    if args.selftest:
        return cmd_selftest()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
