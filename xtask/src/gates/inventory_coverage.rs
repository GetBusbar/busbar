//! `cargo xtask gate inventory-coverage` — the successor to `scripts/inventory-coverage.py`,
//! claim for claim.
//!
//! ARCHITECTURE.md Appendix B claims that every row of every inventory file under
//! `docs/design/inventory/` is a parity binding AND an oracle cell. Nothing checked that claim
//! before the Python this gate replaces. It:
//!
//! 1. reads every row id out of `docs/design/inventory/*.md` — only rows in a table whose header
//!    row is literally `| id | ...` count;
//! 2. reads `testing/shadow-oracle/cells.json` (read-only — that tree belongs to another owner)
//!    and asks, for each inventory id, whether any oracle cell cites it: the id text appears
//!    word-bounded anywhere in the cell's own JSON, or — for the `ADM` family specifically — an
//!    `admin.ops` cell's second id-segment is the exact `operationId` the ADM row names;
//! 3. reads the golden ledger (read-only) for PASS/SKIP per citing cell, and classifies every id as
//!    `covered` (a citer is PASS), `partial` (cited, but nothing executed against it) or `none`;
//! 4. rewrites the 40-row coverage matrix in `docs/design/1.5.5-BEHAVIOUR.md` between
//!    `<!-- coverage:begin -->` / `<!-- coverage:end -->`;
//! 5. writes `qa/inventory-coverage.json` (full per-id detail) and `qa/inventory-gaps.json` (every
//!    non-`covered` id, one line each).
//!
//! ## The floor
//!
//! The owed set is DISCOVERED — a glob plus a `| id |` header literal — and a discovery that
//! collapsed to nothing satisfies every rule about it vacuously. The recorded per-family totals in
//! the committed `qa/inventory-coverage.json` are therefore a FLOOR: a family whose row count
//! dropped below its recorded total, or vanished from the analysis entirely, is refused — see
//! [`check_floor`].
//!
//! ## A gaps file may not grow by itself
//!
//! `--check` asks only whether every non-covered id is named in `qa/inventory-gaps.json`, and
//! `--write` regenerates that file from the very analysis `--check` reads. Left alone the two
//! agree by construction always, so a regression that drops an id from `covered` would be written
//! into the gaps file by the very run that discovered it. This gate does not implement the
//! upstream `--accept-gap ID` escape hatch (see the module doc in `xtask/src/gates/mod.rs` — no new
//! CLI surface was added for it this round): `--write` here refuses outright when the analysis
//! would add any id to the gaps file, exactly as `inventory-coverage.py --write` with no
//! `--accept-gap` argument does. Accepting a genuine, reviewed loss of coverage still requires
//! hand-editing `qa/inventory-gaps.json` in the same commit as the regression, which is the
//! existing script's own fallback path when no id is passed.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::json_lite::{self, Json, Obj};
use crate::ledger::{Row, Verdict};

pub const ROW_DUPLICATE_ID: &str = "inventory-coverage:duplicate-id";
pub const ROW_FLOOR: &str = "inventory-coverage:floor";
pub const ROW_GAPS_NAMED: &str = "inventory-coverage:gaps-named";
pub const ROW_COVERAGE_ARTIFACT: &str = "inventory-coverage:coverage-artifact";
pub const ROW_GAPS_ARTIFACT: &str = "inventory-coverage:gaps-artifact";
pub const ROW_BEHAVIOUR_TABLE: &str = "inventory-coverage:behaviour-table";

const INVENTORY_DIR: &str = "docs/design/inventory";
const BEHAVIOUR_MD: &str = "docs/design/1.5.5-BEHAVIOUR.md";
const CELLS_JSON: &str = "testing/shadow-oracle/cells.json";
const GOLDEN_LEDGER: &str = "testing/shadow-oracle/golden/1.5.5/ledger.tsv";
const COVERAGE_JSON: &str = "qa/inventory-coverage.json";
const GAPS_JSON: &str = "qa/inventory-gaps.json";

const BEGIN_MARK: &str = "<!-- coverage:begin -->";
const END_MARK: &str = "<!-- coverage:end -->";

const INVENTORY_FLOOR: usize = 8;

/// Which id families each 40-row matrix section can be bound to. A row mapped to a family that
/// turns out to have zero ids (its source file has no `| id |` column) is honestly UNMAPPED.
const ROW_FAMILIES: &[(&str, &[&str], &str)] = &[
    ("C1", &["CONF"], "config keys (205) with defaults"),
    ("C2", &["BOOT"], "boot refusals + warnings (228)"),
    (
        "C3",
        &["BOOT", "CONF"],
        "reserved names, precedence, migration, reload",
    ),
    ("C4", &["SEC"], "secret refs"),
    ("R1", &["LST"], "listeners and router separation"),
    ("R2", &["RT"], "data-plane routes (37) and ladder"),
    ("R3", &["ADM"], "admin operations (66)"),
    (
        "R4",
        &["RT"],
        "error envelopes, KIND_*, timeouts, Retry-After",
    ),
    ("R5", &["ADM"], "admin audit chain"),
    ("G1", &[], "bucket topology and windows"),
    ("G2", &[], "admission order and charges"),
    ("G3", &[], "refunds"),
    ("G4", &[], "per-lane controls"),
    ("G5", &[], "cost model"),
    ("G6", &[], "/usage arithmetic"),
    ("G7", &[], "write-behind and store failure"),
    ("P1", &[], "request lifecycle, hooks, ranking, failover"),
    ("P2", &[], "status and error mapping (29 rows)"),
    ("P3", &[], "egress auth schemes (9)"),
    ("P4", &[], "network guard"),
    ("D1", &[], "dialect catalogue and 36 pairs"),
    ("D2", &[], "streaming and usage extraction"),
    ("D3", &[], "error mapping per dialect"),
    ("D4", &[], "headers"),
    ("A1", &[], "credential forms and precedence"),
    ("A2", &[], "key lifecycle and idempotency"),
    ("A3", &[], "token exchange and provisioning"),
    ("A4", &[], "auth plugin ABI and modules"),
    ("A5", &[], "admin auth and mTLS"),
    ("A6", &[], "secrets and TLS"),
    ("S1", &[], "ABI versions and loader"),
    ("S2", &[], "store contract and memory store"),
    ("S3", &[], "export"),
    ("S4", &[], "reload/rollback"),
    ("O1", &[], "CLI and env vars"),
    ("O2", &[], "lifecycle, health, signals, shutdown"),
    ("O3", &[], "metrics (25)"),
    ("O4", &[], "logs, spans, OTLP"),
    ("O5", &[], "/stats and operational signals"),
    ("O6", &[], "documented behaviour cross-check"),
];

// ── THE LOADER ───────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct InventoryId {
    id: String,
    family: String,
    file: String,
    line: usize,
    operation_id: String,
}

struct Refusal {
    row: &'static str,
    why: String,
}

fn is_id_row(s: &str) -> bool {
    let mut chars = s.chars();
    let mut saw_letter = false;
    let mut saw_dash = false;
    for c in &mut chars {
        if c == '-' {
            saw_dash = true;
            break;
        }
        if !c.is_ascii_alphabetic() {
            return false;
        }
        saw_letter = true;
    }
    if !saw_dash || !saw_letter {
        return false;
    }
    let rest: String = chars.collect();
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Parse every `| id | ... |` table in `docs/design/inventory/*.md`, in sorted-path, in-file order
/// — the same order `glob.glob` (sorted) and a top-to-bottom scan give the Python.
fn parse_inventory_ids(cx: &Ctx) -> Result<Vec<InventoryId>, Refusal> {
    let files = cx
        .walk(
            &WalkSpec::new([INVENTORY_DIR])
                .ext("md")
                .min_files(INVENTORY_FLOOR),
        )
        .map_err(|e| Refusal {
            row: ROW_DUPLICATE_ID,
            why: format!("the inventory directory could not be walked: {e}"),
        })?;

    let mut ids: Vec<InventoryId> = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        let lines: Vec<&str> = f.text.lines().collect();
        let mut i = 0usize;
        while i < lines.len() {
            if lines[i].trim().to_lowercase().starts_with("| id |") {
                i += 2; // header + separator
                while i < lines.len() && lines[i].starts_with('|') {
                    let raw = lines[i].trim().trim_matches('|');
                    let cells: Vec<String> = raw.split('|').map(|c| c.trim().to_string()).collect();
                    let row_id = cells.first().cloned().unwrap_or_default();
                    let row_id = row_id.trim_matches(|c| c == '`' || c == ' ').to_string();
                    if is_id_row(&row_id) {
                        let family = row_id.split('-').next().unwrap_or_default().to_string();
                        let op_id = cells
                            .get(1)
                            .map(|c| c.trim_matches(|ch| ch == '`' || ch == ' ').to_string())
                            .unwrap_or_default();
                        if let Some(prior) = ids.iter().find(|x| x.id == row_id) {
                            return Err(Refusal {
                                row: ROW_DUPLICATE_ID,
                                why: format!(
                                    "duplicate inventory id {row_id} in {} and {rel}",
                                    prior.file
                                ),
                            });
                        }
                        ids.push(InventoryId {
                            id: row_id,
                            family,
                            file: rel.clone(),
                            line: i + 1,
                            operation_id: op_id,
                        });
                    }
                    i += 1;
                }
                continue;
            }
            i += 1;
        }
    }
    Ok(ids)
}

/// `testing/shadow-oracle/**` belongs to another owner and may be mid-write in the working copy.
/// Prefer the last-committed (HEAD) version, exactly as the Python's `_read_committed_or_live`
/// does — UNLESS the path is under an active overlay plant, which must win so a selftest mutation
/// is actually seen.
fn read_committed_or_live(cx: &Ctx, rel: &str) -> Option<String> {
    if let Some(ov) = cx.overlay() {
        if ov.paths().any(|p| p.to_string_lossy() == rel) {
            return cx.read(rel).ok();
        }
    }
    if let Ok(text) = cx.git(&["show", &format!("HEAD:{rel}")]) {
        return Some(text);
    }
    cx.read(rel).ok()
}

/// THE ORACLE'S CELLS, OR A REFUSAL -- never an empty list standing in for a file that is absent.
///
/// An absent, unparseable or `cells`-less `testing/shadow-oracle/cells.json` used to read here as
/// "zero cells", and zero cells is not a neutral answer: it is the answer under which EVERY
/// inventory id is uncovered, which is indistinguishable at a glance from a real collapse and is
/// the exact input a `--write` would otherwise fold into the artefacts. This gate is the
/// scoreboard for a parity claim it cannot compute without that file, so not having it is a
/// REFUSAL -- the same posture `parse_inventory_ids` already takes for the inventory tables.
fn read_cells(cx: &Ctx) -> Result<Vec<Json>, Refusal> {
    let refuse = |why: String| Refusal {
        row: ROW_GAPS_NAMED,
        why,
    };
    let Some(text) = read_committed_or_live(cx, CELLS_JSON) else {
        return Err(refuse(format!(
            "{CELLS_JSON} is not in this tree (neither committed at HEAD nor on disk) -- the \
             coverage of every inventory id derives from it, so there is nothing to derive"
        )));
    };
    let Ok(doc) = json_lite::parse(&text) else {
        return Err(refuse(format!("{CELLS_JSON} is not parseable JSON")));
    };
    match doc.get("cells").as_array() {
        Some(cells) => Ok(cells.to_vec()),
        None => Err(refuse(format!(
            "{CELLS_JSON} carries no `cells` array -- it is not the oracle cell set this gate reads"
        ))),
    }
}

/// The fixture-side spelling, for selftest cases that BUILD an overlay out of the real cells: they
/// are planting a tree, not judging one, and a tree they cannot read is a case they skip.
fn load_cells(cx: &Ctx) -> Vec<Json> {
    read_cells(cx).unwrap_or_default()
}

fn load_ledger(cx: &Ctx) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(text) = read_committed_or_live(cx, GOLDEN_LEDGER) else {
        return out;
    };
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let id = parts.next().unwrap_or_default().to_string();
        let status = parts.next().unwrap_or_default().to_string();
        out.insert(id, status);
    }
    out
}

// ── THE DERIVATION ───────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Covered,
    Partial,
    None,
}

impl Status {
    fn as_str(&self) -> &'static str {
        match self {
            Status::Covered => "covered",
            Status::Partial => "partial",
            Status::None => "none",
        }
    }
}

struct Coverage {
    status: Status,
    citers: Vec<String>,
}

/// `re.search(r'\b' + re.escape(needle) + r'\b', haystack)`, word-bounded on ASCII
/// alphanumeric-or-underscore exactly as `is_id_row` restricts an inventory id to. Every inventory
/// id is ASCII by construction, so a byte-level substring search (`str::find`, memchr-backed) finds
/// every candidate position without ever re-materializing `haystack` into a `Vec<char>` — the
/// earlier char-by-char scan re-collected the WHOLE cell text into a fresh `Vec<char>` on every
/// single (id, cell) pair, making `compute_coverage` (552 ids x 2318 cells today) quadratic in the
/// worst way for a gate whose `Tier` is `Fast`.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let hb = haystack.as_bytes();
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut from = 0usize;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word(hb[start - 1]);
        let after_ok = end == hb.len() || !is_word(hb[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn compute_coverage(
    ids: &[InventoryId],
    cells: &[Json],
    ledger: &BTreeMap<String, String>,
) -> BTreeMap<String, Coverage> {
    let cell_text: Vec<(String, String)> = cells
        .iter()
        .map(|c| {
            let id = c.get("id").as_str().unwrap_or_default().to_string();
            (id, json_lite::dump_python(c))
        })
        .collect();

    let mut admin_ops_by_opid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in cells {
        let cid = c.get("id").as_str().unwrap_or_default();
        if let Some(rest) = cid.strip_prefix("admin.ops|") {
            let opid = rest.split('|').next().unwrap_or_default();
            if !opid.is_empty() {
                admin_ops_by_opid
                    .entry(opid.to_string())
                    .or_default()
                    .push(cid.to_string());
            }
        }
    }

    let mut result = BTreeMap::new();
    for info in ids {
        let mut citers: Vec<String> = cell_text
            .iter()
            .filter(|(_, text)| contains_word(text, &info.id))
            .map(|(cid, _)| cid.clone())
            .collect();
        if info.family == "ADM" && !info.operation_id.is_empty() {
            if let Some(extra) = admin_ops_by_opid.get(&info.operation_id) {
                for e in extra {
                    if !citers.contains(e) {
                        citers.push(e.clone());
                    }
                }
            }
        }
        let status = if citers.is_empty() {
            Status::None
        } else if citers
            .iter()
            .any(|cid| ledger.get(cid).map(String::as_str) == Some("PASS"))
        {
            Status::Covered
        } else {
            Status::Partial
        };
        result.insert(info.id.clone(), Coverage { status, citers });
    }
    result
}

#[derive(Debug, Clone, Default)]
struct FamCounts {
    covered: usize,
    partial: usize,
    none: usize,
}

impl FamCounts {
    fn total(&self) -> usize {
        self.covered + self.partial + self.none
    }
}

fn family_summary(
    ids: &[InventoryId],
    coverage: &BTreeMap<String, Coverage>,
) -> BTreeMap<String, FamCounts> {
    let mut out: BTreeMap<String, FamCounts> = BTreeMap::new();
    for info in ids {
        let c = out.entry(info.family.clone()).or_default();
        match coverage[&info.id].status {
            Status::Covered => c.covered += 1,
            Status::Partial => c.partial += 1,
            Status::None => c.none += 1,
        }
    }
    out
}

fn row_status(
    families: &[&str],
    ids: &[InventoryId],
    coverage: &BTreeMap<String, Coverage>,
) -> &'static str {
    let row_ids: Vec<&InventoryId> = ids
        .iter()
        .filter(|i| families.contains(&i.family.as_str()))
        .collect();
    if row_ids.is_empty() {
        return "UNMAPPED";
    }
    let statuses: Vec<&Status> = row_ids.iter().map(|i| &coverage[&i.id].status).collect();
    if statuses.iter().all(|s| **s == Status::Covered) {
        "CELL"
    } else if statuses.iter().all(|s| **s == Status::None) {
        "UNMAPPED"
    } else {
        "PARTIAL"
    }
}

struct MatrixRow {
    row: &'static str,
    label: &'static str,
    families: &'static [&'static str],
    status: &'static str,
}

fn build_matrix(ids: &[InventoryId], coverage: &BTreeMap<String, Coverage>) -> Vec<MatrixRow> {
    ROW_FAMILIES
        .iter()
        .map(|(row, families, label)| MatrixRow {
            row,
            label,
            families,
            status: row_status(families, ids, coverage),
        })
        .collect()
}

fn render_matrix_table(matrix: &[MatrixRow]) -> String {
    let mut lines = vec![
        "| # | Inventory section | Id families | Status |".to_string(),
        "|---|---|---|---|".to_string(),
    ];
    for m in matrix {
        let fams = if m.families.is_empty() {
            "(no id column in source file)".to_string()
        } else {
            m.families.join(", ")
        };
        lines.push(format!(
            "| {} | {} | {} | {} |",
            m.row, m.label, fams, m.status
        ));
    }
    lines.join("\n")
}

/// The rewritten `docs/design/1.5.5-BEHAVIOUR.md`, or `None` if the markers are gone from the tree
/// (this gate — like the Python — requires them to already be present; the first-run,
/// heading-anchored insertion the Python also supported is not reproduced here because the markers
/// have been in the committed file since before this conversion).
fn render_behaviour_md(current: &str, matrix: &[MatrixRow]) -> Option<String> {
    let table = render_matrix_table(matrix);
    let block = format!("{BEGIN_MARK}\n{table}\n{END_MARK}");
    let pre = current.split(BEGIN_MARK).next()?;
    let post = current.split_once(END_MARK)?.1;
    Some(format!("{pre}{block}{post}"))
}

// ── THE FLOOR ────────────────────────────────────────────────────────────────────────────────────

fn load_recorded_totals(cx: &Ctx) -> Option<BTreeMap<String, usize>> {
    let text = cx.read(COVERAGE_JSON).ok()?;
    let doc = json_lite::parse(&text).ok()?;
    let fam = doc.get("family_summary").as_object()?;
    let mut out = BTreeMap::new();
    for (name, counts) in fam.iter() {
        if let Some(total) = counts.get("total").as_i64() {
            out.insert(name.to_string(), total.max(0) as usize);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Every problem with the discovered owed set, measured against the recorded totals. See the
/// module doc: the discovered set is a glob plus a header literal, and a discovery that collapsed
/// to nothing satisfies every later rule vacuously, so this is the check that catches THAT.
fn check_floor(cx: &Ctx, summary: &BTreeMap<String, FamCounts>) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(recorded) = load_recorded_totals(cx) else {
        problems.push(format!(
            "{COVERAGE_JSON} is missing or carries no family_summary — there is no floor to \
             measure the discovered inventory against, so a discovery that collapsed to nothing \
             would read as a clean tree. Run --write and commit it."
        ));
        return problems;
    };
    for (fam, want) in &recorded {
        let got = summary.get(fam).map(FamCounts::total).unwrap_or(0);
        if got < *want {
            problems.push(format!(
                "family {fam}: the inventory now yields {got} row(s), {want} were recorded in \
                 {COVERAGE_JSON}. Rows do not disappear on their own — a renamed file, a retitled \
                 `| id |` header column, or a table whose separator row drifted removes them from \
                 the owed set silently, and every one of them then counts as neither covered nor \
                 owed."
            ));
        }
    }
    let total_now: usize = summary.values().map(FamCounts::total).sum();
    let total_want: usize = recorded.values().sum();
    if total_now < total_want {
        problems.push(format!(
            "the whole inventory yields {total_now} row(s), {total_want} were recorded in \
             {COVERAGE_JSON}."
        ));
    }
    problems
}

// ── GAPS ─────────────────────────────────────────────────────────────────────────────────────────

struct Gap {
    id: String,
    family: String,
    status: Status,
    file: String,
    line: usize,
    reason: String,
}

fn default_gap_reason(info: &InventoryId) -> String {
    format!(
        "no oracle cell in cells.json cites this row ({}:{})",
        info.file, info.line
    )
}

fn build_gaps(ids: &[InventoryId], coverage: &BTreeMap<String, Coverage>) -> Vec<Gap> {
    let mut gaps = Vec::new();
    for info in ids {
        let status = &coverage[&info.id].status;
        if *status == Status::Covered {
            continue;
        }
        let reason = if *status == Status::Partial {
            "every citing cell is SKIP on the golden (or needs_fixture): nothing was executed \
             against this row"
                .to_string()
        } else {
            default_gap_reason(info)
        };
        gaps.push(Gap {
            id: info.id.clone(),
            family: info.family.clone(),
            status: status.clone(),
            file: info.file.clone(),
            line: info.line,
            reason,
        });
    }
    gaps
}

fn named_gap_ids(cx: &Ctx) -> Option<Vec<String>> {
    let text = cx.read(GAPS_JSON).ok()?;
    let doc = json_lite::parse(&text).ok()?;
    let arr = doc.get("gaps").as_array()?;
    Some(
        arr.iter()
            .map(|g| g.get("id").as_str().unwrap_or_default().to_string())
            .collect(),
    )
}

// ── RENDER: THE TWO GENERATED ARTEFACTS, PYTHON'S `json.dump(..., indent=2, ensure_ascii=False)` ──

fn render_coverage_json(
    generated_at: &str,
    ids: &[InventoryId],
    coverage: &BTreeMap<String, Coverage>,
    summary: &BTreeMap<String, FamCounts>,
    matrix: &[MatrixRow],
) -> String {
    let mut root = Obj::new();
    // THE COMMENT NAMES THE GENERATOR OF RECORD. It moves to `cargo xtask gate
    // inventory-coverage` in the SAME commit that retires `scripts/inventory-coverage.py` — never
    // before, where the byte would drift out from under a still-authoritative Python and destroy
    // the parity signal this file exists to prove. See `xtask/src/gates/field_inventory.rs`'s
    // module doc for the same rule stated once.
    root.insert(
        "_comment",
        Json::Array(vec![
            Json::Str(
                "GENERATED by scripts/inventory-coverage.py --write. Do not edit by hand.".into(),
            ),
            Json::Str(
                "Answers, for every row id in docs/design/inventory/*.md, whether an oracle cell"
                    .into(),
            ),
            // Spelled through the constant so `segregation:oracle-data-allow` sees the allowlisted
            // path, not `cells.json,` with the comma glued on.
            Json::Str(format!(
                "({CELLS_JSON}, checked against the golden ledger) covers it."
            )),
        ]),
    );
    root.insert("generated_at", Json::Str(generated_at.to_string()));

    let mut fam_obj = Obj::new();
    for (fam, c) in summary {
        let mut o = Obj::new();
        o.insert("covered", Json::Int(c.covered as i64));
        o.insert("partial", Json::Int(c.partial as i64));
        o.insert("none", Json::Int(c.none as i64));
        o.insert("total", Json::Int(c.total() as i64));
        fam_obj.insert(fam.clone(), Json::Object(o));
    }
    root.insert("family_summary", Json::Object(fam_obj));

    let mut ids_obj = Obj::new();
    for info in ids {
        let cov = &coverage[&info.id];
        let mut o = Obj::new();
        o.insert("family", Json::Str(info.family.clone()));
        o.insert("file", Json::Str(info.file.clone()));
        o.insert("line", Json::Int(info.line as i64));
        o.insert("status", Json::Str(cov.status.as_str().to_string()));
        o.insert(
            "citers",
            Json::Array(cov.citers.iter().map(|c| Json::Str(c.clone())).collect()),
        );
        ids_obj.insert(info.id.clone(), Json::Object(o));
    }
    root.insert("ids", Json::Object(ids_obj));

    let mut matrix_arr = Vec::new();
    for m in matrix {
        let mut o = Obj::new();
        o.insert("row", Json::Str(m.row.to_string()));
        o.insert("label", Json::Str(m.label.to_string()));
        o.insert(
            "families",
            Json::Array(
                m.families
                    .iter()
                    .map(|f| Json::Str((*f).to_string()))
                    .collect(),
            ),
        );
        o.insert("status", Json::Str(m.status.to_string()));
        matrix_arr.push(Json::Object(o));
    }
    root.insert("matrix", Json::Array(matrix_arr));

    format!(
        "{}\n",
        json_lite::dump_python_indent(&Json::Object(root), 2)
    )
}

fn render_gaps_json(generated_at: &str, gaps: &[Gap]) -> String {
    let mut root = Obj::new();
    root.insert(
        "_comment",
        Json::Array(vec![
            Json::Str(
                "GENERATED by scripts/inventory-coverage.py --write. Do not edit by hand.".into(),
            ),
            Json::Str(
                "Every inventory id NOT covered by a PASSing oracle cell today, with a one-line \
                 reason."
                    .into(),
            ),
            Json::Str(
                "\"status\" is \"none\" (no cell cites it) or \"partial\" (cited only by \
                 SKIP/needs_fixture"
                    .into(),
            ),
            Json::Str(
                "cells, i.e. nothing was executed against it). --check fails if any uncovered id \
                 is"
                .into(),
            ),
            Json::Str(
                "missing from this file, and --write refuses to ADD one without --accept-gap ID."
                    .into(),
            ),
        ]),
    );
    root.insert("generated_at", Json::Str(generated_at.to_string()));
    let arr: Vec<Json> = gaps
        .iter()
        .map(|g| {
            let mut o = Obj::new();
            o.insert("id", Json::Str(g.id.clone()));
            o.insert("family", Json::Str(g.family.clone()));
            o.insert("status", Json::Str(g.status.as_str().to_string()));
            o.insert("file", Json::Str(g.file.clone()));
            o.insert("line", Json::Int(g.line as i64));
            o.insert("reason", Json::Str(g.reason.clone()));
            Json::Object(o)
        })
        .collect();
    root.insert("gaps", Json::Array(arr));
    format!(
        "{}\n",
        json_lite::dump_python_indent(&Json::Object(root), 2)
    )
}

/// Byte-compare two renderings of one of these two artefacts with `"generated_at": "..."`
/// NORMALIZED out — the one field `--write` sets to today and `--check` must not fault on.
fn normalize_generated_at(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.split_inclusive('\n') {
        if let Some(pos) = line.find("\"generated_at\": \"") {
            out.push_str(&line[..pos]);
            out.push_str("\"generated_at\": \"NORMALIZED\"");
            if let Some(nl) = line.rfind(['\n']) {
                out.push_str(&line[nl..]);
            } else if line.ends_with(',') {
                out.push(',');
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

// ── THE ROWS ─────────────────────────────────────────────────────────────────────────────────────

fn unproven(id: &str, why: &str) -> Row {
    Row::skip(
        id,
        "unproven — the derivation refused above this check",
        why.to_string(),
    )
}

fn all_rows() -> [&'static str; 6] {
    [
        ROW_DUPLICATE_ID,
        ROW_FLOOR,
        ROW_GAPS_NAMED,
        ROW_COVERAGE_ARTIFACT,
        ROW_GAPS_ARTIFACT,
        ROW_BEHAVIOUR_TABLE,
    ]
}

// ── THE ANALYSIS, SHARED BY `run()`'S TWO ARMS AND THE PARITY TRANSLATOR ───────────────────────────
//
// Factored out so the parity translator (`translate_check`, below) can build the SAME rows a live
// `--check` run would, from the SAME derivation, and use the legacy script's stdout only to
// CROSS-CHECK which categories it called red — never to synthesize a row's wording. Two prose
// parsers agreeing proves the parsers agree, not the gates; two identical constructors fed the same
// derivation is the actual claim.

fn refusal_rows(refusal: &Refusal) -> Vec<Row> {
    let mut rows = vec![Row::fail(
        refusal.row,
        "the inventory table set was refused",
        refusal.why.clone(),
    )];
    for id in all_rows() {
        if id != refusal.row {
            rows.push(unproven(
                id,
                "the inventory set was refused, so nothing was derived from it",
            ));
        }
    }
    rows
}

fn row_duplicate_ok(ids: &[InventoryId], summary: &BTreeMap<String, FamCounts>) -> Row {
    Row::pass(
        ROW_DUPLICATE_ID,
        "every inventory id is declared exactly once",
        format!(
            "{} id(s) across {} family(ies), no collision",
            ids.len(),
            summary.len()
        ),
    )
}

fn row_floor_from(floor_problems: &[String], summary: &BTreeMap<String, FamCounts>) -> Row {
    if floor_problems.is_empty() {
        Row::pass(
            ROW_FLOOR,
            "every family's discovered row count is at or above its recorded floor",
            format!(
                "{} family(ies) checked against {COVERAGE_JSON}",
                summary.len()
            ),
        )
    } else {
        Row::fail(
            ROW_FLOOR,
            "the discovered inventory shrank below its recorded floor",
            floor_problems.join(" | "),
        )
    }
}

fn write_rows(cx: &Ctx, ids: &[InventoryId]) -> Vec<Row> {
    let cells = load_cells(cx);
    let ledger = load_ledger(cx);
    let coverage = compute_coverage(ids, &cells, &ledger);
    let summary = family_summary(ids, &coverage);
    let matrix = build_matrix(ids, &coverage);

    let row_duplicate = row_duplicate_ok(ids, &summary);
    let floor_problems = check_floor(cx, &summary);
    let row_floor = row_floor_from(&floor_problems, &summary);
    let gaps = build_gaps(ids, &coverage);
    let generated_at = today();

    // The floor is enforced BEFORE anything is written — a `--write` under a collapsed discovery
    // must not launder the collapse into the new baseline.
    if !floor_problems.is_empty() {
        let mut rows = vec![row_duplicate, row_floor];
        for id in [
            ROW_GAPS_NAMED,
            ROW_COVERAGE_ARTIFACT,
            ROW_GAPS_ARTIFACT,
            ROW_BEHAVIOUR_TABLE,
        ] {
            rows.push(unproven(id, "refusing to --write over a floor violation"));
        }
        return rows;
    }

    let coverage_text = render_coverage_json(&generated_at, ids, &coverage, &summary, &matrix);
    let row_coverage_artifact = match std::fs::write(cx.abs(COVERAGE_JSON), &coverage_text) {
        Ok(()) => Row::pass(
            ROW_COVERAGE_ARTIFACT,
            "the committed coverage detail is the fresh derivation",
            format!("{COVERAGE_JSON} written ({} id(s))", ids.len()),
        ),
        Err(e) => Row::fail(
            ROW_COVERAGE_ARTIFACT,
            "the coverage detail could not be written",
            format!("{COVERAGE_JSON}: {e}"),
        ),
    };

    let previously_named: Vec<String> = named_gap_ids(cx).unwrap_or_default();
    let new_gaps: Vec<&Gap> = gaps
        .iter()
        .filter(|g| !previously_named.contains(&g.id))
        .collect();
    let row_gaps_named = if new_gaps.is_empty() {
        Row::pass(
            ROW_GAPS_NAMED,
            "no id newly lost coverage",
            format!("{} gap(s), all already named in {GAPS_JSON}", gaps.len()),
        )
    } else {
        Row::fail(
            ROW_GAPS_NAMED,
            "--write would add id(s) to the gaps file that are not yet named",
            format!(
                "{} id(s) newly uncovered and not accepted: {}. A gaps file that grows on its own \
                 turns a coverage regression into the record that excuses it; restore the coverage \
                 or accept the loss by hand-editing {GAPS_JSON} in the same commit.",
                new_gaps.len(),
                new_gaps
                    .iter()
                    .map(|g| g.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };

    if !new_gaps.is_empty() {
        return vec![
            row_duplicate,
            row_floor,
            row_gaps_named,
            row_coverage_artifact,
            unproven(
                ROW_GAPS_ARTIFACT,
                "refusing to write a gaps file that grew unaccepted",
            ),
            unproven(
                ROW_BEHAVIOUR_TABLE,
                "refusing to update the table under an unaccepted gap",
            ),
        ];
    }

    let gaps_text = render_gaps_json(&generated_at, &gaps);
    let row_gaps_artifact = match std::fs::write(cx.abs(GAPS_JSON), &gaps_text) {
        Ok(()) => Row::pass(
            ROW_GAPS_ARTIFACT,
            "the committed gaps file is the fresh derivation",
            format!("{GAPS_JSON} written ({} gap(s))", gaps.len()),
        ),
        Err(e) => Row::fail(
            ROW_GAPS_ARTIFACT,
            "the gaps file could not be written",
            format!("{GAPS_JSON}: {e}"),
        ),
    };

    let row_behaviour = match cx
        .read(BEHAVIOUR_MD)
        .ok()
        .and_then(|cur| render_behaviour_md(&cur, &matrix))
    {
        Some(new_text) => match std::fs::write(cx.abs(BEHAVIOUR_MD), &new_text) {
            Ok(()) => Row::pass(
                ROW_BEHAVIOUR_TABLE,
                "the coverage matrix in the behaviour doc is the fresh derivation",
                format!("{BEHAVIOUR_MD} coverage table written"),
            ),
            Err(e) => Row::fail(
                ROW_BEHAVIOUR_TABLE,
                "the behaviour doc could not be written",
                format!("{BEHAVIOUR_MD}: {e}"),
            ),
        },
        None => Row::fail(
            ROW_BEHAVIOUR_TABLE,
            "the coverage markers are missing from the behaviour doc",
            format!("{BEHAVIOUR_MD} does not carry both {BEGIN_MARK} and {END_MARK}"),
        ),
    };

    vec![
        row_duplicate,
        row_floor,
        row_gaps_named,
        row_coverage_artifact,
        row_gaps_artifact,
        row_behaviour,
    ]
}

fn check_rows(cx: &Ctx, ids: &[InventoryId]) -> Vec<Row> {
    let cells = load_cells(cx);
    let ledger = load_ledger(cx);
    let coverage = compute_coverage(ids, &cells, &ledger);
    let summary = family_summary(ids, &coverage);
    let matrix = build_matrix(ids, &coverage);

    let row_duplicate = row_duplicate_ok(ids, &summary);
    let floor_problems = check_floor(cx, &summary);
    let row_floor = row_floor_from(&floor_problems, &summary);
    let gaps = build_gaps(ids, &coverage);
    let generated_at = today();

    let row_gaps_named = match named_gap_ids(cx) {
        None => Row::fail(
            ROW_GAPS_NAMED,
            "the gaps file does not exist",
            format!(
                "{GAPS_JSON} does not exist — run cargo xtask gate inventory-coverage --write first"
            ),
        ),
        Some(named) => {
            let unnamed: Vec<&Gap> = gaps.iter().filter(|g| !named.contains(&g.id)).collect();
            if unnamed.is_empty() {
                Row::pass(
                    ROW_GAPS_NAMED,
                    "every uncovered id is a named gap",
                    format!(
                        "{} id(s) not covered by a PASSing cell, all named in {GAPS_JSON}",
                        gaps.len()
                    ),
                )
            } else {
                Row::fail(
                    ROW_GAPS_NAMED,
                    "an uncovered id is not named in the gaps file",
                    format!(
                        "{} id(s) are not covered and are not named in {GAPS_JSON}: {}",
                        unnamed.len(),
                        unnamed
                            .iter()
                            .take(20)
                            .map(|g| g.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            }
        }
    };

    let row_coverage_artifact = artifact_row(
        cx,
        COVERAGE_JSON,
        ROW_COVERAGE_ARTIFACT,
        "coverage detail",
        &render_coverage_json(&generated_at, ids, &coverage, &summary, &matrix),
    );
    let row_gaps_artifact = artifact_row(
        cx,
        GAPS_JSON,
        ROW_GAPS_ARTIFACT,
        "gaps file",
        &render_gaps_json(&generated_at, &gaps),
    );

    let row_behaviour = match cx.read(BEHAVIOUR_MD).ok() {
        None => Row::fail(
            ROW_BEHAVIOUR_TABLE,
            "the behaviour doc is missing",
            BEHAVIOUR_MD.to_string(),
        ),
        Some(current) => match render_behaviour_md(&current, &matrix) {
            None => Row::fail(
                ROW_BEHAVIOUR_TABLE,
                "the coverage markers are missing from the behaviour doc",
                format!("{BEHAVIOUR_MD} does not carry both {BEGIN_MARK} and {END_MARK}"),
            ),
            Some(fresh) if fresh == current => Row::pass(
                ROW_BEHAVIOUR_TABLE,
                "the coverage matrix in the behaviour doc is the fresh derivation",
                format!("{BEHAVIOUR_MD} is up to date"),
            ),
            Some(_) => Row::fail(
                ROW_BEHAVIOUR_TABLE,
                "the coverage matrix in the behaviour doc is STALE",
                format!("{BEHAVIOUR_MD} does not match the fresh derivation; run --write"),
            ),
        },
    };

    vec![
        row_duplicate,
        row_floor,
        row_gaps_named,
        row_coverage_artifact,
        row_gaps_artifact,
        row_behaviour,
    ]
}

/// THE PARITY TRANSLATOR. Reads `cargo xtask gate inventory-coverage --parity --
/// python3 scripts/inventory-coverage.py --check`'s legacy half: the row CONTENT is this gate's own
/// [`check_rows`] derivation (so wording cannot differ for a reason that is not about the tree), and
/// the legacy's stdout is read only to CROSS-CHECK that it called the same two categories red or
/// green that this derivation does. A disagreement there is a translator error, not a silent pass.
///
/// The Python's `--check` never inspects the three generated-artifact rows at all — it neither
/// writes nor reads `qa/inventory-coverage.json`'s bytes, `qa/inventory-gaps.json`'s bytes, or the
/// behaviour-doc table during `--check` — so there is nothing in its stdout to cross-check those
/// three against. They are asserted through the SAME [`check_rows`] call the real gate makes, which
/// is exactly the claim `--write`'s twin-artefact requirement (module doc, above) already rests on:
/// the two are byte-identical whenever a `--write` has run since the last change to either input.
fn translate_check(cx: &Ctx, run: &crate::parity::LegacyRun) -> Result<Vec<Row>, String> {
    let lines: Vec<&str> = run.lines().collect();

    // The duplicate-id refusal fires inside `parse_inventory_ids` (Python: `run_analysis`), before
    // any GREEN/RED banner is printed — `raise SystemExit("duplicate inventory id ...")` writes that
    // one line to stderr and nothing else.
    if let Some(dup_line) = lines.iter().find(|l| l.contains("duplicate inventory id")) {
        return match parse_inventory_ids(cx) {
            Err(refusal) if refusal.row == ROW_DUPLICATE_ID => Ok(refusal_rows(&refusal)),
            _ => Err(format!(
                "parity: the legacy script reported a duplicate id ({dup_line:?}) but this gate's \
                 own loader does not — the two disagree about the tree, not merely about wording"
            )),
        };
    }

    let saw_green = lines.iter().any(|l| l.starts_with("GREEN:"));
    let saw_red = lines.iter().any(|l| l.trim() == "RED:");
    if !saw_green && !saw_red {
        return Err(format!(
            "the legacy translator recognised neither a GREEN nor a RED verdict in `{}`'s output — \
             silence read as a passing claim is the defect this gate exists for. stdout: {}",
            run.argv.join(" "),
            run.stdout.trim()
        ));
    }

    let legacy_floor_red = lines.iter().any(|l| {
        l.contains("the inventory now yields") || l.contains("the whole inventory yields")
    });
    let legacy_gaps_red = lines.iter().any(|l| {
        l.contains("are not covered by a PASSing oracle cell and are not named in")
            || l.contains("does not exist — run --write first")
            || l.contains("does not exist -- run --write first")
    });

    let ids = parse_inventory_ids(cx)
        .map_err(|r| format!("parity: this gate's own loader refused the tree: {}", r.why))?;
    let rows = check_rows(cx, &ids);

    let rust_floor_red = rows
        .iter()
        .any(|r| r.id == ROW_FLOOR && r.status != crate::ledger::Status::Pass);
    let rust_gaps_red = rows
        .iter()
        .any(|r| r.id == ROW_GAPS_NAMED && r.status != crate::ledger::Status::Pass);

    if rust_floor_red != legacy_floor_red {
        return Err(format!(
            "parity: the floor verdict disagrees — this gate says {}, `{}` says {}",
            if rust_floor_red { "RED" } else { "green" },
            run.argv.join(" "),
            if legacy_floor_red { "RED" } else { "green" }
        ));
    }
    if rust_gaps_red != legacy_gaps_red {
        return Err(format!(
            "parity: the gaps-named verdict disagrees — this gate says {}, `{}` says {}",
            if rust_gaps_red { "RED" } else { "green" },
            run.argv.join(" "),
            if legacy_gaps_red { "RED" } else { "green" }
        ));
    }

    Ok(rows)
}

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────

pub struct InventoryCoverageGate;

impl Gate for InventoryCoverageGate {
    fn name(&self) -> &'static str {
        "inventory-coverage"
    }

    fn owed(&self) -> Vec<String> {
        all_rows().iter().map(|s| (*s).to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let ids = match parse_inventory_ids(cx) {
            Ok(ids) => ids,
            Err(refusal) => return Verdict::of(refusal_rows(&refusal)),
        };

        if let Err(refusal) = read_cells(cx) {
            return Verdict::of(refusal_rows(&refusal));
        }

        if cx.env().write {
            Verdict::of(write_rows(cx, &ids))
        } else {
            Verdict::of(check_rows(cx, &ids))
        }
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(
        &self,
        cx: &Ctx,
        runs: &[crate::parity::LegacyRun],
    ) -> Option<Result<Vec<Row>, String>> {
        Some(translate_check(cx, &runs[0]))
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        let all = all_rows();

        report.push(prove_green(
            cx,
            self,
            "the real tree's inventory is at parity with its recorded coverage",
            &all,
        ));

        // ── DUPLICATE ID ─────────────────────────────────────────────────────────────────────────
        {
            let text = cx
                .read(format!("{INVENTORY_DIR}/1.5.5-config.md"))
                .unwrap_or_default();
            let dup = text.replacen("CONF-002", "CONF-001", 1);
            let mut ov = Overlay::new();
            ov.set(format!("{INVENTORY_DIR}/1.5.5-config.md"), dup);
            report.push(prove_red(
                cx,
                self,
                "a duplicated inventory id is refused, not silently merged",
                &[ROW_DUPLICATE_ID],
                ov,
                &["duplicate inventory id CONF-001"],
            ));
        }

        // ── THE FLOOR: a whole family is dropped from the discovery ────────────────────────────────
        {
            let path = format!("{INVENTORY_DIR}/1.5.5-config.md");
            let text = cx.read(&path).unwrap_or_default();
            let dropped: String = text
                .lines()
                .map(|l| format!("{l}\n"))
                .filter(|l| !l.contains("| CONF-"))
                .collect();
            let mut ov = Overlay::new();
            ov.set(&path, dropped);
            report.push(prove_red(
                cx,
                self,
                "a family that vanished from the discovery entirely is refused, not read as a clean tree",
                &[ROW_FLOOR],
                ov,
                &["family CONF:"],
            ));
        }
        {
            let path = format!("{INVENTORY_DIR}/1.5.5-config.md");
            let text = cx.read(&path).unwrap_or_default();
            let mut removed_one = false;
            let shrunk: String = text
                .lines()
                .filter(|l| {
                    if !removed_one && l.trim_start().starts_with("| CONF-") {
                        removed_one = true;
                        return false;
                    }
                    true
                })
                .map(|l| format!("{l}\n"))
                .collect();
            let mut ov = Overlay::new();
            ov.set(&path, shrunk);
            report.push(prove_red(
                cx,
                self,
                "losing even one row of a recorded family is refused",
                &[ROW_FLOOR],
                ov,
                &["family CONF:"],
            ));
        }

        // ── GAPS NAMED: an id that lost its only PASSing citer becomes an unnamed gap ──────────────
        {
            let cells = load_cells(cx);
            let ledger = load_ledger(cx);
            let ids = parse_inventory_ids(cx).unwrap_or_default();
            let coverage = compute_coverage(&ids, &cells, &ledger);
            let covered_ids: Vec<&InventoryId> = ids
                .iter()
                .filter(|i| coverage[&i.id].status == Status::Covered)
                .collect();
            if let Some(target) = covered_ids.first() {
                let removed: Vec<String> = coverage[&target.id]
                    .citers
                    .iter()
                    .filter(|cid| ledger.get(*cid).map(String::as_str) == Some("PASS"))
                    .cloned()
                    .collect();
                let kept: Vec<Json> = cells
                    .iter()
                    .filter(|c| {
                        !removed.contains(&c.get("id").as_str().unwrap_or_default().to_string())
                    })
                    .cloned()
                    .collect();
                let mut root = Obj::new();
                root.insert("cells", Json::Array(kept));
                let mut ov = Overlay::new();
                ov.set(
                    CELLS_JSON,
                    format!("{}\n", json_lite::dump_python(&Json::Object(root))),
                );
                report.push(prove_red(
                    cx,
                    self,
                    "an id that loses its only PASSing citer, and is not yet a named gap, is refused",
                    &[ROW_GAPS_NAMED],
                    ov,
                    &[&target.id],
                ));
            } else {
                report.note_infra_failure(
                    "inventory-coverage selftest: no currently-covered id in the real tree to plant this case against"
                        .to_string(),
                );
            }
        }

        // ── PARTIAL IS OWED: dropping a partial id's own named gap entry is refused ─────────────────
        {
            let cells = load_cells(cx);
            let ledger = load_ledger(cx);
            let ids = parse_inventory_ids(cx).unwrap_or_default();
            let coverage = compute_coverage(&ids, &cells, &ledger);
            let partial_id = ids
                .iter()
                .find(|i| coverage[&i.id].status == Status::Partial);
            match (partial_id, cx.read(GAPS_JSON).ok().and_then(|t| json_lite::parse(&t).ok())) {
                (Some(target), Some(doc)) => {
                    let arr = doc.get("gaps").as_array().unwrap_or(&[]);
                    let kept: Vec<Json> =
                        arr.iter().filter(|g| g.get("id").as_str() != Some(target.id.as_str())).cloned().collect();
                    let mut root = doc.as_object().cloned().unwrap_or_default();
                    root.insert("gaps", Json::Array(kept));
                    let mut ov = Overlay::new();
                    ov.set(GAPS_JSON, format!("{}\n", json_lite::dump_python_indent(&Json::Object(root), 2)));
                    report.push(prove_red(
                        cx,
                        self,
                        "a \"partial\" id (nothing executed against it) is owed by --check, not silently forgiven",
                        &[ROW_GAPS_NAMED],
                        ov,
                        &[&target.id],
                    ));
                }
                _ => report.note_infra_failure(
                    "inventory-coverage selftest: no currently-\"partial\" id (or no readable gaps file) in the \
                     real tree to plant this case against"
                        .to_string(),
                ),
            }
        }

        // ── ARTIFACT DRIFT: qa/inventory-coverage.json ──────────────────────────────────────────────
        {
            let current = cx.read(COVERAGE_JSON).unwrap_or_default();
            let mut ov = Overlay::new();
            ov.set(
                COVERAGE_JSON,
                current.replacen(
                    "\"family_summary\"",
                    "\"_planted\": 1, \"family_summary\"",
                    1,
                ),
            );
            report.push(prove_red(
                cx,
                self,
                "a committed coverage detail that is not the derivation is STALE",
                &[ROW_COVERAGE_ARTIFACT],
                ov,
                &["STALE", COVERAGE_JSON],
            ));
        }

        // ── ARTIFACT DRIFT: qa/inventory-gaps.json ──────────────────────────────────────────────────
        {
            let current = cx.read(GAPS_JSON).unwrap_or_default();
            let mut ov = Overlay::new();
            ov.set(
                GAPS_JSON,
                current.replacen("\"gaps\"", "\"_planted\": 1, \"gaps\"", 1),
            );
            report.push(prove_red(
                cx,
                self,
                "a committed gaps file that is not the derivation is STALE",
                &[ROW_GAPS_ARTIFACT],
                ov,
                &["STALE", GAPS_JSON],
            ));
        }

        // ── ARTIFACT DRIFT: the behaviour-doc coverage table ────────────────────────────────────────
        {
            let current = cx.read(BEHAVIOUR_MD).unwrap_or_default();
            let mutated = current.replace(BEGIN_MARK, &format!("{BEGIN_MARK}\n<!-- planted -->"));
            let mut ov = Overlay::new();
            ov.set(BEHAVIOUR_MD, mutated);
            report.push(prove_red(
                cx,
                self,
                "a committed coverage table that is not the derivation is STALE",
                &[ROW_BEHAVIOUR_TABLE],
                ov,
                &["STALE", BEHAVIOUR_MD],
            ));
        }
        {
            let current = cx.read(BEHAVIOUR_MD).unwrap_or_default();
            let mutated = current.replace(BEGIN_MARK, "").replace(END_MARK, "");
            let mut ov = Overlay::new();
            ov.set(BEHAVIOUR_MD, mutated);
            report.push(prove_red(
                cx,
                self,
                "a behaviour doc with the coverage markers removed is refused, not silently skipped",
                &[ROW_BEHAVIOUR_TABLE],
                ov,
                &["markers are missing"],
            ));
        }

        // -- A MISSING INPUT IS A REFUSAL, NOT AN EMPTY DERIVATION ---------------------------------
        //
        // The cell set is the one input whose absence this gate cannot notice by arithmetic: read as
        // "zero cells" it produces a full, well-formed, entirely uncovered analysis. Both spellings
        // of absence are planted -- a file that is not JSON, and JSON that is not the oracle's shape
        // -- because the loader has a separate arm for each and one arm covering both would let the
        // other rot.
        {
            let mut ov = Overlay::new();
            ov.set(CELLS_JSON, "this is not json\n".to_string());
            report.push(prove_red(
                cx,
                self,
                "an unparseable cells.json is REFUSED, not read as zero cells",
                &[ROW_GAPS_NAMED],
                ov,
                &["not parseable JSON", CELLS_JSON],
            ));
        }
        {
            let mut ov = Overlay::new();
            ov.set(CELLS_JSON, "{\"not_cells\": []}\n".to_string());
            report.push(prove_red(
                cx,
                self,
                "a cells.json with no `cells` array is REFUSED, not read as zero cells",
                &[ROW_GAPS_NAMED],
                ov,
                &["carries no `cells` array"],
            ));
        }

        report
    }
}

fn artifact_row(cx: &Ctx, path: &str, row_id: &'static str, noun: &str, fresh: &str) -> Row {
    match cx.read(path) {
        Err(_) => Row::fail(
            row_id,
            format!("the committed {noun} is missing"),
            format!("{path} is missing; run cargo xtask gate inventory-coverage --write"),
        ),
        Ok(current) if normalize_generated_at(&current) != normalize_generated_at(fresh) => {
            Row::fail(
                row_id,
                format!("the committed {noun} is not the fresh derivation"),
                format!("{path} is STALE; run cargo xtask gate inventory-coverage --write"),
            )
        }
        Ok(_) => Row::pass(
            row_id,
            format!("the committed {noun} is the fresh derivation"),
            format!("{path} is up to date"),
        ),
    }
}

fn today() -> String {
    // `date.today().isoformat()` — with ONE declared divergence: the Python takes the LOCAL date,
    // this takes UTC, the same choice `changelog.rs::today_utc` already made for the same reason
    // (no `chrono`, no TZ database, no shelling out to `date`). It is the one field NORMALIZED out
    // of every byte comparison in this file (see `normalize_generated_at`), only `--write` ever
    // reads it, and what it writes is a plain, reviewable `YYYY-MM-DD`; a `--write` run late in
    // the evening west of Greenwich stamps tomorrow's date where the Python stamped today's.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    civil_from_days(days as i64)
}

/// Days-since-epoch to a proleptic-Gregorian `YYYY-MM-DD`, Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> String {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
