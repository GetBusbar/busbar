//! `cargo xtask pin-missing-cells [--write]` — REGENERATE `qa/method-coverage.missing`, the pinned
//! MISSING work queue.
//!
//! THIS IS A GENERATOR A HUMAN RUNS, AND IT LIVES OUTSIDE THE GATE ON PURPOSE.
//!
//! `crates/busbar/tests/method_coverage.rs` used to carry this regeneration itself, behind an
//! environment variable: set the variable and the gate rewrote the pinned file from whatever the
//! tree currently said, then returned green. A gate that its own caller can talk into agreeing with
//! the tree is not a gate — the pinned queue stops recording what was OWED and starts recording what
//! happens to be built. So the write lives here, where a human runs it deliberately and reads the
//! diff, and the test only ever compares.
//!
//! The MISSING set is defined exactly as the gate defines it, and the gate is the authority: a cell
//! of `qa/method-inventory.json` is MISSING when it is
//!
//! * owed at all            — `na_reason` is absent (an N/A cell is not owed an implementation),
//! * not claimed            — its id is absent from `qa/method-coverage.status`, and
//! * not argued impossible  — its id is absent from `qa/WAIVERS.md`.
//!
//! If this command and the gate ever disagree, the gate goes RED in the direction of the
//! disagreement and this command is what is wrong. Never edit the test to agree with this file.
//!
//! * `cargo xtask pin-missing-cells`          print the diff against the pinned file; exit 1 if any
//! * `cargo xtask pin-missing-cells --write`  rewrite the pinned file, preserving its header
//!
//! A faithful port of the retired Python script of the same name.

use crate::ctx::Ctx;
use std::collections::BTreeSet;

pub const INVENTORY: &str = "qa/method-inventory.json";
pub const STATUS: &str = "qa/method-coverage.status";
pub const WAIVERS: &str = "qa/WAIVERS.md";
pub const PINNED: &str = "qa/method-coverage.missing";

/// Every cell id the status file claims, `implemented` or `waived`. The gate's parser validates the
/// SHAPE of each line (a waiver needs a date and a reason); this only needs the id, and a malformed
/// line is the gate's failure to report, not this command's.
pub fn claimed_ids(status: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for raw in status.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || !line.contains('=') {
            continue;
        }
        ids.insert(line.split('=').next().unwrap_or("").trim().to_string());
    }
    ids
}

/// Every cell id argued impossible in `qa/WAIVERS.md`: a row is ``- `<cell-id>` --- <argument>``.
pub fn impossible_ids(waivers: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for raw in waivers.lines() {
        let Some(rest) = raw.strip_prefix("- `") else {
            continue;
        };
        let Some((id, _)) = rest.split_once('`') else {
            continue;
        };
        ids.insert(id.to_string());
    }
    ids
}

/// The computed MISSING set, sorted and deduplicated.
pub fn computed_missing(
    inventory: &str,
    status: &str,
    waivers: &str,
) -> Result<Vec<String>, String> {
    let doc: serde_json::Value =
        serde_json::from_str(inventory).map_err(|e| format!("{INVENTORY}: {e}"))?;
    let cells = doc
        .get("cells")
        .and_then(|c| c.as_array())
        .ok_or_else(|| format!("{INVENTORY}: no `cells` array"))?;
    let claimed = claimed_ids(status);
    let impossible = impossible_ids(waivers);
    let mut out = BTreeSet::new();
    for c in cells {
        let id = c
            .get("id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| format!("{INVENTORY}: a cell has no string `id`"))?;
        let na = c.get("na_reason").is_some_and(|v| !v.is_null());
        if !na && !claimed.contains(id) && !impossible.contains(id) {
            out.insert(id.to_string());
        }
    }
    Ok(out.into_iter().collect())
}

/// The pinned file's cell lines, comments stripped, sorted and deduplicated.
pub fn pinned_lines(text: &str) -> Vec<String> {
    let body: BTreeSet<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    body.into_iter().collect()
}

/// The pinned file's leading comment block — the prose that says what the file is. It is preserved
/// verbatim across a rewrite: it is a human's explanation, not generated content.
pub fn header_of(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            out.push(line);
        } else {
            break;
        }
    }
    format!("{}\n", out.join("\n").trim_end_matches('\n'))
}

/// `difflib.unified_diff(a, b, fromfile, tofile, lineterm="")` over two line lists, three lines of
/// context. The inputs here are sorted and duplicate-free, so the longest-common-subsequence
/// alignment used below is the alignment difflib finds.
pub fn unified_diff(a: &[String], b: &[String], from: &str, to: &str) -> Vec<String> {
    // LCS table.
    let (n, m) = (a.len(), b.len());
    let mut t = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[i][j] = if a[i] == b[j] {
                t[i + 1][j + 1] + 1
            } else {
                t[i + 1][j].max(t[i][j + 1])
            };
        }
    }
    // Opcodes as a flat edit script: (tag, line) with tag ' ', '-', '+'.
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((' ', &a[i]));
            i += 1;
            j += 1;
        } else if i < n && (j >= m || t[i + 1][j] >= t[i][j + 1]) {
            ops.push(('-', &a[i]));
            i += 1;
        } else {
            ops.push(('+', &b[j]));
            j += 1;
        }
    }
    if ops.iter().all(|(c, _)| *c == ' ') {
        return vec![];
    }
    // Group into hunks with `context` lines either side, merging when the gap is <= 2*context.
    let context = 3usize;
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, (c, _))| *c != ' ')
        .map(|(k, _)| k)
        .collect();
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for &k in &changed {
        match groups.last_mut() {
            Some((_, end)) if k <= *end + 2 * context => *end = k,
            _ => groups.push((k, k)),
        }
    }
    let mut out = vec![format!("--- {from}"), format!("+++ {to}")];
    let range = |start: usize, len: usize| -> String {
        let mut beginning = start + 1;
        if len == 1 {
            return beginning.to_string();
        }
        if len == 0 {
            beginning -= 1;
        }
        format!("{beginning},{len}")
    };
    for (first, last) in groups {
        let lo = first.saturating_sub(context);
        let hi = (last + context + 1).min(ops.len());
        // Line numbers consumed before `lo`.
        let a_start = ops[..lo].iter().filter(|(c, _)| *c != '+').count();
        let b_start = ops[..lo].iter().filter(|(c, _)| *c != '-').count();
        let a_len = ops[lo..hi].iter().filter(|(c, _)| *c != '+').count();
        let b_len = ops[lo..hi].iter().filter(|(c, _)| *c != '-').count();
        out.push(format!(
            "@@ -{} +{} @@",
            range(a_start, a_len),
            range(b_start, b_len)
        ));
        for (c, line) in &ops[lo..hi] {
            out.push(format!("{c}{line}"));
        }
    }
    out
}

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    let write = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => false,
        ["--write"] => true,
        _ => {
            eprintln!("usage: cargo xtask pin-missing-cells [--write]");
            return 2;
        }
    };
    let read = |rel: &str| cx.read(rel);
    let (inv, status, waivers, pinned_text) =
        match (read(INVENTORY), read(STATUS), read(WAIVERS), read(PINNED)) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            (a, b, c, d) => {
                for e in [a.err(), b.err(), c.err(), d.err()].into_iter().flatten() {
                    eprintln!("pin-missing-cells: {e}");
                }
                return 3;
            }
        };
    let computed = match computed_missing(&inv, &status, &waivers) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pin-missing-cells: {e}");
            return 3;
        }
    };
    let pinned = pinned_lines(&pinned_text);

    if computed == pinned {
        println!(
            "qa/method-coverage.missing is already exact: {} cells.",
            computed.len()
        );
        return 0;
    }

    let diff = unified_diff(
        &pinned,
        &computed,
        "pinned (on disk)",
        "computed (from the tree)",
    );
    println!("{}", diff.join("\n"));
    let cset: BTreeSet<&String> = computed.iter().collect();
    let pset: BTreeSet<&String> = pinned.iter().collect();
    println!(
        "\n{} cell(s) newly MISSING, {} cell(s) now covered.",
        cset.difference(&pset).count(),
        pset.difference(&cset).count()
    );

    if !write {
        println!(
            "\nRe-run with --write to pin this. READ THE DIFF FIRST: every added line is a gap."
        );
        return 1;
    }

    let mut text = header_of(&pinned_text);
    for cell in &computed {
        text.push_str(cell);
        text.push('\n');
    }
    if let Err(e) = cx.write_file(PINNED, text) {
        eprintln!("pin-missing-cells: cannot write {PINNED}: {e}");
        return 3;
    }
    println!(
        "\nwrote qa/method-coverage.missing ({} cells).",
        computed.len()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = r#"{"cells":[
        {"id":"a|1","na_reason":"n/a"},
        {"id":"b|2"},
        {"id":"c|3","na_reason":null},
        {"id":"d|4"},
        {"id":"e|5"},
        {"id":"b|2"}
    ]}"#;

    #[test]
    fn a_cell_is_missing_unless_na_claimed_or_argued_impossible() {
        let status = "# comment\nb|2 = implemented  # note\n\nnot a claim\n";
        let waivers = "intro\n- `d|4` --- impossible because\n- `unterminated\n";
        let missing = computed_missing(INV, status, waivers).expect("computes");
        // a: N/A. b: claimed. c: null na_reason is owed. d: impossible. e: owed.
        assert_eq!(missing, vec!["c|3".to_string(), "e|5".to_string()]);
    }

    #[test]
    fn claimed_and_impossible_parsers() {
        let c = claimed_ids("x = implemented\n y|z=waived 2026 why\n#only comment\n=\n");
        assert!(c.contains("x") && c.contains("y|z") && c.contains(""));
        assert_eq!(c.len(), 3);
        let i = impossible_ids("- `a|b` --- why\n-`nope`\n  - `indented`\n- `c|d` x `e`\n");
        assert_eq!(i.into_iter().collect::<Vec<_>>(), vec!["a|b", "c|d"]);
    }

    #[test]
    fn a_malformed_inventory_is_an_error_not_an_empty_queue() {
        assert!(computed_missing("{}", "", "").is_err());
        assert!(computed_missing("not json", "", "").is_err());
    }

    #[test]
    fn the_header_is_preserved_verbatim() {
        let text = "# one\n\n# two\nrow|1\n# late comment\nrow|2\n";
        assert_eq!(header_of(text), "# one\n\n# two\n");
        assert_eq!(header_of("row\n"), "\n");
        assert_eq!(pinned_lines(text), vec!["row|1", "row|2"]);
        assert_eq!(pinned_lines("b # x\na\na\n"), vec!["a", "b"]);
    }

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn the_diff_is_difflibs_unified_format() {
        assert!(unified_diff(&v(&["a"]), &v(&["a"]), "x", "y").is_empty());
        assert_eq!(
            unified_diff(
                &v(&["aaa", "zzz"]),
                &v(&["mmm"]),
                "pinned (on disk)",
                "computed (from the tree)"
            ),
            vec![
                "--- pinned (on disk)",
                "+++ computed (from the tree)",
                "@@ -1,2 +1 @@",
                "-aaa",
                "-zzz",
                "+mmm"
            ]
        );
        // Pure addition to an empty side: the empty range is `0,0`.
        assert_eq!(
            unified_diff(&[], &v(&["a", "b"]), "f", "t"),
            vec!["--- f", "+++ t", "@@ -0,0 +1,2 @@", "+a", "+b"]
        );
        // Context of three lines, and two far-apart changes make two hunks.
        let a: Vec<String> = (0..20).map(|i| format!("l{i:02}")).collect();
        let mut b = a.clone();
        b.remove(1);
        b.remove(17);
        let d = unified_diff(&a, &b, "f", "t");
        assert_eq!(
            d.iter().filter(|l| l.starts_with("@@")).count(),
            2,
            "{d:#?}"
        );
        assert_eq!(d[2], "@@ -1,5 +1,4 @@");
    }
}
