//! The cell decomposition of `gate --format=tsv`, judged against busbar-release's own examples
//! (its `testdata/trust/github.json` law0 and deps rows, as `cargo xtask gate kind-isolation
//! --format=tsv` printed them), and the proof that busbar-release's row reader reads the same rows,
//! byte for byte, with the cell lines in the output.

use super::*;
use crate::ledger::{Row, Status};

/// busbar-release `turnstile::gate::parse_tsv_rows` (origin/main), verbatim but for its
/// `GateRow` being a JSON object here: the reader busbar-release builds its gate report from.
pub(crate) fn busbar_release_parse_tsv_rows(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut f = line.splitn(4, '\t');
            let id = f.next()?.trim();
            let status = f.next()?.trim();
            if id.is_empty()
                || !(status.eq_ignore_ascii_case("PASS")
                    || status.eq_ignore_ascii_case("FAIL")
                    || status.eq_ignore_ascii_case("SKIP"))
            {
                return None;
            }
            Some(serde_json::json!({
                "id": id.to_string(),
                "status": status.to_ascii_uppercase(),
                "title": f.next().unwrap_or("").trim().to_string(),
                "detail": f.next().unwrap_or("").trim().to_string(),
            }))
        })
        .collect()
}

/// The `--format=tsv` text BEFORE cell lines: each row's [`Row::tsv`] line, nothing else.
pub(crate) fn rows_only(rows: &[Row]) -> String {
    rows.iter().map(|r| format!("{}\n", r.tsv())).collect()
}

/// busbar-release's JSON report rows for `stdout`, as one byte string.
pub(crate) fn report_json(stdout: &str) -> String {
    serde_json::to_string_pretty(&busbar_release_parse_tsv_rows(stdout)).expect("json")
}

/// A ModernCI-style reader: the failing ids of a log, `<id>\tFAIL\t...` after trimming the line,
/// ids with no space (ModernCI `item::failures`).
pub(crate) fn failing_ids(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| {
            let (id, rest) = l.trim().split_once('\t')?;
            (rest.starts_with("FAIL\t") && !id.contains(' ')).then(|| id.to_string())
        })
        .collect()
}

/// busbar-release `testdata/trust/github.json`, `base-remeasured-ledger/gate-kind-isolation.log`:
/// the law0 row's detail as the wire carried it (tabs already flattened).
const LAW0_WIRE: &str =
    "20 hit(s) off the [[law0]] ceilings, 3 finding(s) over 14 neutral crate(s): \
law0-rise busbar × instance:secret 37 hit(s) against a ceiling of 35: this landing grew a neutral \
crate's instance vocabulary. Ceilings only fall (measured on predev f830faa691 (ARCHITECT \
2026-10-07, Law 9) | law0-rise busbar-kernel × transport 286 hit(s) against a ceiling of 269: this \
landing grew a neutral crate's instance vocabulary. Ceilings only fall (measured on predev \
f830faa691 (ARCHITECT 2026-10-07, Law 9) | law0-slack busbar-kernel × plane 1173 hit(s) under a \
ceiling of 1175: lower the `[[law0]]` row to 1173 in the commit that drained it";

/// The same log's deps row: a coded finding whose prose carries no count until its tail.
const DEPS_WIRE: &str = "3 finding(s), 93 shipped edge instance(s) over 30 class(es), 93 \
declaration(s); 56 `[[dep]]` row(s), 0 question(s): unlisted-dep-edge legacy -> plane busbar-llm \
-> busbar-plane-llm is a shipped edge with no `[[dep]]` row in qa/kind-isolation.toml. An edge \
nobody wrote down is an edge nobody reviewed: add the row with `count = \"1\"` and its citation, \
or delete the dependency. 1 declaration(s), in dependencies.";

#[test]
fn the_law0_wire_decomposes_into_busbar_releases_cells() {
    let found = findings(LAW0_WIRE).expect("a list of coded findings");
    assert_eq!(found.len(), 3, "{found:#?}");
    let parts: Vec<(&str, String, Option<u64>)> = found.iter().map(|f| finding_parts(f)).collect();
    assert_eq!(
        parts,
        vec![
            (
                "law0-rise",
                "busbar × instance:secret".to_string(),
                Some(37)
            ),
            (
                "law0-rise",
                "busbar-kernel × transport".to_string(),
                Some(286)
            ),
            (
                "law0-slack",
                "busbar-kernel × plane".to_string(),
                Some(1173)
            ),
        ]
    );
    // The ` | ` inside a cite that opens no code continues its finding, never a fourth cell.
    assert!(found[0].ends_with("Law 9)"), "{}", found[0]);
    assert_eq!(
        found.iter().map(|f| ceiling_of(f)).collect::<Vec<_>>(),
        vec![Some(35), Some(269), Some(1175)]
    );
}

#[test]
fn an_unstructured_fail_row_prints_one_line_per_busbar_release_cell() {
    let row = Row::fail(
        "kind-isolation:law0",
        "a neutral crate's Law 0 count",
        LAW0_WIRE,
    );
    let lines = cell_lines(&row);
    assert_eq!(
        lines
            .iter()
            .map(|l| l.splitn(5, '\t').take(4).collect::<Vec<_>>().join("\t"))
            .collect::<Vec<_>>(),
        vec![
            "\tkind-isolation:law0/busbar×instance:secret\tFAIL\t37/35",
            "\tkind-isolation:law0/busbar-kernel×plane\tFAIL\t1173/1175",
            "\tkind-isolation:law0/busbar-kernel×transport\tFAIL\t286/269",
        ]
    );
    // The key is busbar-release's, however long: the words after the code up to the first count.
    let deps = Row::fail("kind-isolation:deps", "a dependency edge", DEPS_WIRE);
    let lines = cell_lines(&deps);
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let cols: Vec<&str> = lines[0].splitn(5, '\t').collect();
    assert_eq!(
        cols[1],
        format!(
            "kind-isolation:deps/{}",
            finding_parts(&findings(DEPS_WIRE).unwrap()[0])
                .1
                .split_whitespace()
                .collect::<String>()
        )
    );
    assert!(
        cols[1].starts_with("kind-isolation:deps/legacy->planebusbar-llm->"),
        "{}",
        cols[1]
    );
    assert_eq!((cols[2], cols[3]), ("FAIL", "1/-"));
}

#[test]
fn a_row_with_no_coded_findings_keeps_its_single_line() {
    let rows = vec![
        Row::pass(
            "kind-isolation:name",
            "names",
            "40 crate(s); law0-rise a × b 3 hit(s)",
        ),
        Row::fail(
            "loc:kernel",
            "the kernel LOC",
            "busbar-kernel 29590 (ceiling 29284)",
        ),
        Row::fail("x:y", "a list", "2 finding(s): Foo bar | Baz qux"),
        Row::skip("x:z", "skipped", "reason: not-run here"),
    ];
    assert_eq!(render(&rows), rows_only(&rows));
    // busbar-release's `findings` reads the LOC row as one finding, filed under the unnamed cell:
    // the row itself, so no `loc:kernel/` line repeats it.
    let loc = findings("busbar-kernel 29590 (ceiling 29284)").expect("one finding");
    assert_eq!(finding_parts(&loc[0]).1, "");
}

/// THE READER busbar-release BUILDS ITS REPORT FROM SEES THE SAME ROWS: every cell line opens with
/// a tab, so its column 1 is empty and the line is not a row to it. A trimming reader reads one
/// failing id per FAIL cell.
#[test]
fn busbar_releases_rows_are_byte_identical_and_a_trimming_reader_sees_the_cells() {
    let rows = vec![
        Row::pass("kind-isolation:name", "names", "40 crate(s)"),
        Row::fail("kind-isolation:law0", "law0", LAW0_WIRE),
        Row::fail("kind-isolation:deps", "deps", DEPS_WIRE),
    ];
    let before = rows_only(&rows);
    let after = render(&rows);
    assert_ne!(before, after);
    assert_eq!(report_json(&after), report_json(&before));
    let ids = failing_ids(&after);
    assert!(ids.contains(&"kind-isolation:law0".to_string()), "{ids:#?}");
    assert!(
        ids.contains(&"kind-isolation:law0/busbar-kernel×transport".to_string()),
        "{ids:#?}"
    );
    assert_eq!(
        ids.iter()
            .filter(|i| i.starts_with("kind-isolation:law0/"))
            .count(),
        3
    );
}

#[test]
fn a_measured_cell_set_is_printed_as_measured_and_only_under_a_fail_row() {
    let cells = vec![
        crate::ledger::Cell {
            key: "busbar × plane".to_string(),
            status: Status::Pass,
            figure: Some(4),
            ceiling: Some(4),
            detail: "4 hit(s) at its `[[law0]]` ceiling of 4".to_string(),
        },
        crate::ledger::Cell {
            key: "busbar × vendor".to_string(),
            status: Status::Fail,
            figure: Some(3),
            ceiling: None,
            detail: "law0-new\tbusbar × vendor\t3 hit(s)".to_string(),
        },
    ];
    let fail = Row::fail("k:law0", "t", "d").with_cells(cells.clone());
    assert_eq!(
        cell_lines(&fail),
        vec![
            "\tk:law0/busbar×plane\tPASS\t4/4\t4 hit(s) at its `[[law0]]` ceiling of 4",
            "\tk:law0/busbar×vendor\tFAIL\t3/-\tlaw0-new busbar × vendor 3 hit(s)",
        ]
    );
    let pass = Row::pass("k:law0", "t", "d").with_cells(cells);
    assert!(cell_lines(&pass).is_empty());
}
