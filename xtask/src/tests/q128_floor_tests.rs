//! XA1#3: the Q128 judge reads "a clean audit ledger" (1.6.0-QUESTIONS.md Q128) as the ledger's
//! floor met, not as the absence of a red rule. Before this it blocked on `l.red` alone and copied
//! `clean_pct` into the record without judging it.

use super::*;

const HEAD: &str = "1111111111111111111111111111111111111111";
const TREE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn run(ledger: LedgerView) -> Report {
    judge(&Inputs {
        head: Some(HEAD),
        head_tree: Some(TREE),
        record_path: RECORD_REL,
        record_text: Some(
            format!(r#"{{"candidate": "{HEAD}", "auditor": "fresh-auditor", "findings": []}}"#)
                .as_str(),
        ),
        tree_of: &|c: &str| (c == HEAD).then(|| TREE.to_string()),
        changed: &|c: &str| (c == HEAD).then(Vec::new),
        ledger: Ok(ledger),
    })
}

/// XA1#3 RED: a ledger whose check found no red rule but in which no production scope is clean is
/// not a clean ledger, and the audit does not pass on it.
#[test]
fn a_ledger_with_no_production_scope_clean_blocks() {
    let f = CheckFindings {
        scopes: 154,
        clean_pct: 0.0,
        ..CheckFindings::default()
    };
    let r = run(LedgerView::of(&f));
    assert_eq!(r.verdict(), "BLOCK", "{:#}", r.json);
    assert!(
        r.findings
            .iter()
            .any(|x| x["title"] == "the audit ledger is not clean"),
        "{:#}",
        r.json
    );
}

/// The judge reads the floor itself, not only the check's `red`: a view with every rule quiet but
/// a production scope not clean, or no production scope at all, still blocks.
#[test]
fn the_judge_holds_the_floor_whatever_the_rules_say() {
    let view = |production: usize, production_clean: usize| LedgerView {
        red: false,
        rules: vec![("open-high-medium", 0)],
        opens: vec![],
        scopes: 4,
        production,
        production_clean,
        clean_pct: 100.0,
    };
    for (p, c) in [(3, 2), (0, 0)] {
        let r = run(view(p, c));
        assert_eq!(r.verdict(), "BLOCK", "{p}/{c}: {:#}", r.json);
        assert_eq!(r.json["ledger"]["clean"], false, "{p}/{c}");
    }
    let r = run(view(3, 3));
    assert_eq!(r.verdict(), "PASS", "positive control: {:#}", r.json);
    assert_eq!(r.json["ledger"]["clean"], true);
}
