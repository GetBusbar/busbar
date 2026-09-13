//! `kind-isolation:truths` — THE THREE PLACES THAT NAME THE PLUGIN KINDS SAY THE SAME THING.
//!
//! There are three statements of the taxonomy in this repository and nothing compared them:
//!
//! * `docs/design/ARCHITECTURE.md` is normative and states TEN kinds — plane, dialect, transport,
//!   **control**, auth, egress-auth, store, secret, hook, export — plus one core row, `unit`;
//! * the gate's own kind table is the MATCHER, which decides what a crate name resolves to;
//! * `qa/construction.toml [gate.plugin_kinds]` is the SCOPE, which decides which directories each
//!   kind's construction rules read.
//!
//! They are not three copies of one list — each is for something different — and that is exactly why
//! they could drift. On the base this row was written against, `[gate.plugin_kinds]` named ten keys
//! and had no `dialect`, no `unit` and no `control`: three of the eleven kinds the design states had
//! NO construction scope at all, and all three files reported green about a taxonomy none of them
//! shared. This row compares them, in both directions, and any disagreement is RED.
//!
//! The two translation tables ([`ARCH_KIND_KEYS`] here and the gate's `CONSTRUCTION_KIND_KEYS`) are
//! the only place a difference of SPELLING is allowed to live, and every entry of each is
//! stale-checked: a translation whose left side is no longer in the document, or whose right side is
//! no longer in the table, is itself a finding — the rule every waiver in this tree is held to.
//!
//! ## THE DIRECTION THAT WAS MISSING
//!
//! The registry row already refused a `[gate.plugin_kinds]` key that maps onto no kind here. The
//! REVERSE was unchecked, and the hole was measured: deleting `plane = [...]` from
//! `[gate.plugin_kinds]` left this gate GREEN and left the construction gate's failing-row count
//! unchanged, because a kind with no globs reads as "the kind simply has no crate yet" and every
//! rule scoped by it then scans the empty set and reports clean. That is the passing answer to a
//! rule that has been switched off, and it is what `missing-construction-kind` is for.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::Ctx;
use crate::ledger::Row;

use super::{CrateInfo, CONSTRUCTION_KIND_KEYS};

pub const ROW_TRUTHS: &str = "kind-isolation:truths";

/// The normative kind list, and the file that carries it.
pub const ARCH: &str = "docs/design/ARCHITECTURE.md";
pub const CONSTRUCTION: &str = "qa/construction.toml";

/// The sentence the list is read out of. Anchored on its own words rather than on a section number,
/// so renumbering the document does not silently turn this row into a reader of nothing.
const KINDS_OPEN: &str = "plugin kinds** —";
const KINDS_CLOSE: &str = "— and one core row,";

/// The document's word for a kind, mapped onto the kind table's name for it.
///
/// Only two differ, and both differences are old: the document writes `hook` where the table writes
/// `hooks`, and it splits `auth` from `egress-auth` where the table has one `auth` kind whose
/// members are both. Every entry is stale-checked in both directions by [`rule_truths`].
const ARCH_KIND_KEYS: &[(&str, &str)] = &[
    ("plane", "plane"),
    ("dialect", "dialect"),
    ("transport", "transport"),
    ("control", "control"),
    ("auth", "auth"),
    ("egress-auth", "auth"),
    ("store", "store"),
    ("secret", "secret"),
    ("hook", "hooks"),
    ("export", "export"),
    ("unit", "unit"),
];

/// The sentence that names the crates the design deliberately does NOT make kinds.
const TCB_CLOSE: &str = "are TCB crates, not kinds";

/// The number words the document is allowed to count in. A list whose length does not match the word
/// in front of it is a list somebody added to without re-reading the sentence.
const NUMBER_WORDS: &[(&str, usize)] = &[
    ("eight", 8),
    ("nine", 9),
    ("ten", 10),
    ("eleven", 11),
    ("twelve", 12),
    ("thirteen", 13),
];

/// THE ROW. `table_kinds` is the gate's own kind table, handed in rather than read here so this
/// module cannot drift from the table it is reconciling.
pub fn rule_truths(cx: &Ctx, table_kinds: &[&str], crates: &[CrateInfo]) -> Row {
    let mut findings: Vec<String> = Vec::new();
    let table: BTreeSet<&str> = table_kinds.iter().copied().collect();

    // ── truth 1: the document ───────────────────────────────────────────────────────────────────
    let arch_text = cx.read(ARCH).unwrap_or_default();
    let doc_kinds = match cx
        .read(ARCH)
        .map_err(|e| e.to_string())
        .and_then(|t| arch_kinds(&t))
    {
        Ok(k) => k,
        Err(e) => {
            return Row::fail(
                ROW_TRUTHS,
                "the normative kind list could not be read at all",
                format!(
                    "{ARCH}: {e} — the taxonomy's own statement of itself is the left-hand side of \
                     every comparison below, and a comparison against nothing is not one that \
                     passed"
                ),
            )
        }
    };
    // THE TWO KEYS THE DESIGN EXCUSES BY NAME. `loader` and `abi` are `[gate.plugin_kinds]` keys
    // and the document says in the same paragraph as the kind list that they are TCB crates and NOT
    // kinds — so demanding they be in the list would be demanding the document contradict itself.
    // The excuse is READ FROM THE DOCUMENT rather than written here, so a key that stops being
    // excused there stops being excused here on the same commit.
    let tcb = arch_tcb(&arch_text);
    let arch_map: BTreeMap<&str, &str> = ARCH_KIND_KEYS.iter().copied().collect();
    for word in &doc_kinds {
        match arch_map.get(word.as_str()) {
            Some(kind) if table.contains(kind) => {}
            Some(kind) => findings.push(format!(
                "no-table-row\t{ARCH}\t`{word}` is normative and maps onto `{kind}`, which is in no \
                 row of the kind table — a kind the design states and the gate cannot recognise is \
                 a kind nothing measures"
            )),
            None => findings.push(format!(
                "untranslated-kind\t{ARCH}\t`{word}` is in the normative list and this gate has no \
                 word for it; add it to the kind table and to ARCH_KIND_KEYS, or the design and the \
                 instrument are two taxonomies"
            )),
        }
    }
    for (word, kind) in ARCH_KIND_KEYS {
        if !doc_kinds.iter().any(|w| w == word) {
            findings.push(format!(
                "stale-translation\tARCH_KIND_KEYS\t`{word}` -> `{kind}` translates a word the \
                 normative list no longer uses; strike it"
            ));
        }
        if !table.contains(kind) {
            findings.push(format!(
                "stale-translation\tARCH_KIND_KEYS\t`{word}` -> `{kind}` names no row of the kind \
                 table; strike it or restore the row"
            ));
        }
    }

    // ── truth 3: the ceilings file, in BOTH directions ──────────────────────────────────────────
    match cx.read(CONSTRUCTION) {
        Ok(text) => {
            let keys = super::plugin_kind_keys(&text);
            for (key, kind) in CONSTRUCTION_KIND_KEYS {
                if !keys.iter().any(|k| k == key) {
                    findings.push(format!(
                        "missing-construction-kind\t{CONSTRUCTION}\t[gate.plugin_kinds] no longer \
                         declares `{key}` (the `{kind}` kind). Every construction rule scoped by \
                         that key now scans the empty set and reports clean, which is the passing \
                         answer to a rule that has been switched off"
                    ));
                }
                if !table.contains(kind) {
                    findings.push(format!(
                        "stale-translation\tCONSTRUCTION_KIND_KEYS\t`{key}` -> `{kind}` names no \
                         row of the kind table; strike it or restore the row"
                    ));
                }
                if !tcb.iter().any(|t| t == key)
                    && !doc_kinds
                        .iter()
                        .any(|w| arch_map.get(w.as_str()) == Some(kind))
                {
                    findings.push(format!(
                        "unstated-construction-kind\t{ARCH}\t[gate.plugin_kinds] scopes `{key}` to \
                         the `{kind}` kind, and the normative kind list neither names that kind nor \
                         excuses `{key}` as a TCB crate"
                    ));
                }
            }
        }
        Err(e) => findings.push(format!(
            "unreadable\t{CONSTRUCTION}\t{e} — the third vocabulary cannot be compared"
        )),
    }

    // ── EVERY KIND THE DESIGN STATES HAS A CONSTRUCTION SCOPE ───────────────────────────────────
    //
    // The kind table carries rows the design does not state as plugin kinds — `kernel`, `caps`,
    // `contract`, `root`, the retiring `legacy` spine — and that is correct: they are what the
    // matcher needs in order to say what a crate is NOT. The claim that must hold in the other
    // direction is narrower and is the one that was false: a kind the DESIGN states, with no
    // `[gate.plugin_kinds]` key, is a kind no construction rule reads a single file of.
    let construction: BTreeSet<&str> = CONSTRUCTION_KIND_KEYS.iter().map(|(_, k)| *k).collect();
    let stated: BTreeSet<&str> = doc_kinds
        .iter()
        .filter_map(|w| arch_map.get(w.as_str()).copied())
        .collect();
    for kind in stated.iter().filter(|k| !construction.contains(*k)) {
        findings.push(format!(
            "unscoped-kind\t{CONSTRUCTION}\t`{kind}` is a kind the design states and \
             [gate.plugin_kinds] scopes no directory to it, so no construction rule reads a single \
             file of it"
        ));
    }

    findings.sort();
    findings.dedup();
    if findings.is_empty() {
        let live: BTreeSet<&str> = crates.iter().filter_map(|c| c.kind).collect();
        return Row::pass(
            ROW_TRUTHS,
            "the design, the kind table and the ceilings file name the same kinds",
            format!(
                "{} normative kind(s), {} table row(s), {} construction key(s), {} kind(s) live in \
                 the census — reconciled in both directions",
                doc_kinds.len(),
                table.len(),
                CONSTRUCTION_KIND_KEYS.len(),
                live.len()
            ),
        );
    }
    Row::fail(
        ROW_TRUTHS,
        "the three places that name the plugin kinds do not agree",
        format!("{} finding(s): {}", findings.len(), findings.join(" | ")),
    )
}

/// The normative kind list, read out of the sentence that states it.
///
/// THE COUNT WORD IS READ TOO. "ten plugin kinds" in front of eleven names is the drift this is
/// most likely to catch, because adding a kind to the list is a smaller edit than re-reading the
/// sentence around it.
pub fn arch_kinds(text: &str) -> Result<Vec<String>, String> {
    let open = text.find(KINDS_OPEN).ok_or_else(|| {
        format!(
            "no sentence containing `{KINDS_OPEN}` — the normative list has been reworded, and this \
             row is reading nothing"
        )
    })?;
    let rest = &text[open + KINDS_OPEN.len()..];
    let close = rest
        .find(KINDS_CLOSE)
        .ok_or_else(|| format!("the list opened and no `{KINDS_CLOSE}` closed it"))?;
    let mut kinds: Vec<String> = rest[..close]
        .split(',')
        .map(|s| s.trim().trim_matches('*').trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if kinds.is_empty() {
        return Err("the normative list is empty".to_string());
    }

    // The count word sits immediately before `plugin kinds**`, inside the same emphasis.
    let head = &text[..open];
    let word = head
        .rsplit(|c: char| !c.is_ascii_alphabetic())
        .find(|w| !w.is_empty())
        .unwrap_or("");
    // A LIST WITH NO STATED SIZE HAS NOTHING TO CHECK AGAINST, so a sentence that does not count
    // is refused before the list it introduces is read as agreement.
    let Some((word_read, stated)) = NUMBER_WORDS.iter().find(|(w, _)| *w == word) else {
        return Err(format!(
            "`{word}` is not a number word this row can count in; the sentence must state how many \
             kinds it is about, or the list has no stated size to check against"
        ));
    };
    if *stated != kinds.len() {
        return Err(format!(
            "the sentence says `{word_read}` and lists {} — a list somebody added to without \
             re-reading the sentence in front of it",
            kinds.len()
        ));
    }

    // The core row is named after the list and is a kind for every purpose this gate has.
    let tail = &rest[close + KINDS_CLOSE.len()..];
    if let Some(core) = tail.split('`').nth(1) {
        if !core.trim().is_empty() {
            kinds.push(core.trim().to_string());
        }
    }
    Ok(kinds)
}

/// The `[gate.plugin_kinds]` keys the document excuses from being kinds, read out of its own
/// sentence: "`loader` and `abi` are TCB crates, not kinds".
pub fn arch_tcb(text: &str) -> Vec<String> {
    let Some(at) = text.find(TCB_CLOSE) else {
        return Vec::new();
    };
    // The names are the backticked words immediately before the clause; take the last few ticks of
    // the line rather than the whole document.
    let head = &text[..at];
    let line_start = head.rfind('\n').map(|i| i + 1).unwrap_or(0);
    head[line_start..]
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// THE RED PROOFS, one per disagreement the row is written to catch.
///
/// Each plants the DOCUMENT the truth lives in rather than the code that reads it, because the
/// finding is always about a document having drifted from the other two — a plant in the reader
/// would prove the reader can be broken, which is not the claim.
pub fn selftest<'a>(
    cx: &Ctx,
    gate: &'a dyn crate::gates::Gate,
    report: &mut crate::gates::Report<'a>,
) {
    use crate::ctx::Overlay;
    use crate::gates::{prove_rows_green, prove_rows_red};

    report.push(prove_rows_green(
        cx,
        gate,
        "on this tree the design, the kind table and the ceilings file name the same kinds",
        &[ROW_TRUTHS],
        Overlay::new(),
    ));

    // THE MEASURED HOLE. Deleting `plane = [...]` from `[gate.plugin_kinds]` left this gate GREEN
    // and left the construction gate's failing-row count unchanged: every rule scoped by that key
    // scanned the empty set and reported clean.
    if let Ok(text) = cx.read(CONSTRUCTION) {
        let cut: String = text
            .lines()
            .filter(|l| !l.starts_with("plane = ["))
            .collect::<Vec<_>>()
            .join("\n");
        let mut ov = Overlay::new();
        ov.set(CONSTRUCTION, cut);
        report.push(prove_rows_red(
            cx,
            gate,
            "a kind vocabulary key that vanished from the ceilings file is refused",
            &[ROW_TRUTHS],
            ov,
            &["missing-construction-kind", "`plane`"],
        ));
    } else {
        report.note_infra_failure(
            "the ceilings file could not be read, so the cross-check cannot be planted",
        );
    }

    // THE DOCUMENT'S OWN SENTENCE. Striking a kind from the normative list without re-reading the
    // count word in front of it is the likelier drift, and it is the one this catches first.
    if let Ok(text) = cx.read(ARCH) {
        let mut ov = Overlay::new();
        ov.set(ARCH, text.replace(", **control**,", ","));
        report.push(prove_rows_red(
            cx,
            gate,
            "a normative kind list that no longer matches its own count is refused, never half-read",
            &[ROW_TRUTHS],
            ov,
            &["says `ten` and lists 9", "could not be read at all"],
        ));
    } else {
        report
            .note_infra_failure("ARCHITECTURE.md could not be read, so the list cannot be planted");
    }

    registry_selftest(cx, gate, report);
}

/// THE REGISTRY ROW'S SUB-CHECKS, ONE PLANT EACH.
///
/// `kind-isolation:registry` is one row over many independent refusals, and only some of them had a
/// plant. That is the shape of an honest-looking selftest that is not one: gutting a whole rule is
/// caught, because the row stops going red under the case written for it, but gutting ONE ARM of a
/// rule with several is not — the row still reds under the other arms' plants and the report still
/// says "the gate is proven RED-able". The `unmapped-kind` arm was proven gut-able exactly that way:
/// with its match arm emptied the gate ran GREEN over the tree and the self-test reported every case
/// passing.
fn registry_selftest<'a>(
    cx: &Ctx,
    gate: &'a dyn crate::gates::Gate,
    report: &mut crate::gates::Report<'a>,
) {
    use crate::ctx::Overlay;
    use crate::gates::prove_rows_red;

    if let Ok(text) = cx.read(CONSTRUCTION) {
        // A key here that names no kind there is the second vocabulary starting to drift.
        let mut ov = Overlay::new();
        ov.set(
            CONSTRUCTION,
            text.replace(
                "[gate.plugin_kinds]\n",
                "[gate.plugin_kinds]\nconductor = [\"crates/busbar-conductor-*\"]\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            gate,
            "a plugin-kind key that maps onto no kind in the table is refused",
            &[super::ROW_REGISTRY],
            ov,
            &["unmapped-kind", "conductor"],
        ));

        // The table renamed away: the cross-check is now reading nothing, which is not agreement.
        let mut ov = Overlay::new();
        ov.set(
            CONSTRUCTION,
            text.replace("[gate.plugin_kinds]", "[gate.plugin_kinds_renamed_away]"),
        );
        report.push(prove_rows_red(
            cx,
            gate,
            "a plugin-kind table that was renamed away leaves the cross-check reading nothing",
            &[super::ROW_REGISTRY],
            ov,
            &["no-construction-kinds"],
        ));
    }

    // The file gone entirely. `cx.read` failing is its own arm, and a rule that goes quiet when its
    // second input vanishes is a rule with a one-file off switch.
    let mut ov = Overlay::new();
    ov.remove(CONSTRUCTION);
    report.push(prove_rows_red(
        cx,
        gate,
        "the ceilings file absent is a refusal, not a comparison that found nothing",
        &[super::ROW_REGISTRY],
        ov,
        &["unreadable"],
    ));

    // THE CENSUS FLOOR. A census that finds almost nothing recognises almost everything, so the
    // floor is a rule and not a sanity check — and a rule owes a plant.
    let mut ov = Overlay::new();
    let mut removed = 0usize;
    if let Ok(dir) = std::fs::read_dir(cx.root().join("crates")) {
        let mut names: Vec<String> = dir
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let rel = format!("crates/{name}/Cargo.toml");
            if cx.exists(&rel) {
                ov.remove(&rel);
                removed += 1;
            }
        }
    }
    if removed > 0 {
        report.push(prove_rows_red(
            cx,
            gate,
            "a census that collapsed below its floor recognises almost everything, and is refused",
            &[super::ROW_REGISTRY],
            ov,
            &["floor"],
        ));
    } else {
        report.note_infra_failure(
            "no crate manifest could be removed, so the census floor cannot be planted",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTENCE: &str = "There are **ten plugin kinds** — plane, dialect, transport, \
                            **control**, auth, egress-auth, store, secret, hook, export — and one \
                            core row, `unit`, which is never loadable.";

    #[test]
    fn the_normative_list_is_read_with_its_core_row() {
        let k = arch_kinds(SENTENCE).expect("the sentence parses");
        assert_eq!(
            k,
            vec![
                "plane",
                "dialect",
                "transport",
                "control",
                "auth",
                "egress-auth",
                "store",
                "secret",
                "hook",
                "export",
                "unit"
            ]
        );
    }

    /// The count word is the cheap half of the check and the likelier drift: a kind is appended to
    /// the list and the word in front of it is not re-read.
    #[test]
    fn a_list_that_outgrew_its_own_count_word_is_refused() {
        let grown = SENTENCE.replace("export —", "export, ledger —");
        let e = arch_kinds(&grown).expect_err("eleven names under `ten` is a refusal");
        assert!(e.contains("says `ten` and lists 11"), "{e}");
    }

    /// The TCB excuse is the document's, not this file's: it is read from the sentence, so a key
    /// that stops being excused there stops being excused here on the same commit.
    #[test]
    fn the_tcb_excuse_is_read_from_the_document() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("the workspace root is the xtask crate's parent")
                .join(ARCH),
        )
        .expect("ARCHITECTURE.md is readable");
        let tcb = arch_tcb(&text);
        assert!(tcb.iter().any(|t| t == "loader"), "{tcb:?}");
        assert!(tcb.iter().any(|t| t == "abi"), "{tcb:?}");
        assert!(
            arch_tcb("nothing here says it").is_empty(),
            "an excuse that is not written down excuses nothing"
        );
    }

    #[test]
    fn a_reworded_sentence_is_a_refusal_and_never_an_empty_list() {
        assert!(arch_kinds("there are some kinds").is_err());
        assert!(arch_kinds("**ten plugin kinds** — plane, store").is_err());
    }

    /// Every translation is stale-checked by the row; this asserts the table itself is consistent
    /// with the committed sentence, so a typo here is a test failure rather than a gate finding
    /// nobody expected.
    #[test]
    fn every_translation_names_a_word_the_committed_sentence_uses() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("the workspace root is the xtask crate's parent")
                .join(ARCH),
        )
        .expect("ARCHITECTURE.md is readable");
        let doc = arch_kinds(&text).expect("the committed sentence parses");
        for (word, _) in ARCH_KIND_KEYS {
            assert!(
                doc.iter().any(|d| d == word),
                "ARCH_KIND_KEYS translates `{word}`, which the committed sentence does not use"
            );
        }
    }
}
