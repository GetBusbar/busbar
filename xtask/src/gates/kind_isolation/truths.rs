//! `kind-isolation:truths` — THE THREE PLACES THAT NAME THE PLUGIN KINDS SAY THE SAME THING.
//!
//! DECISIONS #3 (locked) concluded the taxonomy: **seven plugin kinds** — store, secret, auth,
//! hook, export, plane, transport. `auth` is ONE kind (inbound-verify and outbound-sign are
//! OPERATIONS of it; there is no separate `egress-auth` kind). `transport` is ONE kind. `control`
//! (admin/oauth2 = cleanliness crates, #5) and `dialect` (a thing INSIDE a plane, #4) are NOT
//! kinds; `unit`/`loader`/`abi` are core/TCB infra, not plugin kinds.
//!
//! FOUR statements of that taxonomy live in this repository and nothing else compares them:
//!
//! * the gate's own KIND TABLE (`xtask/src/gates/kind_isolation.rs`), the MATCHER, which decides
//!   what a crate name resolves to — handed in as `table_kinds`;
//! * `qa/construction.toml [gate.plugin_kinds]`, the SCOPE, which decides which directories each
//!   plugin kind's construction rules read;
//! * `qa/kind-isolation.toml`, the LEDGER, whose `[[cell]]`/`[[edge]]` rows name a kind per row;
//! * `busbar_contract::Kind` itself, the ENUM — the code the decision is encoded IN, read as its
//!   compiled `Kind::ALL` variant set. The three data files a decision can DRIFT from; the enum is
//!   the decision, and an 8th variant (a resurrected `EgressAuth`) is a code change that would slip
//!   every data-file check, so it is reconciled here too.
//!
//! They are not four copies of one list — each is for something different — and that is exactly why
//! they could drift. This row compares them, in both directions, against the CONCLUDED 7-kind model,
//! and any disagreement is RED. `ARCHITECTURE.md` is owned elsewhere and is NOT a
//! left-hand side here: the code and its two data files must agree among themselves, on the decision
//! DECISIONS #3 locked, without waiting on prose.
//!
//! The stale 10-kind model reached this row through `control`, `dialect` and the
//! `egress-auth`/`pure_auth` split. Each is now a NAMED REFUSAL ([`FORBIDDEN_KINDS`]): a table row,
//! a construction key or a ledger row that still names one is the drift, reported by name.

use std::collections::BTreeSet;

use crate::ctx::Ctx;
use crate::ledger::Row;

use super::{CrateInfo, CONSTRUCTION_KIND_KEYS};

pub const ROW_TRUTHS: &str = "kind-isolation:truths";

/// The two data files the code is reconciled against.
pub const CONSTRUCTION: &str = "qa/construction.toml";
pub const LEDGER: &str = "qa/kind-isolation.toml";

/// DECISIONS #3 (locked): the SEVEN plugin kinds, in the gate's own spelling (the design writes
/// `hook`; the table writes `hooks`). Every one must be a row of the kind table and must have a
/// construction scope, or a plugin kind is a kind nothing measures.
const PLUGIN_KINDS: &[&str] = &[
    "store",
    "secret",
    "auth",
    "hooks",
    "export",
    "plane",
    "transport",
];

/// The words the STALE 10-kind model named as kinds and DECISIONS #3/#4/#5 struck. None of the three
/// vocabularies may name any of them: `control` and `dialect` are not kinds, and the auth kind has
/// no separate `egress-auth` (the `pure_auth`/`egress_auth` construction split is collapsed into one
/// `auth`). Each spelling the data files could carry is listed so the refusal names it.
const FORBIDDEN_KINDS: &[&str] = &[
    "control",
    "dialect",
    "egress-auth",
    "egress_auth",
    "pure_auth",
];

/// The seven locked kinds in the ENUM's own spelling — `busbar_contract::Kind`'s `Display`/`name`
/// (the design writes `hook`; the gate's kind TABLE writes `hooks`, so this list is NOT
/// [`PLUGIN_KINDS`]). This is the left-hand side the compiled variant set is reconciled against.
const CONTRACT_KIND_NAMES: &[&str] = &[
    "plane",
    "transport",
    "auth",
    "store",
    "secret",
    "hook",
    "export",
];

/// Reconcile the live `busbar_contract::Kind` variant set (its `Display` names, HANDED IN) against
/// the seven locked kinds — the fourth vocabulary [`rule_truths`] compares, and the one the enum
/// itself defines. Handed in rather than read here for the same reason `table_kinds` is: so the
/// selftest can plant an 8th variant this module cannot otherwise inject, and so a resurrected
/// `EgressAuth` variant (which Displays as `egress-auth`) is caught by name rather than by count.
fn reconcile_enum_kinds(enum_names: &[&str]) -> Vec<String> {
    let mut findings = Vec::new();
    let live: BTreeSet<&str> = enum_names.iter().copied().collect();
    let expected: BTreeSet<&str> = CONTRACT_KIND_NAMES.iter().copied().collect();
    for name in enum_names {
        if FORBIDDEN_KINDS.contains(name) {
            findings.push(format!(
                "forbidden-enum-kind\tbusbar_contract::Kind\tthe enum carries a variant that spells \
                 `{name}`, which DECISIONS #3/#4/#5 struck as a kind — auth is ONE kind and there is \
                 no separate `egress-auth`; delete the variant"
            ));
        } else if !expected.contains(name) {
            findings.push(format!(
                "unknown-enum-kind\tbusbar_contract::Kind\tthe enum carries a variant `{name}` that \
                 is not one of the seven locked kinds (DECISIONS #3)"
            ));
        }
    }
    for want in CONTRACT_KIND_NAMES {
        if !live.contains(want) {
            findings.push(format!(
                "missing-enum-kind\tbusbar_contract::Kind\t`{want}` is one of the seven locked kinds \
                 (DECISIONS #3) and the enum has no variant that spells it"
            ));
        }
    }
    findings
}

/// THE ROW. `table_kinds` is the gate's own kind table, handed in rather than read here so this
/// module cannot drift from the table it is reconciling.
pub fn rule_truths(cx: &Ctx, table_kinds: &[&str], crates: &[CrateInfo]) -> Row {
    let mut findings: Vec<String> = Vec::new();
    let table: BTreeSet<&str> = table_kinds.iter().copied().collect();

    // ── truth 1: the KIND TABLE ─────────────────────────────────────────────────────────────────
    for pk in PLUGIN_KINDS {
        if !table.contains(pk) {
            findings.push(format!(
                "no-table-row\tKIND TABLE\t`{pk}` is one of the seven plugin kinds (DECISIONS #3) \
                 and is in no row of the kind table — a kind the decision states and the gate \
                 cannot recognise is a kind nothing measures"
            ));
        }
    }
    for bad in FORBIDDEN_KINDS {
        if table.contains(bad) {
            findings.push(format!(
                "forbidden-kind\tKIND TABLE\t`{bad}` is not a kind (DECISIONS #3/#4/#5) and the \
                 kind table still carries a row for it; strike the row"
            ));
        }
    }

    // ── truth 2: the CONSTRUCTION ceilings, in BOTH directions ───────────────────────────────────
    match cx.read(CONSTRUCTION) {
        Ok(text) => {
            let keys = super::plugin_kind_keys(&text);
            // Every CONSTRUCTION_KIND_KEYS translation is stale-checked both ways.
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
            }
            // A construction key that maps onto no kind here is the second vocabulary drifting, and
            // a key naming a FORBIDDEN kind is the stale taxonomy surviving in the ceilings file.
            let mapped: BTreeSet<&str> = CONSTRUCTION_KIND_KEYS.iter().map(|(k, _)| *k).collect();
            for key in &keys {
                if FORBIDDEN_KINDS.contains(&key.as_str()) {
                    findings.push(format!(
                        "forbidden-construction-kind\t{CONSTRUCTION}\t[gate.plugin_kinds] declares \
                         `{key}`, which DECISIONS #3/#4/#5 struck as a kind; strike the key"
                    ));
                } else if !mapped.contains(key.as_str()) {
                    findings.push(format!(
                        "unmapped-construction-kind\t{CONSTRUCTION}\t[gate.plugin_kinds] declares \
                         `{key}`, which maps onto no kind in CONSTRUCTION_KIND_KEYS; map it or \
                         strike it"
                    ));
                }
            }
            // EVERY PLUGIN KIND HAS A CONSTRUCTION SCOPE. A plugin kind with no `[gate.plugin_kinds]`
            // key is a kind no construction rule reads a single file of.
            let scoped: BTreeSet<&str> = CONSTRUCTION_KIND_KEYS.iter().map(|(_, k)| *k).collect();
            for pk in PLUGIN_KINDS {
                if !scoped.contains(pk) {
                    findings.push(format!(
                        "unscoped-plugin-kind\t{CONSTRUCTION}\t`{pk}` is a plugin kind (DECISIONS \
                         #3) and [gate.plugin_kinds] scopes no directory to it, so no construction \
                         rule reads a single file of it"
                    ));
                }
            }
        }
        Err(e) => findings.push(format!(
            "unreadable\t{CONSTRUCTION}\t{e} — the second vocabulary cannot be compared"
        )),
    }

    // ── truth 3: the LEDGER, which must not carry the stale taxonomy ──────────────────────────────
    match cx.read(LEDGER) {
        Ok(text) => {
            for (kind, count) in ledger_kinds(&text) {
                if FORBIDDEN_KINDS.contains(&kind.as_str()) {
                    findings.push(format!(
                        "forbidden-ledger-kind\t{LEDGER}\t{count} row(s) name the kind `{kind}`, \
                         which DECISIONS #3/#4/#5 struck; strike the rows — the ledger is measuring \
                         a kind the taxonomy no longer has"
                    ));
                } else if !table.contains(kind.as_str()) {
                    findings.push(format!(
                        "unknown-ledger-kind\t{LEDGER}\t{count} row(s) name the kind `{kind}`, \
                         which is in no row of the kind table; the ledger and the matcher are two \
                         taxonomies"
                    ));
                }
            }
        }
        Err(e) => findings.push(format!(
            "unreadable\t{LEDGER}\t{e} — the third vocabulary cannot be compared"
        )),
    }

    // ── truth 4: the ENUM ITSELF — the compiled `busbar_contract::Kind` variant set is exactly the
    // seven locked kinds ──────────────────────────────────────────────────────────────────────────
    // The three vocabularies above are data files a decision can drift from; the enum is the code the
    // decision is encoded IN, and until this row nothing compared the variant set to the seven. An
    // 8th variant (a resurrected `EgressAuth`) would pass every check above — it is a code change, not
    // a data one — so this reads `Kind::ALL` (kept complete by the enum's own exhaustive-match guard)
    // and reconciles it, closing the gap that let the split return invisibly.
    let enum_names: Vec<&str> = busbar_contract::Kind::ALL.iter().map(|k| k.name()).collect();
    findings.extend(reconcile_enum_kinds(&enum_names));

    findings.sort();
    findings.dedup();
    if findings.is_empty() {
        let live: BTreeSet<&str> = crates.iter().filter_map(|c| c.kind).collect();
        return Row::pass(
            ROW_TRUTHS,
            "the kind table, the construction ceilings, the kind-isolation ledger and the compiled \
             busbar_contract::Kind enum name the same seven plugin kinds and infra families",
            format!(
                "{} plugin kind(s), {} table row(s), {} construction key(s), {} kind(s) live in the \
                 census, {} enum variant(s) — reconciled on the DECISIONS #3 taxonomy in all four \
                 vocabularies",
                PLUGIN_KINDS.len(),
                table.len(),
                CONSTRUCTION_KIND_KEYS.len(),
                live.len(),
                busbar_contract::Kind::ALL.len(),
            ),
        );
    }
    Row::fail(
        ROW_TRUTHS,
        "the three places that name the plugin kinds do not agree on the DECISIONS #3 taxonomy",
        format!("{} finding(s): {}", findings.len(), findings.join(" | ")),
    )
}

/// The kinds a ledger names, with how many rows name each. ONLY the tables whose fields are KINDS are
/// read: a `[[cell]]`'s `kind`, an `[[edge]]`'s `from` and `to`, and a `[[registered]]`/`[[announced]]`
/// row's `kind`. `[[dep]]` and `[[transitional]]` carry CRATE names in their `from`/`to`, not kinds,
/// so they are skipped — reading them would report every crate as an unknown kind. Read as a bag so a
/// stale-taxonomy word is reported with its weight rather than once.
fn ledger_kinds(text: &str) -> Vec<(String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut table = "";
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with("[[") {
            table = t.trim_start_matches("[[").trim_end_matches("]]").trim();
            continue;
        }
        if t.starts_with('[') {
            table = "";
            continue;
        }
        if t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let is_kind_field = match table {
            "cell" | "registered" | "announced" => key == "kind",
            "edge" => key == "from" || key == "to",
            _ => false,
        };
        if !is_kind_field {
            continue;
        }
        let word = v.trim().trim_matches('"').trim();
        if word.is_empty() {
            continue;
        }
        *counts.entry(word.to_string()).or_default() += 1;
    }
    counts.into_iter().collect()
}

/// THE RED PROOFS, one per disagreement the row is written to catch. Each plants the DATA FILE the
/// drift would live in rather than the code that reads it, because the finding is always about a
/// data file having drifted from the code the decision is encoded in.
pub fn selftest<'a>(
    cx: &Ctx,
    gate: &'a dyn crate::gates::Gate,
    report: &mut crate::gates::Report<'a>,
) {
    use crate::ctx::Overlay;
    use crate::gates::{prove_rows_green, prove_rows_red, Case, CasePlan, Expect};

    report.push(prove_rows_green(
        cx,
        gate,
        "on this tree the table, the ceilings and the ledger name the same seven plugin kinds",
        &[ROW_TRUTHS],
        Overlay::new(),
    ));

    // TRUTH 4'S RED-BEFORE-GREEN — the enum-variant assertion. The enum is COMPILED IN, not a data
    // file, so it cannot be planted through an `Overlay`; the check is a pure function handed the
    // variant names (exactly as `table_kinds` is handed to the row). These two cases feed it the REAL
    // `Kind::ALL` set (must be clean) and a set with an 8th `egress-auth` variant planted back in
    // (must go RED, naming it) — the same reconciliation the row runs against the compiled enum.
    report.push(CasePlan::new(|| {
        let live: Vec<&str> = busbar_contract::Kind::ALL.iter().map(|k| k.name()).collect();
        let findings = reconcile_enum_kinds(&live);
        Case {
            name: "the live busbar_contract::Kind variant set is exactly the seven locked kinds"
                .to_string(),
            covers: vec![ROW_TRUTHS.to_string()],
            expected: Expect::Green,
            got: if findings.is_empty() {
                Expect::Green
            } else {
                Expect::Red { naming: findings }
            },
        }
    }));
    report.push(CasePlan::new(|| {
        // The 8th kind DECISIONS #3 struck, planted back into the variant-name list.
        let planted = [
            "plane",
            "transport",
            "auth",
            "store",
            "secret",
            "hook",
            "export",
            "egress-auth",
        ];
        let findings = reconcile_enum_kinds(&planted);
        Case {
            name: "an 8th `egress-auth` variant planted into the Kind set is refused".to_string(),
            covers: vec![ROW_TRUTHS.to_string()],
            expected: Expect::Red {
                naming: vec!["forbidden-enum-kind".to_string(), "egress-auth".to_string()],
            },
            got: if findings.is_empty() {
                Expect::Green
            } else {
                Expect::Red { naming: findings }
            },
        }
    }));

    // THE MEASURED HOLE. Deleting a plugin kind's key from `[gate.plugin_kinds]` left this gate
    // GREEN and left the construction gate's failing-row count unchanged: every rule scoped by that
    // key scanned the empty set and reported clean.
    if let Ok(text) = cx.read(CONSTRUCTION) {
        let cut: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("plane = ["))
            .collect::<Vec<_>>()
            .join("\n");
        let mut ov = Overlay::new();
        ov.set(CONSTRUCTION, cut);
        report.push(prove_rows_red(
            cx,
            gate,
            "a plugin-kind key that vanished from the ceilings file is refused",
            &[ROW_TRUTHS],
            ov,
            &["missing-construction-kind", "`plane`"],
        ));
    } else {
        report.note_infra_failure(
            "the ceilings file could not be read, so the cross-check cannot be planted",
        );
    }

    // THE STALE TAXONOMY SURVIVING IN THE CEILINGS FILE. A `control` or `dialect` key is the
    // 10-kind model coming back, and DECISIONS #4/#5 struck both.
    if let Ok(text) = cx.read(CONSTRUCTION) {
        let mut ov = Overlay::new();
        ov.set(
            CONSTRUCTION,
            text.replace(
                "[gate.plugin_kinds]\n",
                "[gate.plugin_kinds]\ndialect = [\"crates/busbar-plane-*-*\"]\n",
            ),
        );
        report.push(prove_rows_red(
            cx,
            gate,
            "a struck kind re-declared as a construction scope is refused (dialect is not a kind)",
            &[ROW_TRUTHS],
            ov,
            &["forbidden-construction-kind", "dialect"],
        ));
    } else {
        report.note_infra_failure("the ceilings file could not be read, so it cannot be planted");
    }

    // THE STALE TAXONOMY SURVIVING IN THE LEDGER. A `[[cell]]` naming the `control` kind is the
    // matrix measuring a kind the taxonomy no longer has.
    if let Ok(text) = cx.read(LEDGER) {
        let mut ov = Overlay::new();
        ov.set(
            LEDGER,
            format!(
                "{text}\n[[cell]]\ncrate = \"busbar-admin\"\nkind = \"control\"\ncount = \"1\"\n"
            ),
        );
        report.push(prove_rows_red(
            cx,
            gate,
            "a ledger row naming a struck kind is refused (control is not a kind)",
            &[ROW_TRUTHS],
            ov,
            &["forbidden-ledger-kind", "control"],
        ));
    } else {
        report.note_infra_failure("the ledger could not be read, so it cannot be planted");
    }

    registry_selftest(cx, gate, report);
}

/// THE REGISTRY ROW'S SUB-CHECKS, ONE PLANT EACH.
///
/// `kind-isolation:registry` is one row over many independent refusals, and only some of them had a
/// plant. That is the shape of an honest-looking selftest that is not one: gutting a whole rule is
/// caught, but gutting ONE ARM of a rule with several is not.
fn registry_selftest<'a>(
    cx: &Ctx,
    gate: &'a dyn crate::gates::Gate,
    report: &mut crate::gates::Report<'a>,
) {
    use crate::ctx::Overlay;
    use crate::gates::prove_rows_red;

    if let Ok(text) = cx.read(CONSTRUCTION) {
        // A key here that names no kind in the table is the second vocabulary starting to drift.
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

    #[test]
    fn the_seven_plugin_kinds_are_the_decisions_3_taxonomy() {
        assert_eq!(PLUGIN_KINDS.len(), 7);
        for k in [
            "store",
            "secret",
            "auth",
            "hooks",
            "export",
            "plane",
            "transport",
        ] {
            assert!(PLUGIN_KINDS.contains(&k), "{k} is a plugin kind");
        }
    }

    #[test]
    fn the_struck_kinds_are_forbidden_in_every_vocabulary() {
        for k in [
            "control",
            "dialect",
            "egress-auth",
            "egress_auth",
            "pure_auth",
        ] {
            assert!(
                FORBIDDEN_KINDS.contains(&k),
                "{k} is struck (DECISIONS #3/#4/#5)"
            );
        }
        // A plugin kind can never also be forbidden.
        for pk in PLUGIN_KINDS {
            assert!(
                !FORBIDDEN_KINDS.contains(pk),
                "{pk} is both plugin and forbidden"
            );
        }
    }

    #[test]
    fn the_compiled_enum_is_exactly_the_seven_locked_kinds() {
        // The real variant set reconciles clean, in the enum's own Display spelling.
        let live: Vec<&str> = busbar_contract::Kind::ALL.iter().map(|k| k.name()).collect();
        assert!(
            reconcile_enum_kinds(&live).is_empty(),
            "the compiled Kind set is not the seven locked kinds: {:?}",
            reconcile_enum_kinds(&live)
        );
        // And CONTRACT_KIND_NAMES is the enum's own truth, not a hand-kept second copy.
        assert_eq!(live, CONTRACT_KIND_NAMES);
    }

    #[test]
    fn a_resurrected_egress_auth_variant_is_named_red() {
        let planted = [
            "plane",
            "transport",
            "auth",
            "store",
            "secret",
            "hook",
            "export",
            "egress-auth",
        ];
        let findings = reconcile_enum_kinds(&planted);
        assert!(
            findings.iter().any(|f| f.contains("egress-auth")),
            "an 8th egress-auth variant must be named: {findings:?}"
        );
        // A dropped kind is caught the other way too.
        let short = ["plane", "transport", "auth", "store", "secret", "hook"];
        assert!(reconcile_enum_kinds(&short)
            .iter()
            .any(|f| f.contains("missing-enum-kind") && f.contains("export")));
    }

    #[test]
    fn the_ledger_kinds_reader_bags_cell_and_edge_words() {
        let text = "[[cell]]\ncrate = \"c\"\nkind = \"plane\"\ncount = \"1\"\n\
                    [[edge]]\nfrom = \"plane\"\nto = \"contract\"\n# kind = \"ignored comment\"\n";
        let bag: std::collections::BTreeMap<String, usize> =
            ledger_kinds(text).into_iter().collect();
        assert_eq!(bag.get("plane"), Some(&2));
        assert_eq!(bag.get("contract"), Some(&1));
        assert!(!bag.contains_key("ignored comment"), "comments are skipped");
    }
}
