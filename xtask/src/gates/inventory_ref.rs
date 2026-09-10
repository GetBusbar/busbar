//! `cargo xtask gate inventory-ref` — EVERY DESIGN BINDING'S `inventory` COLUMN NAMES A FILE THAT
//! EXISTS, and the binding set it read is big enough for that claim to mean anything.
//!
//! This is the Rust successor to `scripts/inventory-ref-lint.py`. The design binding table says
//! "where a binding paraphrases its row, the row wins" — which binds nothing at all if the row a
//! binding cites lives in a file that was renamed or never existed. A pointer nobody can follow is
//! unfalsifiable, so it is the pointer, not the prose, that gets checked here.
//!
//! Like the Python it replaces, this deliberately does NOT resolve the finer-grained anchors
//! (section numbers, `BOOT-172`-style row ids, source line numbers) inside the cited file. Those
//! drift with every renumbering and the table's free-text formatting for them is not consistent
//! enough to parse without false positives. The FILE-level pointer is both load-bearing and
//! reliably checkable; the within-file anchor is neither.
//!
//! Four rules, four ledger rows, because the Python's single "list of problem strings" return type
//! hid three different ways of answering "no dangling references" that are not the same answer:
//!
//! 1. `inventory-ref:manifest` — the binding manifest was read, parsed, and carries the key the
//!    scanner reads bindings out of. The Python's `doc.get("bindings", [])` turned a RENAMED
//!    manifest key into an empty binding list and therefore into "zero dangling references", i.e.
//!    a PASS printed over a scanner that had just lost its entire input. A missing key, an
//!    unreadable file, malformed JSON and a binding entry with no `id` are each a named FAIL here.
//! 2. `inventory-ref:binding-floor` — at least [`BINDING_FLOOR`] bindings were discovered. A
//!    binding set that collapsed has nothing left to dangle, so "for each binding, assert the file
//!    exists" is vacuously true over it. Zero is never clean.
//! 3. `inventory-ref:prefix` — every `;`-separated segment of an `inventory` column either names a
//!    known inventory file by its prefix word, or is one of the two shapes that point at no
//!    inventory file at all (a bare backtick source path, a `PB-N` self-reference). Anything else
//!    is an unrecognized prefix, which is a pointer this lint cannot follow and must not pretend
//!    it did.
//! 4. `inventory-ref:file-exists` — the file a recognized prefix names is on disk.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_MANIFEST: &str = "inventory-ref:manifest";
pub const ROW_FLOOR: &str = "inventory-ref:binding-floor";
pub const ROW_PREFIX: &str = "inventory-ref:prefix";
pub const ROW_FILE: &str = "inventory-ref:file-exists";

/// The manifest the bindings are read out of, and the key inside it. Both are named in the FAIL
/// text so a rename reads as a rename rather than as an empty scan.
pub const BINDINGS_PATH: &str = "qa/design-bindings.json";
pub const BINDINGS_KEY: &str = "bindings";

/// The discovery floor under the binding count. Today's table carries ~103 bindings, so ordinary
/// work never approaches this, but it is far enough above zero that a manifest whose shape moved
/// cannot answer "no dangling references" by having no references.
pub const BINDING_FLOOR: usize = 40;

/// File-prefix word (as it appears in a binding's `inventory` column) -> the inventory file it
/// names. The order is the Python dict's order; no alias is a prefix of another, so the first
/// match is the only match either way.
pub const ALIASES: &[(&str, &str)] = &[
    (
        "auth-secrets",
        "docs/design/inventory/1.5.5-auth-secrets.md",
    ),
    ("config", "docs/design/inventory/1.5.5-config.md"),
    ("dialects", "docs/design/inventory/1.5.5-dialects.md"),
    (
        "governance",
        "docs/design/inventory/1.5.5-governance-billing.md",
    ),
    ("ops", "docs/design/inventory/1.5.5-ops-observability.md"),
    (
        "plugins-stores",
        "docs/design/inventory/1.5.5-plugins-stores.md",
    ),
    ("proxy-hooks", "docs/design/inventory/1.5.5-proxy-hooks.md"),
    (
        "routes-admin",
        "docs/design/inventory/1.5.5-routes-admin.md",
    ),
    ("1.5.5-behaviour", "docs/design/1.5.5-BEHAVIOUR.md"),
];

/// One known table-parsing artifact carried over verbatim from the Python: PB-20's binding text
/// embeds a literal pipe-joined string, and the unescaped `|` characters inside a markdown table
/// cell split it like any other column boundary, so the derived `inventory` field for that ONE row
/// is a fragment of that string rather than a pointer. The row itself, read rendered, is
/// unambiguous. Named here rather than swallowed silently by the prefix heuristic.
pub const KNOWN_PARSE_ARTIFACTS: &[&str] = &["PB-20"];

/// The master rule's own row describes the whole inventory instead of pointing at one file.
const MASTER_RULE_PREFIX: &str = "every row of every inventory file";

pub struct InventoryRefGate;

/// One binding, reduced to the two fields this lint reads.
#[derive(Debug, Clone)]
struct Binding {
    id: String,
    inventory: String,
}

/// What a `;`-separated segment of an `inventory` column resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Resolved {
    /// A known inventory file, by its prefix word.
    Alias(&'static str, &'static str),
    /// A prefix word this lint does not know. NOT "nothing to check": a pointer that cannot be
    /// followed is exactly the failure this gate exists to name.
    Unrecognized,
}

/// True when the segment begins with a word, i.e. an optional run of whitespace, then at most one
/// backtick, then an ASCII letter. The Python matches a regex here and then uses only whether it
/// matched, so this reproduces the decision the regex actually makes.
fn starts_with_word(segment: &str) -> bool {
    let mut chars = segment.chars().skip_while(|c| c.is_whitespace());
    let mut first = chars.next();
    if first == Some('`') {
        first = chars.next();
    }
    matches!(first, Some(c) if c.is_ascii_alphabetic())
}

/// Resolve one segment. `None` means the segment names no inventory file at all — a bare backtick
/// source path (`` `config/mod.rs:1796-1799` ``) or a `PB-N` self-reference — which is nothing to
/// check rather than a dangling reference.
///
/// The alias scan runs BEFORE the backtick/`PB-` escape, exactly as the Python does: a backticked
/// path whose first word happens to be an alias resolves to that alias' file, and since that file
/// exists the result is the same clean answer either way.
fn resolve_prefix(segment: &str) -> Option<Resolved> {
    if !starts_with_word(segment) {
        return None;
    }
    let words = segment.trim().trim_matches('`').to_ascii_lowercase();
    for (alias, path) in ALIASES {
        if words.starts_with(alias) {
            return Some(Resolved::Alias(alias, path));
        }
    }
    let trimmed = segment.trim();
    if trimmed.starts_with('`') || trimmed.starts_with("PB-") {
        return None;
    }
    Some(Resolved::Unrecognized)
}

/// Read the binding manifest. Every way this can go wrong is an `Err` carrying its own sentence:
/// none of them may be reachable as "an empty binding list".
fn load_bindings(cx: &Ctx) -> Result<Vec<Binding>, String> {
    let text = cx.read(BINDINGS_PATH).map_err(|e| {
        format!(
            "{BINDINGS_PATH} is unreadable ({e}) — a scanner that lost its input has not proven \
             that nothing dangles"
        )
    })?;
    let doc: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("{BINDINGS_PATH} did not parse as JSON: {e}"))?;
    let Some(array) = doc.get(BINDINGS_KEY).and_then(|v| v.as_array()) else {
        return Err(format!(
            "{BINDINGS_PATH} carries no `{BINDINGS_KEY}` array — the key was renamed or the \
             manifest changed shape, which reads as zero bindings and therefore as zero dangling \
             references, which is a pass over a scanner with no input"
        ));
    };
    let mut out = Vec::with_capacity(array.len());
    for (i, entry) in array.iter().enumerate() {
        let Some(id) = entry.get("id").and_then(|v| v.as_str()) else {
            return Err(format!(
                "{BINDINGS_PATH} `{BINDINGS_KEY}`[{i}] has no string `id` — a binding this lint \
                 cannot name is a binding it cannot report, so it is refused rather than skipped"
            ));
        };
        out.push(Binding {
            id: id.to_string(),
            inventory: entry
                .get("inventory")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(out)
}

/// The two problem lists, in the Python's wording, so a ledger row means the same thing before and
/// after the conversion.
fn scan(cx: &Ctx, bindings: &[Binding]) -> (Vec<String>, Vec<String>) {
    let mut unrecognized = Vec::new();
    let mut missing = Vec::new();
    let mut exists_cache: BTreeMap<&str, bool> = BTreeMap::new();

    for b in bindings {
        if KNOWN_PARSE_ARTIFACTS.contains(&b.id.as_str()) {
            continue;
        }
        let inv = b.inventory.trim();
        // The master rule's own row is a description of the whole inventory, not a pointer.
        if inv.is_empty() || inv.starts_with(MASTER_RULE_PREFIX) {
            continue;
        }
        for segment in inv.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            match resolve_prefix(segment) {
                None => continue,
                Some(Resolved::Unrecognized) => unrecognized.push(format!(
                    "{}: unrecognized inventory file prefix in segment '{segment}'",
                    b.id
                )),
                Some(Resolved::Alias(alias, path)) => {
                    let present = *exists_cache.entry(path).or_insert_with(|| cx.exists(path));
                    if !present {
                        missing.push(format!(
                            "{}: inventory file missing for '{alias}': {path}",
                            b.id
                        ));
                    }
                }
            }
        }
    }
    (unrecognized, missing)
}

impl Gate for InventoryRefGate {
    fn name(&self) -> &'static str {
        "inventory-ref"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MANIFEST.to_string(),
            ROW_FLOOR.to_string(),
            ROW_PREFIX.to_string(),
            ROW_FILE.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let bindings = match load_bindings(cx) {
            Ok(b) => b,
            Err(why) => {
                // A manifest that did not load leaves the other three rules UNPROVEN. Emitting a
                // PASS for them here is precisely the false green this gate was rewritten to
                // remove: nothing was scanned, so nothing was found, so nothing dangles.
                let unproven = format!("unproven: the binding manifest did not load — {why}");
                return Verdict::of(vec![
                    Row::fail(ROW_MANIFEST, "the binding manifest did not load", why),
                    Row::fail(ROW_FLOOR, "the binding count is unknown", unproven.clone()),
                    Row::fail(
                        ROW_PREFIX,
                        "no inventory prefix was resolved",
                        unproven.clone(),
                    ),
                    Row::fail(ROW_FILE, "no inventory file was checked", unproven),
                ]);
            }
        };

        let mut rows = vec![Row::pass(
            ROW_MANIFEST,
            "the binding manifest loaded and carries its binding array",
            format!(
                "{} binding(s) read from {BINDINGS_PATH} under `{BINDINGS_KEY}`",
                bindings.len()
            ),
        )];

        if bindings.len() < BINDING_FLOOR {
            rows.push(Row::fail(
                ROW_FLOOR,
                "the binding set collapsed below its discovery floor",
                format!(
                    "only {} binding(s) were discovered (floor {BINDING_FLOOR}). A binding set that \
                     collapsed has nothing left to dangle, so every reference check over it is \
                     vacuously true.",
                    bindings.len()
                ),
            ));
        } else {
            rows.push(Row::pass(
                ROW_FLOOR,
                "enough bindings were discovered for the reference checks to mean anything",
                format!("{} binding(s) (floor {BINDING_FLOOR})", bindings.len()),
            ));
        }

        // The reference rules still run below the floor: a floor that suppresses its neighbours
        // cannot be told apart from them in a self-test.
        let (unrecognized, missing) = scan(cx, &bindings);

        if unrecognized.is_empty() {
            rows.push(Row::pass(
                ROW_PREFIX,
                "every inventory segment names a file prefix this lint can follow",
                format!("{} known prefix(es)", ALIASES.len()),
            ));
        } else {
            rows.push(Row::fail(
                ROW_PREFIX,
                "a binding cites an inventory file prefix this lint cannot follow",
                unrecognized.join(" | "),
            ));
        }

        if missing.is_empty() {
            rows.push(Row::pass(
                ROW_FILE,
                "every cited inventory file exists",
                format!("{} binding(s) checked", bindings.len()),
            ));
        } else {
            rows.push(Row::fail(
                ROW_FILE,
                "a binding cites an inventory file that is not there",
                format!(
                    "{} — a reference to a file that was renamed or never existed binds nothing",
                    missing.join(" | ")
                ),
            ));
        }

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every binding in the real tree cites an inventory file that exists",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));
        for plant in plants() {
            report.push(plant.case(cx, self));
        }
        report
    }

    /// THE SAME PLANTS, DRIVEN THROUGH BOTH IMPLEMENTATIONS.
    ///
    /// One probe per planted violation, reusing [`plants`] rather than a second set of fixtures:
    /// a parity probe built from its own overlay is comparing something the self-test never proved.
    ///
    /// The legacy script has no `--root`; it anchors on `Path(__file__).parents[1]`, so the harness
    /// copies it into the plant and runs it from there. Everything it can read has to be in that
    /// plant — the binding manifest, every inventory file a binding can cite, and the two
    /// `docs/design` files the alias table can resolve to — because a path left out is a path the
    /// script reads out of the REAL repository, and the probe then grades the wrong tree.
    ///
    /// A plant that makes a file ABSENT deliberately omits that file from `materialize`: the
    /// harness writes the overlaid view of each listed path, and asking it to write a file the
    /// overlay says is gone is an error, not a deletion.
    fn parity_probes(&self, cx: &Ctx) -> Vec<crate::gates::ParityProbe> {
        let all = readable_inputs(cx);
        plants()
            .into_iter()
            .map(|p| {
                let materialize: Vec<String> = all
                    .iter()
                    .filter(|path| !p.absent.iter().any(|a| a == *path))
                    .cloned()
                    .collect();
                let probe = crate::gates::ParityProbe::red(
                    p.label,
                    p.overlay,
                    materialize,
                    p.rule.to_string(),
                );
                match legacy_wording(p.label) {
                    Some(w) => probe.named_by(w),
                    None => probe.diverges(crate::gates::Divergence::LegacyCrashes {
                        reason: "the legacy reaches this verdict by raising out of its own file \
                                 read rather than by reporting a rule, and an interpreter traceback \
                                 and a considered refusal leave the same exit code."
                            .to_string(),
                    }),
                }
            })
            .collect()
    }
}

/// What the LEGACY script calls each planted violation.
///
/// Keyed by the PLANT, not by the row id, because two plants that this gate reports under one row
/// are two different sentences on the legacy's side: a manifest whose `bindings` key was renamed
/// and a manifest that is not JSON at all both land on `inventory-ref:manifest` here. `None` means
/// the legacy has no sentence for it at all -- it dies instead -- which is a declared divergence
/// rather than a gap in this table.
fn legacy_wording(label: &str) -> Option<&'static str> {
    match label {
        "the manifest's binding array was renamed away" => {
            Some("carries no top-level `bindings` key")
        }
        "the binding set collapsed below its floor" => Some("floor 40"),
        "a binding cites an unrecognized inventory file prefix" => {
            Some("unrecognized inventory file prefix")
        }
        "an inventory file a binding cites was renamed away" => Some("inventory file missing for"),
        // The unreadable and not-JSON arms: the legacy raises rather than reporting.
        _ => None,
    }
}

/// Every path the legacy script can read out of the tree it judges: the binding manifest, the two
/// `docs/design` files the alias table names directly, and every inventory file under the inventory
/// directory. Derived by walking, not listed by hand, so an inventory file added tomorrow is
/// materialized without a second edit here.
fn readable_inputs(cx: &Ctx) -> Vec<String> {
    let mut out = vec![
        BINDINGS_PATH.to_string(),
        "docs/design/ARCHITECTURE.md".to_string(),
    ];
    for (_, path) in ALIASES {
        out.push((*path).to_string());
    }
    if let Ok(files) = cx.walk(&WalkSpec::new(["docs/design/inventory"]).ext("md")) {
        out.extend(files.iter().map(SourceFile::rel_str));
    }
    out.retain(|p| cx.exists(p));
    out.sort();
    out.dedup();
    out
}

/// One planted violation: the overlay, the owed row it must be reported by, and the substring the
/// RED report has to contain. Shared by [`Gate::selftest`] and [`Gate::parity_probes`] so the two
/// cannot drift apart.
struct Plant {
    label: &'static str,
    rule: &'static str,
    naming: Vec<String>,
    overlay: Overlay,
    /// Paths this plant makes absent. Named so the parity harness is never asked to materialize a
    /// file the overlay has removed.
    absent: Vec<String>,
}

impl Plant {
    fn case<'a>(self, cx: &'a Ctx, gate: &'a dyn Gate) -> crate::gates::CasePlan<'a> {
        if !cx.exists(BINDINGS_PATH) {
            // NOTHING TO PLANT is a visible, counted case — never a silent green.
            return Case {
                name: self.label.to_string(),
                covers: vec![self.rule.to_string()],
                expected: Expect::Red {
                    naming: self.naming.clone(),
                },
                got: Expect::Skipped,
            }
            .into();
        }
        let naming: Vec<&str> = self.naming.iter().map(String::as_str).collect();
        prove_red(cx, gate, self.label, &[self.rule], self.overlay, &naming)
    }
}

fn set_bindings(content: String) -> Overlay {
    let mut ov = Overlay::new();
    ov.set(BINDINGS_PATH, content);
    ov
}

/// The six planted violations, one per refusal this gate makes.
fn plants() -> Vec<Plant> {
    let clean = repeat_binding("routes-admin LST-001", BINDING_FLOOR + 1);

    let mut renamed_file = set_bindings(bindings_json(&clean, None));
    renamed_file.remove(alias_path("routes-admin"));

    let mut gone = Overlay::new();
    gone.remove(BINDINGS_PATH);

    vec![
        // Rule 1, first refusal: the key the bindings live under was renamed. This is the arm the
        // Python answered PASS to.
        Plant {
            label: "the manifest's binding array was renamed away",
            rule: ROW_MANIFEST,
            naming: vec!["carries no `bindings` array".to_string()],
            overlay: set_bindings(
                r#"{"design_bindings": [{"id": "PB-X1", "inventory": "routes-admin LST-001"}]}"#
                    .to_string(),
            ),
            absent: Vec::new(),
        },
        // Rule 1, second refusal: the manifest is not there at all.
        Plant {
            label: "the manifest is unreadable",
            rule: ROW_MANIFEST,
            naming: vec!["is unreadable".to_string()],
            overlay: gone,
            absent: vec![BINDINGS_PATH.to_string()],
        },
        // Rule 1, third refusal: the bytes are not JSON.
        Plant {
            label: "the manifest is not JSON",
            rule: ROW_MANIFEST,
            naming: vec!["did not parse as JSON".to_string()],
            overlay: set_bindings("{ this is not json".to_string()),
            absent: Vec::new(),
        },
        // Rule 2 gets its OWN discriminating fixture: a manifest that loads cleanly, whose every
        // binding resolves, and which is simply too small. Only the floor may go red here — a floor
        // proven alongside its neighbours is a floor that could be deleted unnoticed.
        Plant {
            label: "the binding set collapsed below its floor",
            rule: ROW_FLOOR,
            naming: vec![format!("floor {BINDING_FLOOR}")],
            overlay: set_bindings(bindings_json(
                &repeat_binding("routes-admin LST-001", 3),
                None,
            )),
            absent: Vec::new(),
        },
        // Rule 3, alone: a manifest well clear of the floor, every file present, one segment whose
        // prefix word names no inventory file.
        Plant {
            label: "a binding cites an unrecognized inventory file prefix",
            rule: ROW_PREFIX,
            naming: vec!["unrecognized inventory file prefix".to_string()],
            overlay: set_bindings(bindings_json(&clean, Some("not-a-real-file ZZZ-001"))),
            absent: Vec::new(),
        },
        // Rule 4, alone: every prefix resolves, the floor is clear, and the file one of them names
        // has been renamed out from under it.
        Plant {
            label: "an inventory file a binding cites was renamed away",
            rule: ROW_FILE,
            naming: vec!["inventory file missing for 'routes-admin'".to_string()],
            overlay: renamed_file,
            absent: vec![alias_path("routes-admin").to_string()],
        },
    ]
}

/// The path a known alias names. Panics only on this module's own bug (an alias literal that is not
/// in [`ALIASES`]), which is what the trait's contract permits a gate to panic on.
fn alias_path(alias: &str) -> &'static str {
    ALIASES
        .iter()
        .find(|(a, _)| *a == alias)
        .map(|(_, p)| *p)
        .unwrap_or_else(|| {
            panic!("inventory-ref selftest names an alias it does not define: {alias}")
        })
}

fn repeat_binding(inventory: &str, n: usize) -> Vec<String> {
    (0..n).map(|_| inventory.to_string()).collect()
}

/// A binding manifest carrying `good` clean segments plus an optional extra segment, serialised
/// through `serde_json` so the fixture cannot be malformed by hand-built string escaping.
fn bindings_json(good: &[String], extra: Option<&str>) -> String {
    let mut entries: Vec<serde_json::Value> = good
        .iter()
        .enumerate()
        .map(|(i, inv)| serde_json::json!({ "id": format!("PB-F{i}"), "inventory": inv }))
        .collect();
    if let Some(extra) = extra {
        entries.push(serde_json::json!({ "id": "PB-FX", "inventory": extra }));
    }
    let mut doc = serde_json::Map::new();
    doc.insert(BINDINGS_KEY.to_string(), serde_json::Value::Array(entries));
    serde_json::Value::Object(doc).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx::workspace().expect("workspace context")
    }

    #[test]
    fn a_backtick_source_path_and_a_self_reference_name_no_inventory_file() {
        // The Python's own third self-test case: neither shape is a dangling reference.
        assert_eq!(resolve_prefix("PB-72"), None);
        // A backticked path whose first word is an alias still resolves to that alias' file, which
        // exists — the same clean answer the Python gives, by the same ordering.
        assert_eq!(
            resolve_prefix("`config/mod.rs:1796-1799`"),
            Some(Resolved::Alias(
                "config",
                "docs/design/inventory/1.5.5-config.md"
            ))
        );
        assert_eq!(resolve_prefix("`src/lib.rs:12`"), None);
    }

    #[test]
    fn a_known_prefix_resolves_and_an_unknown_one_is_refused() {
        assert_eq!(
            resolve_prefix("routes-admin LST-001"),
            Some(Resolved::Alias(
                "routes-admin",
                "docs/design/inventory/1.5.5-routes-admin.md"
            ))
        );
        assert_eq!(
            resolve_prefix("not-a-real-file ZZZ-001"),
            Some(Resolved::Unrecognized)
        );
    }

    #[test]
    fn a_segment_that_starts_with_no_word_is_not_a_pointer() {
        assert!(!starts_with_word("|seq|ts|action"));
        assert!(starts_with_word("  `config/mod.rs"));
        assert!(starts_with_word("ops OBS-004"));
    }

    #[test]
    fn the_master_rule_row_and_the_known_artifact_are_not_pointers() {
        let cx = cx();
        let bindings = vec![
            Binding {
                id: "PB-0".to_string(),
                inventory: "every row of every inventory file under `inventory/`".to_string(),
            },
            Binding {
                id: "PB-20".to_string(),
                inventory: "seq|ts|action".to_string(),
            },
        ];
        let (unrecognized, missing) = scan(&cx, &bindings);
        assert!(unrecognized.is_empty(), "{unrecognized:?}");
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// A renamed manifest key must NOT read as an empty binding list. This is the whole audit fix.
    #[test]
    fn a_renamed_binding_key_is_a_refusal_not_an_empty_scan() {
        let mut ov = Overlay::new();
        ov.set(BINDINGS_PATH, r#"{"design_bindings": []}"#);
        let planted = cx().with_overlay(ov);
        let err = load_bindings(&planted).expect_err("a renamed key must not load");
        assert!(err.contains("carries no `bindings` array"), "{err}");
    }

    /// The ids that went FAIL under a planted binding manifest.
    fn failed_ids(content: String) -> Vec<String> {
        let mut ov = Overlay::new();
        ov.set(BINDINGS_PATH, content);
        let planted = cx().with_overlay(ov);
        crate::gates::execute(&InventoryRefGate, &planted)
            .rows
            .iter()
            .filter(|r| r.status != crate::ledger::Status::Pass)
            .map(|r| r.id.clone())
            .collect()
    }

    /// THE FLOOR MUST FAIL ALONE. A manifest that loads, parses, and whose every segment resolves
    /// to a file that is there is clean by rules 1, 3 and 4 and small by rule 2 — so if this
    /// fixture reds anything else, rule 2 is being proven by its neighbours and could be deleted
    /// with the self-test still green.
    #[test]
    fn the_binding_floor_rejects_alone() {
        assert_eq!(
            failed_ids(bindings_json(
                &repeat_binding("routes-admin LST-001", 3),
                None
            )),
            vec![ROW_FLOOR.to_string()]
        );
    }

    /// And the reference rules must fail alone too, above the floor.
    #[test]
    fn the_reference_rules_reject_alone() {
        assert_eq!(
            failed_ids(bindings_json(
                &repeat_binding("routes-admin LST-001", BINDING_FLOOR + 1),
                Some("not-a-real-file ZZZ-001")
            )),
            vec![ROW_PREFIX.to_string()]
        );
    }

    /// Both arms of the framework, over the real tree.
    #[test]
    fn the_gate_is_green_on_the_workspace() {
        let verdict = crate::gates::execute(&InventoryRefGate, &cx());
        assert!(
            !verdict.red,
            "inventory-ref is RED on the real tree: {:?}",
            verdict.problems
        );
    }

    #[test]
    fn the_selftest_proves_every_owed_row() {
        let cx = cx();
        let report = InventoryRefGate.selftest(&cx);
        crate::gates::verify_report(&InventoryRefGate, &report)
            .unwrap_or_else(|errs| panic!("inventory-ref selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
