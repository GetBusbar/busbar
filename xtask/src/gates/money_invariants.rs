// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate money-invariants` — THE W3.b MONEY-MODEL INVARIANTS, ENFORCED.
//!
//! This is the wave-W3.b proof (arm-gate-per-wave). DECISIONS #77 locks the money model; W3.a
//! relocated the money-path durable records out of `busbar-api`; #83/#84 landed their SHAPES in
//! `busbar-contract/src/records.rs`, which is where this gate reads them. The read-time
//! pricing VIEW (`cost/project.rs derive_spend_*`) and the class-keyed usage COUNTS
//! (`usage/meter.rs`) already exist — what was missing were the GATES that keep the invariants from
//! silently regressing. This gate holds three of #77's structural claims, each red-before-green.
//!
//! | row | the claim it holds (cited to #77) |
//! | --- | --- |
//! | `money-invariants:no-plugin-keyed-money` | #77(1): the money-path durable records key money by `(principal, meter_class[, lane], units, timestamp)` and hold NO plugin/plane identity field — so per-plugin/per-plane pricing is UNREPRESENTABLE, not merely banned. "Different price per plane" is a plane DECLARING a different meter-class STRING, never a plugin-named field on a money AMOUNT record. |
//! | `money-invariants:no-stored-price` | #77(3) (+#71/#43): price is NEVER stored — money is a read-time conversion `Σ count × rate_card(class, card_at(ts))`. No money-path record carries a persisted price/spend/cents/nanos figure; the records store RAW COUNTS only. |
//! | `money-invariants:single-seal-site` | #77(2): ONE sealed FACTS line per unit, written ONCE at the END — never per-plugin. The facts-line constructor (`Posted::settle`/`Posted::settle_late`) is spelled in production only in core/kernel crates, never in a plane/plugin crate. |
//!
//! ## Scoping the #77(1) rule correctly — the routing record is NOT a money record
//!
//! #77(1) forbids keying money AMOUNTS by plugin/plane. It does NOT forbid a routing record from
//! naming a plane: [`busbar_contract::records::PlaneRecord`]'s `kind` is exactly that — the
//! neutral routing selector that replaces a protocol-named store method, carrying an OPAQUE body and
//! no money figure at all. So `PlaneRecord`/`PlaneSelector`/`PlaneDisposition` are deliberately
//! OUTSIDE the money-record set this gate scans: the rule is "money amounts aren't keyed by plugin",
//! not "no record may name a plane". The scanned set is the records that carry usage/amount truth.
//!
//! The scan is comment-stripped (a doc note naming a forbidden field is prose, not a field). Rows (a)
//! and (b) read the one records file; row (c) walks production `crates/` the way `seal-witness` does.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_NO_PLUGIN_KEYED: &str = "money-invariants:no-plugin-keyed-money";
pub const ROW_NO_STORED_PRICE: &str = "money-invariants:no-stored-price";
pub const ROW_SINGLE_SEAL: &str = "money-invariants:single-seal-site";

/// The money-path durable records that carry usage/amount truth — the set #77(1)/#77(3) govern.
/// `PlaneRecord` & friends are the ROUTING records and are deliberately absent (see the module doc).
pub const MONEY_RECORDS: &[&str] = &[
    "VirtualKey",
    "ModelTokens",
    "UsageLedger",
    "ModelTokensDelta",
    "UsageDelta",
    "MeteringDelta",
    "MeteringRow",
    "AuditRecord",
];

/// #77(1): a money AMOUNT record may not carry a plugin/plane IDENTITY field. A field NAME containing
/// one of these tokens is per-plugin/per-plane money keying, which #77 makes unrepresentable.
const IDENTITY_TOKENS: &[&str] = &["plugin", "plane"];

/// #77(3): price is a READ-TIME view, never stored. A field NAME containing one of these money-figure
/// tokens is a stored price/spend — forbidden on the counts-only durable records.
const PRICE_TOKENS: &[&str] = &[
    "spend", "price", "cents", "nanos", "micros", "dollar", "usd", "cost", "fee",
];

/// Field names that name PRICING PROVENANCE (which card was in force), not a stored price. `Σ`-free:
/// `pricing_version` is a version STRING #44 requires be surfaced, never a money figure. Kept as an
/// explicit allowlist so the intent is legible even though no `PRICE_TOKENS` entry substring-matches
/// it today.
const PRICE_ALLOW: &[&str] = &["pricing_version"];

/// The one records file the money-path durable record SHAPES live in. W3.a relocated them out of
/// `busbar-api` into `busbar-kernel-ledger`; #83/#84 relocated them on into `busbar-contract` (shapes
/// are contract, ledger semantics are not, and nothing on the plugin path may link semantics).
const RECORDS_PATH: &str = "crates/busbar-contract/src/records.rs";

/// The facts-line constructors (#77(2) / `busbar-contract` `Posted`). One sealed line per unit.
const SEAL_MARKERS: &[&str] = &["Posted::settle(", "Posted::settle_late("];

/// Where the facts line may be sealed: core/kernel crates and the composition root ONLY — never a
/// plane/plugin crate. `busbar-contract` is the type's home (and carries doc examples); the kernel
/// crates own the settle path; `busbar` is the composition root that drives late settlement.
const SEAL_ALLOWED_ROOTS: &[&str] = &[
    "crates/busbar-contract/",
    "crates/busbar-kernel/",
    "crates/busbar-kernel-ledger/",
    "crates/busbar-kernel-budget/",
    "crates/busbar/",
];

/// The production `.rs` under `crates/`, tests excluded — the same classification `seal-witness` uses.
const ROOTS: &[&str] = &["crates"];
const EXCLUDE: &[&str] = &["/tests/", "/tests.rs", "_tests.rs", "/benches/", "/target/"];
/// A walk that finds fewer production files than this is broken, not clean.
const SCAN_FLOOR: usize = 200;

/// Whether `needle` appears in `hay` as a WHOLE word (identifier-boundaried) — so `plane` does not
/// fire on `explanation` and `fee` does not fire on `coffee`, while a real `plugin`/`spend_cents`
/// field name is caught. A field-name token check, run over the identifier before the `:`.
fn token_in_ident(ident: &str, needle: &str) -> bool {
    let bytes = ident.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > bytes.len() {
        return false;
    }
    let wordy = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // A field name is one identifier, so `_`-separated segments are the word boundaries: match the
    // token as a segment (`spend_cents` → segments `spend`,`cents`) OR anchored at a segment edge.
    for i in 0..=(bytes.len() - n.len()) {
        if &bytes[i..i + n.len()] != n {
            continue;
        }
        let before = i == 0 || bytes[i - 1] == b'_';
        let after =
            i + n.len() == bytes.len() || bytes[i + n.len()] == b'_' || !wordy(bytes[i + n.len()]);
        if before && after {
            return true;
        }
    }
    false
}

/// The struct name a `pub struct NAME {` (or `struct NAME {`) line opens, or `None`.
fn struct_opens(trimmed: &str) -> Option<&str> {
    let rest = trimmed
        .strip_prefix("pub struct ")
        .or_else(|| trimmed.strip_prefix("struct "))?;
    if !trimmed.ends_with('{') {
        return None;
    }
    let name = rest
        .split(|c: char| c == '{' || c == '<' || c.is_whitespace())
        .next()?;
    (!name.is_empty()).then_some(name)
}

/// The field name a struct-body line declares (`pub name: Type,` → `name`), or `None` for an
/// attribute/blank/non-field line.
fn field_name(trimmed: &str) -> Option<&str> {
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    let decl = trimmed
        .strip_prefix("pub(crate) ")
        .or_else(|| trimmed.strip_prefix("pub "))
        .unwrap_or(trimmed);
    let colon = decl.find(':')?;
    let name = decl[..colon].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name)
}

struct RecordScan {
    /// The [`MONEY_RECORDS`] names whose `struct` was actually FOUND in the records file — the
    /// measured denominator of both record rows. The constant's length is what the rows were asked
    /// to scan; this is what they did scan, and only this may be printed as "scanned" (items
    /// 210/211: a rename or a file split left both rows green over zero structs while printing 8).
    found: Vec<&'static str>,
    /// Fields on a money record whose name carries a plugin/plane identity token (#77(1)).
    plugin_keyed: Vec<String>,
    /// Fields on a money record whose name carries a stored-price token (#77(3)).
    stored_price: Vec<String>,
}

fn scan_records(src: &str) -> RecordScan {
    let mut plugin_keyed = Vec::new();
    let mut stored_price = Vec::new();
    let mut found: Vec<&'static str> = Vec::new();
    let mut current: Option<&'static str> = None;
    let mut in_block = false;
    for (i, raw) in src.lines().enumerate() {
        let code = scan::strip_comment_line(raw, &mut in_block);
        let trimmed = code.trim();
        if let Some(name) = struct_opens(trimmed) {
            current = MONEY_RECORDS.iter().copied().find(|m| *m == name);
            if let Some(m) = current {
                if !found.contains(&m) {
                    found.push(m);
                }
            }
            continue;
        }
        let Some(rec) = current else { continue };
        if trimmed == "}" {
            current = None;
            continue;
        }
        let Some(field) = field_name(trimmed) else {
            continue;
        };
        for tok in IDENTITY_TOKENS {
            if token_in_ident(field, tok) {
                plugin_keyed.push(format!("`{field}` on {rec} at {RECORDS_PATH}:{}", i + 1));
            }
        }
        if PRICE_ALLOW.contains(&field) {
            continue;
        }
        for tok in PRICE_TOKENS {
            if token_in_ident(field, tok) {
                stored_price.push(format!("`{field}` on {rec} at {RECORDS_PATH}:{}", i + 1));
            }
        }
    }
    plugin_keyed.sort();
    stored_price.sort();
    RecordScan {
        found,
        plugin_keyed,
        stored_price,
    }
}

struct SealScan {
    files: usize,
    seals_outside: Vec<String>,
}

fn scan_seal_sites(cx: &Ctx) -> Result<SealScan, String> {
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = cx.walk(&spec).map_err(|e| format!("{e:?}"))?;
    let mut seals_outside = Vec::new();
    for f in &files {
        let rel = f.rel_str();
        let allowed = SEAL_ALLOWED_ROOTS.iter().any(|root| rel.starts_with(root));
        if allowed {
            continue;
        }
        let mut in_block = false;
        for (i, raw) in f.text.lines().enumerate() {
            let code = scan::strip_comment_line(raw, &mut in_block);
            for marker in SEAL_MARKERS {
                if code.contains(marker) {
                    seals_outside.push(format!("`{marker}` at {rel}:{}", i + 1));
                }
            }
        }
    }
    seals_outside.sort();
    Ok(SealScan {
        files: files.len(),
        seals_outside,
    })
}

fn join_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

pub struct MoneyInvariantsGate;

impl MoneyInvariantsGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let src = match cx.read(RECORDS_PATH) {
            Ok(s) => s,
            Err(e) => {
                let fail = |id| {
                    Row::fail(
                        id,
                        "the money-invariants records scan could not run",
                        format!("could not read {RECORDS_PATH}: {e}"),
                    )
                };
                return vec![
                    fail(ROW_NO_PLUGIN_KEYED),
                    fail(ROW_NO_STORED_PRICE),
                    Self::seal_row(cx),
                ];
            }
        };
        let scan = scan_records(&src);

        // EXISTENCE BEFORE VERDICT. Both record rows are claims ABOUT the money records; a money
        // record the scan did not find is a record neither row inspected, so each row refuses
        // rather than passing over the gap. This is the record scan's floor: all of them, because
        // the set is named, not sampled.
        let missing: Vec<&str> = MONEY_RECORDS
            .iter()
            .copied()
            .filter(|m| !scan.found.contains(m))
            .collect();
        if !missing.is_empty() {
            let fail = |id| {
                Row::fail(
                    id,
                    "a money record this row governs was not found — the scan cannot vouch for it",
                    format!(
                        "{} of {} money record type(s) found in {RECORDS_PATH}; no `struct` for: {} \
                         (renamed, moved or split out — repoint MONEY_RECORDS/RECORDS_PATH at it)",
                        scan.found.len(),
                        MONEY_RECORDS.len(),
                        missing.join(", ")
                    ),
                )
            };
            return vec![
                fail(ROW_NO_PLUGIN_KEYED),
                fail(ROW_NO_STORED_PRICE),
                Self::seal_row(cx),
            ];
        }

        let no_plugin = if scan.plugin_keyed.is_empty() {
            Row::pass(
                ROW_NO_PLUGIN_KEYED,
                "no money-path record carries a plugin/plane identity field (#77(1))",
                format!(
                    "{} money record type(s) scanned; money is keyed by (principal, meter_class, \
                     units, timestamp) — per-plugin pricing is unrepresentable",
                    scan.found.len()
                ),
            )
        } else {
            Row::fail(
                ROW_NO_PLUGIN_KEYED,
                "a money-path record keys money by plugin/plane — #77(1) makes this unrepresentable",
                format!(
                    "{} plugin/plane-keyed money field(s): {}",
                    scan.plugin_keyed.len(),
                    join_or_none(&scan.plugin_keyed)
                ),
            )
        };

        let no_price = if scan.stored_price.is_empty() {
            Row::pass(
                ROW_NO_STORED_PRICE,
                "no money-path record stores a price/spend figure — price is read-time (#77(3))",
                format!(
                    "{} money record type(s) scanned; the durable records carry RAW COUNTS only; \
                     spend = Σ count × rate_card at read time",
                    scan.found.len()
                ),
            )
        } else {
            Row::fail(
                ROW_NO_STORED_PRICE,
                "a money-path record stores a price/spend figure — #77(3) requires read-time pricing",
                format!(
                    "{} stored-price field(s): {}",
                    scan.stored_price.len(),
                    join_or_none(&scan.stored_price)
                ),
            )
        };

        vec![no_plugin, no_price, Self::seal_row(cx)]
    }

    fn seal_row(cx: &Ctx) -> Row {
        match scan_seal_sites(cx) {
            Err(e) => Row::fail(
                ROW_SINGLE_SEAL,
                "the money-invariants seal-site scan could not run",
                e,
            ),
            Ok(scan) if scan.seals_outside.is_empty() => Row::pass(
                ROW_SINGLE_SEAL,
                "the facts-line seal is sealed only in core/kernel crates, never per-plugin (#77(2))",
                format!(
                    "{} production files scanned; `Posted::settle`/`settle_late` appears only under \
                     {}",
                    scan.files,
                    SEAL_ALLOWED_ROOTS.join(", ")
                ),
            ),
            Ok(scan) => Row::fail(
                ROW_SINGLE_SEAL,
                "a plane/plugin crate seals a money facts line — #77(2) is one seal site, not per-plugin",
                format!(
                    "{} seal site(s) outside the core/kernel crates: {}",
                    scan.seals_outside.len(),
                    join_or_none(&scan.seals_outside)
                ),
            ),
        }
    }
}

impl Gate for MoneyInvariantsGate {
    fn name(&self) -> &'static str {
        "money-invariants"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_NO_PLUGIN_KEYED.to_string(),
            ROW_NO_STORED_PRICE.to_string(),
            ROW_SINGLE_SEAL.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(MoneyInvariantsGate::rows(cx))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed money model holds all three invariants",
            &[ROW_NO_PLUGIN_KEYED, ROW_NO_STORED_PRICE, ROW_SINGLE_SEAL],
        ));

        // RED (a): a plugin-keyed field on a money record is caught (#77(1)).
        let src = cx.read(RECORDS_PATH).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            RECORDS_PATH,
            src.replace(
                "pub struct MeteringRow {",
                "pub struct MeteringRow {\n    pub plugin: String,",
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a per-plugin field on a money record is RED",
            &[ROW_NO_PLUGIN_KEYED],
            ov,
            &["plugin"],
        ));

        // RED (b): a stored price/spend field on a money record is caught (#77(3)).
        let mut ov2 = Overlay::new();
        ov2.set(
            RECORDS_PATH,
            src.replace(
                "pub struct UsageLedger {",
                "pub struct UsageLedger {\n    pub spend_cents: u64,",
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a stored price/spend field on a money record is RED",
            &[ROW_NO_STORED_PRICE],
            ov2,
            &["spend"],
        ));

        // RED (d) — items 210/211: a money record the scan cannot FIND is not a record it passed.
        // Rename `UsageLedger` and give the renamed struct a plane-keyed field: before this case
        // both record rows stayed green ("8 money record type(s) scanned") because the renamed
        // struct was simply never inspected.
        let mut ov4 = Overlay::new();
        ov4.set(
            RECORDS_PATH,
            src.replace(
                "pub struct UsageLedger {",
                "pub struct UsageBook {\n    pub plane_id: String,",
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a renamed money record is RED on both record rows, not scanned-past",
            &[ROW_NO_PLUGIN_KEYED, ROW_NO_STORED_PRICE],
            ov4,
            &["UsageLedger", "7 of 8"],
        ));

        // RED (c): a plane/plugin crate sealing its own facts line is caught (#77(2)).
        let victim = "crates/busbar-llm/src/lib.rs";
        let vtext = cx.read(victim).unwrap_or_default();
        let mut ov3 = Overlay::new();
        ov3.set(
            victim,
            format!("{vtext}\nfn __money_invariants_probe() {{ let _ = Posted::settle(); }}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "a plane crate sealing a facts line is RED",
            &[ROW_SINGLE_SEAL],
            ov3,
            &["busbar-llm"],
        ));

        report
    }
}
