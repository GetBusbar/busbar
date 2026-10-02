// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate money-invariants` — THE W3.b MONEY-MODEL INVARIANTS, ENFORCED.
//!
//! This is the wave-W3.b proof (arm-gate-per-wave). DECISIONS #77 locks the money model; the
//! read-time pricing VIEW (`cost/project.rs derive_spend_*`) and the class-keyed usage COUNTS
//! (`usage/meter.rs`) already exist — what was missing were the GATES that keep the invariants from
//! silently regressing. This gate holds three of #77's structural claims, each red-before-green.
//!
//! | row | the claim it holds (cited to #77) |
//! | --- | --- |
//! | `money-invariants:no-plugin-keyed-money` | #77(1): the durable money records key money by `(principal, meter_class[, lane], units, timestamp)` and hold NO plugin/plane identity field — so per-plugin/per-plane pricing is UNREPRESENTABLE, not merely banned. "Different price per plane" is a plane DECLARING a different meter-class STRING, never a plugin-named field on a money AMOUNT record. |
//! | `money-invariants:no-stored-price` | #77(3) (+#71/#43): price is NEVER stored — money is a read-time conversion `Σ count × rate_card(class, card_at(ts))`. No durable record carries a persisted price/spend/amount/cents/nanos figure; the records store RAW COUNTS only. |
//! | `money-invariants:single-seal-site` | #77(2): ONE sealed FACTS line per unit, written ONCE at the END — never per-plugin. The facts-line constructor (`Posted::settle`/`Posted::settle_late`) is spelled in production only in core/kernel crates, never in a plane/plugin crate. |
//!
//! ## THE POPULATION IS DERIVED, NOT TYPED (item 9, Law 8)
//!
//! This gate used to read ONE file — `busbar-contract/src/records.rs`, the store record SHAPES —
//! against a hand-written list of eight type names. Production writes its money record somewhere
//! else: the durability seam journals the FIXED AUDIT RECORD of `busbar-kernel-audit/src/record.rs`,
//! whose `amount: Amount` is a priced figure in nano-units, and the gate had never looked at that
//! file. Its list also named 8 of the 17 types `records.rs` declares. Both are the hand-written
//! denominator Law 8 names: the gate was correct about what it was told to look at and silent
//! about the rest.
//!
//! So the population is now read off the tree, from the two places durable records are defined:
//!
//! 1. **The store record file** ([`STORE_RECORDS_PATH`]): EVERY `struct`/`enum` it declares. That
//!    file exists to hold durable store shapes, so membership is the file, not a list. The routing
//!    records (`PlaneRecord` and friends) are in it and are scanned like the rest: #77(1) is a rule
//!    about FIELD NAMES, and `PlaneRecord.kind` — the neutral routing selector — names no plugin.
//! 2. **The journal** ([`JOURNAL_SEAM`]): every type the durability seam turns into a journal body —
//!    the argument type of each `fn <name>_body(x: &T)` and every `impl T` carrying `fn body(&self)`.
//!    Each is resolved to its ONE definition through the seam's own `use` lines (a type the seam
//!    defines itself resolves there), and every type its fields name that the same crate defines is
//!    folded in, transitively — `AuditRecord`'s `amount: Amount` pulls in `Amount`, whose fields are
//!    where the priced figure actually sits.
//!
//! EXISTENCE BEFORE VERDICT. Both record rows refuse, rather than pass over a gap, when: a record
//! source cannot be read; the store file declares fewer types than [`STORE_TYPE_FLOOR`]; the seam
//! yields fewer journal record types than [`JOURNAL_ROOT_FLOOR`]; a journal type resolves to no
//! definition or to more than one; or [`REQUIRED_HOMES`] (the audit record file BUSBAR-1.6.0 Part 0
//! names) is not among the files the population was drawn from. A rename is therefore not a hiding
//! place: the seam still names the old type, and a name that resolves to nothing is a refusal.
//!
//! The scan is comment-stripped and test-module-stripped (a doc note naming a forbidden field is
//! prose, not a field). Row (c) walks production `crates/` the way `seal-witness` does.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_red, prove_rows_green, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_NO_PLUGIN_KEYED: &str = "money-invariants:no-plugin-keyed-money";
pub const ROW_NO_STORED_PRICE: &str = "money-invariants:no-stored-price";
pub const ROW_SINGLE_SEAL: &str = "money-invariants:single-seal-site";

/// #77(1): a money AMOUNT record may not carry a plugin/plane IDENTITY field. A field NAME containing
/// one of these tokens is per-plugin/per-plane money keying, which #77 makes unrepresentable.
const IDENTITY_TOKENS: &[&str] = &["plugin", "plane"];

/// #77(3): price is a READ-TIME view, never stored. A field NAME containing one of these money-figure
/// tokens is a stored price/spend — forbidden on the counts-only durable records.
///
/// `amount` and `priced` joined the list with item 9: the fixed audit record spells its stored money
/// figure `amount: Amount { priced, .. }`, and neither word was here, so the gate could not have
/// named it even had it been reading the file.
const PRICE_TOKENS: &[&str] = &[
    "spend", "price", "priced", "amount", "cents", "nanos", "micros", "dollar", "usd", "cost",
    "fee",
];

/// Field names that name PRICING PROVENANCE (which card was in force, and from when) or a COUNT,
/// not a stored price:
///
/// * `pricing_version` — a version STRING #44 requires be surfaced, never a money figure.
/// * `priced_from_ms` — the INSTANT the dated rate-card history is resolved at (`MeteringDelta` /
///   `MeteringRow`), a `u64` epoch in milliseconds. It is the provenance #77(3)'s read-time view
///   needs in order to price a row at the card it was earned under; it matches the `priced` token
///   item 9 added and carries no money.
/// * `fee_count` — HOW MANY request fees a unit incurred (`Amount`): a count of fee units, the raw
///   quantity #71 says a record stores and a read-time view multiplies by the card's fee. The price
///   of those fees is not in it.
const PRICE_ALLOW: &[&str] = &["pricing_version", "priced_from_ms", "fee_count"];

/// The store record SHAPES. #83/#84 relocated them out of `busbar-kernel-ledger` into
/// `busbar-contract` (shapes are contract, ledger semantics are not). Every type this file declares
/// is in the population.
const STORE_RECORDS_PATH: &str = "crates/busbar-contract/src/records.rs";

/// The store file's declared-type count, MEASURED 2026-09-24: 15 structs + 3 enums — the 17
/// top-level types item 9 counted, plus the nested `VirtualKeyWire` serde twin, which is what a
/// `VirtualKey` is actually persisted as. Fewer is a type moved or split out of the file the
/// population is drawn from — a record the rows would no longer see — and refuses. Arming at today's
/// number; a reviewed diff lowers it with the move.
const STORE_TYPE_FLOOR: usize = 18;

/// The durability seam: the one production file that turns records into journal bodies
/// (`Entry::new(RecordClass::…, <x>_body(..))`). Its `<x>_body` functions and `body(&self)` impls
/// are what DEFINE which types are durable journal records.
/// `847c22f98` split the seam (structure-lint oversized) into `durability/mod.rs` (the seam
/// itself, the journal writers, the money-book impl) and `durability/replay.rs` (the book-rebuild
/// replay it split out). Every `<x>_body`/`body(&self)` writer this gate derives the journal
/// population from stayed in `mod.rs` — the split moved replay code, not writer code — so the seam
/// this row reads is still the one file.
const JOURNAL_SEAM: &str = "crates/busbar/src/root/durability/mod.rs";

/// The seam's journal record types, RE-MEASURED 2026-09-24 against the tree at commit
/// `847c22f98^` (the seam's shape before the structure-lint split, so the recount is over the same
/// content the split only relocated): `Posting` (`impl Posting { fn body }`), `HoldOpened`
/// (`impl HoldOpened { fn body }`, the journalled hold), `UnitMark` (`impl UnitMark { fn body }`),
/// `ClaimRecord` (`impl ClaimRecord { fn body }`), `AuditRecord` (`audit_body`), `Checkpoint`
/// (`checkpoint_body`), `MigrationMarker` (`migration_body`) — SEVEN, not the five this constant
/// used to name; `UnitMark` and `ClaimRecord` were already writers at the cited commit and the old
/// count had simply never counted them. Fewer is a journal writer the derivation stopped seeing.
/// The floor is the count, not below it: a floor one short lets exactly one writer vanish in
/// silence, which is the defect it exists to refuse.
const JOURNAL_ROOT_FLOOR: usize = 7;

/// The record files BUSBAR-1.6.0 Part 0 holds this gate to by name. The population is derived; this
/// is the check that the derivation still REACHES them — the defect item 9 names is exactly this
/// file being outside the scan.
const REQUIRED_HOMES: &[&str] = &["crates/busbar-kernel-audit/src/record.rs"];

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

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// Strip a leading visibility (`pub `, `pub(crate) `, `pub(in …) `) off a trimmed line.
fn strip_vis(t: &str) -> &str {
    if let Some(rest) = t.strip_prefix("pub(") {
        if let Some(close) = rest.find(')') {
            return rest[close + 1..].trim_start();
        }
    }
    t.strip_prefix("pub ").unwrap_or(t)
}

/// The type name a `struct NAME` / `enum NAME` declaration line opens, or `None`.
fn decl_opens(trimmed: &str) -> Option<&str> {
    let rest = strip_vis(trimmed);
    let rest = rest
        .strip_prefix("struct ")
        .or_else(|| rest.strip_prefix("enum "))?;
    let name = rest
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()?;
    is_ident(name).then_some(name)
}

/// Every `name: Type` field a (comment-stripped) body line declares. A line normally declares one;
/// an inline enum variant (`Foo { a: u64, b: String },`) declares several.
fn fields_on(trimmed: &str) -> Vec<(String, String)> {
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Vec::new();
    }
    let inner = match (trimmed.find('{'), trimmed.rfind('}')) {
        (Some(o), Some(c)) if c > o => &trimmed[o + 1..c],
        (Some(o), None) => &trimmed[o + 1..],
        _ => trimmed,
    };
    // Split on the commas BETWEEN fields only — `BTreeMap<String, ModelTokens>` is one type.
    let mut parts = Vec::new();
    let (mut depth, mut from) = (0i32, 0usize);
    for (k, c) in inner.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&inner[from..k]);
                from = k + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[from..]);
    let mut out = Vec::new();
    for part in parts {
        let decl = strip_vis(part.trim());
        let Some(colon) = decl.find(':') else {
            continue;
        };
        // `a::b` is a path, not a field.
        if decl[colon..].starts_with("::") {
            continue;
        }
        let name = decl[..colon].trim();
        if !is_ident(name) {
            continue;
        }
        let ty = decl[colon + 1..].trim().trim_end_matches(',').trim();
        out.push((name.to_string(), ty.to_string()));
    }
    out
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    ty: String,
    line: usize,
}

#[derive(Debug, Clone)]
struct TypeDecl {
    name: String,
    file: String,
    fields: Vec<Field>,
}

/// Every production `struct`/`enum` a source file declares, with its named fields. Test modules and
/// comments are dropped first (through the one scanner), braces are counted on literal-blanked text.
fn parse_decls(file: &str, src: &str) -> Vec<TypeDecl> {
    let lines = scan::production_lines(src);
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (_, text) = &lines[i];
        let trimmed = text.trim();
        let Some(name) = decl_opens(trimmed) else {
            i += 1;
            continue;
        };
        let mut decl = TypeDecl {
            name: name.to_string(),
            file: file.to_string(),
            fields: Vec::new(),
        };
        // Find the body: a `{` before any `;` opens one; a `;` first is a tuple/unit type with no
        // named fields.
        let mut depth: i32 = 0;
        let mut opened = false;
        let mut j = i;
        'body: while j < lines.len() {
            let (no, t) = &lines[j];
            let blanked = scan::blank_literals(t);
            if !opened {
                match (blanked.find('{'), blanked.find(';')) {
                    (Some(o), s) if s.is_none_or(|s| o < s) => {
                        opened = true;
                        // Fields on the opening line itself (`struct A { x: u64 }`).
                        let after = &t[o..];
                        if j != i || after.contains(':') {
                            for (n, ty) in fields_on(after.trim()) {
                                decl.fields.push(Field {
                                    name: n,
                                    ty,
                                    line: *no,
                                });
                            }
                        }
                        depth += scan::delta(&blanked[o..], '{', '}');
                        if depth <= 0 {
                            break 'body;
                        }
                    }
                    (_, Some(_)) => break 'body,
                    _ => {}
                }
            } else {
                for (n, ty) in fields_on(t.trim()) {
                    decl.fields.push(Field {
                        name: n,
                        ty,
                        line: *no,
                    });
                }
                depth += scan::delta(&blanked, '{', '}');
                if depth <= 0 {
                    break 'body;
                }
            }
            j += 1;
        }
        out.push(decl);
        i = j.max(i) + 1;
    }
    out
}

/// The journal record type names the durability seam writes: the `&T` argument of every
/// `fn <name>_body(x: &T)`, and every `T` whose `impl T { .. }` carries `fn body(&self)`.
fn journal_roots(seam_src: &str) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        if !roots.iter().any(|r| r == t) {
            roots.push(t.to_string());
        }
    };
    let mut current_impl: Option<String> = None;
    for (_, text) in scan::production_lines(seam_src) {
        let t = text.trim();
        if !text.starts_with(char::is_whitespace) {
            current_impl = t
                .strip_prefix("impl ")
                .and_then(|r| {
                    r.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .next()
                })
                .filter(|n| is_ident(n) && !t.contains(" for "))
                .map(str::to_string);
        }
        let sig = strip_vis(t);
        let Some(rest) = sig.strip_prefix("fn ") else {
            continue;
        };
        let Some(paren) = rest.find('(') else {
            continue;
        };
        let fname = &rest[..paren];
        let args = &rest[paren + 1..];
        if fname == "body" && args.starts_with("&self") {
            if let Some(owner) = &current_impl {
                push(owner);
            }
            continue;
        }
        if fname.ends_with("_body") {
            if let Some(amp) = args.find('&') {
                let ty: String = args[amp + 1..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if is_ident(&ty) && ty != "self" {
                    push(&ty);
                }
            }
        }
    }
    roots
}

/// The crate source directory a type the seam imports lives in: the first path segment of the `use`
/// statement that names it (`busbar_kernel_audit` → `crates/busbar-kernel-audit/src`).
fn crate_dir_of(seam_src: &str, ty: &str) -> Option<String> {
    let code: String = scan::production_lines(seam_src)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    for stmt in code.split(';') {
        let s = stmt.trim();
        let Some(path) = s
            .strip_prefix("use ")
            .or_else(|| s.strip_prefix("pub use "))
        else {
            continue;
        };
        let names_it = path
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|w| w == ty);
        if !names_it {
            continue;
        }
        let first = path.split("::").next()?.trim();
        let dir = match first {
            "crate" | "super" | "self" => "crates/busbar/src".to_string(),
            krate => format!("crates/{}/src", krate.replace('_', "-")),
        };
        return Some(dir);
    }
    None
}

/// Every production declaration under a crate source directory, keyed by type name.
fn crate_decls(cx: &Ctx, dir: &str) -> Result<BTreeMap<String, Vec<TypeDecl>>, String> {
    let spec = WalkSpec::new([dir.to_string()])
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(1);
    let files = cx.walk(&spec).map_err(|e| format!("{dir}: {e:?}"))?;
    let mut map: BTreeMap<String, Vec<TypeDecl>> = BTreeMap::new();
    for f in &files {
        for d in parse_decls(&f.rel_str(), &f.text) {
            map.entry(d.name.clone()).or_default().push(d);
        }
    }
    Ok(map)
}

/// Where one population member came from, printed so a reader can check the derivation.
#[derive(Debug, Clone)]
struct Member {
    decl: TypeDecl,
}

struct Population {
    members: Vec<Member>,
    /// Refusals that mean the rows cannot vouch for the population.
    gaps: Vec<String>,
    journal_roots: Vec<String>,
    store_types: usize,
}

impl Population {
    fn files(&self) -> Vec<String> {
        let mut f: Vec<String> = self.members.iter().map(|m| m.decl.file.clone()).collect();
        f.sort();
        f.dedup();
        f
    }
}

fn derive_population(cx: &Ctx) -> Population {
    let mut members: Vec<Member> = Vec::new();
    let mut gaps = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut admit = |d: TypeDecl, members: &mut Vec<Member>| {
        if seen.insert((d.file.clone(), d.name.clone())) {
            members.push(Member { decl: d });
        }
    };

    // 1. THE STORE FILE — every type it declares.
    let mut store_types = 0;
    match cx.read(STORE_RECORDS_PATH) {
        Ok(src) => {
            let decls = parse_decls(STORE_RECORDS_PATH, &src);
            store_types = decls.len();
            if store_types < STORE_TYPE_FLOOR {
                gaps.push(format!(
                    "{STORE_RECORDS_PATH} declares {store_types} type(s), below the floor of \
                     {STORE_TYPE_FLOOR} — a record moved or split out of the file this population \
                     is drawn from (follow it; do not lower the floor to fit)"
                ));
            }
            for d in decls {
                admit(d, &mut members);
            }
        }
        Err(e) => gaps.push(format!("could not read {STORE_RECORDS_PATH}: {e}")),
    }

    // 2. THE JOURNAL — every type the durability seam writes, and what its fields name.
    let mut roots = Vec::new();
    match cx.read(JOURNAL_SEAM) {
        Err(e) => gaps.push(format!("could not read {JOURNAL_SEAM}: {e}")),
        Ok(seam) => {
            roots = journal_roots(&seam);
            if roots.len() < JOURNAL_ROOT_FLOOR {
                gaps.push(format!(
                    "{JOURNAL_SEAM} yields {} journal record type(s) ({}), below the floor of \
                     {JOURNAL_ROOT_FLOOR} — a journal writer the derivation no longer sees",
                    roots.len(),
                    roots.join(", ")
                ));
            }
            let seam_decls = parse_decls(JOURNAL_SEAM, &seam);
            let mut crate_cache: BTreeMap<String, BTreeMap<String, Vec<TypeDecl>>> =
                BTreeMap::new();
            for root in &roots {
                // A type the seam defines itself resolves there; any other resolves through the
                // seam's own `use` line to the crate that defines it.
                let (dir, local) = if seam_decls.iter().any(|d| &d.name == root) {
                    ("crates/busbar/src/root".to_string(), true)
                } else {
                    match crate_dir_of(&seam, root) {
                        Some(d) => (d, false),
                        None => {
                            gaps.push(format!(
                                "journal record `{root}` ({JOURNAL_SEAM}) is neither defined there \
                                 nor named by any `use` line — the scan cannot find its definition"
                            ));
                            continue;
                        }
                    }
                };
                if !crate_cache.contains_key(&dir) {
                    match crate_decls(cx, &dir) {
                        Ok(m) => {
                            crate_cache.insert(dir.clone(), m);
                        }
                        Err(e) => {
                            gaps.push(format!(
                                "journal record `{root}`: its crate could not be walked: {e}"
                            ));
                            continue;
                        }
                    }
                }
                let decls = &crate_cache[&dir];
                let candidates: Vec<&TypeDecl> = if local {
                    seam_decls.iter().filter(|d| &d.name == root).collect()
                } else {
                    decls
                        .get(root)
                        .map(|v| v.iter().collect())
                        .unwrap_or_default()
                };
                let def = match candidates.as_slice() {
                    [one] => (*one).clone(),
                    [] => {
                        gaps.push(format!(
                            "journal record `{root}` resolves to NO definition under {dir} — \
                             renamed or moved; the rows cannot vouch for a record they cannot read"
                        ));
                        continue;
                    }
                    many => {
                        gaps.push(format!(
                            "journal record `{root}` resolves to {} definitions under {dir} ({}) — \
                             the scan cannot tell which one the seam writes",
                            many.len(),
                            many.iter().map(|d| d.file.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                        continue;
                    }
                };
                // THE FIELD CLOSURE: every type a member's fields name that this crate defines
                // exactly once. `AuditRecord.amount: Amount` is how `Amount` is reached.
                let mut queue = vec![def];
                while let Some(d) = queue.pop() {
                    for f in &d.fields {
                        for word in
                            f.ty.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                                .filter(|w| is_ident(w))
                        {
                            let pool: Vec<&TypeDecl> = if local {
                                seam_decls.iter().filter(|x| x.name == word).collect()
                            } else {
                                decls
                                    .get(word)
                                    .map(|v| v.iter().collect())
                                    .unwrap_or_default()
                            };
                            if let [one] = pool.as_slice() {
                                if !members
                                    .iter()
                                    .any(|m| m.decl.name == one.name && m.decl.file == one.file)
                                {
                                    queue.push((*one).clone());
                                }
                            }
                        }
                    }
                    admit(d, &mut members);
                }
            }
        }
    }

    let files: Vec<String> = members.iter().map(|m| m.decl.file.clone()).collect();
    for home in REQUIRED_HOMES {
        if !files.iter().any(|f| f == home) {
            gaps.push(format!(
                "{home} is not in the derived population — the durable record file BUSBAR-1.6.0 \
                 Part 0 holds this gate to is unseen"
            ));
        }
    }

    Population {
        members,
        gaps,
        journal_roots: roots,
        store_types,
    }
}

struct RecordScan {
    plugin_keyed: Vec<String>,
    stored_price: Vec<String>,
}

fn scan_population(pop: &Population) -> RecordScan {
    let mut plugin_keyed = Vec::new();
    let mut stored_price = Vec::new();
    for m in &pop.members {
        let d = &m.decl;
        for f in &d.fields {
            let where_ = format!("`{}` on {} at {}:{}", f.name, d.name, d.file, f.line);
            if IDENTITY_TOKENS.iter().any(|t| token_in_ident(&f.name, t)) {
                plugin_keyed.push(where_.clone());
            }
            if PRICE_ALLOW.contains(&f.name.as_str()) {
                continue;
            }
            if PRICE_TOKENS.iter().any(|t| token_in_ident(&f.name, t)) {
                stored_price.push(where_);
            }
        }
    }
    plugin_keyed.sort();
    stored_price.sort();
    RecordScan {
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

/// The overlay that REMOVES every stored-price field the gate measures on `cx` — the selftest's
/// fixture baseline for `no-stored-price`, which is standing RED on the real tree (item 9's true
/// finding). Derived from the gate's own scan, so it neutralises exactly today's findings and no
/// more; a plant laid over it is the only thing that can turn the row red again.
fn price_free_fixture(cx: &Ctx) -> Overlay {
    let pop = derive_population(cx);
    let mut by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for m in &pop.members {
        for f in &m.decl.fields {
            if PRICE_ALLOW.contains(&f.name.as_str()) {
                continue;
            }
            if PRICE_TOKENS.iter().any(|t| token_in_ident(&f.name, t)) {
                by_file.entry(m.decl.file.clone()).or_default().push(f.line);
            }
        }
    }
    let mut ov = Overlay::new();
    for (file, lines) in by_file {
        let Ok(src) = cx.read(&file) else { continue };
        let kept: Vec<&str> = src
            .lines()
            .enumerate()
            .filter(|(i, _)| !lines.contains(&(i + 1)))
            .map(|(_, l)| l)
            .collect();
        ov.set(&file, format!("{}\n", kept.join("\n")));
    }
    ov
}

pub struct MoneyInvariantsGate;

impl MoneyInvariantsGate {
    fn rows(cx: &Ctx) -> Vec<Row> {
        let pop = derive_population(cx);

        // EXISTENCE BEFORE VERDICT. Both record rows are claims ABOUT the durable records; a record
        // source the derivation could not read, resolve or reach is a record neither row
        // inspected, so each row refuses rather than passing over the gap.
        if !pop.gaps.is_empty() {
            let fail = |id| {
                Row::fail(
                    id,
                    "a durable record this row governs could not be found — the scan cannot vouch for it",
                    format!(
                        "{} gap(s) in the derived record population: {}",
                        pop.gaps.len(),
                        pop.gaps.join("; ")
                    ),
                )
            };
            return vec![
                fail(ROW_NO_PLUGIN_KEYED),
                fail(ROW_NO_STORED_PRICE),
                Self::seal_row(cx),
            ];
        }
        let scan = scan_population(&pop);
        let scanned = format!(
            "{} durable record type(s) scanned ({} declared in {STORE_RECORDS_PATH}; journal \
             records {} and the types their fields name) across {}",
            pop.members.len(),
            pop.store_types,
            pop.journal_roots.join(", "),
            pop.files().join(", ")
        );

        let no_plugin = if scan.plugin_keyed.is_empty() {
            Row::pass(
                ROW_NO_PLUGIN_KEYED,
                "no money-path record carries a plugin/plane identity field (#77(1))",
                format!(
                    "{scanned}; money is keyed by (principal, meter_class, units, timestamp) — \
                     per-plugin pricing is unrepresentable"
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
                "no durable record stores a price/spend figure — price is read-time (#77(3))",
                format!(
                    "{scanned}; the durable records carry RAW COUNTS only; spend = Σ count × \
                     rate_card at read time"
                ),
            )
        } else {
            Row::fail(
                ROW_NO_STORED_PRICE,
                "a durable record stores a price/spend figure — #77(3) requires read-time pricing",
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

/// `base` with `path`'s content replaced by `f(<path's content under base>)`.
fn plant_over(cx: &Ctx, base: &Overlay, path: &str, f: impl FnOnce(String) -> String) -> Overlay {
    let current = cx.with_overlay(base.clone()).read(path).unwrap_or_default();
    let mut ov = base.clone();
    ov.set(path, f(current));
    ov
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
        const AUDIT: &str = "crates/busbar-kernel-audit/src/record.rs";

        // THE FIXTURE BASELINE. `no-stored-price` is standing RED on the real tree — item 9's true
        // finding, a priced `amount` on the journalled audit record — so a plant into the real
        // tree could prove nothing about that row (PROOF IMPOSSIBLE). Every stored-price case
        // below therefore runs over the real tree with today's measured stored-price fields
        // removed, where the row is GREEN, and plants its defect on top of that.
        let fixture = price_free_fixture(cx);
        let fcx = cx.with_overlay(fixture.clone());

        // GREEN (control): the rows that are green on the real tree stay green unplanted.
        report.push(prove_rows_green(
            cx,
            self,
            "the committed tree holds no plugin-keyed money field and one seal site",
            &[ROW_NO_PLUGIN_KEYED, ROW_SINGLE_SEAL],
            Overlay::new(),
        ));
        // GREEN (control): removing exactly the measured stored-price fields turns the row green —
        // so the finding list is complete, and the fixture every RED below plants into is clean.
        report.push(prove_rows_green(
            cx,
            self,
            "with today's measured stored-price fields removed the durable records are counts-only",
            &[ROW_NO_STORED_PRICE],
            fixture.clone(),
        ));

        // RED (a): a plugin-keyed field on a store record is caught (#77(1)).
        let src = cx.read(STORE_RECORDS_PATH).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            STORE_RECORDS_PATH,
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

        // RED (e) — item 9, the exit test: a stored price on the journalled AUDIT record — the file
        // this gate never read — is caught.
        let ov5 = plant_over(cx, &fixture, AUDIT, |s| {
            s.replace(
                "pub struct AuditRecord {",
                "pub struct AuditRecord {\n    pub price: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a stored price on the journalled audit record is RED",
            &[ROW_NO_STORED_PRICE],
            ov5,
            &["`price` on AuditRecord", AUDIT],
        ));

        // RED (f): a stored price on a type reached ONLY through the field closure (`Controls` →
        // `HookApplied`) is caught — the closure is part of the population, not decoration.
        let ov6 = plant_over(cx, &fixture, AUDIT, |s| {
            s.replace(
                "pub struct HookApplied {",
                "pub struct HookApplied {\n    pub hook_cost: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a stored price on a type the audit record reaches by field is RED",
            &[ROW_NO_STORED_PRICE],
            ov6,
            &["`hook_cost` on HookApplied"],
        ));

        // RED (b): a stored price/spend field on a store record is caught (#77(3)).
        let ov2 = plant_over(cx, &fixture, STORE_RECORDS_PATH, |s| {
            s.replace(
                "pub struct UsageLedger {",
                "pub struct UsageLedger {\n    pub spend_cents: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a stored price/spend field on a money record is RED",
            &[ROW_NO_STORED_PRICE],
            ov2,
            &["spend"],
        ));

        // RED (d) — items 210/211, rebuilt on the derived population: a journal record the scan
        // cannot RESOLVE is not a record it passed. Rename the audit record's definition and give
        // it a plane-keyed field: the seam still journals `AuditRecord`, which now names nothing,
        // so both record rows refuse naming it instead of scanning past the renamed struct.
        let ov4 = plant_over(cx, &fixture, AUDIT, |s| {
            s.replace(
                "pub struct AuditRecord {",
                "pub struct AuditRow {\n    pub plane_id: String,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a renamed journal record is RED on both record rows, not scanned-past",
            &[ROW_NO_PLUGIN_KEYED, ROW_NO_STORED_PRICE],
            ov4,
            &["`AuditRecord` resolves to NO definition"],
        ));

        // RED (g): the journal derivation has a floor — a seam whose body writers stop being
        // recognisable is a population collapsing, not a clean one.
        let ov7 = plant_over(cx, &fixture, JOURNAL_SEAM, |s| {
            s.replace("pub fn audit_body(", "pub fn audit_bytes(")
        });
        report.push(prove_red(
            &fcx,
            self,
            "a journal writer the derivation stops seeing is RED, not a smaller clean population",
            &[ROW_NO_PLUGIN_KEYED, ROW_NO_STORED_PRICE],
            ov7,
            &[&format!("below the floor of {JOURNAL_ROOT_FLOOR}")],
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
