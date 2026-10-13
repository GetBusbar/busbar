// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `cargo xtask gate money-invariants` — THE W3.b MONEY-MODEL INVARIANTS, ENFORCED.
//!
//! This is the wave-W3.b proof (arm-gate-per-wave). DECISIONS #77 locks the money model; the
//! read-time pricing VIEW (`cost/project.rs derive_spend_*`) and the class-keyed usage COUNTS
//! (`usage/series.rs`) already exist — what was missing were the GATES that keep the invariants from
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
//! 2. **The journal**: every type a JOURNAL WRITER turns into a journal body — the argument type of
//!    each `fn <name>_body(x: &T)` or free `fn body(x: &T)`, and every `impl T` carrying
//!    `fn body(&self)`. The writers are DERIVED, not named: every production file under `crates/`
//!    that builds a journal entry (`Entry::new(`) and names a money record class
//!    ([`MONEY_CLASSES`]) — today `durability/mod.rs` and `durability/amend.rs`, whose amendment
//!    record is journalled as a `Transaction`. Each type is resolved to its ONE definition through
//!    its writer file's own `use` lines (a type the file defines itself resolves there), and every
//!    type its fields name that the same crate defines is folded in, transitively —
//!    `AuditRecord`'s `amount: Amount` pulls in `Amount`, whose fields are where the priced figure
//!    actually sits.
//!
//! WHAT THE JOURNAL STORES, NOT WHAT A FIELD IS CALLED (audit xtask G HIGH 1). A name list misses
//! a figure under a name it does not know (`Posting.settled: i128`), so the stored-price row also
//! reads each journal WRITER: the fields of the record it reads (`self.key`, `record` handed on
//! whole; a `.len()` of a field is a count of it, not the field), and every type such a field names,
//! whole, across crates through the writer file's `use` lines. A written field whose type is a
//! money figure's ([`MONEY_TYPES`]) is red whatever it is called, and so is any
//! `BodyWriter::figure` call in a writer. An enum's tuple variant is the field its payload is
//! (`Figure(u64)` is `figure: u64`), for both record rows.
//!
//! EXISTENCE BEFORE VERDICT. Both record rows refuse, rather than pass over a gap, when: a record
//! source cannot be read; the store file declares fewer types than [`STORE_TYPE_FLOOR`]; the
//! journal writers yield fewer journal record types than [`JOURNAL_ROOT_FLOOR`]; a journal type
//! resolves to no definition or to more than one; or [`REQUIRED_HOMES`] (the audit record file
//! BUSBAR-1.6.0 Part 0 names, and the amendment record file) is not among the files the population
//! was drawn from. A rename is therefore not a hiding place: the writer still names the old type,
//! and a name that resolves to nothing is a refusal.
//!
//! The scan is comment-stripped and test-module-stripped (a doc note naming a forbidden field is
//! prose, not a field). Row (c) walks production `crates/` the way `seal-witness` does.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_red, prove_rows_green, Case, Expect, Gate, Report};
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

/// The durability seam, where most journal writers live. The gate does NOT read the journal from
/// this one file (that was the hand-named denominator that left `durability/amend.rs`'s amendment
/// record unread): the writer files are derived ([`journal_writers`]). The selftest names it to
/// plant into it.
const JOURNAL_SEAM: &str = "crates/busbar/src/root/durability/mod.rs";

/// The journal record classes that carry money (`busbar-kernel-wal`'s `RecordClass`): a hold,
/// dispatch, settlement or adjustment (`Transaction`), a slice drawn or returned against a bucket
/// window (`Slice`), a sealed checkpoint of balances (`Checkpoint`), a reconciliation pass
/// (`Reconciliation`) and the opening of balances after an upgrade (`Migration`). A production file
/// that builds a journal entry and names one of these is a journal writer this gate reads.
const MONEY_CLASSES: &[&str] = &[
    "RecordClass::Transaction",
    "RecordClass::Slice",
    "RecordClass::Checkpoint",
    "RecordClass::Reconciliation",
    "RecordClass::Migration",
];

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
///
/// EIGHT since the writer files are derived (audit xtask G HIGH 2, 2026-10-13): `Amendment`
/// (`durability/amend.rs`, free `fn body(amendment: &Amendment)`), the count correction journalled
/// as a `Transaction` record, joins the seven the seam writes.
const JOURNAL_ROOT_FLOOR: usize = 8;

/// The record files BUSBAR-1.6.0 Part 0 holds this gate to by name, and the amendment record file a
/// correction is journalled from (audit xtask G HIGH 2). The population is derived; this is the
/// check that the derivation still REACHES them — the defect item 9 names is exactly such a file
/// being outside the scan.
const REQUIRED_HOMES: &[&str] = &[
    "crates/busbar-kernel-audit/src/record.rs",
    "crates/busbar-kernel-audit/src/amend.rs",
];

/// The facts-line constructors (#77(2) / `busbar-contract` `Posted`). One sealed line per unit.
const SEAL_MARKERS: &[&str] = &["Posted::settle(", "Posted::settle_late("];

/// Where the facts line may be sealed: core/kernel crates and the composition root ONLY — never a
/// plane/plugin crate. `busbar-contract` is the type's home (and carries doc examples); the kernel
/// crates own the settle path; `busbar` is the composition root that drives late settlement.
const SEAL_ALLOWED_ROOTS: &[&str] = &[
    "crates/busbar-contract/",
    "crates/busbar-kernel/",
    "crates/busbar-kernel-ledger/",
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

/// An enum's TUPLE VARIANT as the field its payload is: `Figure(u64)` is `figure: u64` (audit xtask
/// G HIGH 1). A payload is what the variant carries onto the chain exactly as a named field is, so a
/// figure in one is judged like a field — before this, a line with no `name:` was not a field at
/// all and `Held::Figure(u64)` was invisible. The variant name is snake-cased so the token match
/// sees its `_` segments (`PrincipalId` is `principal_id`).
fn tuple_variant(trimmed: &str) -> Option<(String, String)> {
    let open = trimmed.find('(')?;
    let close = trimmed.rfind(')')?;
    let name = trimmed[..open].trim();
    if close <= open || !is_ident(name) || !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    let mut snake = String::new();
    for (k, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if k > 0 {
                snake.push('_');
            }
            snake.push(c.to_ascii_lowercase());
        } else {
            snake.push(c);
        }
    }
    Some((snake, trimmed[open + 1..close].trim().to_string()))
}

/// Every production `struct`/`enum` a source file declares, with its named fields — and, for an
/// enum, each tuple variant's payload ([`tuple_variant`]). Test modules and comments are dropped
/// first (through the one scanner), braces are counted on literal-blanked text.
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
        let is_enum = strip_vis(trimmed).starts_with("enum ");
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
                // A variant line sits at depth 1 of the enum's body.
                if is_enum && depth == 1 {
                    if let Some((n, ty)) = tuple_variant(t.trim()) {
                        decl.fields.push(Field {
                            name: n,
                            ty,
                            line: *no,
                        });
                    }
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

/// One journal record type and the writer that turns it into a journal body.
#[derive(Debug, Clone)]
struct Root {
    /// The record type.
    ty: String,
    /// The writer file it was derived from, and the writer's line there.
    file: String,
    line: usize,
    /// The name the writer reads the record through: `self`, or the argument's name.
    recv: String,
    /// The writer's body, from its opening brace to the brace that closes it.
    writer: String,
}

/// The journal record types one journal writer file writes: the `&T` argument of every
/// `fn <name>_body(x: &T)` or free `fn body(x: &T)`, and every `T` whose `impl T { .. }` carries
/// `fn body(&self)` — each with the writer's own text, which is what says what reaches the chain.
fn journal_roots(file: &str, src: &str) -> Vec<Root> {
    let lines = scan::production_lines(src);
    let mut roots: Vec<Root> = Vec::new();
    let mut current_impl: Option<String> = None;
    for (k, (no, text)) in lines.iter().enumerate() {
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
        let found: Option<(String, String)> = if fname == "body" && args.starts_with("&self") {
            current_impl
                .clone()
                .map(|owner| (owner, "self".to_string()))
        } else if fname == "body" || fname.ends_with("_body") {
            args.find('&').and_then(|amp| {
                let ty: String = args[amp + 1..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                // The argument's own name: the identifier just before its `:`.
                let recv = args[..amp]
                    .trim_end()
                    .trim_end_matches(':')
                    .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("")
                    .to_string();
                (is_ident(&ty) && ty != "self").then_some((ty, recv))
            })
        } else {
            None
        };
        let Some((ty, recv)) = found else {
            continue;
        };
        if roots.iter().any(|r| r.ty == ty) {
            continue;
        }
        roots.push(Root {
            ty,
            file: file.to_string(),
            line: *no,
            recv,
            writer: fn_body(&lines[k..]),
        });
    }
    roots
}

/// The body of the function whose signature opens `lines[0]`: its text from the opening brace to
/// the brace that closes it (braces counted on literal-blanked text). Empty for a signature with no
/// body.
fn fn_body(lines: &[(usize, String)]) -> String {
    let mut out = String::new();
    let mut depth: i32 = 0;
    let mut opened = false;
    for (_, text) in lines {
        let blanked = scan::blank_literals(text);
        let from = if opened {
            0
        } else if let (Some(_), Some(raw)) = (blanked.find('{'), text.find('{')) {
            opened = true;
            raw
        } else if blanked.contains(';') {
            break;
        } else {
            continue;
        };
        depth += scan::delta(&blanked, '{', '}');
        out.push_str(&text[from..]);
        out.push('\n');
        if depth <= 0 {
            break;
        }
    }
    out
}

/// The byte offsets just past every WHOLE-WORD occurrence of `needle` in `hay`.
fn word_ends(hay: &str, needle: &str) -> Vec<usize> {
    let wordy = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    let mut from = 0;
    while let Some(at) = hay[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        from = end;
        let before = hay[..start].chars().next_back().is_none_or(|c| !wordy(c));
        let after = hay[end..].chars().next().is_none_or(|c| !wordy(c));
        if before && after {
            out.push(end);
        }
    }
    out
}

/// Reads of a field that put a COUNT or a flag of it on the chain, not the field itself:
/// `checkpoint.totals.len()` is how many balances a checkpoint sealed, never their figures.
const COUNT_READS: &[&str] = &[".len()", ".is_some()", ".is_none()", ".is_empty()"];

/// Whether the writer hands the record on WHOLE (`journal_body(record)`): an occurrence of its name
/// that is not a field read. A writer whose argument the derivation could not name is read as
/// whole too — over-reading is a red to look at, under-reading is a hole.
fn passes_whole(writer: &str, recv: &str) -> bool {
    recv.is_empty()
        || word_ends(writer, recv)
            .into_iter()
            .any(|end| !writer[end..].starts_with('.'))
}

/// Whether the writer reads `recv.field` other than as a count of it.
fn writes_field(writer: &str, recv: &str, field: &str) -> bool {
    word_ends(writer, &format!("{recv}.{field}"))
        .into_iter()
        .any(|end| !COUNT_READS.iter().any(|m| writer[end..].starts_with(*m)))
}

/// THE SERIALIZATION READ (audit xtask G HIGH 1): the fields of a journal record its writer puts on
/// the chain. `Posting` holds `reserved`/`settled`/`overdraft` as readings its writer never writes;
/// a field the writer does read — `self.key`, `self.held`, `self.counts` — reaches the chain.
fn written_fields(def: &TypeDecl, root: &Root) -> Vec<Field> {
    if passes_whole(&root.writer, &root.recv) {
        return def.fields.clone();
    }
    def.fields
        .iter()
        .filter(|f| writes_field(&root.writer, &root.recv, &f.name))
        .cloned()
        .collect()
}

/// The types a money FIGURE is held in: the ledger's signed figure width (`i128` — what
/// `BodyWriter::figure` takes, and what every `Totals` running figure and every `Posting` reading
/// is), its unsigned twin, and the cost view's `Money`. A count is a `u64` or a contract `Count`,
/// never one of these — so a field of one of these types on the chain is a stored figure whatever
/// it is called.
const MONEY_TYPES: &[&str] = &["i128", "u128", "Money"];

/// The identifier words a field's type text names (`Option<UnitCounts>` → `Option`, `UnitCounts`).
fn type_words(ty: &str) -> impl Iterator<Item = &str> + '_ {
    ty.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| is_ident(w))
}

fn money_typed(ty: &str) -> bool {
    type_words(ty).any(|w| MONEY_TYPES.contains(&w))
}

/// THE JOURNAL WRITERS, DERIVED (audit xtask G HIGH 2): every production file under `crates/` that
/// builds a journal entry (`Entry::new(`) and names a money record class ([`MONEY_CLASSES`]), with
/// its text. The FILE is the unit, not the call: a writer may pick the class before it builds the
/// entry (`durability/amend.rs` matches an adjustment to `RecordClass::Transaction` and passes the
/// class as a variable).
fn journal_writers(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = cx.walk(&spec).map_err(|e| format!("{e:?}"))?;
    let mut out = Vec::new();
    for f in &files {
        let code: String = scan::production_lines(&f.text)
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("Entry::new(") && MONEY_CLASSES.iter().any(|c| code.contains(c)) {
            out.push((f.rel_str(), f.text.clone()));
        }
    }
    Ok(out)
}

/// Every `use` path a source file declares (production code only), joined across lines.
fn use_paths(src: &str) -> Vec<String> {
    let code: String = scan::production_lines(src)
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    code.split(';')
        .filter_map(|stmt| {
            let s = stmt.trim();
            s.strip_prefix("use ")
                .or_else(|| s.strip_prefix("pub use "))
                .map(str::to_string)
        })
        .collect()
}

/// The crate source directory a type a file imports lives in: the first path segment of the `use`
/// path that names it (`busbar_kernel_audit` → `crates/busbar-kernel-audit/src`).
fn crate_dir_in(uses: &[String], ty: &str) -> Option<String> {
    for path in uses {
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

type Decls = BTreeMap<String, Vec<TypeDecl>>;
type Cache = BTreeMap<String, Result<Decls, String>>;

/// Where a type name is looked up: the writer file's own declarations, or one crate's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pool {
    Local,
    Crate(String),
}

/// Every definition of `name` in `pool`. `Err` when the pool's crate cannot be walked.
fn lookup(
    cx: &Ctx,
    cache: &mut Cache,
    local: &[TypeDecl],
    pool: &Pool,
    name: &str,
) -> Result<Vec<TypeDecl>, String> {
    match pool {
        Pool::Local => Ok(local.iter().filter(|d| d.name == name).cloned().collect()),
        Pool::Crate(dir) => match cache
            .entry(dir.clone())
            .or_insert_with(|| crate_decls(cx, dir))
        {
            Ok(map) => Ok(map.get(name).cloned().unwrap_or_default()),
            Err(e) => Err(e.clone()),
        },
    }
}

/// The ONE definition a field's type word names, and the pool it was found in: the member's own
/// pool first, then — for a type the writer file imports from another crate (`TotalsKey`,
/// `PostingFlags`, audit xtask G HIGH 1) — the crate its `use` line names. `None` for a word that
/// names no type the tree defines exactly once (a primitive, a std type, an alias, a name two
/// definitions share).
fn resolve_word(
    cx: &Ctx,
    cache: &mut Cache,
    local: &[TypeDecl],
    uses: &[String],
    pool: &Pool,
    word: &str,
) -> Option<(TypeDecl, Pool)> {
    match lookup(cx, cache, local, pool, word).ok()?.as_slice() {
        [one] => return Some((one.clone(), pool.clone())),
        [] => {}
        _ => return None,
    }
    let other = Pool::Crate(crate_dir_in(uses, word)?);
    if other == *pool {
        return None;
    }
    match lookup(cx, cache, local, &other, word).ok()?.as_slice() {
        [one] => Some((one.clone(), other.clone())),
        _ => None,
    }
}

/// One field a journal writer puts on the chain, and which writer.
#[derive(Debug, Clone)]
struct Written {
    owner: String,
    file: String,
    field: Field,
    writer: String,
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
    /// The derived journal writer files the roots were read from.
    writers: Vec<String>,
    /// Every field a journal writer puts on the chain (the serialization read).
    written: Vec<Written>,
    /// Every `BodyWriter::figure` call in a journal writer.
    figures: Vec<String>,
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

    // 2. THE JOURNAL — every type a derived journal writer writes, and what its fields name.
    let mut roots: Vec<String> = Vec::new();
    let mut writers: Vec<String> = Vec::new();
    let mut written: Vec<Written> = Vec::new();
    let mut figures: Vec<String> = Vec::new();
    match journal_writers(cx) {
        Err(e) => gaps.push(format!("the journal-writer walk could not run: {e}")),
        Ok(files) => {
            let mut cache: Cache = BTreeMap::new();
            for (seam_path, seam) in &files {
                writers.push(seam_path.clone());
                let seam_decls = parse_decls(seam_path, seam);
                let uses = use_paths(seam);
                for root in journal_roots(seam_path, seam) {
                    roots.push(root.ty.clone());
                    let name = root.ty.as_str();
                    // A type the writer file defines itself resolves there; any other resolves
                    // through the file's own `use` line to the crate that defines it.
                    let (pool, dir) = if seam_decls.iter().any(|d| d.name == name) {
                        (Pool::Local, seam_path.clone())
                    } else {
                        match crate_dir_in(&uses, name) {
                            Some(d) => (Pool::Crate(d.clone()), d),
                            None => {
                                gaps.push(format!(
                                    "journal record `{name}` ({seam_path}) is neither defined \
                                     there nor named by any `use` line — the scan cannot find its \
                                     definition"
                                ));
                                continue;
                            }
                        }
                    };
                    let candidates = match lookup(cx, &mut cache, &seam_decls, &pool, name) {
                        Ok(c) => c,
                        Err(e) => {
                            gaps.push(format!(
                                "journal record `{name}`: its crate could not be walked: {e}"
                            ));
                            continue;
                        }
                    };
                    let def = match candidates.as_slice() {
                        [one] => one.clone(),
                        [] => {
                            gaps.push(format!(
                                "journal record `{name}` resolves to NO definition under {dir} — \
                                 renamed or moved; the rows cannot vouch for a record they cannot \
                                 read"
                            ));
                            continue;
                        }
                        many => {
                            gaps.push(format!(
                                "journal record `{name}` resolves to {} definitions under {dir} \
                                 ({}) — the scan cannot tell which one {seam_path} writes",
                                many.len(),
                                many.iter()
                                    .map(|d| d.file.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                            continue;
                        }
                    };
                    // THE FIELD CLOSURE: every type a member's fields (and variant payloads) name
                    // that its crate — or, imported, another crate — defines exactly once.
                    // `AuditRecord.amount: Amount` is how `Amount` is reached.
                    let mut queue = vec![(def.clone(), pool.clone())];
                    while let Some((d, p)) = queue.pop() {
                        for f in &d.fields {
                            for word in type_words(&f.ty) {
                                let Some((one, q)) =
                                    resolve_word(cx, &mut cache, &seam_decls, &uses, &p, word)
                                else {
                                    continue;
                                };
                                if !members
                                    .iter()
                                    .any(|m| m.decl.name == one.name && m.decl.file == one.file)
                                {
                                    queue.push((one, q));
                                }
                            }
                        }
                        admit(d, &mut members);
                    }
                    // THE SERIALIZATION READ (audit xtask G HIGH 1): what the writer puts on the
                    // chain — the root's fields its writer reads, and every type such a field
                    // names, whole. A `BodyWriter::figure` call is a ledger figure by the writer's
                    // own API.
                    let at = format!("the `{}` writer at {}:{}", root.ty, root.file, root.line);
                    if root.writer.contains(".figure(") {
                        figures.push(format!(
                            "`BodyWriter::figure` (a signed ledger figure) in {at}"
                        ));
                    }
                    let mut chain = vec![(written_fields(&def, &root), def, pool)];
                    let mut read = std::collections::BTreeSet::new();
                    while let Some((fields, d, p)) = chain.pop() {
                        if !read.insert((d.file.clone(), d.name.clone())) {
                            continue;
                        }
                        for f in fields {
                            for word in type_words(&f.ty) {
                                if let Some((one, q)) =
                                    resolve_word(cx, &mut cache, &seam_decls, &uses, &p, word)
                                {
                                    chain.push((one.fields.clone(), one, q));
                                }
                            }
                            written.push(Written {
                                owner: d.name.clone(),
                                file: d.file.clone(),
                                field: f,
                                writer: at.clone(),
                            });
                        }
                    }
                }
            }
            if roots.len() < JOURNAL_ROOT_FLOOR {
                gaps.push(format!(
                    "the journal writers ({}) yield {} journal record type(s) ({}), below the \
                     floor of {JOURNAL_ROOT_FLOOR} — a journal writer the derivation no longer sees",
                    writers.join(", "),
                    roots.len(),
                    roots.join(", ")
                ));
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
        writers,
        written,
        figures,
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
    // WHAT THE JOURNAL STORES, by type (audit xtask G HIGH 1): a field a journal writer puts on the
    // chain whose type is a money figure's, whatever its name — `Posting.settled: i128` written by
    // `Posting::body` is a stored figure though no token names it.
    let mut judged = std::collections::BTreeSet::new();
    for w in &pop.written {
        if money_typed(&w.field.ty)
            && judged.insert((w.file.clone(), w.field.line, w.field.name.clone()))
        {
            stored_price.push(format!(
                "`{}: {}` on {} at {}:{} — a money-typed figure {} puts on the chain",
                w.field.name, w.field.ty, w.owner, w.file, w.field.line, w.writer
            ));
        }
    }
    stored_price.extend(pop.figures.iter().cloned());
    plugin_keyed.sort();
    stored_price.sort();
    RecordScan {
        plugin_keyed,
        stored_price,
    }
}

/// THE POLICY RECORD CLASS (ARCHITECT ruling, row 159, 2026-10-13). A Policy record carries the
/// RATE CARD the counts are priced by at read time — a rate is not money moved — so it may carry
/// exact integer RATES at a DECLARED scale, never `Money` and never a moved amount. The rule is
/// EXHAUSTIVE BY DECLARED ROLE: every integer field a Policy writer puts on the chain is listed in
/// [`POLICY_FIELDS`] with its role, so a new money field can never ride in as a "count".
const POLICY_CLASS: &str = "RecordClass::Policy";

/// The roles an integer on a Policy record may hold. `money-rate` carries its scale (minor units 2,
/// nanos 9: [`RATE_SCALES`]); the others carry none.
const POLICY_ROLES: &[&str] = &["money-rate", "time", "seq", "epoch", "count"];

/// The scales a rate may be declared at: minor units (2) and nano-units (9).
const RATE_SCALES: &[u8] = &[2, 9];

/// The integer type words a Policy field is judged by. `u8` is bytes (a digest, a payload), not a
/// number, and is not one of them.
const INT_WORDS: &[&str] = &[
    "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

/// EVERY integer field a Policy writer puts on the chain, by `(record type, field)`, with its role
/// and, for a rate, its scale. Measured on predev 2026-10-13: the card applied by config
/// (`root/kernel.rs` `CardApplied::body`) and the operator's rate amendment
/// (`root/units_admin/mod.rs` `amendment_body`). `flat`, `planes` (per-plane request and session
/// fees) and `sealed_fee` are the card's fees in MINOR units (`card.fee()`, scale 2); `cells`,
/// `units` and `rates` are per-unit rates in nanos (scale 9).
const POLICY_FIELDS: &[(&str, &str, &str, Option<u8>)] = &[
    ("CardApplied", "effective_from", "time", None),
    ("CardApplied", "appended_at", "time", None),
    ("CardApplied", "policy_epoch", "epoch", None),
    ("CardForm", "flat", "money-rate", Some(2)),
    ("CardForm", "cells", "money-rate", Some(9)),
    ("CardForm", "units", "money-rate", Some(9)),
    ("CardForm", "planes", "money-rate", Some(2)),
    ("AmendmentRecord", "effective_from", "time", None),
    ("AmendmentRecord", "effective_until", "time", None),
    ("AmendmentRecord", "amended_at_ms", "time", None),
    ("AmendmentRecord", "sealed_fee", "money-rate", Some(2)),
    ("AmendmentRecord", "rates", "money-rate", Some(9)),
    ("CommitUpgradeRecord", "at", "time", None),
];

/// The Policy record types the writers yield today (`CardApplied`, `AmendmentRecord`,
/// `CommitUpgradeRecord`): fewer is a Policy writer the derivation stopped seeing.
const POLICY_ROOT_FLOOR: usize = 3;

/// The call that seals a Policy record (`AmendmentJournal::seal_policy`). A file that calls it is a
/// Policy writer file, and its first argument must be a typed body writer's (`<name>_body(..)` or
/// `.body()`), never a body built inline.
const POLICY_SEAL: &str = "seal_policy(";

/// The first argument of every `seal_policy(` call in `code` that is not a typed body writer's.
fn inline_policy_bodies(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in code.match_indices(POLICY_SEAL) {
        // The declaration (`fn seal_policy(`) is not a call.
        if code[..i].trim_end().ends_with("fn") {
            continue;
        }
        let rest = &code[i + POLICY_SEAL.len()..];
        let mut depth = 0i32;
        let arg: String = rest
            .chars()
            .take_while(|c| {
                match c {
                    '(' | '{' | '[' => depth += 1,
                    ')' | '}' | ']' if depth == 0 => return false,
                    ')' | '}' | ']' => depth -= 1,
                    ',' if depth == 0 => return false,
                    _ => {}
                }
                true
            })
            .collect();
        let arg = arg.trim();
        let head: String = arg
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
            .collect();
        let typed = (head.ends_with("_body") && arg[head.len()..].starts_with('('))
            || arg.ends_with(".body()");
        if !typed {
            out.push(arg.to_string());
        }
    }
    out
}

/// The table's own rules: a known role; a rate with a declared scale the ledger knows; nothing
/// else with a scale. One finding per broken row.
fn policy_table_problems(table: &[(&str, &str, &str, Option<u8>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (ty, field, role, scale) in table {
        let at = format!("the Policy field table's `{ty}.{field}`");
        if !POLICY_ROLES.contains(role) {
            out.push(format!(
                "{at} names role `{role}`, which is none of {POLICY_ROLES:?}"
            ));
        } else if *role == "money-rate" {
            match scale {
                None => out.push(format!("{at} is a money-rate with no declared scale")),
                Some(n) if !RATE_SCALES.contains(n) => out.push(format!(
                    "{at} declares scale {n}, which is none of {RATE_SCALES:?}"
                )),
                Some(_) => {}
            }
        } else if scale.is_some() {
            out.push(format!("{at} is a `{role}` and declares a scale"));
        }
    }
    out
}

/// The Policy writers' verdict: `(findings, gaps)`. A finding is a field or a figure the rule
/// refuses; a gap is a Policy record the scan could not read.
fn policy_scan(cx: &Ctx, table: &[(&str, &str, &str, Option<u8>)]) -> (Vec<String>, Vec<String>) {
    let mut findings = policy_table_problems(table);
    let mut gaps = Vec::new();
    let spec = WalkSpec::new(ROOTS.iter().copied())
        .ext("rs")
        .exclude(EXCLUDE.iter().copied())
        .min_files(SCAN_FLOOR);
    let files = match cx.walk(&spec) {
        Ok(f) => f,
        Err(e) => {
            return (
                findings,
                vec![format!("the Policy writer walk could not run: {e:?}")],
            )
        }
    };
    let mut roots = 0usize;
    let mut seen_fields: std::collections::BTreeSet<(String, String)> = Default::default();
    let mut cache: Cache = BTreeMap::new();
    for f in &files {
        let code: String = scan::production_lines(&f.text)
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
        let seals = code.contains(POLICY_SEAL);
        if !((code.contains("Entry::new(") && code.contains(POLICY_CLASS)) || seals) {
            continue;
        }
        let path = f.rel_str();
        for arg in inline_policy_bodies(&code) {
            findings.push(format!(
                "a Policy body built inline (`seal_policy({arg}, ..)` in {path}) — a Policy record \
                 is written by a typed body writer whose fields the rule reads"
            ));
        }
        let local = parse_decls(&path, &f.text);
        let uses = use_paths(&f.text);
        for root in journal_roots(&path, &f.text) {
            let Some(def) = local.iter().find(|d| d.name == root.ty).cloned() else {
                gaps.push(format!(
                    "Policy record `{}` ({path}) is not defined in its writer file — the scan \
                     cannot read its fields",
                    root.ty
                ));
                continue;
            };
            roots += 1;
            let at = format!("the `{}` writer at {}:{}", root.ty, root.file, root.line);
            // A ledger figure written onto a Policy record must be a listed rate.
            for (i, _) in root.writer.match_indices(".figure(") {
                let arg: String = root.writer[i + ".figure(".len()..]
                    .chars()
                    .take_while(|c| *c != ';')
                    .collect();
                let rate = table.iter().any(|(ty, field, role, _)| {
                    *ty == root.ty && *role == "money-rate" && arg.contains(&format!(".{field}"))
                });
                if !rate {
                    findings.push(format!(
                        "`BodyWriter::figure({})` in {at} writes a figure that is no listed rate",
                        arg.trim().trim_end_matches(')')
                    ));
                }
            }
            let mut chain = vec![(written_fields(&def, &root), def, Pool::Local)];
            let mut read = std::collections::BTreeSet::new();
            while let Some((fields, d, pool)) = chain.pop() {
                if !read.insert((d.file.clone(), d.name.clone())) {
                    continue;
                }
                for field in fields {
                    for word in type_words(&field.ty) {
                        if let Some((one, q)) =
                            resolve_word(cx, &mut cache, &local, &uses, &pool, word)
                        {
                            chain.push((one.fields.clone(), one, q));
                        }
                    }
                    let where_ = format!(
                        "`{}: {}` on {} at {}:{} ({at})",
                        field.name, field.ty, d.name, d.file, field.line
                    );
                    if type_words(&field.ty).any(|w| w == "Money") {
                        findings.push(format!("{where_} is Money on a Policy record"));
                        continue;
                    }
                    if !type_words(&field.ty).any(|w| INT_WORDS.contains(&w)) {
                        continue;
                    }
                    seen_fields.insert((d.name.clone(), field.name.clone()));
                    if !table
                        .iter()
                        .any(|(ty, name, _, _)| *ty == d.name && *name == field.name)
                    {
                        findings.push(format!(
                            "{where_} is an integer on a Policy record with no declared role"
                        ));
                    }
                }
            }
        }
    }
    if roots < POLICY_ROOT_FLOOR {
        gaps.push(format!(
            "the Policy writers yield {roots} Policy record type(s), below the floor of \
             {POLICY_ROOT_FLOOR} — a Policy writer the derivation no longer sees"
        ));
    }
    for (ty, field, _, _) in table {
        if !seen_fields.contains(&(ty.to_string(), field.to_string())) {
            findings.push(format!(
                "the Policy field table lists `{ty}.{field}`, an integer no Policy writer puts on \
                 the chain (a stale row)"
            ));
        }
    }
    (findings, gaps)
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
        let mut pop = derive_population(cx);
        // THE POLICY RECORDS (ARCHITECT ruling, row 159): exact integer rates at a declared scale,
        // every integer by its declared role, no Money. Their gaps refuse like the money records'.
        let (policy_findings, policy_gaps) = policy_scan(cx, POLICY_FIELDS);
        pop.gaps.extend(policy_gaps);

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
        let mut scan = scan_population(&pop);
        scan.stored_price.extend(policy_findings);
        scan.stored_price.sort();
        let scanned = format!(
            "{} durable record type(s) scanned ({} declared in {STORE_RECORDS_PATH}; journal \
             records {} written by {} and the types their fields name) across {}",
            pop.members.len(),
            pop.store_types,
            pop.journal_roots.join(", "),
            pop.writers.join(", "),
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

        // RED (h) — audit xtask G HIGH 2: a stored price on the AMENDMENT record is caught. The
        // count correction is journalled as a `Transaction` record from `durability/amend.rs`, a
        // writer file the gate used to never open (it read the one hand-named seam, `mod.rs`), so
        // `Amendment` was outside the population and this plant passed GREEN.
        const AMEND: &str = "crates/busbar-kernel-audit/src/amend.rs";
        let ov8 = plant_over(cx, &fixture, AMEND, |s| {
            s.replace(
                "pub struct Amendment {",
                "pub struct Amendment {\n    pub price: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a stored price on the journalled amendment record is RED",
            &[ROW_NO_STORED_PRICE],
            ov8,
            &["`price` on Amendment", AMEND],
        ));

        // RED (i) — audit xtask G HIGH 1: a money figure the posting writer puts on the chain under
        // a name no token knows. `Posting.settled` is an `i128` reading; the old gate judged field
        // NAMES only, so one `body.num(self.settled as u64)` in `Posting::body` passed GREEN.
        let ov9 = plant_over(cx, &fixture, JOURNAL_SEAM, |s| {
            s.replace(
                "body.num(self.rate_card_version);",
                "body.num(self.rate_card_version);\n        body.num(self.settled as u64);",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a money-typed field the journal writer writes is RED whatever it is called",
            &[ROW_NO_STORED_PRICE],
            ov9,
            &["`settled: i128` on Posting"],
        ));

        // RED (j) — audit xtask G HIGH 1: a money figure carried as an ENUM VARIANT PAYLOAD of a
        // journalled record (`UnitMark.mark: Mark`, written by `UnitMark::body`). The old gate read
        // only `name: Type` parts, so a tuple variant was no field at all and this passed GREEN.
        let ov10 = plant_over(cx, &fixture, JOURNAL_SEAM, |s| {
            s.replace("pub enum Mark {", "pub enum Mark {\n    Charged(i128),")
        });
        report.push(prove_red(
            &fcx,
            self,
            "a money figure in an enum variant payload on a journalled record is RED",
            &[ROW_NO_STORED_PRICE],
            ov10,
            &["`charged: i128` on Mark"],
        ));

        // RED (k) — audit xtask G HIGH 1: a journal writer calling `BodyWriter::figure`, the
        // journal's own "signed ledger figure" field. The old gate never read a writer.
        let ov11 = plant_over(cx, &fixture, JOURNAL_SEAM, |s| {
            s.replace(
                "body.text(&self.taken.claim);",
                "body.text(&self.taken.claim);\n        body.figure(0);",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a ledger figure a journal writer writes is RED",
            &[ROW_NO_STORED_PRICE],
            ov11,
            &["`BodyWriter::figure`"],
        ));

        // RED (l) — audit xtask G HIGH 1: a stored price on a type reached ONLY through a variant
        // payload (`Amendment.body: AmendBody` → `AmendBody::Adjust(Adjust)`). The old closure
        // stopped at the enum, so `Adjust` was never read and this passed GREEN.
        let ov12 = plant_over(cx, &fixture, AMEND, |s| {
            s.replace(
                "pub struct Adjust {",
                "pub struct Adjust {\n    pub fee_nanos: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a stored price on a type a variant payload carries is RED",
            &[ROW_NO_STORED_PRICE],
            ov12,
            &["`fee_nanos` on Adjust"],
        ));

        // RED (m) — audit xtask G HIGH 1: a money figure inside an IMPORTED type the writer puts on
        // the chain (`Posting.key: TotalsKey`, written through `write_key`). `TotalsKey` lives in
        // `busbar-kernel-ledger`; the old closure of a seam-local record never left the seam file,
        // and judged no type.
        const TOTALS: &str = "crates/busbar-kernel-ledger/src/totals.rs";
        let ov13 = plant_over(cx, &fixture, TOTALS, |s| {
            s.replace(
                "pub struct TotalsKey {",
                "pub struct TotalsKey {\n    pub ceiling: i128,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a money figure in an imported type a journal writer writes is RED",
            &[ROW_NO_STORED_PRICE],
            ov13,
            &["`ceiling: i128` on TotalsKey"],
        ));

        // THE POLICY RECORDS (ARCHITECT ruling, row 159, 2026-10-13): exact integer rates at a
        // declared scale, every integer by its declared role, never Money.
        const KERNEL: &str = "crates/busbar/src/root/kernel.rs";
        // RED (n): Money on a Policy record (the applied card's form, written whole) is refused.
        let ov14 = plant_over(cx, &fixture, KERNEL, |s| {
            s.replace(
                "pub struct CardForm {",
                "pub struct CardForm {\n    charge: Money,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "Money on a Policy record is RED",
            &[ROW_NO_STORED_PRICE],
            ov14,
            &["`charge: Money` on CardForm", "is Money on a Policy record"],
        ));
        // RED (o): an integer on a Policy record the table gives no role is refused — a new money
        // field cannot ride in as a "count".
        let ov15 = plant_over(cx, &fixture, KERNEL, |s| {
            s.replace(
                "pub struct CardForm {",
                "pub struct CardForm {\n    extra_cents: u64,",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "an unlisted integer on a Policy record is RED",
            &[ROW_NO_STORED_PRICE],
            ov15,
            &["`extra_cents: u64` on CardForm", "no declared role"],
        ));
        // RED (p): a rate the table lists with no declared scale is refused.
        let unscaled = policy_table_problems(&[("CardForm", "flat", "money-rate", None)]);
        report.push(Case {
            name: "a Policy rate field with no declared scale is RED".to_string(),
            covers: Vec::new(),
            expected: Expect::Red {
                naming: vec!["is a money-rate with no declared scale".to_string()],
            },
            got: if unscaled.is_empty() {
                Expect::Green
            } else {
                Expect::Red { naming: unscaled }
            },
        });
        // GREEN (q): the Policy records as they are — listed time, epoch and rate fields — pass.
        let (policy_findings, policy_gaps) = policy_scan(cx, POLICY_FIELDS);
        report.push(Case {
            name: "the Policy records' listed time, epoch and rate fields are GREEN".to_string(),
            covers: Vec::new(),
            expected: Expect::Green,
            got: if policy_findings.is_empty() && policy_gaps.is_empty() {
                Expect::Green
            } else {
                Expect::Red {
                    naming: policy_findings.into_iter().chain(policy_gaps).collect(),
                }
            },
        });

        // RED (r): a Policy body built inline, out of the field-role rule's reach, is refused.
        const BOUND: &str = "crates/busbar/src/root/units_admin/bound.rs";
        let ov16 = plant_over(cx, &fixture, BOUND, |s| {
            s.replace(
                "journal.seal_policy(commit_upgrade_body(&record), at)",
                "journal.seal_policy(busbar_kernel_wal::BodyWriter::new().finish(), at)",
            )
        });
        report.push(prove_red(
            &fcx,
            self,
            "a Policy body built inline is RED",
            &[ROW_NO_STORED_PRICE],
            ov16,
            &["a Policy body built inline"],
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
