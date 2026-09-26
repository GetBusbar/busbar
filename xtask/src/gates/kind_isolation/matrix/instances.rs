//! THE FIVE MISSING AXES — C1 over every plugin kind, not two (item 118 / C1-KIND).
//!
//! C1 says *core names no instance*, and DECISIONS #3 gives seven plugin kinds: store, secret,
//! auth, hook, export, plane, transport. The matrix measured two of them. `plane` and `transport`
//! are the two families the kind table gives an INSTANCE vocabulary, so their bare ids (`llm`,
//! `ws`) count everywhere; the other five are `Family::Neutral`, whose members contribute only
//! their package name and kind-qualified id — so `busbar-kernel/src/config/sections.rs` could hold
//! `EXPORT_MODULES = ["prometheus", "request-log-webhook", "request-log-file", "otlp"]`, a closed
//! list of export plugin INSTANCE names inside the engine, and `config/mod.rs` could refuse every
//! name outside it, with this gate green. That is a C1 breach, and a C2 breach with it: a
//! dropped-in export plugin cannot be named in config at all.
//!
//! ## THE VOCABULARY IS READ OFF THE TREE, NEVER TYPED HERE
//!
//! A witness that enumerates instances by hand cannot see a new one (item 3). So each of the five
//! kinds' instance names is the union of two derivations, both re-run on every run:
//!
//! 1. THE CENSUS — every crate of the kind contributes its instance id, the name segments after
//!    its marker (`busbar-store-memory` -> `memory`, `busbar-hooks-ranking` -> `ranking`). A new
//!    plugin crate teaches this row its name on the commit that lands it.
//! 2. THE MODULE-NAME CONSTANTS — every production `const` under `crates/` whose identifier carries
//!    the segment `MODULE`/`MODULES` and whose type is `&str` or `&[&str]`: the names an operator
//!    writes after `module:`. That is where a COMPILED-IN instance is named, which is the breach
//!    itself (`EXPORT_MODULE_OTLP`, `STORE_MODULE_VALKEY`, `RETIRED_STORE_MODULES_1_5_3`,
//!    `SECRET_MODULE_ENV`, `ADMIN_TOKENS_MODULE`). Each value is attributed to a kind by, in order:
//!    a kind word among the identifier's segments; a kind word among the declaring file's stem
//!    segments (`config/auth.rs`); the declaring crate's own kind; or the value being a census id of
//!    exactly that kind. A value NO declaration attributes is RED (`unattributed-instance-name`):
//!    an instance name this row cannot place is an instance name this row cannot count.
//!
//! ## WHAT IS COUNTED: THE NAME AS A VALUE
//!
//! A hit is a STRING LITERAL whose whole content is an instance name — `"prometheus"`,
//! `"admin-tokens"`, `"valkey"` — in any file of a `Family::Neutral` crate other than its
//! `Cargo.toml` (a manifest edge is `:deps`' to govern, as it is for the Law 0 class). That is the
//! shape of a closed dispatch on instance names, and it is exactly what the breach is made of.
//!
//! It is narrower than the plane/transport columns ON PURPOSE, and the reason is measurable: the
//! five kinds' real instance names include `file`, `env`, `none`, `keys` and `memory`. Counted as
//! bare words everywhere, `none` is every `None` in the kernel and `file` is every file — a line
//! counter wearing a gate, the thing this module's header refuses for `sse` and `ws`. Counted as a
//! whole literal, `"file"` is a name being matched or declared. The literal is read the way the
//! compiler reads it (escapes decoded, adjacent literals joined — [`super::decoded_line`]), so
//! `"\x6f\x74lp"` and `concat!("ot", "lp")` are `"otlp"`.
//!
//! ## ARMED AT TODAY'S NUMBER
//!
//! Every non-zero cell carries an `[[instance]]` row in `qa/kind-isolation.toml` with TODAY'S
//! measured count (a first measurement, not a raise). The ratchet is exact in both
//! directions like `[[cell]]`: a rise is the landing that grew the naming, a fall with the row left
//! standing is stale slack, and a row over a zero cell is dead. The ship twin owes zero in every
//! neutral crate through the Law 0 class. The drain is Phase 4's.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{is_shipped_source, CrateInfo, Family};

/// The `[[instance]]` table's name in the ledger.
pub const TABLE: &str = "instance";

/// THE FIVE AXES, DERIVED: the plugin kinds (DECISIONS #3) whose family is `Neutral`. `plane` and
/// `transport` are not here because their bare ids are already counted everywhere by the ordinary
/// columns; everything else in the seven is.
pub fn axes() -> Vec<&'static str> {
    super::super::truths::PLUGIN_KINDS
        .iter()
        .copied()
        .filter(|k| super::super::family_of(Some(k)) == Family::Neutral)
        .collect()
}

/// Whether `seg` (an identifier or file-stem segment) is kind `k`'s word: `store`, `stores`,
/// `hook`, `hooks`.
fn is_kind_word(seg: &str, k: &str) -> bool {
    let s = seg.to_ascii_lowercase();
    s == k || Some(s.as_str()) == k.strip_suffix('s') || s == format!("{k}s")
}

/// One instance name, where it came from.
#[derive(Debug, Clone)]
pub struct Source {
    /// The crate that IS this instance, when the name came from the census — never counted against
    /// itself.
    pub owner: Option<String>,
    /// `crate` or `file:line IDENT` — for the report.
    pub from: String,
}

/// The five kinds' instance vocabularies, and every module-name value no rule could attribute.
#[derive(Debug, Default)]
pub struct Vocab {
    pub names: BTreeMap<&'static str, BTreeMap<String, Vec<Source>>>,
    pub unattributed: Vec<String>,
}

/// One `const` declaration a module name was read from.
struct Decl {
    rel: String,
    line: usize,
    ident: String,
    /// The string literals and the bare identifiers of its value.
    literals: Vec<String>,
    idents: Vec<String>,
}

/// The string-literal contents of `s`, in order, RAW — escapes are kept as written (an escaped
/// quote stays inside its literal) for [`decoded_literals`] to decode.
fn literals(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut esc = false;
    for ch in s.chars() {
        match (&mut cur, ch) {
            (Some(buf), _) if esc => {
                buf.push(ch);
                esc = false;
            }
            (Some(buf), '\\') => {
                buf.push('\\');
                esc = true;
            }
            (Some(_), '"') => out.push(cur.take().unwrap_or_default()),
            (Some(buf), _) => buf.push(ch),
            (None, '"') => cur = Some(String::new()),
            (None, _) => {}
        }
    }
    out
}

/// Each literal of `s` read the way the compiler reads it: escapes decoded, ONE LITERAL AT A TIME.
/// [`super::decoded_line`] also joins ADJACENT literals (its `concat!` defence), which turns
/// `&["redis", "busbar-store-redis"]` into one string — right for finding a name split across two
/// literals, wrong for reading a list of names. Callers that need both take the union.
fn decoded_literals(s: &str) -> Vec<String> {
    literals(s)
        .into_iter()
        .map(|lit| {
            let quoted = format!("\"{lit}\"");
            super::decoded_line(&quoted)
                .and_then(|d| literals(&d).into_iter().next())
                .unwrap_or(lit)
        })
        .collect()
}

/// Every `const IDENT: <&str | &[&str]> = …;` whose IDENT carries `MODULE`/`MODULES`.
fn module_decls(rel: &str, text: &str) -> Vec<Decl> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(off) = text[from..].find("const ") {
        let at = from + off;
        from = at + 6;
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let rest = &text[at + 6..];
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if ident.is_empty() || !ident.split('_').any(|s| s == "MODULE" || s == "MODULES") {
            continue;
        }
        let after = rest[ident.len()..].trim_start();
        let Some(ty_and_value) = after.strip_prefix(':') else {
            continue;
        };
        let Some((ty, value)) = ty_and_value.split_once('=') else {
            continue;
        };
        let ty = ty.replace(' ', "");
        if !(ty == "&str" || ty == "&'staticstr" || ty == "&[&str]" || ty == "&[&'staticstr]") {
            continue;
        }
        let value = value.split(';').next().unwrap_or("");
        let mut idents = Vec::new();
        let mut stripped = String::new();
        let mut in_lit = false;
        let mut esc = false;
        for ch in value.chars() {
            if in_lit {
                if esc {
                    esc = false;
                } else if ch == '\\' {
                    esc = true;
                } else if ch == '"' {
                    in_lit = false;
                }
                stripped.push(' ');
                continue;
            }
            if ch == '"' {
                in_lit = true;
                stripped.push(' ');
                continue;
            }
            stripped.push(ch);
        }
        for tok in stripped.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if !tok.is_empty()
                && tok
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                && tok.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            {
                idents.push(tok.to_string());
            }
        }
        out.push(Decl {
            rel: rel.to_string(),
            line: text[..at].matches('\n').count() + 1,
            ident,
            literals: decoded_literals(value),
            idents,
        });
    }
    out
}

/// THE VOCABULARY, READ OFF THE TREE. See the module header for both derivations.
pub fn vocabulary(crates: &[CrateInfo], files: &[(String, String)]) -> Vocab {
    let axes = axes();
    let mut v = Vocab::default();
    for k in &axes {
        v.names.entry(k).or_default();
    }

    // 1. THE CENSUS.
    let mut census: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for c in crates {
        let Some(kind) = c.kind else { continue };
        let Some(k) = axes.iter().copied().find(|k| *k == kind) else {
            continue;
        };
        let Some(id) = super::own_id(c) else { continue };
        census.entry(id.clone()).or_default().insert(k);
        v.names
            .entry(k)
            .or_default()
            .entry(id)
            .or_default()
            .push(Source {
                owner: Some(c.name.clone()),
                from: c.name.clone(),
            });
    }

    // 2. THE MODULE-NAME CONSTANTS.
    let dir_kind: BTreeMap<&str, Option<&'static str>> =
        crates.iter().map(|c| (c.dir.as_str(), c.kind)).collect();
    let mut decls: Vec<Decl> = Vec::new();
    for (rel, text) in files {
        if !rel.ends_with(".rs") || !is_shipped_source(rel) {
            continue;
        }
        decls.extend(module_decls(rel, text));
    }
    // An identifier in a list (`EXPORT_MODULES = &[EXPORT_MODULE_OTLP, …]`) is the value of the
    // `&str` constant it names.
    let by_ident: BTreeMap<&str, Vec<&str>> = {
        let mut m: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for d in &decls {
            if d.literals.len() == 1 && d.idents.is_empty() {
                m.entry(d.ident.as_str())
                    .or_default()
                    .push(d.literals[0].as_str());
            }
        }
        m
    };
    // value -> (kinds any declaration attributes it to, where it was declared)
    let mut values: BTreeMap<String, (BTreeSet<&'static str>, Vec<String>)> = BTreeMap::new();
    for d in &decls {
        let mut vals: Vec<String> = d.literals.clone();
        for i in &d.idents {
            if let Some(vs) = by_ident.get(i.as_str()) {
                vals.extend(vs.iter().map(|s| (*s).to_string()));
            }
        }
        let stem = d
            .rel
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".rs")
            .to_string();
        let krate_kind = super::owning_dir(&d.rel)
            .and_then(|dir| dir_kind.get(dir.as_str()).copied().flatten())
            .filter(|k| axes.contains(k));
        for val in vals {
            if val.trim().is_empty() {
                continue;
            }
            let mut kinds: BTreeSet<&'static str> = BTreeSet::new();
            for k in &axes {
                if d.ident.split('_').any(|s| is_kind_word(s, k)) {
                    kinds.insert(k);
                }
            }
            if kinds.is_empty() {
                for k in &axes {
                    if stem.split('_').any(|s| is_kind_word(s, k)) {
                        kinds.insert(k);
                    }
                }
            }
            if kinds.is_empty() {
                if let Some(k) = krate_kind {
                    kinds.insert(k);
                }
            }
            if kinds.is_empty() {
                if let Some(ks) = census.get(&val) {
                    kinds.extend(ks.iter().copied());
                }
            }
            let e = values.entry(val).or_default();
            e.0.extend(kinds);
            e.1.push(format!("{}:{} {}", d.rel, d.line, d.ident));
        }
    }
    for (val, (kinds, from)) in values {
        if kinds.is_empty() {
            v.unattributed.push(format!(
                "unattributed-instance-name\t{}\t`\"{val}\"` is a plugin MODULE name and no rule \
                 places it in a plugin kind: not its identifier, not its file, not its crate, not \
                 the census. An instance name this row cannot place is one it cannot count. Name \
                 the kind in the constant (`<KIND>_MODULE_…`) or declare it in that kind's config \
                 module.",
                from.join(", ")
            ));
            continue;
        }
        for k in kinds {
            v.names
                .entry(k)
                .or_default()
                .entry(val.clone())
                .or_default()
                .push(Source {
                    owner: None,
                    from: from.join(", "),
                });
        }
    }
    v
}

/// One measured cell: a neutral crate naming one kind's instance, as a value.
#[derive(Debug, Default, Clone)]
pub struct Cell {
    pub count: usize,
    /// `name\tfile:line` per hit — the drain list.
    pub hits: Vec<String>,
}

pub type Instances = BTreeMap<(String, &'static str), Cell>;

/// THE LITERALS OF ONE FILE, MEMOISED. Every self-test case re-runs the gate and a plant changes
/// one file; re-extracting the literals of 1 800 unchanged files per case is the battery's time, not
/// the rule's. Keyed by the path and the bytes, so a memo is never a stale reading.
type LiteralMemo = std::sync::Mutex<BTreeMap<u64, std::sync::Arc<Vec<(usize, String)>>>>;
static LITERAL_MEMO: std::sync::OnceLock<LiteralMemo> = std::sync::OnceLock::new();

fn file_literals(rel: &str, text: &str) -> std::sync::Arc<Vec<(usize, String)>> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    let memo = LITERAL_MEMO.get_or_init(Default::default);
    if let Some(found) = memo.lock().expect("never poisoned").get(&key) {
        return std::sync::Arc::clone(found);
    }
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        if !raw.contains('"') {
            continue;
        }
        // Every literal on its own, and then any string the JOINED reading adds — a name split
        // across `concat!("ot", "lp")` is one name to the compiler and one hit here.
        let own: Vec<String> = decoded_literals(raw)
            .into_iter()
            .map(|l| l.trim().to_ascii_lowercase())
            .collect();
        let joined: Vec<String> = super::decoded_line(raw)
            .map(|d| literals(&d))
            .unwrap_or_default()
            .into_iter()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|l| !own.contains(l))
            .collect();
        for t in own.into_iter().chain(joined) {
            if !t.is_empty() && t.len() <= 64 {
                out.push((i + 1, t));
            }
        }
    }
    let out = std::sync::Arc::new(out);
    memo.lock()
        .expect("never poisoned")
        .insert(key, std::sync::Arc::clone(&out));
    out
}

/// THE FIVE AXES, MEASURED over every `Family::Neutral` crate.
pub fn measure(crates: &[CrateInfo], files: &[(String, String)], vocab: &Vocab) -> Instances {
    let by_dir: BTreeMap<&str, &CrateInfo> = crates
        .iter()
        .filter(|c| c.family == Family::Neutral)
        .map(|c| (c.dir.as_str(), c))
        .collect();
    let mut lookup: BTreeMap<String, Vec<(&'static str, Vec<&str>)>> = BTreeMap::new();
    for (k, names) in &vocab.names {
        for (name, sources) in names {
            let owners: Vec<&str> = sources.iter().filter_map(|s| s.owner.as_deref()).collect();
            lookup
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push((k, owners));
        }
    }
    let mut out = Instances::new();
    for (rel, text) in files {
        if rel.ends_with("Cargo.toml") {
            continue;
        }
        let Some(dir) = super::owning_dir(rel) else {
            continue;
        };
        let Some(c) = by_dir.get(dir.as_str()) else {
            continue;
        };
        for (line, lit) in file_literals(rel, text).iter() {
            let Some(kinds) = lookup.get(lit) else {
                continue;
            };
            for (k, owners) in kinds {
                // A crate is never measured against its own name.
                if owners.contains(&c.name.as_str()) {
                    continue;
                }
                let cell = out.entry((c.name.clone(), *k)).or_default();
                cell.count += 1;
                cell.hits.push(format!("{lit}\t{rel}:{line}"));
            }
        }
    }
    out
}

/// The files a cell's number is made of, heaviest first.
fn heaviest(cell: &Cell) -> String {
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for h in &cell.hits {
        if let Some(at) = h.split('\t').nth(1).and_then(|p| p.rsplit_once(':')) {
            *per.entry(at.0).or_default() += 1;
        }
    }
    let mut v: Vec<(&str, usize)> = per.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.truncate(6);
    v.iter()
        .map(|(f, n)| format!("{f} ({n})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// THE RATCHET — every finding the `[[instance]]` table owes, exact in both directions.
pub fn offenders(
    measured: &Instances,
    vocab: &Vocab,
    reg: &super::super::KindRegistry,
) -> Vec<String> {
    let mut out: Vec<String> = vocab.unattributed.clone();
    let led = super::super::REGISTRY_FILE;

    // A KIND WITH NO INSTANCE NAME IS AN AXIS THAT SEES NOTHING, which reads exactly like an axis
    // over a clean tree. Every one of the five has instances today.
    for (k, names) in &vocab.names {
        if names.is_empty() {
            out.push(format!(
                "empty-instance-vocabulary\t{k}\tneither the census nor any module-name constant \
                 names a single `{k}` instance, so this axis measures nothing — and a measurement \
                 of nothing is indistinguishable from a clean tree."
            ));
        }
    }

    let mut listed: BTreeMap<(String, String), i64> = BTreeMap::new();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for c in &reg.instance_cells {
        listed.insert((c.krate.clone(), c.kind.clone()), c.count);
        *seen.entry((c.krate.clone(), c.kind.clone())).or_default() += 1;
    }
    for ((krate, kind), n) in seen {
        if n > 1 {
            out.push(format!(
                "duplicate-row\t{krate} \u{d7} {kind}\t{n} `[[{TABLE}]]` rows name it. Two rows for \
                 one cell are two answers."
            ));
        }
    }

    for ((krate, kind), cell) in measured {
        let key = (krate.clone(), (*kind).to_string());
        match listed.get(&key) {
            None => out.push(format!(
                "unlisted-instance\t{krate} \u{d7} {kind} = {}\t{krate} names {} `{kind}` \
                 instance(s) as a value and there is no `[[{TABLE}]] crate = \"{krate}\", kind = \
                 \"{kind}\"` in {led}. C1: core names no instance. {}",
                cell.count,
                cell.count,
                heaviest(cell)
            )),
            Some(&n) if n as usize != cell.count => {
                let verb = if (n as usize) < cell.count {
                    "RAISED — this landing grew the naming"
                } else {
                    "STALE SLACK — the count fell and the ceiling did not; slack is how drift hides"
                };
                out.push(format!(
                    "instance-ratchet\t{krate} \u{d7} {kind}\tceiling {n} vs measured {} ({verb}). \
                     The ceiling must equal the count, exactly. {}",
                    cell.count,
                    heaviest(cell)
                ));
            }
            Some(_) => {}
        }
    }
    for (krate, kind) in listed.keys() {
        let live = measured
            .iter()
            .any(|((k, kd), c)| k == krate && kd == kind && c.count > 0);
        if !live {
            out.push(format!(
                "dead-instance\t{krate} \u{d7} {kind}\tthe `[[{TABLE}]]` row covers nothing: the \
                 cell measures 0. Strike it."
            ));
        }
    }
    out
}

/// THE LAW 0/1 CLASS OVER THE FIVE AXES — a neutral crate's instance ceiling is 0, no row raises
/// it. `enforced` as in [`super::law0_offenders`].
pub fn law0(measured: &Instances, enforced: Option<&[&str]>) -> Vec<String> {
    let mut out = Vec::new();
    for ((krate, kind), cell) in measured {
        if cell.count == 0 {
            continue;
        }
        if let Some(list) = enforced {
            if !list.contains(&krate.as_str()) {
                continue;
            }
        }
        out.push(format!(
            "law0-neutral-instance\t{krate} \u{d7} {kind}\t{} `{kind}` instance name(s) written as a \
             value. A NEUTRAL crate may name NO plugin instance: ceiling 0, ARMED — no [[{TABLE}]] \
             row raises it. {}",
            cell.count,
            heaviest(cell)
        ));
    }
    out
}

/// `--report`: the vocabulary and the measured axes, one line each.
pub fn render(measured: &Instances, vocab: &Vocab) -> String {
    let mut s = String::new();
    for (k, names) in &vocab.names {
        for (name, sources) in names {
            let from: Vec<&str> = sources.iter().map(|x| x.from.as_str()).collect();
            s.push_str(&format!("vocab\t{k}\t{name}\t{}\n", from.join(" ; ")));
        }
    }
    for ((krate, kind), cell) in measured {
        s.push_str(&format!("cell\t{krate}\t{kind}\t{}\n", cell.count));
    }
    for ((krate, kind), cell) in measured {
        for h in &cell.hits {
            s.push_str(&format!("hit\t{krate}\t{kind}\t{h}\n"));
        }
    }
    s
}

/// ONE INSTANCE NAME PER AXIS, read off the tree's own vocabulary — never typed into a fixture.
/// A module-name constant is preferred (it is the compiled-in name the breach is made of); an axis
/// with none falls back to its first census id.
fn one_name_per_axis(cx: &crate::ctx::Ctx) -> Result<Vec<(&'static str, String)>, String> {
    let mut crates = super::super::census(cx)?;
    let (planes, ports) = super::super::vocabularies(&crates);
    super::super::assign_instances(&mut crates, &planes, &ports);
    let (files, _) = super::scan_set(cx)?;
    let vocab = vocabulary(&crates, &files);
    let mut out = Vec::new();
    for k in axes() {
        let names = vocab.names.get(k).cloned().unwrap_or_default();
        let pick = names
            .iter()
            .find(|(_, src)| src.iter().all(|s| s.owner.is_none()))
            .or_else(|| names.iter().next())
            .map(|(n, _)| n.clone())
            .ok_or_else(|| format!("the `{k}` axis has no instance name on this tree"))?;
        out.push((k, pick));
    }
    Ok(out)
}

/// THE RED PROOFS THE FIVE AXES OWE (item 118): a planted store/secret/auth/hook/export instance
/// name in core turns `:matrix` RED, on both registrations.
pub fn selftest<'a>(
    cx: &'a crate::ctx::Ctx,
    gate: &'a dyn crate::gates::Gate,
    ship: bool,
    report: &mut crate::gates::Report<'a>,
) {
    use super::ROW_MATRIX;
    use crate::gates::{prove_rows_green, prove_rows_red};

    // THE CORE CRATE THE PLANTS LAND IN. `busbar-core-connsec` is a `core` crate — neutral, and
    // with no `[[instance]]` row today, so each plant is a cell that was ZERO and is not.
    const CORE: &str = "crates/busbar-core-connsec";
    const CORE_NAME: &str = "busbar-core-connsec";

    let names = match one_name_per_axis(cx) {
        Ok(n) => n,
        Err(why) => {
            report.push(crate::gates::CasePlan::from(super::super::unplantable(
                "the five instance axes each have a name to plant",
                &[ROW_MATRIX],
                &["instance"],
                why,
            )));
            return;
        }
    };

    for (k, name) in &names {
        let rel = format!("{CORE}/src/planted_{k}_instance.rs");
        let body = format!("pub const PLANTED: &str = \"{name}\";\n");
        if ship {
            report.push(prove_rows_red(
                cx,
                gate,
                format!(
                    "at the ship ceiling of zero, core writing the `{k}` instance `{name}` is RED"
                ),
                &[ROW_MATRIX],
                super::plant(cx, &rel, &body),
                &[
                    "law0-neutral-instance",
                    &format!("{CORE_NAME} \u{d7} {k}"),
                    &rel,
                ],
            ));
        } else {
            report.push(prove_rows_red(
                cx,
                gate,
                format!("core writing the `{k}` instance `{name}` is an unlisted instance cell"),
                &[ROW_MATRIX],
                super::plant(cx, &rel, &body),
                &[
                    "unlisted-instance",
                    &format!("{CORE_NAME} \u{d7} {k} = 1"),
                    &rel,
                ],
            ));
        }
    }
    if ship {
        return;
    }

    // THE BREACH ITSELF, ONE MORE: the kernel growing its closed list of export instance names.
    if let Some((_, name)) = names.iter().find(|(k, _)| *k == "export") {
        report.push(prove_rows_red(
            cx,
            gate,
            "the kernel naming one more export instance is a RAISED instance cell",
            &[ROW_MATRIX],
            super::plant(
                cx,
                "crates/busbar-kernel/src/planted_export_instance.rs",
                &format!("pub const ALSO: &str = \"{name}\";\n"),
            ),
            &["instance-ratchet", "busbar-kernel \u{d7} export", "RAISED"],
        ));
    }

    // A NEW PLUGIN CRATE TEACHES THE AXIS ITS NAME ON THE COMMIT THAT LANDS IT — item 3's lesson,
    // proven: nothing in this module lists `zanzibar`, and core naming it is RED all the same.
    let mut ov = super::plant(
        cx,
        "crates/busbar-store-zanzibar/Cargo.toml",
        "[package]\nname = \"busbar-store-zanzibar\"\nversion = \"0.0.0\"\n",
    );
    ov.set(
        format!("{CORE}/src/planted_new_store.rs"),
        "pub const S: &str = \"zanzibar\";\n".to_string(),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a store instance that landed this commit is seen in core the same commit",
        &[ROW_MATRIX],
        ov,
        &[
            "unlisted-instance",
            "busbar-core-connsec \u{d7} store = 1",
            "planted_new_store.rs",
        ],
    ));

    // A MODULE NAME NO RULE CAN PLACE IS REFUSED, not dropped: an instance this axis cannot place
    // is an instance it cannot count.
    report.push(prove_rows_red(
        cx,
        gate,
        "a plugin module-name constant no rule can attribute to a kind is refused",
        &[ROW_MATRIX],
        super::plant(
            cx,
            "crates/busbar-kernel/src/planted_frob.rs",
            "pub const FROB_MODULE: &str = \"frobnicate\";\n",
        ),
        &["unattributed-instance-name", "frobnicate", "FROB_MODULE"],
    ));

    // A CRATE IS NEVER MEASURED AGAINST ITS OWN NAME — the store instance writing its own id is
    // the instance, not a neutral crate naming one.
    report.push(prove_rows_green(
        cx,
        gate,
        "a plugin instance writing its own name is not a finding",
        &[ROW_MATRIX],
        super::plant(
            cx,
            "crates/store-memory/src/planted_self.rs",
            "pub const ME: &str = \"memory\";\n",
        ),
    ));

    // THE RATCHET IS EXACT BOTH WAYS, and a ceiling for an axis nothing measures is refused at load.
    //
    // THE STALE-SLACK CASE BUILDS ITS OWN ROW. It used to add 1 to the live `busbar-kernel ×
    // export` ceiling, a cell whose ceiling sits BELOW its count on this tree (54 vs 79, RAISED —
    // owner question Q77): ceiling + 1 is still below the count, so the planted run could only say
    // RAISED again and never STALE SLACK — a proof that could not be had (item 89). The fixture
    // here is a cell the live tree does not have: `busbar-kernel-scope` names the store instance
    // `memory` once, in a file of its own, and the ledger gains an `[[instance]]` row for exactly
    // that cell. At `count = "1"` the row equals its measurement and the row is GREEN (the control
    // below); at `count = "2"` the ceiling sits one above the count, which is the stale slack this
    // case exists to prove the ratchet refuses. Only the number differs between the two plants.
    let slack_fixture = |count: &str| {
        let mut ov = super::plant(
            cx,
            "crates/busbar-kernel-scope/src/planted_slack.rs",
            "pub const S: &str = \"memory\";\n",
        );
        ov.set(
            super::LEDGER,
            format!(
                "{}\n\n[[instance]]\ncrate = \"busbar-kernel-scope\"\nkind = \"store\"\ncount = \"{count}\"\n",
                cx.read(super::LEDGER).unwrap_or_default().trim_end()
            ),
        );
        ov
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "an [[instance]] ceiling equal to its count is green (the stale-slack fixture's control)",
        &[ROW_MATRIX],
        slack_fixture("1"),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "an [[instance]] ceiling left above its count is stale slack",
        &[ROW_MATRIX],
        slack_fixture("2"),
        &[
            "instance-ratchet",
            "busbar-kernel-scope \u{d7} store",
            "ceiling 2 vs measured 1",
            "STALE SLACK",
        ],
    ));
    let text = cx.read(super::LEDGER).unwrap_or_default();
    report.push(prove_rows_red(
        cx,
        gate,
        "an [[instance]] row over a cell that measures zero is a dead allowance",
        &[ROW_MATRIX],
        super::plant(
            cx,
            super::LEDGER,
            &format!(
                "{}\n\n[[instance]]\ncrate = \"busbar-kernel-scope\"\nkind = \"store\"\ncount = \"1\"\n",
                text.trim_end()
            ),
        ),
        &["dead-instance", "busbar-kernel-scope \u{d7} store"],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "an [[instance]] row for a kind that is not an instance axis is refused at load",
        &[super::super::ROW_REGISTRY],
        super::plant(
            cx,
            super::LEDGER,
            &format!(
                "{}\n\n[[instance]]\ncrate = \"busbar-kernel\"\nkind = \"plane\"\ncount = \"1\"\n",
                text.trim_end()
            ),
        ),
        &["bad-instance-kind", "plane"],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_list_is_read_through_the_constants_it_names() {
        let text = "pub const EXPORT_MODULE_OTLP: &str = \"otlp\";\n\
                    pub const EXPORT_MODULES: &[&str] = &[\n    EXPORT_MODULE_OTLP,\n    \"x\",\n];\n\
                    pub const NOT_A_NAME: &str = \"y\";\n\
                    pub const ADMIN_MODULE_UNRESOLVED: Diagnostic = Diagnostic {};\n";
        let d = module_decls("crates/k/src/config/sections.rs", text);
        let idents: Vec<&str> = d.iter().map(|d| d.ident.as_str()).collect();
        assert_eq!(idents, vec!["EXPORT_MODULE_OTLP", "EXPORT_MODULES"]);
        assert_eq!(d[1].literals, vec!["x"]);
        assert_eq!(d[1].idents, vec!["EXPORT_MODULE_OTLP"]);
    }

    #[test]
    fn a_literal_is_read_as_the_compiler_reads_it() {
        assert_eq!(literals(r#"a("otlp", "b\"c")"#), vec!["otlp", r#"b\"c"#]);
        assert_eq!(decoded_literals(r#"let x = "\x6ftlp";"#), vec!["otlp"]);
        // A LIST stays a list: adjacent literals are not joined when read one at a time.
        assert_eq!(
            decoded_literals(r#"&["redis", "busbar-store-redis"]"#),
            vec!["redis", "busbar-store-redis"]
        );
        // …and a name split across a concat! is still one name to the per-file reading.
        let lits = file_literals("crates/x/src/a.rs", "let n = concat!(\"ot\", \"lp\");\n");
        assert!(lits.iter().any(|(_, l)| l == "otlp"), "{lits:?}");
    }

    #[test]
    fn kind_words_take_both_numbers() {
        assert!(is_kind_word("HOOK", "hooks"));
        assert!(is_kind_word("hooks", "hooks"));
        assert!(is_kind_word("STORES", "store"));
        assert!(!is_kind_word("STOREFRONT", "store"));
    }
}
