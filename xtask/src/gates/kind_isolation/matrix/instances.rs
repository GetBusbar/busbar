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
//! ## A NAME SHORTER THAN THREE LETTERS IS NO NEEDLE
//!
//! A name LEARNED off another name — a census id, a `plugins.yaml` alias — is admitted only at
//! [`MIN_NEEDLE_LEN`] characters or more. `plugins.yaml` files the C-built secret plugin as alias
//! `c`, and a whole literal `"c"` (folded to lower case) is every `extern "C"` ABI string and every
//! one-letter test key in core: 262 of the secret axis's 444 Law 0 hits on predev 5c99befcfa were
//! that, not an instance. Three is the floor because every other alias and census id of the five
//! kinds is at least that long (the shortest is the secret alias `env`), so the floor drops `c` and
//! nothing else; one- and two-letter literals (`"c"`, `"id"`, `"ok"`) are keys and fixtures far
//! more often than names. A module-name CONSTANT is not learned, it is the compiled-in name itself,
//! and it counts at any length.
//!
//! ## PRESENCE, NOT SIZE
//!
//! Every non-zero cell carries an `[[instance]]` row in `qa/kind-isolation.toml` — crate and kind,
//! no count, exactly like `[[cell]]`. Size is not a CI check (owner 2026-10-02): a cell with no row
//! is a NEW naming and is RED (`unlisted-instance`), a row over a zero cell is dead, and more names
//! inside a listed cell change nothing here. The ship twin owes zero in every neutral crate through
//! the Law 0 class. The drain is Phase 4's.

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
    /// Every `[[core-name]]` row that would mask a PLUGIN's name, and so masks nothing.
    pub refused_core: Vec<String>,
    /// `(kind, name, from)`: every learned name under [`MIN_NEEDLE_LEN`], kept out of `names` and
    /// printed by `--report` so the floor is read, not silent.
    pub short: Vec<(&'static str, String, String)>,
}

/// THE SHORTEST LEARNED NAME THAT IS A NEEDLE (row 159, ARCHITECT 2026-10-13). See the module
/// header: a census id or `plugins.yaml` alias under three characters (`c`) matches `extern "C"`
/// and one-letter fixtures, not an instance.
pub(super) const MIN_NEEDLE_LEN: usize = 3;

/// Whether a learned name is long enough to be counted as a whole-literal needle.
fn is_needle(name: &str) -> bool {
    name.chars().count() >= MIN_NEEDLE_LEN
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
///
/// `core` is the ledger's `[[core-name]]` table: words a module-name constant spells that the spec
/// names as CORE'S OWN rather than a plugin's (`keys`, the badge press's verifier; `literal` and
/// `none`, core secret grammar — BUSBAR-1.6.0.md:155,175). They are struck from the learned vocabulary after
/// both derivations run, and ONLY when no plugin could be what they name: a census id (a plugin
/// crate is named for it) or a constant declared outside the kernel and contract tiers keeps the
/// name counted and turns the row RED (`core-name-is-plugin`).
pub fn vocabulary(
    crates: &[CrateInfo],
    files: &[(String, String)],
    core: &[super::super::CoreName],
    registry: &str,
) -> Vocab {
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
        if !is_needle(&id) {
            v.short.push((k, id, c.name.clone()));
            continue;
        }
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

    // 1b. THE REGISTRY (BUSBAR-1.6.0.md: "the instance census must read plugins.yaml aliases and
    // manifest names, so it can see external plugins"). An out-of-tree plugin has no crate here to
    // teach the census its name; `plugins.yaml` files it under its kind with the `module:` word an
    // operator writes (`alias`). Owned by its plugin crate, so it is never counted against itself.
    // An alias under [`MIN_NEEDLE_LEN`] still attributes a constant that spells it, and is no needle.
    for (kind, alias, krate) in registry_aliases(registry) {
        let Some(k) = axes.iter().copied().find(|k| *k == kind) else {
            continue;
        };
        census.entry(alias.clone()).or_default().insert(k);
        if !is_needle(&alias) {
            v.short.push((k, alias, format!("plugins.yaml {krate}")));
            continue;
        }
        v.names
            .entry(k)
            .or_default()
            .entry(alias)
            .or_default()
            .push(Source {
                owner: Some(krate.clone()),
                from: format!("plugins.yaml {krate}"),
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
    // value -> the kinds of the crates whose constants spell it (`None`: a crate of no kind).
    let mut declared_in: BTreeMap<String, BTreeSet<Option<&'static str>>> = BTreeMap::new();
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
        let decl_kind =
            super::owning_dir(&d.rel).and_then(|dir| dir_kind.get(dir.as_str()).copied().flatten());
        let krate_kind = decl_kind.filter(|k| axes.contains(k));
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
            declared_in
                .entry(val.clone())
                .or_default()
                .insert(decl_kind);
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

    // 3. CORE'S OWN WORDS, STRUCK — and never a plugin's. A word is core's own only when EVERY
    //    source of it is a constant the kernel or the contract declares: a plugin crate named for it,
    //    or a constant spelling it anywhere else (the root's `ADMIN_TOKENS_MODULE`, a plugin's own),
    //    is an instance, and masking it would be the C1 breach wearing a cite.
    for row in core {
        let Some(k) = axes.iter().copied().find(|k| *k == row.kind) else {
            continue;
        };
        let Some(names) = v.names.get_mut(k) else {
            continue;
        };
        let Some(sources) = names.get(&row.name) else {
            continue;
        };
        let plugin_owner: Vec<&str> = sources.iter().filter_map(|s| s.owner.as_deref()).collect();
        let foreign_decl = declared_in
            .get(&row.name)
            .is_some_and(|ks| ks.iter().any(|k| !matches!(k, Some("kernel" | "contract"))));
        if !plugin_owner.is_empty() || foreign_decl {
            v.refused_core.push(format!(
                "core-name-is-plugin\t{}\t`[[core-name]] {} / {}` ({}) would mask a PLUGIN's \
                 name: {}. A core name is a word only the kernel and the contract declare; no \
                 plugin name may ever enter the table, so the name stays counted.",
                super::LEDGER,
                row.kind,
                row.name,
                row.cite,
                if plugin_owner.is_empty() {
                    format!(
                        "a module-name constant outside the kernel and contract spells it ({})",
                        sources
                            .iter()
                            .map(|s| s.from.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                } else {
                    format!(
                        "the plugin crate(s) {} are named for it",
                        plugin_owner.join(", ")
                    )
                }
            ));
            continue;
        }
        names.remove(&row.name);
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
    let rust = rel.ends_with(".rs");
    for (i, line) in text.lines().enumerate() {
        if !line.contains('"') {
            continue;
        }
        // An `extern "…"` ABI string is Rust syntax, not vocabulary (ARCHITECT ruling on #787).
        let unabi = if rust {
            without_abi_strings(line)
        } else {
            std::borrow::Cow::Borrowed(line)
        };
        let raw: &str = &unabi;
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
    // A NAME SPLIT ACROSS LINES ([`super::joined_runs`]): `"ot\` + `lp"` (a string continuation)
    // and `concat!(` / `"ot",` / `"lp"` / `)` are `"otlp"` to the compiler and on no one line. Each
    // run is read whole, and a literal it holds that none of its own lines held is filed on the
    // run's first line.
    let lines: Vec<std::borrow::Cow<'_, str>> = text
        .lines()
        .map(|l| {
            if rust {
                without_abi_strings(l)
            } else {
                std::borrow::Cow::Borrowed(l)
            }
        })
        .collect();
    let plain: Vec<&str> = lines.iter().map(|l| l.as_ref()).collect();
    for (first, last, run) in super::joined_runs(&plain) {
        let seen: BTreeSet<String> = out
            .iter()
            .filter(|(line, _)| (first + 1..=last + 1).contains(line))
            .map(|(_, l)| l.clone())
            .collect();
        let mut found: Vec<String> = decoded_literals(&run);
        if let Some(d) = super::decoded_line(&run) {
            found.extend(literals(&d));
        }
        let mut fresh: BTreeSet<String> = BTreeSet::new();
        for t in found {
            let t = t.trim().to_ascii_lowercase();
            if !t.is_empty() && t.len() <= 64 && !seen.contains(&t) && fresh.insert(t.clone()) {
                out.push((first + 1, t));
            }
        }
    }
    out.sort_by_key(|(line, _)| *line);
    let out = std::sync::Arc::new(out);
    memo.lock()
        .expect("never poisoned")
        .insert(key, std::sync::Arc::clone(&out));
    out
}

/// `line` without the string of an ABI POSITION: the literal right after the keyword `extern`
/// (`extern "C" fn`, `extern "C-unwind" {`, `unsafe extern "C"`) and the value of an `abi = "…"`
/// argument (an attribute's ABI form). That string names a calling convention: it is Rust syntax,
/// not instance vocabulary, so the instance axes do not read it (ARCHITECT ruling on #787: a
/// scanner precision fix, not a Law 0 drain). Exactly that position: the same word in any other
/// literal, the next one on the line included, is still read.
fn without_abi_strings(line: &str) -> std::borrow::Cow<'_, str> {
    if !line.contains("extern") && !line.contains("abi") {
        return std::borrow::Cow::Borrowed(line);
    }
    let bytes = line.as_bytes();
    let word_at = |at: usize, word: &str| {
        bytes[at..].starts_with(word.as_bytes())
            && (at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_'))
            && bytes
                .get(at + word.len())
                .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
    };
    let skip_ws = |mut at: usize| {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        at
    };
    // Bytes are walked for the syntax (a quote and a backslash are one byte in UTF-8 and never a
    // continuation byte); the text is copied in slices, so a multi-byte character is never split.
    let mut out = String::with_capacity(line.len());
    let mut copied = 0usize;
    let mut at = 0usize;
    let mut in_str = false;
    while at < bytes.len() {
        let b = bytes[at];
        if in_str {
            if b == b'\\' {
                at += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            at += 1;
            continue;
        }
        let abi_after = if word_at(at, "extern") {
            Some(skip_ws(at + "extern".len()))
        } else if word_at(at, "abi") {
            let eq = skip_ws(at + "abi".len());
            (bytes.get(eq) == Some(&b'=')).then(|| skip_ws(eq + 1))
        } else {
            None
        };
        if let Some(open) = abi_after.filter(|o| bytes.get(*o) == Some(&b'"')) {
            if let Some(len) = line[open + 1..].find('"') {
                out.push_str(&line[copied..open]);
                at = open + 1 + len + 1;
                copied = at;
                continue;
            }
        }
        if b == b'"' {
            in_str = true;
        }
        at += 1;
    }
    out.push_str(&line[copied.min(line.len())..]);
    std::borrow::Cow::Owned(out)
}

/// THE INSTANCE NAMES THAT ARE ALSO AN HTTP WORD (TODO: "a word collision never raises a cell: it
/// gets a mask"; ARCHITECT ruling 2026-09-30, kernel × auth instance-ratchet +14). `header` is the
/// auth instance `busbar-auth-header`'s id, and it is also the word HTTP uses for a request line:
/// RFC 9728's `bearer_methods_supported: ["header"]` (customer bytes), the config's credential
/// placement, a JSON object's key, a panic message. When the census learned `header` from the new
/// crate's name, 8 pre-existing kernel lines of that word started counting as kernel × auth.
///
/// A `"header"` literal is masked ONLY in these contexts (see [`word_collisions`]):
///
/// * PROSE — it sits in a `.rs` `//` comment (a doc quoting a value);
/// * A PANIC MESSAGE — it is the whole argument of `.expect(…)`;
/// * AN OBJECT KEY — it is followed by `:` (not `::`): `json!({"header": …})`, a `.json` key;
/// * THE RFC 9728/6750 BEARER METHOD — its line, or the non-blank line before it, names
///   `bearer_methods_supported`;
/// * A CREDENTIAL PLACEMENT — in a `.json`, an element of a `"variants": [` array of a type whose
///   name ends `Placement` (the config schema's `CredentialPlacement`);
/// * AN OPENAPI LOCATION — the string value of an OpenAPI `"in":` key (a parameter's or a
///   securityScheme's location, customer bytes: `"in": "header"`; ARCHITECT ruling 2026-09-30,
///   WIRE-AUTH RISE (a), `busbar-core-admin × auth` +31).
///
/// Everything else still counts: `m == "header"`, `lookup("header", …)`, `const AUTH_MODULE: &str
/// = "header"`, a match arm, a list element. The mask only ever LOWERS a cell; it never re-spells
/// a name (Q81), and a literal spelled any other way (`" header"`, a `concat!`) is not masked.
pub(super) const COLLIDING_LITERALS: &[&str] = &["header"];

/// How many `"word"` literals on line `at` (0-based) of `lines`, a file at `rel`, are the WORD and
/// not the instance (see [`COLLIDING_LITERALS`]).
fn word_collisions(rel: &str, lines: &[&str], at: usize, word: &str) -> usize {
    let Some(line) = lines.get(at).copied() else {
        return 0;
    };
    let low = line.to_ascii_lowercase();
    let quoted = format!("\"{word}\"");
    let prose_at = if rel.ends_with(".rs") {
        super::comment_start(line)
    } else {
        None
    };
    let prev = lines[..at]
        .iter()
        .rev()
        .find(|l| !l.trim().is_empty())
        .copied()
        .unwrap_or("");
    let bearer_method =
        line.contains("bearer_methods_supported") || prev.contains("bearer_methods_supported");
    let placement = rel.ends_with(".json") && placement_variant(lines, at);
    let mut n = 0;
    let mut from = 0;
    while let Some(off) = low[from..].find(&quoted) {
        let i = from + off;
        let j = i + quoted.len();
        from = j;
        let before = line[..i].trim_end();
        let after = line[j..].trim_start();
        let prose = prose_at.is_some_and(|p| i >= p);
        let message = before.ends_with(".expect(") && after.starts_with(')');
        let key = after.starts_with(':') && !after.starts_with("::");
        let openapi_in = before.ends_with("\"in\":");
        if prose || message || key || bearer_method || placement || openapi_in {
            n += 1;
        }
    }
    n
}

/// Whether line `at` of a `.json` sits in a `"variants": [` array of a type named `…Placement`.
fn placement_variant(lines: &[&str], at: usize) -> bool {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut k = at;
    let open = loop {
        if k == 0 {
            return false;
        }
        k -= 1;
        let t = lines[k].trim();
        if t.contains(']') {
            return false;
        }
        if t.ends_with('[') {
            if !t.starts_with("\"variants\"") {
                return false;
            }
            break k;
        }
    };
    let depth = indent(lines[open]);
    let owner = lines[..open]
        .iter()
        .rev()
        .find(|l| indent(l) < depth && l.trim_end().ends_with('{'));
    let name = owner.map_or("", |l| l.trim().trim_end_matches(&['{', ':', ' ', '"'][..]));
    name.trim_start_matches('"').ends_with("Placement")
}

/// Whether line `at` (0-based) of `lines`, a file at `rel`, is the line a `[[shape-word]]` row's
/// `holder` names: in a `.rs` file the line declaring `const <holder>:`; in a `.json` file a line
/// inside the object keyed `"<holder>"` (the nearest enclosing `"<key>": {` at a lower indent).
fn holds(rel: &str, lines: &[&str], at: usize, holder: &str) -> bool {
    let Some(line) = lines.get(at) else {
        return false;
    };
    if rel.ends_with(".rs") {
        return line.contains(&format!("const {holder}:"));
    }
    if !rel.ends_with(".json") {
        return false;
    }
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut depth = indent(line);
    for l in lines[..at].iter().rev() {
        if l.trim().is_empty() || indent(l) >= depth {
            continue;
        }
        depth = indent(l);
        let t = l.trim();
        if t.ends_with('{') {
            return t.trim_end_matches('{').trim().trim_end_matches(':').trim()
                == format!("\"{holder}\"");
        }
    }
    false
}

/// THE FIVE AXES, MEASURED over every `Family::Neutral` crate, with the `[[shape-word]]` rows'
/// NAMED RESERVATIONS (ARCHITECT ruling on #787):
/// each row reserves exactly one literal hit, its word in its file on the line its holder names,
/// and nothing else. Also answers a finding per row that reserved nothing: a reservation over no
/// spelling is a dead allowance.
pub fn measure_reserved(
    crates: &[CrateInfo],
    files: &[(String, String)],
    vocab: &Vocab,
    shapes: &[super::super::ShapeWord],
    frozen: &super::frozen::Frozen,
) -> (Instances, Vec<String>) {
    let mut spent: BTreeSet<usize> = BTreeSet::new();
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
        // A FROZEN 1.5.5 CUSTOMER-OBSERVABLE LINE IN PLACE ([`super::frozen`], ARCHITECT ruling
        // 2026-10-21): on the same line a named artifact carried at the pinned v1.5.5, unchanged, a
        // JSON document's literal is that release's wire (the line is skipped below), and so is a
        // Rust artifact's real string literal, whose content is struck before the literals are read;
        // a quoted name in a comment on that line is no literal and still counts.
        let struck = super::frozen::literals_struck(frozen, rel, text, text);
        let lits = file_literals(rel, struck.as_deref().unwrap_or(text));
        let frozen_mask = super::frozen::exempt_lines(frozen, rel, text);
        // A 1.5.x CONFIG WORD THE MIGRATOR WRITES, AT ITS ONE DECLARATION (architect ruling
        // 2026-10-23, addition to R-3; [`super::config_words::FROZEN_CONFIG_LITERALS`]).
        let frozen_decl_lines: Vec<&str> = if super::config_words::holds_frozen_literal(rel) {
            text.lines().collect()
        } else {
            Vec::new()
        };
        let reserving: Vec<usize> = shapes
            .iter()
            .enumerate()
            .filter(|(_, row)| row.file == *rel)
            .map(|(i, _)| i)
            .collect();
        let all_lines: Vec<&str> = if reserving.is_empty() {
            Vec::new()
        } else {
            text.lines().collect()
        };
        let collides = |l: &String| COLLIDING_LITERALS.contains(&l.as_str());
        let lines: Vec<&str> = if lits.iter().any(|(_, l)| collides(l)) {
            text.lines().collect()
        } else {
            Vec::new()
        };
        // Per line and colliding word: how many of its literals are still the word, not the name.
        let mut words_left: BTreeMap<(usize, &str), usize> = BTreeMap::new();
        for (line, lit) in lits.iter() {
            let Some(kinds) = lookup.get(lit) else {
                continue;
            };
            // A NAMED SHAPE RESERVATION takes this one hit, and only it.
            let reserved = reserving.iter().copied().find(|i| {
                !spent.contains(i)
                    && shapes[*i].word == *lit
                    && holds(rel, &all_lines, line - 1, &shapes[*i].holder)
            });
            if let Some(i) = reserved {
                spent.insert(i);
                continue;
            }
            if frozen_mask
                .as_ref()
                .is_some_and(|m| super::frozen::at(m, *line))
            {
                continue;
            }
            let line_text = line
                .checked_sub(1)
                .and_then(|i| frozen_decl_lines.get(i).copied())
                .unwrap_or("");
            if super::config_words::frozen_literal(rel, line_text, lit) {
                continue;
            }
            if let Some(w) = COLLIDING_LITERALS.iter().find(|w| **w == lit.as_str()) {
                let left = words_left
                    .entry((*line, *w))
                    .or_insert_with(|| word_collisions(rel, &lines, line - 1, w));
                if *left > 0 {
                    *left -= 1;
                    continue;
                }
            }
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
    let stale = shapes
        .iter()
        .enumerate()
        .filter(|(i, _)| !spent.contains(i))
        .map(|(_, row)| {
            format!(
                "shape-word-unused\t{} in {} at {}\tthe `[[shape-word]]` row ({}) reserves a \
                 spelling that is not there. A reservation over nothing is a dead allowance: strike \
                 the row",
                row.word, row.file, row.holder, row.cite
            )
        })
        .collect();
    (out, stale)
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

/// The files a cell's names sit in, heaviest first, WITHOUT their counts: a finding that is about
/// presence names where to look and carries no figure (size is not a CI check, owner 2026-10-02).
fn files_of(cell: &Cell) -> String {
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for h in &cell.hits {
        if let Some(at) = h.split('\t').nth(1).and_then(|p| p.rsplit_once(':')) {
            *per.entry(at.0).or_default() += 1;
        }
    }
    let mut v: Vec<(&str, usize)> = per.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.truncate(6);
    v.iter().map(|(f, _)| *f).collect::<Vec<_>>().join(", ")
}

/// EVERY FINDING THE `[[instance]]` TABLE OWES — presence only: an unlisted cell, a dead row, a
/// duplicate row.
pub fn offenders(
    measured: &Instances,
    vocab: &Vocab,
    reg: &super::super::KindRegistry,
) -> Vec<String> {
    let mut out: Vec<String> = vocab.unattributed.clone();
    out.extend(vocab.refused_core.iter().cloned());
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

    let mut listed: BTreeSet<(String, String)> = BTreeSet::new();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for c in &reg.instance_cells {
        listed.insert((c.krate.clone(), c.kind.clone()));
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
        if cell.count == 0 || listed.contains(&(krate.clone(), (*kind).to_string())) {
            continue;
        }
        out.push(format!(
            "unlisted-instance\t{krate} \u{d7} {kind}\t{krate} names `{kind}` instances as a \
             value and there is no `[[{TABLE}]] crate = \"{krate}\", kind = \"{kind}\"` in \
             {led}. C1: core names no instance. In: {}",
            files_of(cell)
        ));
    }
    for (krate, kind) in &listed {
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
    for (k, name, from) in &vocab.short {
        s.push_str(&format!(
            "short\t{k}\t{name}\t{from} (under {MIN_NEEDLE_LEN} characters: no needle)\n"
        ));
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

/// The plugin registry the census also reads.
pub const REGISTRY: &str = "plugins.yaml";

/// Every `plugins.yaml` entry that states a `kind:`, an `alias:` and a `crate:`, as
/// `(kind, alias, crate)`.
pub fn registry_aliases(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut cur: [Option<String>; 3] = [None, None, None];
    let flush = |cur: &mut [Option<String>; 3], out: &mut Vec<(String, String, String)>| {
        if let [Some(k), Some(a), Some(c)] = std::mem::take(cur) {
            out.push((k, a, c));
        }
    };
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('#') {
            continue;
        }
        let entry = t.strip_prefix("- ");
        if entry.is_some() {
            flush(&mut cur, &mut out);
        }
        let Some((key, val)) = entry.unwrap_or(t).split_once(':') else {
            continue;
        };
        let val = val.trim().trim_matches('"').to_string();
        match key.trim() {
            "kind" => cur[0] = Some(val),
            "alias" => cur[1] = Some(val),
            "crate" => cur[2] = Some(val),
            _ => {}
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// ONE INSTANCE NAME PER AXIS, read off the tree's own vocabulary — never typed into a fixture.
/// A module-name constant is preferred (it is the compiled-in name the breach is made of); an axis
/// with none falls back to its first census id.
pub(super) fn one_name_per_axis(
    cx: &crate::ctx::Ctx,
) -> Result<Vec<(&'static str, String)>, String> {
    let mut crates = super::super::census(cx)?;
    let (planes, ports) = super::super::vocabularies(&crates);
    super::super::assign_instances(&mut crates, &planes, &ports);
    let (files, _) = super::scan_set(cx)?;
    let reg = super::super::load_registry(cx)?;
    let registry = cx.read(REGISTRY).unwrap_or_default();
    let vocab = vocabulary(&crates, &files, &reg.core_names, &registry);
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

/// THE FIXTURE CRATE: a neutral `kernel`-kind crate that exists only in the overlay,
/// so the instance cases measure a cell no live crate owns and no fold can take away.
// qa-names: crates/busbar-kernel-planted -- xtask/src/gates/kind_isolation/matrix/instances.rs -- an overlay-only fixture crate the instance and cell cases plant whole (manifest and sources); it is absent from the tree on purpose, so no live crate or fold decides what those cases measure
pub(super) const FIXTURE_DIR: &str = "crates/busbar-kernel-planted";
pub(super) const FIXTURE_CRATE: &str = "busbar-kernel-planted";

/// [`FIXTURE_CRATE`]'s manifest and an empty library root, and nothing else.
pub(super) fn fixture_crate() -> crate::ctx::Overlay {
    let mut ov = crate::ctx::Overlay::new();
    ov.set(
        format!("{FIXTURE_DIR}/Cargo.toml"),
        format!("[package]\nname = \"{FIXTURE_CRATE}\"\nversion = \"0.0.0\"\n"),
    );
    ov.set(
        format!("{FIXTURE_DIR}/src/lib.rs"),
        "//! Fixture.\n".to_string(),
    );
    ov
}

/// THE RED PROOFS THE FIVE AXES OWE (item 118): a planted store/secret/auth/hook/export instance
/// name in core turns `:matrix` RED, on both registrations.
pub fn selftest<'a>(
    cx: &'a crate::ctx::Ctx,
    gate: &'a dyn crate::gates::Gate,
    // The subject of the GREEN cases planted into [`FIXTURE_CRATE`]: the bare fixture's own
    // findings out of view (`super::OverFixture`). Every red case keeps `gate`.
    over_fixture: &'a dyn crate::gates::Gate,
    ship: bool,
    report: &mut crate::gates::Report<'a>,
) {
    use super::ROW_MATRIX;
    use crate::gates::{prove_rows_green, prove_rows_red};

    // THE CORE-SIDE CRATE THE PLANTS LAND IN. `busbar-core-connector` is a `cleanliness` crate —
    // `Family::Neutral`, and with no `[[instance]]` row today, so each plant is a cell that was ZERO
    // and is not.
    const CORE: &str = "crates/busbar-core-connector";
    const CORE_NAME: &str = "busbar-core-connector";

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
                    &format!("{CORE_NAME} \u{d7} {k}"),
                    &rel,
                ],
            ));
        }
    }
    if ship {
        return;
    }

    // PRESENCE, NOT SIZE (owner 2026-10-02: size is not a CI check). The kernel's export cell is
    // a listed `[[instance]]` row, so one more export instance name inside it is not a new edge and
    // adds no finding. The RED half of the same rule is every `unlisted-instance` case above: a
    // cell with no row at all.
    if let Some((_, name)) = names.iter().find(|(k, _)| *k == "export") {
        report.push(prove_rows_green(
            cx,
            gate,
            "the kernel naming one more export instance inside its listed cell adds no finding",
            &[ROW_MATRIX],
            super::plant(
                cx,
                "crates/busbar-kernel/src/planted_export_instance.rs",
                &format!("pub const ALSO: &str = \"{name}\";\n"),
            ),
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
            "busbar-core-connector \u{d7} store",
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

    // A WORD COLLISION NEVER RAISES A CELL: IT GETS A MASK — and the mask is not a hole. Core
    // writing `"header"` as the HTTP word, in every masked shape the kernel holds (a doc, a panic
    // message, a JSON key, RFC 9728's bearer method, the config's credential placement), is no
    // auth instance; the same file with ONE real reference to the `header` auth instance added
    // counts exactly that one. The auth-header manifest is planted only if the tree has none, so
    // the pair measures the `header` instance whatever the crate's future.
    let header_words = || {
        let mut ov = super::plant(
            cx,
            &format!("{CORE}/src/planted_header_words.rs"),
            "/// `bearer_methods_supported` is `[\"header\"]` and is not a parameter.\n\
             pub fn doc() -> serde_json::Value {\n    \
                 let _ = std::str::from_utf8(b\"x\").expect(\"header\");\n    \
                 let _ = serde_json::json!({\"header\": 1, \"trim_start\": false});\n    \
                 let _ = (\n        \"bearer_methods_supported\",\n        \
                 vec![\"header\"],\n    );\n    \
                 serde_json::json!({\"bearer_methods_supported\": [\"header\"]})\n\
             }\n",
        );
        let schema = "{\n  \"types\": {\n    \"CredentialPlacement\": {\n      \"kind\": \
                      \"enum\",\n      \"variants\": [\n        \"bearer\",\n        \
                      \"header\"\n      ]\n    }\n  }\n}\n";
        ov.set(
            format!("{CORE}/src/planted-schema.snapshot.json"),
            schema.to_string(),
        );
        // qa-names: crates/busbar-auth-header/Cargo.toml -- xtask/src/gates/kind_isolation/matrix/instances.rs -- the header auth plugin's manifest at its census mount: the crate left for GetBusbar/busbar-auth-header (P5) and is read from its pinned checkout, so the plant writes the manifest into the virtual tree only when nothing is there
        const AUTH_HEADER: &str = "crates/busbar-auth-header/Cargo.toml";
        if !cx.exists(AUTH_HEADER) {
            ov.set(
                AUTH_HEADER,
                "[package]\nname = \"busbar-auth-header\"\nversion = \"0.0.0\"\n".to_string(),
            );
        }
        ov
    };
    report.push(prove_rows_green(
        cx,
        gate,
        "`\"header\"` as the HTTP word (doc, panic message, JSON key, bearer method, credential \
         placement) is no auth instance",
        &[ROW_MATRIX],
        header_words(),
    ));
    let mut real = header_words();
    real.set(
        format!("{CORE}/src/planted_header_pick.rs"),
        "pub fn pick(module: &str) -> bool {\n    module == \"header\"\n}\n".to_string(),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a real reference to the `header` auth instance still counts beside the masked words",
        &[ROW_MATRIX],
        real,
        &[
            // Presence, not size (owner 2026-10-03): the `unlisted-instance` finding names the
            // cell, not its count. The green twin above carries the proof that the masked HTTP
            // words do not count; this red twin's one real `header` reference makes the cell an
            // instance the ledger does not list.
            "unlisted-instance",
            "busbar-core-connector \u{d7} auth",
            "planted_header_pick.rs",
        ],
    ));

    // THE OPENAPI LOCATION: `"in": "header"` (customer bytes) is the HTTP word and leaves the cell
    // where it was; a bare `"header"` instance literal in the same crate still raises it. Presence
    // cannot observe this on `busbar-core-admin` any more — that cell is a LISTED `[[instance]]` row
    // (owner 2026-10-03, count→presence), so a `header` reference there is green whatever it is, and
    // a listed cell has no count for a `header` literal to ratchet. The MASK is a scanner property,
    // not an admin one (the rule reads any OpenAPI `"in"` location), so it is proven where presence
    // CAN see a green→red transition: the unlisted fixture crate's `× auth` cell. The openapi-only
    // plant keeps that cell at zero (masked) and GREEN; the same plant plus one bare `module ==
    // "header"` makes it an `unlisted-instance` the ledger does not list — RED.
    let openapi: &[(&str, &str)] = &[(
        "planted_openapi.json",
        "{\n  \"parameters\": [\n    {\n      \"in\": \"header\",\n      \"name\": \
         \"If-Match\"\n    }\n  ],\n  \"adminToken\": {\"type\": \"apiKey\", \"in\": \
         \"header\", \"name\": \"x\"}\n}\n",
    )];
    report.push(prove_rows_green(
        cx,
        over_fixture,
        "an OpenAPI `\"in\": \"header\"` location is no auth instance (the HTTP word is masked)",
        &[ROW_MATRIX],
        super::fixture_files(openapi),
    ));
    let bare: Vec<(&str, &str)> = openapi
        .iter()
        .copied()
        .chain(std::iter::once((
            "planted_header_pick.rs",
            "pub fn pick(module: &str) -> bool {\n    module == \"header\"\n}\n",
        )))
        .collect();
    report.push(prove_rows_red(
        cx,
        gate,
        "a bare `header` instance literal still raises the fixture's × auth cell beside the masked OpenAPI word",
        &[ROW_MATRIX],
        super::fixture_files(&bare),
        &[
            "unlisted-instance",
            &super::fixture_subject("auth"),
            "planted_header_pick.rs",
        ],
    ));

    // AN `extern "…"` ABI STRING IS SYNTAX, NOT VOCABULARY (ARCHITECT ruling on #787): the `c`
    // secret plugin's name (plugins.yaml `busbar-secret-c`) is the lower-cased string of every
    // `extern "C"`, and that position is not read. GREEN: a neutral crate's `extern "C" fn` and an
    // attribute's `abi = "C"` name no instance.
    report.push(prove_rows_green(
        cx,
        over_fixture,
        "an `extern \"C\"` ABI string names no secret instance",
        &[ROW_MATRIX],
        super::fixture_files(&[(
            "planted_abi.rs",
            "pub extern \"C\" fn planted_abi() {}\npub unsafe extern \"C-unwind\" fn planted_unwind() {}\n#[planted(abi = \"C\")]\npub struct PlantedAbi;\n",
        )]),
    ));

    // A ONE-LETTER ALIAS IS NO NEEDLE (row 159, ARCHITECT 2026-10-13), AND A REAL ALIAS STILL IS.
    // `plugins.yaml` files the C-built secret plugin as alias `c`; read as a needle, the fixture's
    // `extern "C"` ABI string and its one-letter `"c"` key were two `× secret` hits, an
    // `unlisted-instance` on a crate that names no plugin. Every alias the live registry gives an
    // axis under [`MIN_NEEDLE_LEN`] is planted the same way, and the cell stays at zero: GREEN.
    // The same plant plus one comparison against a real registry alias of the same tree (`vault`
    // today, read off `plugins.yaml`, never typed here) is that axis's `unlisted-instance`: RED.
    let axis_aliases: Vec<(String, String, String)> =
        registry_aliases(&cx.read(REGISTRY).unwrap_or_default())
            .into_iter()
            .filter(|(k, _, _)| axes().contains(&k.as_str()))
            .collect();
    let mut short_body = String::from(
        "pub extern \"C\" fn planted_one() {}\n\
         pub fn planted_two(c: &str) -> bool {\n    c == \"c\"\n}\n",
    );
    for (i, (_, alias, _)) in axis_aliases
        .iter()
        .filter(|(_, a, _)| !is_needle(a))
        .enumerate()
    {
        short_body.push_str(&format!(
            "pub const PLANTED_SHORT_{i}: &str = \"{alias}\";\n"
        ));
    }
    report.push(prove_rows_green(
        cx,
        over_fixture,
        "`extern \"C\"` and a one-letter `\"c\"` in a neutral crate are no secret instance (an \
         alias under three characters is no needle)",
        &[ROW_MATRIX],
        super::fixture_files(&[("planted_short_alias.rs", short_body.as_str())]),
    ));
    let long = axis_aliases
        .iter()
        .filter(|(_, a, _)| is_needle(a))
        .find(|(k, _, _)| k == "secret")
        .or_else(|| axis_aliases.iter().find(|(_, a, _)| is_needle(a)));
    match long {
        Some((kind, alias, _)) => {
            let pick =
                format!("pub fn pick(module: &str) -> bool {{\n    module == \"{alias}\"\n}}\n");
            report.push(prove_rows_red(
                cx,
                gate,
                format!(
                    "a real `{kind}` registry alias (`{alias}`) still counts beside the planted short \
                     aliases"
                ),
                &[ROW_MATRIX],
                super::fixture_files(&[
                    ("planted_short_alias.rs", short_body.as_str()),
                    ("planted_alias_pick.rs", pick.as_str()),
                ]),
                &[
                    "unlisted-instance",
                    &super::fixture_subject(kind),
                    "planted_alias_pick.rs",
                ],
            ));
        }
        None => report.push(crate::gates::CasePlan::from(super::super::unplantable(
            "the instance registry gives an axis an alias of three characters or more",
            &[ROW_MATRIX],
            &["instance"],
            format!("{REGISTRY} files no alias of {MIN_NEEDLE_LEN}+ characters under any axis"),
        ))),
    }
    // A NAMED SHAPE RESERVATION (ARCHITECT ruling on #787). A `[[shape-word]]` row reserves ONE
    // spelling of a word that is a shape (the 1.5.5 placement key `header`): the constant its
    // holder names, in the file it names. GREEN with the row; the same row beside a second spelling
    // of the word in that file is RED (the reservation is never word-wide); a row whose holder
    // spells nothing is RED as a dead allowance.
    let ledger = cx.read(super::LEDGER).unwrap_or_default();
    let shape_file = format!("{FIXTURE_DIR}/src/planted_shape.rs");
    let reserved = |source: &str, holder: &str| {
        let mut ov = super::fixture_files(&[("planted_shape.rs", source)]);
        ov.set(
            super::LEDGER,
            format!(
                "{}\n\n[[shape-word]]\nword = \"header\"\nfile = \"{shape_file}\"\nholder = \
                 \"{holder}\"\ncite = \"BUSBAR-1.6.0.md:2284\"\n",
                ledger.trim_end()
            ),
        );
        ov
    };
    let shape = "pub const PLANTED_PLACEMENT_KEY: &str = \"header\";\n";
    report.push(prove_rows_green(
        cx,
        over_fixture,
        "a `[[shape-word]]` row reserves the one constant it names",
        &[ROW_MATRIX],
        reserved(shape, "PLANTED_PLACEMENT_KEY"),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a second spelling of a reserved word in the same file still counts",
        &[ROW_MATRIX],
        reserved(
            &format!("{shape}pub fn pick(module: &str) -> bool {{\n    module == \"header\"\n}}\n"),
            "PLANTED_PLACEMENT_KEY",
        ),
        &[
            "unlisted-instance",
            &super::fixture_subject("auth"),
            "planted_shape.rs",
        ],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a `[[shape-word]]` row whose holder spells nothing is a dead allowance",
        &[ROW_MATRIX],
        reserved(shape, "NO_SUCH_CONSTANT"),
        &["shape-word-unused", "NO_SUCH_CONSTANT"],
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
            "crates/busbar-store-memory/src/planted_self.rs",
            "pub const ME: &str = \"memory\";\n",
        ),
    ));

    // CORE'S OWN WORDS (ARCHITECT 2026-09-30, KERNEL-AUTH-ZERO Q1). A `[[core-name]]` row masks a
    // word the kernel declares and the spec names as core's own; it can never mask a plugin's.
    // `zebedee` is typed nowhere in the tree: the kernel declares it as an auth module name, core
    // writes it once, and only the ledger row differs between the RED control and the GREEN mask.
    let text = cx.read(super::LEDGER).unwrap_or_default();
    let core_word = |row: bool, plugin: bool| {
        let mut ov = super::plant(
            cx,
            "crates/busbar-kernel/src/config/planted_core_word.rs",
            "pub const PLANTED_AUTH_MODULE: &str = \"zebedee\";\n",
        );
        ov.set(
            format!("{CORE}/src/planted_core_word.rs"),
            "pub const W: &str = \"zebedee\";\n".to_string(),
        );
        if plugin {
            ov.set(
                "crates/busbar-auth-zebedee/Cargo.toml",
                "[package]\nname = \"busbar-auth-zebedee\"\nversion = \"0.0.0\"\n".to_string(),
            );
        }
        if row {
            ov.set(
                super::LEDGER,
                format!(
                    "{}\n\n[[core-name]]\nkind = \"auth\"\nname = \"zebedee\"\ncite = \
                     \"BUSBAR-1.6.0.md:155\"\n",
                    text.trim_end()
                ),
            );
        }
        ov
    };
    report.push(prove_rows_red(
        cx,
        gate,
        "a kernel-declared auth module name core writes, with no [[core-name]] row, is counted",
        &[ROW_MATRIX],
        core_word(false, false),
        &[
            "unlisted-instance",
            &format!("{CORE_NAME} \u{d7} auth"),
            "planted_core_word.rs",
        ],
    ));
    report.push(prove_rows_green(
        cx,
        gate,
        "a [[core-name]] row masks core's own word, and only it",
        &[ROW_MATRIX],
        core_word(true, false),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a [[core-name]] row naming a word a plugin crate is named for masks nothing",
        &[ROW_MATRIX],
        core_word(true, true),
        &["core-name-is-plugin", "busbar-auth-zebedee", "zebedee"],
    ));
    // The live plugin name the kernel USED to spell: the root declares it, so it is an instance.
    report.push(prove_rows_red(
        cx,
        gate,
        "a [[core-name]] row naming a module the root declares masks nothing",
        &[ROW_MATRIX],
        super::plant(
            cx,
            super::LEDGER,
            &format!(
                "{}\n\n[[core-name]]\nkind = \"auth\"\nname = \"admin-tokens\"\ncite = \
                 \"BUSBAR-1.6.0.md:155\"\n",
                text.trim_end()
            ),
        ),
        &["core-name-is-plugin", "admin-tokens"],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a [[core-name]] row with no spec line is refused at load",
        &[super::super::ROW_REGISTRY],
        super::plant(
            cx,
            super::LEDGER,
            &format!(
                "{}\n\n[[core-name]]\nkind = \"auth\"\nname = \"zebedee\"\ncite = \"it is \
                 ours\"\n",
                text.trim_end()
            ),
        ),
        &["bad-core-name-cite", "zebedee"],
    ));

    // A LISTED CELL IS GREEN, AND A ROW FOR AN AXIS NOTHING MEASURES IS REFUSED AT LOAD.
    //
    // THE FIXTURE IS WHOLLY THE BATTERY'S: [`FIXTURE_CRATE`], a neutral kernel-kind crate that
    // exists only in the overlay, names the store instance `memory` once. With an `[[instance]]`
    // row for exactly that cell it is GREEN; without one it is `unlisted-instance` (RED). Only the
    // row differs between the two plants. The row carries no count — presence only (owner
    // 2026-10-02) — and a `count` written back into it is refused at load.
    //
    // THE ROW PRE-DATES THE BRANCH, because the base's copy of the ledger is planted with it. A row
    // that is in no copy of the ledger at the merge-base is `minted-row`, so without that the
    // control could never be green; with it, the row is the only thing either case is about.
    let listed_fixture = |row: Option<&str>| {
        let mut ov = fixture_crate();
        ov.set(
            format!("{FIXTURE_DIR}/src/planted_listed.rs"),
            "pub const S: &str = \"memory\";\n".to_string(),
        );
        if let Some(extra) = row {
            let ledger = format!(
                "{}\n\n[[instance]]\ncrate = \"{FIXTURE_CRATE}\"\nkind = \"store\"\n{extra}",
                cx.read(super::LEDGER).unwrap_or_default().trim_end()
            );
            if let Some(sha) = super::super::debt_free::pinned_base(cx) {
                ov.set_command(format!("git-show:{sha}:{}", super::LEDGER), ledger.clone());
            }
            ov.set(super::LEDGER, ledger);
        }
        ov
    };
    report.push(prove_rows_green(
        cx,
        over_fixture,
        "an [[instance]] row over a live cell is green, whatever the cell's size",
        &[ROW_MATRIX],
        listed_fixture(Some("")),
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "the same cell with no [[instance]] row is an unlisted instance cell",
        &[ROW_MATRIX],
        listed_fixture(None),
        &[
            "unlisted-instance",
            &format!("{FIXTURE_CRATE} \u{d7} store"),
            "planted_listed.rs",
        ],
    ));
    report.push(prove_rows_red(
        cx,
        gate,
        "a `count` written back into an [[instance]] row is refused at load — presence only",
        &[super::super::ROW_REGISTRY],
        listed_fixture(Some("count = \"1\"\n")),
        &["unknown-field", "`[[instance]]` declares `count`"],
    ));
    let text = cx.read(super::LEDGER).unwrap_or_default();
    let mut dead = fixture_crate();
    dead.set(
        super::LEDGER,
        format!(
            "{}\n\n[[instance]]\ncrate = \"{FIXTURE_CRATE}\"\nkind = \"store\"\n",
            text.trim_end()
        ),
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "an [[instance]] row over a cell that measures zero is a dead allowance",
        &[ROW_MATRIX],
        dead,
        &["dead-instance", &format!("{FIXTURE_CRATE} \u{d7} store")],
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
                "{}\n\n[[instance]]\ncrate = \"busbar-kernel\"\nkind = \"plane\"\n",
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

    /// Q128 (xtask part 24 #2): a name split across lines is one name to the compiler, so it is
    /// one literal here, filed on the line it opens on.
    #[test]
    fn a_literal_split_across_lines_is_read_whole() {
        let continued = file_literals("crates/x/src/b.rs", "let n = \"ot\\\n    lp\";\n");
        assert!(
            continued.contains(&(1, "otlp".to_string())),
            "{continued:?}"
        );
        let concat = file_literals(
            "crates/x/src/c.rs",
            "let n = concat!(\n    \"ot\",\n    \"lp\",\n);\n",
        );
        assert!(concat.contains(&(2, "otlp".to_string())), "{concat:?}");
        // A list across lines still reads each name on its own line.
        let list = file_literals("crates/x/src/d.rs", "&[\n    \"otlp\",\n    \"x\",\n]\n");
        assert!(list.contains(&(2, "otlp".to_string())), "{list:?}");
    }

    #[test]
    fn header_the_http_word_is_masked_and_header_the_instance_is_not() {
        let n = |rel: &str, text: &str| {
            let lines: Vec<&str> = text.lines().collect();
            (0..lines.len())
                .map(|at| word_collisions(rel, &lines, at, "header"))
                .sum::<usize>()
        };
        // The kernel's eight shapes, one each.
        let rs = "/// `bearer_methods_supported` is `[\"header\"]` and is not a parameter\n\
                  /// `[\"header\"]` tells a conforming client not to try the others\n\
                  doc.insert(\n    \"bearer_methods_supported\".into(),\n    \
                  Value::from(vec![\"header\"]),\n);\n\
                  assert_eq!(body[\"bearer_methods_supported\"], json!([\"header\"]));\n\
                  HeaderValue::from_str(&sig).expect(\"header\"),\n\
                  HeaderValue::from_str(&x).expect( \"header\" ),\n\
                  serde_json::json!({\"header\": header, \"trim_start\": trim_start})\n";
        assert_eq!(n("crates/k/src/a.rs", rs), 7);
        let json = "{\n  \"CredentialPlacement\": {\n    \"kind\": \"enum\",\n    \
                    \"variants\": [\n      \"bearer\",\n      \"header\"\n    ]\n  }\n}\n";
        assert_eq!(
            n("crates/k/src/config/config-schema.snapshot.json", json),
            1
        );
        // OpenAPI locations, in a `.json` document and in a `.rs` `json!` literal.
        let openapi = "        \"in\": \"header\",\n\
                       \"adminToken\": {\"type\": \"apiKey\", \"in\": \"header\", \"name\": X},\n";
        assert_eq!(n("crates/k/src/v1/json/openapi.json", openapi), 2);
        assert_eq!(n("crates/k/src/v1/json/handlers.rs", openapi), 2);
        // THE INSTANCE STILL COUNTS: a comparison, a call argument, a module constant, a match arm,
        // a list element, a value after a key, and a variant of a type that is not a placement.
        for real in [
            "if module == \"header\" {",
            "lookup_credential(\"header\", key)",
            "pub const AUTH_MODULE_HEADER: &str = \"header\";",
            "    \"header\" => Kind::Header,",
            "const AUTHS: &[&str] = &[\"header\", \"sigv4\"];",
            "json!({\"module\": \"header\"})",
            "json!({\"within\": \"header\"})",
            "path::to::x(\"header\")::y",
        ] {
            assert_eq!(n("crates/k/src/a.rs", real), 0, "{real}");
        }
        let modules =
            "{\n  \"AuthModule\": {\n    \"variants\": [\n      \"header\"\n    ]\n  }\n}\n";
        assert_eq!(n("crates/k/src/s.json", modules), 0);
        // A prose `//` inside a string is not a comment, and the placement rule is `.json` only.
        assert_eq!(
            n("crates/k/src/a.rs", "let u = \"a//b\"; f(\"header\");"),
            0
        );
        assert_eq!(n("crates/k/src/a.yaml", json), 0);
    }

    #[test]
    fn an_alias_under_three_characters_is_no_needle_and_a_longer_one_still_is() {
        // RED on predev 5c99befcfa: `c` was a secret needle, so every `extern "C"` and one-letter
        // `"c"` in a neutral crate counted as a secret instance.
        let registry = "plugins:\n  - repo: busbar-secret-c\n    kind: secret\n    alias: c\n    \
                        crate: busbar-secret-c\n  - repo: busbar-secret-vault\n    kind: secret\n    \
                        alias: vault\n    crate: busbar-secret-vault-plugin\n  - repo: \
                        busbar-secret-env\n    kind: secret\n    alias: env\n    crate: \
                        busbar-secret-env-plugin\n";
        let v = vocabulary(&[], &[], &[], registry);
        let secret = v.names.get("secret").expect("the secret axis");
        assert!(!secret.contains_key("c"), "{secret:?}");
        assert!(secret.contains_key("vault"), "{secret:?}");
        assert!(secret.contains_key("env"), "{secret:?}");
        assert_eq!(
            v.short,
            vec![(
                "secret",
                "c".to_string(),
                "plugins.yaml busbar-secret-c".to_string()
            )]
        );
        assert!(render(&Instances::new(), &v).contains("short\tsecret\tc\t"));
    }

    #[test]
    fn kind_words_take_both_numbers() {
        assert!(is_kind_word("HOOK", "hooks"));
        assert!(is_kind_word("hooks", "hooks"));
        assert!(is_kind_word("STORES", "store"));
        assert!(!is_kind_word("STOREFRONT", "store"));
    }
}
