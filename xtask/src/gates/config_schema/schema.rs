//! THE STRUCTURAL FINGERPRINT OF THE CONFIG SURFACE — `scripts/config-schema.py gen`, in Rust.
//!
//! Every serde-`Deserialize` struct and enum in the TRACKED SOURCE SET, plus each hand-written
//! `Deserialize` impl's accepted wire keys / declared member types / REFUSED input forms, plus the
//! named-definition-map type aliases, rendered as canonical JSON. That rendering is what
//! `crates/busbar-core/src/config/config-schema.snapshot.json` freezes, and the freeze is worth
//! nothing unless the two generators agree BYTE FOR BYTE, so the port keeps the Python's shape down
//! to the `_meta` prose and the sorted-key two-space emitter.
//!
//! WHY A FINGERPRINT AND NOT `schemars`: a `JsonSchema` derive on `DeployCfg` needs invasive changes
//! to `config/mod.rs` and a compile step. A fingerprint scraped from the typed config source is
//! derived from the same source of truth, is featureless-safe, and captures exactly the deltas the
//! additive rule cares about.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::scan;
use crate::ctx::{Ctx, WalkSpec};

/// Every tracked grammar source lives in the engine library crate root.
const CORE: &str = "crates/busbar-core/src";

/// The committed fingerprint. DATA: it stays where the config module keeps it.
pub const SNAPSHOT: &str = "crates/busbar-core/src/config/config-schema.snapshot.json";

/// The committed per-path break-waiver file, beside it.
pub const WAIVERS: &str = "crates/busbar-core/src/config/config-schema.waivers";

/// The `_meta` block, verbatim. It names the generator, and the generator's name is part of the
/// frozen bytes: moving it is a snapshot rewrite and belongs in a commit whose whole diff is that
/// rewrite, never bundled with the port that has to prove byte identity against it.
const META_DESCRIPTION: &str = "busbar config-surface structural fingerprint — FROZEN at 1.5.3, \
                                additive-only forever (enforced by the config-stability gate).";
const META_FROZEN_AT: &str = "1.5.3";
const META_GENERATOR: &str = "scripts/config-schema.py gen";
const META_SURFACE: &str = "serde-Deserialize structs/enums (derived AND hand-impl'd, including \
    each hand-impl'd type's declared shape, accepted wire keys, and the input forms it REFUSES \
    outright -- the last frozen in BOTH directions, because a refusal that is dropped widens the \
    grammar to accept exactly the inline literal the type exists to reject) + the \
    named-definition-map type aliases, over the tracked source set (SOURCES in \
    scripts/config-schema.py): the busbar config module, SecretRef, UpstreamCreds, the A2A \
    `agents:` grammar and the MCP `tools:` grammar";

/// LOCATE A PLANE'S CONFIG-GRAMMAR ROOT WHEREVER THE TREE CURRENTLY KEEPS IT.
///
/// The two plane entries in the tracked set are the ENTIRE grammar of the `tools:` and `agents:`
/// sections, and a hardcoded path goes stale on the day the plane moves — at which point the
/// grammar silently leaves the set, which is the exact hole the set's own refusals close.
///
/// A NAME MATCH IS NOT AN OWNERSHIP CLAIM. The wire-codec split gives a plane a SECOND directory
/// under its own name (`busbar-a2a-codec/src/a2a/` beside `busbar-a2a/src/a2a/`) holding
/// bytes-on-the-wire rather than the `agents:` grammar. So a candidate must also CARRY the grammar
/// file. Zero homes and two homes are both hard errors: "pick the first" would freeze one home's
/// shapes and quietly un-freeze the other's, which is a coverage hole that reads green.
pub fn plane_dir(cx: &Ctx, root: &str, plane: &str, grammar: &str) -> Result<String, String> {
    // `.ext("rs")` is not an optimisation, it is what makes this walk possible at all: `Ctx::walk`
    // READS every file it keeps, and `crates/` carries binary artefacts (a gzipped openapi.json
    // among them) that are not UTF-8. The grammar file this resolver looks for is a `.rs` by
    // construction — `grammar` is `config.rs` — so narrowing to Rust sources loses no candidate.
    let files = cx
        .walk(&WalkSpec::new([root]).ext("rs"))
        .map_err(|e| format!("config-schema: {e}"))?;
    let want = format!("/{plane}/{grammar}");
    let mut roots: Vec<String> = files
        .iter()
        .map(|f| f.rel_str())
        .filter(|p| p.ends_with(&want) && !p.split('/').any(|c| c == "target"))
        .map(|p| p[..p.len() - grammar.len() - 1].to_string())
        // `crates/*/**/<plane>`: one component, then zero or more, then the plane directory.
        .filter(|d| d.split('/').count() >= 3)
        .collect();
    roots.sort();
    roots.dedup();
    match roots.len() {
        1 => Ok(roots.remove(0)),
        0 => Err(format!(
            "config-schema: no directory named '{plane}' under {root}/ carries '{grammar}'. That \
             plane's config grammar is the whole of its config section and it has just left the \
             tracked set. Point plane_dir() at its new home; do not delete the SOURCES entries."
        )),
        n => Err(format!(
            "config-schema: '{plane}' resolves to {n} config-grammar directories ({}). Two homes \
             for one plane's grammar means this gate cannot say whose it froze.",
            roots.join(", ")
        )),
    }
}

/// THE TRACKED SOURCE SET — every file whose serde surface IS config grammar.
///
/// A path is a directory (every `*.rs` directly inside it) or a single file, and a path that does
/// not exist is a HARD ERROR rather than a skip: a source silently dropping out of the set would
/// silently un-freeze its grammar, which is the failure this gate exists to prevent.
pub fn sources(cx: &Ctx) -> Result<Vec<String>, String> {
    let mcp = plane_dir(cx, "crates", "mcp", "config.rs")?;
    let a2a = plane_dir(cx, "crates", "a2a", "config.rs")?;
    Ok(vec![
        format!("{CORE}/config"),
        // The bulk of the config GRAMMAR's PURE SHAPES moved DOWN to `busbar-substrate` in the
        // 1.6.0 config-seam migration; the loaders and resolvers that consume them stayed in
        // `busbar-core`, which re-exports every moved item at its historical `config::` path.
        // Tracked as a DIRECTORY so a future file split under it is automatically covered.
        "crates/busbar-substrate/src/config".to_string(),
        // The `plugins:` block is not the substrate's at all: its one reader is the plugin
        // subsystem, so the grammar is declared in `busbar-plugin-loader` beside the resolution of
        // it, and `busbar_core::config` re-exports it at its historical path. Tracked as a FILE
        // because the grammar is one module; a split under it must be added here, which is the
        // point — a source silently leaving this set is how a frozen grammar silently un-freezes.
        "crates/plugin-loader/src/config.rs".to_string(),
        "crates/secret-ref/src/lib.rs".to_string(),
        // `UpstreamCreds` — the `upstream_credentials:` value grammar — moved to the neutral
        // contracts crate in the plane extraction, exactly as `SecretRef` did to `secret-ref`.
        "crates/api/src/auth.rs".to_string(),
        format!("{CORE}/auth/mod.rs"),
        format!("{a2a}/config.rs"),
        // `oauth_as:` — including the `default_grant` CEILING that decides what a self-registered
        // client may ever hold — moved DOWN with the rest of the config grammar's pure shapes and is
        // covered by the `crates/busbar-substrate/src/config` directory entry above.
        format!("{a2a}/creds.rs"),
        format!("{mcp}/config.rs"),
        // `tool_pools:` / `agent_pools:` — one type, two sections, and `repeatable:` is the SAFETY
        // declaration that decides whether an operation with effects may be performed twice.
        format!("{CORE}/failover/mod.rs"),
        // `streams:` — the voice plane's grammar, including the three plane-imposed session
        // CEILINGS that bound what a live-voice deployment may ever hold.
        "crates/busbar-voice/src/config.rs".to_string(),
    ])
}

/// Expand the tracked source set to a deduplicated, sorted list of `.rs` files.
pub fn resolve_sources(cx: &Ctx, paths: &[String]) -> Result<Vec<String>, String> {
    let mut files: BTreeSet<String> = BTreeSet::new();
    for raw in paths {
        if raw.ends_with(".rs") {
            if !cx.exists(raw) {
                return Err(missing(raw));
            }
            files.insert(raw.clone());
            continue;
        }
        // A DIRECTORY: every `*.rs` directly inside it, never recursively.
        let listed = cx.walk(&WalkSpec::new([raw.clone()]).ext("rs"));
        let found: Vec<String> = match listed {
            Ok(f) => f
                .iter()
                .map(|s| s.rel_str())
                .filter(|p| p.rsplit_once('/').map(|(d, _)| d) == Some(raw.as_str()))
                .collect(),
            Err(crate::ctx::WalkError::MissingRoot { .. }) => return Err(missing(raw)),
            Err(e) => return Err(format!("config-schema: {e}")),
        };
        if found.is_empty() {
            return Err(format!(
                "config-schema: tracked source directory '{raw}' contains no *.rs files"
            ));
        }
        files.extend(found);
    }
    Ok(files.into_iter().collect())
}

fn missing(raw: &str) -> String {
    format!(
        "config-schema: tracked source '{raw}' does not exist. The config-grammar gate covers a \
         FIXED set of sources; a vanished one is a coverage hole, not a skip. If the file moved, \
         update the tracked source set."
    )
}

// ── rename_all ───────────────────────────────────────────────────────────────────────────────────

/// serde applies a rename rule to the IDENT, and a field ident is `snake_case` while a variant
/// ident is `PascalCase` — so the SAME rule name is a different transform on each. `kebab-case` on
/// the variant `LeastBad` is `least-bad`, but on the field `max_tokens` it is `max-tokens`, and the
/// PascalCase-shaped transform would leave `max_tokens` untouched. Getting that wrong does not
/// produce a loud error, it produces a fingerprint that quietly disagrees with the parser.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ident {
    Field,
    Variant,
}

fn split_before_upper(s: &str, sep: char) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && c.is_ascii_uppercase() {
            out.push(sep);
        }
        out.push(c);
    }
    out
}

fn capitalize(w: &str) -> String {
    let mut it = w.chars();
    match it.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + &it.as_str().to_ascii_lowercase(),
        None => String::new(),
    }
}

fn apply_rename_all(rule: &str, ident: Ident, s: &str) -> Option<String> {
    let out = match (ident, rule) {
        (Ident::Variant, "snake_case") => split_before_upper(s, '_').to_ascii_lowercase(),
        (Ident::Variant, "kebab-case") => split_before_upper(s, '-').to_ascii_lowercase(),
        (Ident::Variant, "camelCase") => {
            let mut it = s.chars();
            match it.next() {
                Some(c) => c.to_ascii_lowercase().to_string() + it.as_str(),
                None => String::new(),
            }
        }
        (Ident::Variant, "PascalCase") => s.to_string(),
        (Ident::Variant, "SCREAMING_SNAKE_CASE") => split_before_upper(s, '_').to_ascii_uppercase(),
        (Ident::Variant, "SCREAMING-KEBAB-CASE") => split_before_upper(s, '-').to_ascii_uppercase(),
        (Ident::Field, "snake_case") => s.to_string(),
        (Ident::Field, "kebab-case") => s.replace('_', "-"),
        (Ident::Field, "camelCase") => s
            .split('_')
            .enumerate()
            .map(|(i, w)| if i == 0 { w.to_string() } else { capitalize(w) })
            .collect(),
        (Ident::Field, "PascalCase") => s.split('_').map(capitalize).collect(),
        (Ident::Field, "SCREAMING_SNAKE_CASE") => s.to_ascii_uppercase(),
        (Ident::Field, "SCREAMING-KEBAB-CASE") => s.replace('_', "-").to_ascii_uppercase(),
        (_, "lowercase") => s.to_ascii_lowercase(),
        (_, "UPPERCASE") => s.to_ascii_uppercase(),
        _ => return None,
    };
    Some(out)
}

/// An unknown `rename_all` is a hard error rather than a silent identity fallback: it rewrites
/// every wire key on the container, so quietly not applying one would report a grammar the parser
/// does not accept — and a fingerprint that lies is worse than no fingerprint.
fn rename(csd: &Container, ident: Ident, s: &str) -> Result<String, String> {
    match &csd.rename_all {
        None => Ok(s.to_string()),
        Some(rule) => apply_rename_all(rule, ident, s).ok_or_else(|| {
            format!(
                "config-schema: unsupported #[serde(rename_all = '{rule}')] on a {}. Add it to the \
                 rename tables — an unhandled rename_all would fingerprint wire keys the parser \
                 does not actually accept.",
                match ident {
                    Ident::Field => "field",
                    Ident::Variant => "variant",
                }
            )
        }),
    }
}

// ── container / field serde knobs ────────────────────────────────────────────────────────────────

struct Container {
    is_de: bool,
    rename_all: Option<String>,
    deny_unknown_fields: bool,
    transparent: bool,
}

fn container_serde(attrs: &str) -> Container {
    Container {
        is_de: scan::derive_list(attrs).contains("Deserialize"),
        rename_all: scan::serde_string(attrs, "rename_all", false),
        deny_unknown_fields: scan::serde_flag(attrs, "deny_unknown_fields"),
        transparent: scan::serde_flag(attrs, "transparent"),
    }
}

/// The container knobs that are part of the ACCEPTED-DOCUMENT grammar, recorded on every node so a
/// flip is a snapshot delta. `deny_unknown_fields` decides whether a document carrying an extra key
/// parses at all; `transparent` decides whether the wire form is a map or the bare inner value.
/// Both were once parsed and thrown away, so either could be flipped with ZERO snapshot delta.
fn container_flags(csd: &Container, into: &mut Map<String, Value>) {
    into.insert(
        "deny_unknown_fields".into(),
        Value::Bool(csd.deny_unknown_fields),
    );
    into.insert("transparent".into(), Value::Bool(csd.transparent));
}

struct FieldAttrs {
    rename: Option<String>,
    has_default: bool,
    skip: bool,
    flatten: bool,
}

fn field_serde(attrs: &str) -> FieldAttrs {
    FieldAttrs {
        rename: scan::serde_string(attrs, "rename", true),
        has_default: scan::serde_flag(attrs, "default"),
        skip: scan::serde_skip(attrs),
        flatten: scan::serde_flag(attrs, "flatten"),
    }
}

// ── the body parsers ─────────────────────────────────────────────────────────────────────────────

/// Split a struct/enum body on top-level commas, respecting `<>`, `()`, `[]` and `{}` nesting.
fn split_top(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i64;
    let mut cur = String::new();
    for c in body.chars() {
        if matches!(c, '<' | '(' | '[' | '{') {
            depth += 1;
        } else if matches!(c, '>' | ')' | ']' | '}') {
            depth -= 1;
        }
        if c == ',' && depth == 0 {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

/// Strip the leading `#[…]` clusters off one split entry, returning `(attrs, rest)`.
fn take_entry_attrs(seg: &str) -> (String, String) {
    let mut attrs = String::new();
    let mut rest: Vec<char> = seg.chars().collect();
    loop {
        let mut i = 0usize;
        while i < rest.len() && rest[i].is_whitespace() {
            i += 1;
        }
        if !(rest.get(i) == Some(&'#') && rest.get(i + 1) == Some(&'[')) {
            break;
        }
        let mut le = i;
        while le < rest.len() && rest[le] != '\n' {
            le += 1;
        }
        let Some(close) = (i + 2..le).rev().find(|k| rest[*k] == ']') else {
            break;
        };
        attrs.push_str(&scan::text(&rest, i..close + 1));
        attrs.push('\n');
        let mut j = close + 1;
        while j < rest.len() && rest[j].is_whitespace() {
            j += 1;
        }
        rest = rest[j..].to_vec();
    }
    (attrs, rest.into_iter().collect())
}

/// `(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$` with `re.DOTALL`.
fn field_decl(seg: &str) -> Option<(String, String)> {
    let c: Vec<char> = seg.chars().collect();
    let n = c.len();
    let mut i = 0usize;
    if scan::starts_with(&c, 0, "pub") {
        let mut j = 3usize;
        if c.get(j) == Some(&'(') {
            let mut e = j + 1;
            while e < n && c[e] != ')' {
                e += 1;
            }
            if e < n {
                j = e + 1;
            }
        }
        let mut w = j;
        while w < n && c[w].is_whitespace() {
            w += 1;
        }
        if w > j {
            i = w;
        }
    }
    if !c
        .get(i)
        .copied()
        .is_some_and(|x| x.is_ascii_alphabetic() || x == '_')
    {
        return None;
    }
    let ns = i;
    while i < n && scan::is_word(c[i]) {
        i += 1;
    }
    let name = scan::text(&c, ns..i);
    while i < n && c[i].is_whitespace() {
        i += 1;
    }
    if c.get(i) != Some(&':') {
        return None;
    }
    i += 1;
    while i < n && c[i].is_whitespace() {
        i += 1;
    }
    if i >= n {
        return None;
    }
    Some((name, scan::text(&c, i..n)))
}

/// Normalize a Rust field type to `(inner, optional)`. `Option<T>` unwraps to `(T, true)`;
/// whitespace is collapsed so formatting never registers as a retype.
fn norm_type(t: &str) -> (String, bool) {
    let collapsed: String = {
        let mut out = String::new();
        let mut ws = false;
        for c in t.chars() {
            if c.is_whitespace() {
                ws = true;
            } else {
                if ws && !out.is_empty() {
                    out.push(' ');
                }
                ws = false;
                out.push(c);
            }
        }
        out
    };
    let t = collapsed.trim().trim_end_matches(',').trim().to_string();
    if let Some(rest) = t.strip_prefix("Option") {
        let rest = rest.trim_start();
        if let Some(inner) = rest.strip_prefix('<') {
            if let Some(inner) = inner.strip_suffix('>') {
                return (inner.trim().to_string(), true);
            }
        }
    }
    (t, false)
}

fn parse_struct(
    body: &str,
    csd: &Container,
    lifted: &BTreeSet<String>,
    carried: &mut BTreeSet<String>,
) -> Result<Map<String, Value>, String> {
    let mut fields: Map<String, Value> = Map::new();
    let mut pending = String::new();
    for raw in split_top(body) {
        let seg = raw.trim();
        if seg.is_empty() {
            continue;
        }
        let (own, seg) = take_entry_attrs(seg);
        let attrs = pending.clone() + &own;
        pending.clear();
        let Some((name, ty)) = field_decl(&seg) else {
            if !attrs.trim().is_empty() {
                pending = attrs;
            }
            continue;
        };
        let fa = field_serde(&attrs);
        let serde_name = match &fa.rename {
            Some(r) => r.clone(),
            None => rename(csd, Ident::Field, &name)?,
        };
        if fa.skip {
            // THE PRE-PASS EXCEPTION. A skipped field whose wire key the pre-pass lifts is still
            // grammar. It is recorded OPTIONAL because a carrier is: `skip` requires `Default`, so
            // an absent key leaves the default in place.
            if lifted.contains(&serde_name) {
                let (inner, _) = norm_type(&ty);
                fields.insert(serde_name.clone(), field_value(&inner, true));
                carried.insert(serde_name);
            }
            continue;
        }
        let (inner, opt) = norm_type(&ty);
        if fa.flatten {
            // A flattened field contributes its target type's surface; record it as a marker so a
            // change to WHICH type is flattened is caught, without cross-type resolution.
            fields.insert(format!("<<flatten:{inner}>>"), field_value(&inner, true));
            continue;
        }
        fields.insert(serde_name, field_value(&inner, opt || fa.has_default));
    }
    let mut out = Map::new();
    out.insert("kind".into(), Value::String("struct".into()));
    out.insert("fields".into(), Value::Object(fields));
    container_flags(csd, &mut out);
    Ok(out)
}

fn field_value(ty: &str, optional: bool) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), Value::String(ty.to_string()));
    m.insert("optional".into(), Value::Bool(optional));
    Value::Object(m)
}

fn parse_enum(body: &str, csd: &Container) -> Result<Map<String, Value>, String> {
    let mut variants: BTreeSet<String> = BTreeSet::new();
    let mut pending = String::new();
    for raw in split_top(body) {
        let seg = raw.trim();
        if seg.is_empty() {
            continue;
        }
        let (own, seg) = take_entry_attrs(seg);
        let attrs = pending.clone() + &own;
        pending.clear();
        let c: Vec<char> = seg.chars().collect();
        if !c
            .first()
            .copied()
            .is_some_and(|x| x.is_ascii_alphabetic() || x == '_')
        {
            if !attrs.trim().is_empty() {
                pending = attrs;
            }
            continue;
        }
        let mut e = 0usize;
        while e < c.len() && scan::is_word(c[e]) {
            e += 1;
        }
        let vname = scan::text(&c, 0..e);
        let fa = field_serde(&attrs);
        if fa.skip {
            continue;
        }
        variants.insert(match fa.rename {
            Some(r) => r,
            None => rename(csd, Ident::Variant, &vname)?,
        });
    }
    let mut out = Map::new();
    out.insert("kind".into(), Value::String("enum".into()));
    out.insert(
        "variants".into(),
        Value::Array(variants.into_iter().map(Value::String).collect()),
    );
    container_flags(csd, &mut out);
    Ok(out)
}

// ── hand-written `Deserialize` ───────────────────────────────────────────────────────────────────

/// The input forms a hand-written `Deserialize` impl REFUSES OUTRIGHT.
///
/// The wire-key set is the map keys a document may use; it says nothing about whether a bare scalar
/// is accepted at all, and for `SecretRef` that rejection is the whole point of the type. Relaxing
/// any of `visit_str`/`visit_u64`/`visit_i64`/`visit_f64`/`visit_bool`/`visit_bytes` was a
/// ZERO-DELTA change to this fingerprint, so the refusals are recorded and frozen in BOTH
/// directions — a refusal REMOVED widens the grammar to accept exactly the inline literal the type
/// exists to reject, and a refusal ADDED breaks a config that used the form.
///
/// A form counts as refused when its body can only fail: it mentions `Err` and contains no `Ok(` at
/// all. Deliberately CONSERVATIVE — a visitor that can sometimes succeed is simply not recorded.
fn refused_forms(src: &[char], start: usize, end: usize) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (name, after) in scan::visit_fns(src, start, end) {
        let Some(brace) = (after..src.len()).find(|i| src[*i] == '{') else {
            continue;
        };
        if brace >= end {
            continue;
        }
        let body = scan::text(src, brace..scan::match_block(src, brace));
        if body.contains("Err") && !body.contains("Ok(") {
            out.insert(name);
        }
    }
    out.into_iter().collect()
}

/// Fingerprint one `impl<'de> Deserialize<'de> for X`: the accepted wire keys, the declared type of
/// each WIRE-VISIBLE member (taken from `X`'s own struct declaration, which carries no derive and
/// so was skipped entirely by the derive-gated walk), and the refused input forms.
///
/// ONLY wire-visible members are recorded. A hand-impl'd type's declaration is also its PARSED
/// RESULT and the two are not the same set — `LimitCfg` accepts `requests:`/`tokens:` and stores
/// `amount`/`metric`. Freezing the whole declaration would fire RED on a purely internal rename no
/// config can observe, and a gate that cries wolf is a gate that gets muted.
fn manual_de_detail(
    src: &[char],
    open_idx: usize,
    decls: &BTreeMap<String, Map<String, Value>>,
    name: &str,
) -> Value {
    let end = scan::match_block(src, open_idx);
    let body: Vec<char> = src[open_idx..end].to_vec();
    let keys: BTreeSet<String> = scan::match_arm_literals(&body).into_iter().collect();
    let decl_fields = decls
        .get(name)
        .and_then(|d| d.get("fields"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut fields = Map::new();
    for (k, v) in decl_fields {
        if keys.contains(&k) {
            fields.insert(k, v);
        }
    }
    let mut out = Map::new();
    out.insert("kind".into(), Value::String("manual".into()));
    out.insert(
        "wire_keys".into(),
        Value::Array(keys.into_iter().map(Value::String).collect()),
    );
    out.insert(
        "refused".into(),
        Value::Array(
            refused_forms(src, open_idx, end)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert("fields".into(), Value::Object(fields));
    Value::Object(out)
}

// ── the extractor ────────────────────────────────────────────────────────────────────────────────

/// Parse a struct/enum declaration REGARDLESS of whether it derives `Deserialize`, so a
/// hand-written impl in one file can be matched to its type's declaration in another.
fn declared_shape(
    src: &[char],
    item: &scan::Item,
    lifted: &BTreeSet<String>,
    carried: &mut BTreeSet<String>,
) -> Result<Map<String, Value>, String> {
    let csd = container_serde(&item.attrs);
    if item.open == ';' {
        let mut out = Map::new();
        out.insert("fields".into(), Value::Object(Map::new()));
        container_flags(&csd, &mut out);
        return Ok(out);
    }
    let end = scan::match_block(src, item.open_idx);
    let body = scan::text(src, item.open_idx + 1..end - 1);
    if item.kw == "enum" {
        parse_enum(&body, &csd)
    } else {
        parse_struct(&body, &csd, lifted, carried)
    }
}

/// A FINGERPRINT KEY MAY BE CLAIMED ONCE, IN EVERY ONE OF THE THREE NAMESPACES.
///
/// The fingerprint is a FLAT map keyed by the bare Rust ident with no module path, so a second
/// definition REPLACES the first: the replaced grammar stops being covered at all, and the
/// classifier reports the swap as a break in a grammar nobody edited. Both planes really did
/// declare a `PinMechanism`, with different variants, and that is exactly what happened.
///
/// The rule reaches all three key namespaces — the derived types, the `manual-de X` details and the
/// `type X` aliases — because a flat map does not care which of them wrote the key.
fn collide(
    origin: &mut BTreeMap<String, String>,
    key: &str,
    what: &str,
    path: &str,
) -> Result<(), String> {
    if let Some(prior) = origin.get(key) {
        let mut two = [prior.clone(), path.to_string()];
        two.sort();
        return Err(format!(
            "config-schema: {what} '{key}' is declared in BOTH '{}' and '{}'. The fingerprint is \
             keyed by bare name with no module path, so the second one read would REPLACE the \
             first — the replaced grammar would stop being covered entirely, and the classifier \
             would report the swap as a break in a grammar nobody edited. Rename one of the two \
             Rust idents (the ident is not wire grammar; serde's rename_all decides what an \
             operator actually writes).",
            two[0], two[1]
        ));
    }
    origin.insert(key.to_string(), path.to_string());
    Ok(())
}

/// The full fingerprint over an explicit `(path, text)` list.
pub fn extract(files: &[(String, String)]) -> Result<Value, String> {
    let sources: Vec<(String, Vec<char>)> = files
        .iter()
        .map(|(p, t)| {
            let chars: Vec<char> = t.chars().collect();
            (
                p.clone(),
                scan::strip_cfg_test_mods(&scan::strip_comments(&chars)),
            )
        })
        .collect();

    // The pre-pass's lift list, read from its own declarations and BEFORE any declaration is
    // parsed: it decides which skipped fields are still grammar, and a list declared in one file
    // governs a carrier declared in another.
    let mut lifted: BTreeSet<String> = BTreeSet::new();
    for (_, src) in &sources {
        for body in scan::lift_lists(src) {
            lifted.extend(scan::string_literals(&body));
        }
    }
    let mut carried: BTreeSet<String> = BTreeSet::new();

    let mut decls: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for (_, src) in &sources {
        for item in scan::items(src) {
            let mut shape = declared_shape(src, &item, &lifted, &mut carried)?;
            shape.remove("kind");
            decls.insert(item.name.clone(), shape);
        }
    }

    let mut types: Map<String, Value> = Map::new();
    let mut origin: BTreeMap<String, String> = BTreeMap::new();
    for (path, src) in &sources {
        for item in scan::items(src) {
            let csd = container_serde(&item.attrs);
            if !csd.is_de {
                continue;
            }
            // A BARE NAME MAY BE FINGERPRINTED ONCE. The fingerprint is a FLAT map keyed by the
            // bare Rust ident with no module path, so a second definition would REPLACE the first:
            // the replaced grammar stops being covered at all, and the classifier reports the swap
            // as a break in a grammar nobody edited. Both planes really did declare a
            // `PinMechanism`, with different variants, and that is exactly what happened.
            collide(&mut origin, &item.name, "the bare type name", path)?;

            if item.open == ';' {
                let mut out = Map::new();
                out.insert("kind".into(), Value::String("struct".into()));
                out.insert("fields".into(), Value::Object(Map::new()));
                container_flags(&csd, &mut out);
                types.insert(item.name.clone(), Value::Object(out));
                continue;
            }
            let end = scan::match_block(src, item.open_idx);
            let body = scan::text(src, item.open_idx + 1..end - 1);
            let parsed = if item.kw == "enum" {
                parse_enum(&body, &csd)?
            } else {
                parse_struct(&body, &csd, &lifted, &mut carried)?
            };
            types.insert(item.name.clone(), Value::Object(parsed));
        }

        // HAND-WRITTEN `Deserialize` impls carry no derive, so the walk above skips them entirely
        // — yet they ARE config surface. The `X` sentinel records that the type EXISTS, so a
        // section removal is caught RED; the detail lands under a SEPARATE `manual-de X` key rather
        // than being folded in, because folding it in would turn every already-tracked hand-impl'd
        // type's empty field map into a populated one and the classifier would read that fidelity
        // increase as a pile of new REQUIRED fields — a false RED on the commit that adds coverage.
        for (name, end) in scan::manual_de_impls(src) {
            if !types.contains_key(&name) {
                let mut m = Map::new();
                m.insert("kind".into(), Value::String("struct".into()));
                m.insert("fields".into(), Value::Object(Map::new()));
                m.insert("deserialize".into(), Value::String("manual".into()));
                types.insert(name.clone(), Value::Object(m));
            }
            if let Some(open) = (end..src.len()).find(|i| src[*i] == '{') {
                // THE SECOND HALF OF THE COLLISION RULE. `collide` guarded the DERIVED namespace
                // only, so two files each writing `impl<'de> Deserialize<'de> for X` overwrote one
                // another's `manual-de X` silently — last one wins, the replaced impl's accepted
                // wire keys and REFUSED input forms stop being covered entirely, and the classifier
                // reports the swap as a break in a grammar nobody edited. That is the same defect
                // the derived namespace was refused for, in the namespace where the refusals live.
                collide(
                    &mut origin,
                    &format!("manual-de {name}"),
                    "the hand-written `Deserialize` impl for",
                    path,
                )?;
                types.insert(
                    format!("manual-de {name}"),
                    manual_de_detail(src, open, &decls, &name),
                );
            }
        }

        // THE NAMED-DEFINITION-MAP ALIASES are the shape of `hooks:`/`export:`/
        // `identity-providers:` themselves. A field typed `ExportDefs` compares equal even if the
        // alias were retargeted, so the alias TARGET is pinned too.
        for (name, target) in scan::type_aliases(src) {
            let target = norm_type(&target).0;
            // A callback/trait-object alias is plumbing, never config grammar.
            if target.contains("dyn ") || target.contains("Fn(") {
                continue;
            }
            // THE THIRD NAMESPACE, guarded on the same terms. A definition-map alias IS the shape
            // of its section, so two files declaring `type HookDefs` would silently freeze one
            // shape and un-freeze the other.
            collide(
                &mut origin,
                &format!("type {name}"),
                "the definition-map alias",
                path,
            )?;
            let mut m = Map::new();
            m.insert("kind".into(), Value::String("alias".into()));
            m.insert("target".into(), Value::String(target));
            types.insert(format!("type {name}"), Value::Object(m));
        }
    }

    // EVERY LIFTED KEY MUST HAVE A CARRIER FIELD THAT WAS KEPT BECAUSE OF IT. Without this the
    // lift list would be a way to keep a field in the fingerprint after deleting it.
    let orphans: Vec<&String> = lifted.difference(&carried).collect();
    if !orphans.is_empty() {
        return Err(format!(
            "config-schema: the config pre-pass lifts {orphans:?} but no struct in the tracked \
             source set declares a matching skipped carrier field. A lifted key with nowhere to \
             land is either a deleted field the list is still holding open, or a list entry that \
             was never grammar — both are coverage holes, not passes."
        ));
    }

    let mut meta = Map::new();
    meta.insert(
        "description".into(),
        Value::String(META_DESCRIPTION.to_string()),
    );
    meta.insert(
        "frozen_at".into(),
        Value::String(META_FROZEN_AT.to_string()),
    );
    meta.insert(
        "generator".into(),
        Value::String(META_GENERATOR.to_string()),
    );
    meta.insert("surface".into(), Value::String(META_SURFACE.to_string()));

    let mut doc = Map::new();
    doc.insert("_meta".into(), Value::Object(meta));
    doc.insert("types".into(), Value::Object(types));
    Ok(Value::Object(doc))
}

/// `json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"`.
///
/// `serde_json`'s `Map` is a `BTreeMap` here (no `preserve_order` anywhere in the workspace), so its
/// keys come out in the same code-point order Python's `sort_keys` produces, and its pretty printer
/// is two-space with `": "` separators and inline `{}` / `[]` for empty containers — the same shape.
pub fn canonical(doc: &Value) -> String {
    serde_json::to_string_pretty(doc).unwrap_or_default() + "\n"
}

/// The fingerprint over the TRACKED SOURCE SET, as the committed snapshot's bytes.
pub fn render(cx: &Ctx) -> Result<String, String> {
    let files = resolve_sources(cx, &sources(cx)?)?;
    let mut read = Vec::with_capacity(files.len());
    for path in files {
        let text = cx.read(&path)?;
        read.push((path, text));
    }
    Ok(canonical(&extract(&read)?))
}
