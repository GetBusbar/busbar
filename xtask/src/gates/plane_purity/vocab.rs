//! THE INSTANCE VOCABULARY, DERIVED FROM THE TREE — which planes, transports and dialects exist is
//! read off the crates that ARE them, never off a list in this runner.
//!
//! WHY. The scanner used to carry `PLANE_ALTERNATION = ["llm", "mcp", "a2a", "voice"]` and a
//! six-name dialect list, both typed by hand. Measured (1.6.0 item 3): a new plane, a new transport
//! and a new dialect named in `crates/busbar-kernel/src/lib.rs` moved ZERO rows across ten gates —
//! and the hand list was already wrong on the day it was measured: it scanned `voice` (a dialect
//! inside a plane since DECISIONS #18) and not `streaming` or `decision`, two of the five planes
//! DECISIONS #48 names. A witness that enumerates its subjects by hand cannot see a subject nobody
//! enumerated, which is the only kind of subject a neutrality witness exists to catch.
//!
//! WHERE EACH WORD COMES FROM:
//!
//! * **PLANES** — every plane-FAMILY crate the kind census resolves
//!   ([`crate::gates::kind_isolation::plane_kind_src_roots`], the same population the backwards
//!   rule scans): `busbar-plane-<key>[-<dialect>]`, `busbar-<key>-codec` and the legacy
//!   `busbar-<key>` engines each name their key in their directory. And every plane declares its
//!   own key in its `PlaneMeta` impl (`const KEY: &'static str = "…";`), which is read too, so a
//!   plane whose crate is spelled some other way still names itself.
//! * **TRANSPORTS** — every `crates/busbar-transport-<key>` crate.
//! * **DIALECTS** — every `busbar-plane-<plane>-<dialect>` crate (the kind scheme's four-segment
//!   dialect name), plus the dialects a plane crate DECLARES in production source: a `name: "…"`
//!   field of a `Dialect { … }` table row, and a `=> "…"` arm of an `impl Dialect` block.
//!
//! An empty derivation is not a clean tree — it is a scanner with no words — so every class carries
//! a count the gate prints and refuses at zero (see `denominator_row`).

use std::collections::BTreeSet;

use crate::ctx::{Ctx, SourceFile};

/// One derived vocabulary, and every spelling the scanner matches it under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vocab {
    /// Plane keys, lowercase (`llm`, `mcp`, `a2a`, `streaming`, `decision`, `voice`, …).
    pub planes: Vec<String>,
    /// Transport keys, lowercase (`http`, `ws`, …).
    pub transports: Vec<String>,
    /// Dialect names, lowercase, as the plane declares them (`anthropic`, `openai-realtime`, …).
    pub dialects: Vec<String>,
    /// Every instance crate's directory name: the plane family and the transports.
    pub crate_dirs: Vec<String>,

    // ── the spellings, derived once from the four lists above ──
    /// `busbar_plane_llm`, `busbar_transport_http`, … — the SYMBOL rule's crate identifiers.
    pub crate_idents: Vec<String>,
    /// `busbar-plane-llm/`, … — the directory spelling a dual-compile has to name.
    pub dir_needles: Vec<String>,
    /// The KEY rule's bare words: every plane key, and every transport as `transport_<key>` /
    /// `transport-<key>`. A bare transport key is NOT a word here: `http`, `tcp` and `tls` are the
    /// kernel's own protocol stack, and a rule that fired on every one of them would be a rule
    /// nobody reads. The transport is caught on its crate identifier and its compound name instead.
    pub key_words: Vec<String>,
    /// The KEY rule's QUOTED words: a plane key in [`PRIMITIVE_COLLISIONS`] is matched only as a
    /// string literal — `"decision"`, `"decisions"` — the spelling in which code names a plane as
    /// DATA (a config key, a registry lookup, a route), never as the neutral word it also is.
    pub literal_words: Vec<String>,
    /// `Llm`, `Streaming`, `Anthropic`, … — a prefix followed by an uppercase letter is a plane- or
    /// dialect-named type.
    pub camel_prefixes: Vec<String>,
    /// `LLM`, `MCP`, `OPENAI`, `OpenAI`, … — the acronym spellings the CamelCase list cannot see.
    pub screaming_prefixes: Vec<String>,
}

/// A spelling the capitalisation rules cannot produce from the lowercase key, for a key that IS in
/// the derived set. Not an instance list: a row here names nothing unless the tree already derived
/// its key, and it adds a spelling, never a subject.
const IRREGULAR_SPELLINGS: &[(&str, &str)] = &[("openai", "OpenAI")];

/// PLANE KEYS WHOSE BARE WORD IS ALSO A NEUTRAL PRIMITIVE, each with the measurement that says so.
/// Such a key is still scanned — as a quoted literal (see [`Vocab::literal_words`]), on its crate
/// identifier (SYMBOL), on its directory (PATH-INCLUDE) and on its type prefix (TYPE) — but not as
/// a bare token, because the bare token is the kernel's own vocabulary and a rule that fired on it
/// would bury every real leak under a hundred neutral ones.
///
/// * `decision` — `busbar_contract::caps::Decision<Step>` is the loop's step verdict, and
///   `busbar_plugin::hot::Decision` the admit/throttle/deny answer: the primitive governance
///   taxonomy itself. Measured 2026-09-24: the bare word added 98 KEY hits in the neutral crates,
///   every one of them core naming its own verdict type. `plane-abi-neutrality` exempts the same
///   key for the same collision (`PRIMITIVE_COLLISION_KEYS`).
/// * `streaming` — a response SHAPE every plane has (`may_stream`, "a non-streaming response"),
///   not the fourth plane. Measured the same day: 15 KEY hits, none of them the plane.
///
/// NOT A LICENCE, AND NOT AN INSTANCE LIST: an entry only narrows a key the tree has already
/// derived, a NEW plane is scanned on its bare word from the day it lands, and an entry whose key
/// the tree no longer derives narrows nothing.
pub const PRIMITIVE_COLLISIONS: &[&str] = &["decision", "streaming"];

impl Vocab {
    /// Build every spelling from the four derived lists.
    pub fn new(
        planes: BTreeSet<String>,
        transports: BTreeSet<String>,
        dialects: BTreeSet<String>,
        crate_dirs: BTreeSet<String>,
    ) -> Vocab {
        let planes: Vec<String> = planes.into_iter().collect();
        let transports: Vec<String> = transports.into_iter().collect();
        let dialects: Vec<String> = dialects.into_iter().collect();
        let crate_dirs: Vec<String> = crate_dirs.into_iter().collect();

        let crate_idents = crate_dirs.iter().map(|d| d.replace('-', "_")).collect();
        let dir_needles = crate_dirs.iter().map(|d| format!("{d}/")).collect();

        let mut key_words: BTreeSet<String> = BTreeSet::new();
        let mut literal_words: BTreeSet<String> = BTreeSet::new();
        for p in &planes {
            if PRIMITIVE_COLLISIONS.contains(&p.as_str()) {
                literal_words.insert(format!("\"{p}\""));
                literal_words.insert(format!("\"{p}s\""));
            } else {
                key_words.insert(p.clone());
            }
        }
        for t in &transports {
            key_words.insert(format!("transport_{t}"));
            key_words.insert(format!("transport-{t}"));
        }

        // The type stems: every plane key, and the leading segment of every dialect name (the
        // vendor: `openai-realtime` -> `openai`). A stem is spelled Capitalised and UPPERCASE.
        let mut stems: BTreeSet<String> = planes.iter().cloned().collect();
        for d in &dialects {
            if let Some(first) = d.split(['-', '_']).next() {
                if !first.is_empty() {
                    stems.insert(first.to_string());
                }
            }
        }
        let mut camel: BTreeSet<String> = BTreeSet::new();
        let mut screaming: BTreeSet<String> = BTreeSet::new();
        for s in &stems {
            camel.insert(capitalise(s));
            screaming.insert(s.to_ascii_uppercase());
            for (key, spelling) in IRREGULAR_SPELLINGS {
                if key == s {
                    screaming.insert((*spelling).to_string());
                }
            }
        }

        Vocab {
            planes,
            transports,
            dialects,
            crate_dirs,
            crate_idents,
            dir_needles,
            key_words: key_words.into_iter().collect(),
            literal_words: literal_words.into_iter().collect(),
            camel_prefixes: camel.into_iter().collect(),
            screaming_prefixes: screaming.into_iter().collect(),
        }
    }

    /// The counts the gate prints beside its denominator, so a reader can see the words it used.
    pub fn summary(&self) -> String {
        format!(
            "planes={} [{}] transports={} [{}] dialects={} [{}]",
            self.planes.len(),
            self.planes.join(" "),
            self.transports.len(),
            self.transports.join(" "),
            self.dialects.len(),
            self.dialects.join(" ")
        )
    }

    /// Whether any class came back empty — a scanner with no words for a class answers "clean"
    /// about that class whatever the tree says.
    pub fn empty_classes(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.planes.is_empty() {
            out.push("planes");
        }
        if self.transports.is_empty() {
            out.push("transports");
        }
        if self.dialects.is_empty() {
            out.push("dialects");
        }
        out
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => String::new(),
    }
}

/// The directory name a `crates/<dir>/src` root belongs to.
fn dir_of_root(root: &str) -> Option<String> {
    let root = root.strip_suffix("/src").unwrap_or(root);
    root.rsplit('/').next().map(str::to_string)
}

/// The plane key (and dialect, for a four-segment dialect crate) a plane-family directory names.
fn keys_of_plane_dir(dir: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = dir.strip_prefix("busbar-") else {
        return (None, None);
    };
    if let Some(rest) = rest.strip_prefix("plane-") {
        let mut segs = rest.splitn(2, '-');
        let key = segs.next().filter(|s| !s.is_empty()).map(str::to_string);
        let dialect = segs.next().filter(|s| !s.is_empty()).map(str::to_string);
        return (key, dialect);
    }
    if let Some(key) = rest.strip_suffix("-codec") {
        return (Some(key.to_string()), None);
    }
    if !rest.contains('-') && !rest.is_empty() {
        return (Some(rest.to_string()), None);
    }
    (None, None)
}

fn is_test_path(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("/tests.rs")
}

/// The first `"…"` literal on a line, if the line holds one.
fn first_literal(s: &str) -> Option<&str> {
    let start = s.find('"')? + 1;
    let len = s[start..].find('"')?;
    Some(&s[start..start + len])
}

/// A plausible instance word: lowercase ASCII letters, digits, `-` and `_`, starting with a letter.
fn instance_word(s: &str) -> Option<String> {
    let s = s.trim();
    let ok = s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    ok.then(|| s.to_ascii_lowercase())
}

/// What one plane-family source file declares: its `PlaneMeta` key, and its dialect names.
fn declared_in(text: &str, planes: &mut BTreeSet<String>, dialects: &mut BTreeSet<String>) {
    // Braces are counted on the production lines only, which have comments stripped; a literal
    // holding a brace would skew the depth, and no declaration line this reads carries one.
    let mut in_table_row = false;
    let mut impl_depth: Option<i32> = None;
    let mut depth: i32 = 0;
    for (_, line) in crate::scan::production_lines(text) {
        let t = line.trim();
        if t.starts_with("const KEY: &'static str =") || t.starts_with("const KEY: &str =") {
            if let Some(k) = first_literal(t).and_then(instance_word) {
                planes.insert(k);
            }
        }
        if t.ends_with("Dialect {") && !t.contains("struct") && !t.contains("enum") {
            in_table_row = true;
        }
        if in_table_row && t.starts_with("name:") {
            if let Some(d) = first_literal(t).and_then(instance_word) {
                dialects.insert(d);
            }
            in_table_row = false;
        }
        if impl_depth.is_none()
            && (t.starts_with("impl Dialect") || t.starts_with("impl Dialect {"))
        {
            impl_depth = Some(depth);
        }
        if impl_depth.is_some() && t.contains("=> \"") {
            if let Some(d) = t
                .split("=> ")
                .nth(1)
                .and_then(first_literal)
                .and_then(instance_word)
            {
                dialects.insert(d);
            }
        }
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if let Some(d) = impl_depth {
            if depth <= d && line.contains('}') {
                impl_depth = None;
            }
        }
    }
}

/// Every directory directly under `crates/` that holds a `Cargo.toml`, overlay included — a plant
/// that adds a crate adds it here, and a plant that deletes its manifest removes it.
fn crate_dirs_on_tree(cx: &Ctx) -> BTreeSet<String> {
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    if let Ok(rd) = std::fs::read_dir(cx.abs("crates")) {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str() {
                dirs.insert(name.to_string());
            }
        }
    }
    if let Some(ov) = cx.overlay() {
        for p in ov.paths() {
            let s = p.to_string_lossy().replace('\\', "/");
            if let Some(rest) = s.strip_prefix("crates/") {
                if let Some(dir) = rest.split('/').next() {
                    dirs.insert(dir.to_string());
                }
            }
        }
    }
    dirs.into_iter()
        .filter(|d| cx.exists(format!("crates/{d}/Cargo.toml")))
        .collect()
}

/// Derive the vocabulary from the plane-family roots the census resolved, the plane files already
/// walked from them, and the crate directories on the tree.
pub fn derive(cx: &Ctx, plane_roots: &[String], plane_files: &[SourceFile]) -> Vocab {
    let mut planes: BTreeSet<String> = BTreeSet::new();
    let mut transports: BTreeSet<String> = BTreeSet::new();
    let mut dialects: BTreeSet<String> = BTreeSet::new();
    let mut crate_dirs: BTreeSet<String> = BTreeSet::new();

    for root in plane_roots {
        let Some(dir) = dir_of_root(root) else {
            continue;
        };
        let (key, dialect) = keys_of_plane_dir(&dir);
        if let Some(k) = key {
            planes.insert(k);
        }
        if let Some(d) = dialect {
            dialects.insert(d);
        }
        crate_dirs.insert(dir);
    }

    for f in plane_files {
        let rel = f.rel_str();
        if is_test_path(&rel) {
            continue;
        }
        // Cheap pre-filter: only a file that can hold one of the two grammars is parsed.
        if f.text.contains("const KEY") || f.text.contains("Dialect") {
            declared_in(&f.text, &mut planes, &mut dialects);
        }
    }

    for dir in crate_dirs_on_tree(cx) {
        if let Some(t) = dir.strip_prefix("busbar-transport-") {
            if let Some(t) = instance_word(t) {
                transports.insert(t);
                crate_dirs.insert(dir);
            }
        }
    }

    Vocab::new(planes, transports, dialects, crate_dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plane_directory_names_its_key_and_a_four_segment_one_its_dialect() {
        assert_eq!(
            keys_of_plane_dir("busbar-plane-streaming"),
            (Some("streaming".into()), None)
        );
        assert_eq!(
            keys_of_plane_dir("busbar-plane-llm-mistral"),
            (Some("llm".into()), Some("mistral".into()))
        );
        assert_eq!(
            keys_of_plane_dir("busbar-voice-codec"),
            (Some("voice".into()), None)
        );
        assert_eq!(keys_of_plane_dir("busbar-mcp"), (Some("mcp".into()), None));
    }

    #[test]
    fn a_plane_declares_its_key_and_its_dialects_in_source() {
        let src = "impl PlaneMeta for P {\n    const KEY: &'static str = \"quux\";\n}\n\
                   pub const DIALECTS: &[Dialect] = &[\n    Dialect {\n        name: \"zed\",\n    },\n];\n\
                   impl Dialect {\n    pub const fn name(self) -> &'static str {\n        match self {\n\
                   \x20           Dialect::A => \"wave-live\",\n        }\n    }\n}\n\
                   fn other() { let _ = x => \"not-a-dialect\"; }\n";
        let mut planes = BTreeSet::new();
        let mut dialects = BTreeSet::new();
        declared_in(src, &mut planes, &mut dialects);
        assert_eq!(planes.into_iter().collect::<Vec<_>>(), vec!["quux"]);
        assert_eq!(
            dialects.into_iter().collect::<Vec<_>>(),
            vec!["wave-live", "zed"]
        );
    }

    #[test]
    fn every_spelling_is_derived_from_the_derived_words() {
        let v = Vocab::new(
            ["llm".to_string()].into(),
            ["quic".to_string()].into(),
            ["openai-realtime".to_string()].into(),
            [
                "busbar-plane-llm".to_string(),
                "busbar-transport-quic".to_string(),
            ]
            .into(),
        );
        assert!(v
            .crate_idents
            .contains(&"busbar_transport_quic".to_string()));
        assert!(v.dir_needles.contains(&"busbar-plane-llm/".to_string()));
        assert!(v.key_words.contains(&"transport_quic".to_string()));
        assert!(!v.key_words.contains(&"quic".to_string()));
        assert!(v.camel_prefixes.contains(&"Openai".to_string()));
        assert!(v.screaming_prefixes.contains(&"OpenAI".to_string()));
        assert!(v.screaming_prefixes.contains(&"LLM".to_string()));
    }

    #[test]
    fn a_colliding_key_is_quoted_and_a_new_key_is_bare() {
        let v = Vocab::new(
            ["decision".to_string(), "quux".to_string()].into(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        assert!(!v.key_words.contains(&"decision".to_string()));
        assert!(v.literal_words.contains(&"\"decisions\"".to_string()));
        assert!(v.key_words.contains(&"quux".to_string()));
        assert!(v.camel_prefixes.contains(&"Decision".to_string()));
    }
}

/// 1.6.0 ITEM 3's EXIT TEST: a NEW plane, a NEW transport and a NEW dialect, landed the way the
/// tree lands them (a crate, a declaration inside a plane crate) and named in a neutral crate, each
/// move their row from GREEN to RED. Before the vocabulary was derived all three moved nothing:
/// the scanner only knew the words typed into it.
///
/// The standing reds on the real tree are set aside first (their files blanked) so each row starts
/// GREEN — the same fixture-base rule the selftest uses, and for the same reason: a plant into a
/// row that is already red proves nothing.
#[cfg(test)]
mod new_instance_tests {
    use crate::ctx::{Ctx, Overlay};
    use crate::gates::plane_purity::PlanePurityGate;
    use crate::gates::Gate;
    use crate::ledger::{Status, Verdict};

    const KEY: &str = "plane-purity:key";
    const SYMBOL: &str = "plane-purity:symbol";
    const DIALECT: &str = "plane-purity:dialect";
    const PLANT: &str = "crates/busbar-kernel/src/planted_new_instance.rs";

    fn row<'v>(v: &'v Verdict, id: &str) -> (&'v Status, &'v str) {
        let r = v
            .rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no row {id}"));
        (&r.status, r.detail.as_str())
    }

    #[test]
    fn a_new_plane_transport_and_dialect_each_move_their_row_red() {
        let cx = Ctx::workspace().expect("workspace");
        let gate = PlanePurityGate;

        // Set aside every file a failing category row names.
        let mut base = Overlay::new();
        for r in &gate.run(&cx).rows {
            if r.status == Status::Pass || r.id.contains("roots") || r.id.contains("denominator") {
                continue;
            }
            for tok in r.detail.split_whitespace() {
                if let Some((file, line)) = tok.rsplit_once(':') {
                    if file.starts_with("crates/") && line.chars().all(|c| c.is_ascii_digit()) {
                        base.set(file, "");
                    }
                }
            }
        }
        let clean = gate.run(&cx.with_overlay(base.clone()));
        for id in [KEY, SYMBOL, DIALECT] {
            assert_eq!(
                row(&clean, id).0,
                &Status::Pass,
                "{id} must start GREEN: {}",
                row(&clean, id).1
            );
        }

        let mut planted = base;
        planted.set(
            "crates/busbar-plane-quux/Cargo.toml",
            "[package]\nname = \"busbar-plane-quux\"\nversion = \"0.0.0\"\n",
        );
        planted.set(
            "crates/busbar-plane-quux/src/lib.rs",
            "pub struct QuuxPlane;\n",
        );
        planted.set(
            "crates/busbar-transport-quic/Cargo.toml",
            "[package]\nname = \"busbar-transport-quic\"\nversion = \"0.0.0\"\n",
        );
        planted.set(
            "crates/busbar-plane-llm/src/planted_dialect.rs",
            "pub const PLANTED: Dialect = Dialect {\n    name: \"zephyrine\",\n};\n",
        );
        planted.set(
            PLANT,
            "fn a() { let plane = \"quux\"; }\n\
             use busbar_transport_quic::Dialer;\n\
             fn c() { let dialect = \"zephyrine\"; }\n",
        );
        let v = gate.run(&cx.with_overlay(planted));
        for (id, line) in [(KEY, 1), (SYMBOL, 2), (DIALECT, 3)] {
            let (status, detail) = row(&v, id);
            assert_eq!(
                status,
                &Status::Fail,
                "{id} did not see the NEW instance planted at line {line}: {detail}"
            );
            assert!(
                detail.contains(&format!("planted_new_instance.rs:{line}")),
                "{id} went red but not on the plant: {detail}"
            );
        }
    }
}
