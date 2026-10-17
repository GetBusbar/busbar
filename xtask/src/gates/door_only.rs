//! `cargo xtask gate door-only` — THE KERNEL REACHES A PLUGIN ONLY THROUGH ITS DOOR (M0 ABI-SPEC).
//!
//! > "compiled or dropped in is just a convenience for customer; NOTHING CHANGES about the plugin
//! > itself and how it works." — OWNER, 2026-09-27
//!
//! A compiled-in plugin is a row holding the same `door` a dropped-in one exports, and the kernel
//! calls both through the same table: it never holds a plugin crate's Rust types and never calls
//! its Rust functions. Over the WHOLE BINARY CLOSURE — every non-plugin workspace crate the `busbar`
//! binary links, the binary included, `busbar-contract` aside (its own gate is
//! `contract-stateless`):
//!
//! * **`plugin-path`** — a Rust path into a plugin crate (`busbar_plane_llm::…`) other than
//!   `<crate>::door`. The plugins are every one the binary links: workspace members AND the
//!   git-pinned crates ([`one_abi::members_with_pinned`]), each under its package's identifier and
//!   under every key a manifest renames it to. The composition root's generated table counts too
//!   (BUSBAR-1.6.0.md, gate `door-only`: "`linked_gen.rs` names only `<crate>::door`"): every
//!   path `linked_gen.rs` emits off an entry placeholder (`{e}::KEY`) and every entry module the
//!   root's manifest hands it (`[package.metadata.busbar.linked-entry]`, `linked-declares`).
//! * **`static-seam`** — a `static` whose type holds a function pointer, a `Fn` trait or a trait
//!   object: a seam another crate installs Rust code into, bypassing every door. The type is read
//!   through the crate's own declarations: an alias, struct, enum or union the crate declares
//!   whose definition holds code makes every type naming it hold code. Exactly two are exempt, the
//!   oauth2 and admin cleanliness seams the owner ruled core ([`EXEMPT_SEAMS`]); a third is a
//!   finding.
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/door-only.toml`.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;
use std::collections::BTreeSet;

pub const ROW_PATH: &str = "door-only:plugin-path";
pub const ROW_SEAM: &str = "door-only:static-seam";

/// The two static fn-pointer seams the owner ruled core (oauth2 and admin), and no others.
pub const EXEMPT_SEAMS: &[&str] = &[
    "crates/busbar-kernel/src/oauth_as/seam.rs",
    "crates/busbar-kernel/src/admin/seam.rs",
];

pub const SPEC: Spec = Spec {
    gate: "door-only",
    ledger: "qa/door-only.toml",
    rules: &[
        (
            ROW_PATH,
            "the binary closure names no plugin crate's Rust item but its door",
        ),
        (
            ROW_SEAM,
            "the binary closure installs no static fn-pointer seam (oauth2 and admin exempt)",
        ),
    ],
    header: "# door-only: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # The binary closure reaches a plugin only through its door, and installs no static\n\
             # fn-pointer seam but the two ruled core (oauth_as/seam.rs, admin/seam.rs). Each row\n\
             # is one the tree carries today. Strike a row in the commit that drains it; never\n\
             # add one. Regenerate with `cargo xtask gate door-only --write`.\n",
};

/// The name and declared type of a `static` item on this blanked line, if it declares one.
fn static_decl(counted: &str) -> Option<(String, String)> {
    let mut from = 0;
    while let Some(i) = counted[from..].find("static") {
        let at = from + i;
        from = at + 6;
        let before = counted[..at].chars().next_back();
        if before.is_some_and(|c| c == '\'' || c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        if !counted[at + 6..].starts_with(char::is_whitespace) {
            continue;
        }
        let rest = counted[at + 6..].trim_start();
        let rest = rest.strip_prefix("mut ").map_or(rest, str::trim_start);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].trim_start();
        if name.is_empty() || !after.starts_with(':') || after.starts_with("::") {
            continue;
        }
        let ty: String = after[1..]
            .chars()
            .take_while(|c| *c != '=' && *c != ';')
            .collect();
        return Some((name, ty));
    }
    None
}

/// Does a type hold code: a fn pointer, a `Fn` trait or a trait object, spelled out or through one
/// of `names` (the crate's declarations that hold code, [`code_names`])?
fn holds_code(ty: &str, names: &BTreeSet<String>) -> bool {
    ["fn", "Fn", "FnMut", "FnOnce", "dyn"]
        .iter()
        .any(|w| one_abi::has_word(ty, w))
        || names.iter().any(|n| one_abi::has_word(ty, n))
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every `type`, `struct`, `enum` and `union` a blanked source declares, as (name, definition):
/// an alias's right-hand side, an aggregate's generics, bounds and fields.
fn declarations(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for kw in ["type", "struct", "enum", "union"] {
        let mut from = 0;
        while let Some(i) = text[from..].find(kw) {
            let at = from + i;
            from = at + kw.len();
            if text[..at].chars().next_back().is_some_and(is_ident)
                || !text[from..].starts_with(char::is_whitespace)
            {
                continue;
            }
            let rest = text[from..].trim_start();
            let name: String = rest.chars().take_while(|c| is_ident(*c)).collect();
            if name.is_empty() {
                continue;
            }
            let body = &rest[name.len()..];
            // The definition runs to the `;` (an alias, a tuple or unit struct) or through the
            // braces (a struct, enum or union body) at bracket depth 0.
            let mut depth = 0i32;
            let mut end = body.len();
            for (j, c) in body.char_indices() {
                match c {
                    '(' | '[' => depth += 1,
                    ')' | ']' => depth -= 1,
                    ';' if depth == 0 => {
                        end = j;
                        break;
                    }
                    '{' if depth == 0 && kw != "type" => {
                        let mut braces = 0i32;
                        end = body.len();
                        for (k, d) in body[j..].char_indices() {
                            match d {
                                '{' => braces += 1,
                                '}' => {
                                    braces -= 1;
                                    if braces == 0 {
                                        end = j + k;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        break;
                    }
                    _ => {}
                }
            }
            out.push((name, body[..end].to_string()));
        }
    }
    out
}

/// THE CRATE'S DECLARATIONS THAT HOLD CODE (XF#14), to a fixpoint: an alias of a fn pointer, a
/// struct with a `Box<dyn …>` field, and every declaration naming one of those. A seam spelled
/// `OnceLock<Drive>` holds the fn pointer `Drive` aliases as surely as `OnceLock<fn(..)>` does.
/// Read within the crate: a name the crate does not declare is not resolved.
fn code_names(texts: &[String]) -> BTreeSet<String> {
    let decls: Vec<(String, String)> = texts.iter().flat_map(|t| declarations(t)).collect();
    let mut names = BTreeSet::new();
    loop {
        let fresh: Vec<String> = decls
            .iter()
            .filter(|(n, def)| !names.contains(n) && holds_code(def, &names))
            .map(|(n, _)| n.clone())
            .collect();
        if fresh.is_empty() {
            return names;
        }
        names.extend(fresh);
    }
}

/// The paths a line of `linked_gen.rs` emits off an entry placeholder (`{e}::KEY`, `{}::linked`,
/// `{e}::{item}`) whose next segment is not `door`, each as the placeholder text it was read as.
/// A placeholder that continues a path (`crate::root::{module}::…`) names no entry, and `{{` is a
/// literal brace.
fn emitted_not_door(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = code[from..].find("}::") {
        let close = from + i;
        from = close + 3;
        let Some(open) = code[..close].rfind('{') else {
            continue;
        };
        let inner = &code[open + 1..close];
        if inner.contains('}') || code[..open].ends_with('{') || code[..open].ends_with("::") {
            continue;
        }
        let after = &code[close + 3..];
        let tail: String = if after.starts_with('{') {
            after
                .chars()
                .take_while(|c| *c != '}')
                .chain(['}'])
                .collect()
        } else {
            after.chars().take_while(|c| is_ident(*c)).collect()
        };
        if tail != "door" {
            out.push(format!("{{{inner}}}::{tail}"));
        }
    }
    out
}

/// The tables of the root's manifest whose values `linked_gen.rs` emits as paths: each linked
/// row's entry module, and the item that holds its declared metadata.
const ENTRY_TABLES: &[&str] = &[
    "package.metadata.busbar.linked-entry",
    "package.metadata.busbar.linked-declares",
];

/// Each (line, path) an [`ENTRY_TABLES`] row of a manifest states.
fn entry_paths(manifest: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for (i, raw) in manifest.lines().enumerate() {
        let t = raw.trim();
        if let Some(h) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            inside = ENTRY_TABLES.contains(&h.trim());
            continue;
        }
        if !inside || t.starts_with('#') {
            continue;
        }
        if let Some((_, v)) = t.split_once('=') {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                out.push((i + 1, v.to_string()));
            }
        }
    }
    out
}

/// Does `path` name a plugin (an identifier in `needles`) at its head and go on to a segment
/// other than `door`?
fn path_around_door(path: &str, needles: &BTreeSet<String>) -> bool {
    path.split_once("::").is_some_and(|(head, rest)| {
        needles.contains(head)
            && rest
                .chars()
                .take_while(|c| is_ident(*c))
                .collect::<String>()
                != "door"
    })
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    // EVERY PLUGIN THE BINARY LINKS, the git-pinned ones included (XF#15): a plugin that left for
    // its own repo is still reached through the same Rust paths.
    let members = match one_abi::members_with_pinned(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let renames = match cx.read("Cargo.toml") {
        Ok(root) => crate::manifest::workspace_renames(&root),
        Err(e) => return (findings, vec![format!("Cargo.toml: {e}")]),
    };
    let closure = one_abi::binary_closure(&members);
    let plugin_idents: BTreeSet<String> = members
        .iter()
        .filter(|m| one_abi::is_plugin_crate(&m.name))
        .map(|m| m.name.replace('-', "_"))
        .collect();
    let scope: Vec<_> = members
        .iter()
        .filter(|m| {
            closure.contains(&m.name)
                && !one_abi::is_plugin_crate(&m.name)
                && m.name != "busbar-contract"
        })
        .collect();
    if scope.len() < 10 {
        errors.push(format!(
            "the binary closure read as {} crate(s); the scan has gone blind",
            scope.len()
        ));
    }
    for m in scope {
        // THE WORDS THIS CRATE'S SOURCE SPELLS A PLUGIN BY: every plugin's identifier, and the key
        // of each edge this manifest (or the workspace table it inherits) renames to a plugin.
        let mut needles = plugin_idents.clone();
        let mut decls = m.decls.clone();
        crate::manifest::resolve_inherited(&mut decls, &renames);
        for d in &decls {
            if one_abi::is_plugin_crate(&d.pkg) {
                needles.insert(d.key.replace('-', "_"));
            }
        }
        let files = match one_abi::rs_files(cx, &m.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let read: Vec<(String, Vec<crate::scan::ScopeLine>)> = files
            .iter()
            .map(|f| (f.rel_str(), one_abi::production(&f.text)))
            .collect();
        let names = code_names(
            &read
                .iter()
                .map(|(_, lines)| {
                    lines
                        .iter()
                        .map(|l| l.counted.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .collect::<Vec<_>>(),
        );
        // THE COMPOSITION ROOT'S GENERATED TABLE: its entry modules, read off the manifest.
        let linked_gen = format!("{}/src/linked_gen.rs", m.dir);
        if read.iter().any(|(rel, _)| *rel == linked_gen) {
            let manifest = m.manifest_rel();
            for (no, path) in entry_paths(&m.manifest) {
                if path_around_door(&path, &needles) {
                    findings.push(Finding::new(ROW_PATH, &manifest, path, no));
                }
            }
        }
        for (rel, lines) in &read {
            let rel = rel.clone();
            if rel == linked_gen {
                for sl in lines {
                    for item in emitted_not_door(&sl.code) {
                        findings.push(Finding::new(ROW_PATH, &rel, item, sl.no));
                    }
                }
            }
            // A multi-line static's type runs onto the next lines; read up to its `=` or `;`.
            for (idx, sl) in lines.iter().enumerate() {
                for p in &needles {
                    let needle = format!("{p}::");
                    let mut from = 0;
                    while let Some(i) = sl.counted[from..].find(&needle) {
                        let at = from + i;
                        from = at + needle.len();
                        let before = sl.counted[..at].chars().next_back();
                        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                            continue;
                        }
                        let tail: String = sl.counted[at + needle.len()..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        if tail != "door" {
                            findings.push(Finding::new(ROW_PATH, &rel, p.clone(), sl.no));
                        }
                    }
                }
                if EXEMPT_SEAMS.contains(&rel.as_str()) {
                    continue;
                }
                if let Some((name, mut ty)) = static_decl(&sl.counted) {
                    for more in lines.iter().skip(idx + 1).take(6) {
                        if ty.contains('=') || sl.counted.contains('=') || sl.counted.contains(';')
                        {
                            break;
                        }
                        ty.push(' ');
                        ty.push_str(
                            &more
                                .counted
                                .chars()
                                .take_while(|c| *c != '=' && *c != ';')
                                .collect::<String>(),
                        );
                        if more.counted.contains('=') || more.counted.contains(';') {
                            break;
                        }
                    }
                    if holds_code(&ty, &names) {
                        findings.push(Finding::new(ROW_SEAM, &rel, name, sl.no));
                    }
                }
            }
        }
    }
    (findings, errors)
}

pub struct DoorOnlyGate;

impl Gate for DoorOnlyGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        // THE PLUGIN THE PLANT NAMES IS ONE THE WORKSPACE HOLDS. The plant named
        // `busbar_transport_tcp` until that transport left for its own repo (66853bf6e1); the scan
        // only knows the plugin crates that are members, so a path into a departed one is no
        // finding and the red arm proved nothing. The plugins leave this tree one by one, so the
        // plant takes whichever plugin member the census holds first.
        let plugin: &'static str = match one_abi::members(cx).map(|ms| {
            ms.into_iter()
                .find(|m| one_abi::is_plugin_crate(&m.name))
                .map(|m| m.name.replace('-', "_"))
        }) {
            Ok(Some(ident)) => Box::leak(ident.into_boxed_str()),
            Ok(None) => {
                let mut report = Report::new();
                report.note_infra_failure(
                    "door-only selftest: the workspace holds no plugin crate to plant a path into",
                );
                return report;
            }
            Err(e) => {
                let mut report = Report::new();
                report.note_infra_failure(format!("door-only selftest: {e}"));
                return report;
            }
        };
        // A PINNED PLUGIN: one the binary links from its own repo and the workspace does not hold
        // (XF#15). The scan that read workspace members only never knew its name.
        let pinned: &'static str = match one_abi::pinned_plugin_members(cx).and_then(|ps| {
            let have: Vec<String> = one_abi::members(cx)?.into_iter().map(|m| m.name).collect();
            Ok(ps.into_iter().find(|p| !have.contains(&p.name)))
        }) {
            Ok(Some(p)) => Box::leak(p.name.into_boxed_str()),
            Ok(None) => {
                let mut report = Report::new();
                report.note_infra_failure(
                    "door-only selftest: the binary links no pinned plugin to plant a path into",
                );
                return report;
            }
            Err(e) => {
                let mut report = Report::new();
                report.note_infra_failure(format!("door-only selftest: {e}"));
                return report;
            }
        };
        let pinned_ident: &'static str = Box::leak(pinned.replace('-', "_").into_boxed_str());
        let file = "crates/busbar-kernel/src/planted_door_only.rs";
        let mut path = Overlay::new();
        path.set(
            file,
            format!("pub fn planted() {{ {plugin}::carrier::Planted::go(); }}\n"),
        );
        let mut pinned_path = Overlay::new();
        pinned_path.set(
            file,
            format!("pub fn planted() {{ {pinned_ident}::carrier::Planted::go(); }}\n"),
        );
        // A RENAMED EDGE: the manifest's key is the word the source spells, not the package.
        let kernel_manifest = "crates/busbar-kernel/Cargo.toml";
        let mut renamed = Overlay::new();
        renamed.set(
            kernel_manifest,
            cx.read(kernel_manifest).unwrap_or_default().replacen(
                "[dependencies]\n",
                &format!(
                    "[dependencies]\nplanted_door_alias = {{ package = \"{pinned}\", path = \"../{pinned}\" }}\n"
                ),
                1,
            ),
        );
        renamed.set(
            file,
            "pub fn planted() { planted_door_alias::carrier::Planted::go(); }\n",
        );
        // THE COMPOSITION ROOT'S GENERATED TABLE: a path linked_gen.rs emits into a plugin's entry
        // that is not its door (XF#15; BUSBAR-1.6.0.md: "`linked_gen.rs` names only
        // `<crate>::door`").
        let linked_gen = "crates/busbar/src/linked_gen.rs";
        let mut emitted = Overlay::new();
        emitted.set(
            linked_gen,
            format!(
                "{}\npub(crate) fn planted_emission(e: &str) -> String {{\n    format!(\"{{e}}::NOT_DOOR, \")\n}}\n",
                cx.read(linked_gen).unwrap_or_default()
            ),
        );
        // THE ENTRY MODULE linked_gen.rs joins every emitted item onto, read from the root's
        // manifest: an entry that is not the plugin's door reaches around it.
        let root_manifest = "crates/busbar/Cargo.toml";
        let mut entry = Overlay::new();
        entry.set(
            root_manifest,
            cx.read(root_manifest).unwrap_or_default().replacen(
                "[package.metadata.busbar.linked-entry]\n",
                &format!(
                    "[package.metadata.busbar.linked-entry]\nplanted-entry = \"{pinned_ident}::planted_not_door\"\n"
                ),
                1,
            ),
        );
        let mut seam = Overlay::new();
        seam.set(
            file,
            "pub static PLANTED_SEAM: std::sync::OnceLock<fn() -> u8> = std::sync::OnceLock::new();\n",
        );
        // A SEAM SPELLED THROUGH A TYPE ALIAS, and one held in a struct's field (XF#14): the
        // declared type names no `fn`, the alias and the field do.
        let mut alias_seam = Overlay::new();
        alias_seam.set(
            file,
            "pub type PlantedDrive = fn(u8) -> u8;\n\
             pub type PlantedTable = Vec<(&'static str, PlantedDrive)>;\n\
             pub static PLANTED_ALIAS_SEAM: std::sync::OnceLock<PlantedTable> =\n    \
             std::sync::OnceLock::new();\n",
        );
        let mut field_seam = Overlay::new();
        field_seam.set(
            file,
            "pub struct PlantedHolder {\n    pub name: &'static str,\n    pub run: Box<dyn Send + Sync>,\n}\n\
             pub static PLANTED_FIELD_SEAM: std::sync::OnceLock<PlantedHolder> = std::sync::OnceLock::new();\n",
        );
        let mut door = Overlay::new();
        door.set(
            file,
            format!(
                "pub const ROW: fn() = {plugin}::door;\npub const PINNED_ROW: fn() = {pinned_ident}::door;\n\
                 pub type PlantedCount = u64;\npub struct PlantedData {{ pub n: PlantedCount }}\n\
                 pub static NAME: &str = \"x\";\npub static DATA: std::sync::OnceLock<PlantedData> = std::sync::OnceLock::new();\n"
            ),
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_PATH,
                    "the kernel naming a plugin's Rust item is RED, naming the crate",
                    path,
                    vec![file, plugin],
                ),
                (
                    ROW_PATH,
                    "the kernel naming a PINNED plugin's Rust item is RED, naming the crate",
                    pinned_path,
                    vec![file, pinned_ident],
                ),
                (
                    ROW_PATH,
                    "the kernel naming a plugin through a renamed edge is RED, naming the key",
                    renamed,
                    vec![file, "planted_door_alias"],
                ),
                (
                    ROW_PATH,
                    "linked_gen.rs emitting a path into an entry other than its door is RED",
                    emitted,
                    vec![linked_gen, "NOT_DOOR"],
                ),
                (
                    ROW_PATH,
                    "a linked entry module other than the plugin's door is RED, naming it",
                    entry,
                    vec![root_manifest, "planted_not_door"],
                ),
                (
                    ROW_SEAM,
                    "a static fn-pointer seam in the kernel is RED, naming it",
                    seam,
                    vec![file, "PLANTED_SEAM"],
                ),
                (
                    ROW_SEAM,
                    "a static seam typed through an alias of a fn pointer is RED, naming it",
                    alias_seam,
                    vec![file, "PLANTED_ALIAS_SEAM"],
                ),
                (
                    ROW_SEAM,
                    "a static seam typed as a struct whose field holds a trait object is RED",
                    field_seam,
                    vec![file, "PLANTED_FIELD_SEAM"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a row holding <crate>::door, and a static holding data, are not findings",
            &[ROW_PATH, ROW_SEAM],
            door,
        ));
        report
    }
}
