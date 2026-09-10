//! THE ONE CARGO MANIFEST DEPENDENCY READER.
//!
//! > "core is core, plugins are plugins, transport, everything. HAS TO BE PERFECT AND CLEAN." —
//! > owner, 2026-09-08
//!
//! Two gates read the kind-to-kind edges out of `Cargo.toml`, and until this module they read them
//! with two copies of the same four-line loop: `kind_isolation::deps_of` and
//! `construction::tree::read_cargo_deps_text`. Both looked for the literal section name
//! `dependencies`, both recorded the manifest KEY, and both were blind in exactly the same five
//! places — which a red-team pass proved by planting a plane inside a transport five different
//! ways and watching every gate stay green:
//!
//! 1. `[build-dependencies]` — a section name that never equals `dependencies`. The plane is linked
//!    into the build script and the edge is as real as any other.
//! 2. `[target.'cfg(unix)'.dependencies]` — likewise, and `cfg(unix)` is true on every runner this
//!    tree builds on, so the edge is not even conditional.
//! 3. `[dev-dependencies]` — a REAL edge of the `cargo test` build graph. It is not a SHIPPED edge,
//!    which is why it is [`DepTable::Dev`] and scored on its own row rather than folded into the
//!    shipped graph, but "not shipped" is not "not there".
//! 4. `foo = { package = "busbar-plane-llm", … }` — the key is `foo`, the PACKAGE is a plane, and a
//!    reader that records the key sees a crate named `foo` that resolves to no kind at all.
//! 5. `foo = { workspace = true }` where `[workspace.dependencies] foo = { package = "…" }` renames
//!    it — the rename is one file away, so a member manifest can spell an edge in a word that
//!    appears nowhere near the crate it reaches.
//!
//! So: every dependency table, in every spelling Cargo accepts, with the PACKAGE resolved through
//! both rename forms. The reader is deliberately line-based rather than a TOML parse, for the
//! reason the callers already had one: a PLANTED manifest in a gate self-test must be read on
//! exactly the same terms as a real one, and the planted text is the whole input.

use std::collections::BTreeMap;

/// Which of Cargo's three dependency tables a declaration sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepTable {
    /// `[dependencies]`, and its per-target form.
    Normal,
    /// `[dev-dependencies]`, and its per-target form.
    Dev,
    /// `[build-dependencies]`, and its per-target form.
    Build,
}

impl DepTable {
    /// Is this edge in the SHIPPED build graph? A build-dependency is: the build script runs, and
    /// what it links is compiled into the artifact's making. A dev-dependency is not.
    pub fn shipped(self) -> bool {
        !matches!(self, DepTable::Dev)
    }

    fn of_word(word: &str) -> Option<DepTable> {
        match word {
            "dependencies" => Some(DepTable::Normal),
            "dev-dependencies" => Some(DepTable::Dev),
            "build-dependencies" => Some(DepTable::Build),
            _ => None,
        }
    }
}

/// One dependency declaration, as one manifest states it once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepDecl {
    /// THE PACKAGE THE EDGE REACHES: `package = "…"` where the declaration renames it, the key
    /// otherwise. This is the name every kind rule resolves, because it is the crate that is
    /// actually compiled in.
    pub pkg: String,
    /// The key the manifest wrote. Differs from [`DepDecl::pkg`] exactly when the edge is renamed,
    /// and a finding prints both so the reader can find the line.
    pub key: String,
    pub table: DepTable,
    /// The section header, verbatim — `dependencies`, `build-dependencies`,
    /// `target.cfg(unix).dependencies` — so a finding names the table it was read from.
    pub section: String,
    /// The rename is stated by this manifest (`package = …`) rather than inherited.
    pub renamed_here: bool,
    /// The declaration inherits from `[workspace.dependencies]`.
    pub inherits: bool,
    /// The `path = "…"` this declaration states, verbatim and unresolved, when it states one.
    ///
    /// A PATH DEPENDENCY IS A DIFFERENT FACT FROM A REGISTRY ONE, and the rule that needed this
    /// found out the hard way: `xtask/fixtures/dirty-dep-hyphenated/hyper-util/Cargo.toml` declares
    /// a package called `hyper-util`, which is also the name of a real crates.io crate five product
    /// crates depend on. Matching an off-tree manifest by PACKAGE NAME reported all five. What
    /// makes a fixture reachable is the path, so the path is what a rule about reaching one reads.
    pub path: Option<String>,
}

impl DepDecl {
    /// ``busbar-plane-llm (as `wire`) [build-dependencies]`` — the spelling every finding uses.
    pub fn cite(&self) -> String {
        let mut s = self.pkg.clone();
        if self.key != self.pkg {
            s.push_str(&format!(" (as `{}`)", self.key));
        }
        s.push_str(&format!(" [{}]", self.section));
        s
    }
}

/// Split a section header into its segments, honouring the quoting `target.'cfg(unix)'.dependencies`
/// needs. A dot inside quotes is part of the segment, never a separator.
fn header_segments(header: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for ch in header.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '.' => out.push(std::mem::take(&mut cur)),
                _ => cur.push(ch),
            },
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).collect()
}

/// The `package = "…"` an inline table states, if it states one.
fn inline_package(value: &str) -> Option<String> {
    let v = value.trim();
    if !v.starts_with('{') {
        return None;
    }
    scalar_string(v, "package")
}

/// `key = "value"` anywhere in `hay`, at a boundary, as a bare string.
fn scalar_string(hay: &str, key: &str) -> Option<String> {
    let mut rest = hay;
    while let Some(at) = rest.find(key) {
        let before = rest[..at].chars().next_back();
        let after = rest[at + key.len()..].trim_start();
        let boundary = before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if boundary {
            if let Some(v) = after.strip_prefix('=') {
                let v = v.trim_start();
                let q = v.chars().next()?;
                if q == '"' || q == '\'' {
                    let end = v[1..].find(q)? + 1;
                    return Some(v[1..end].to_string());
                }
                return None;
            }
        }
        rest = &rest[at + key.len()..];
    }
    None
}

/// `key = true` anywhere in `hay`, at a boundary.
fn scalar_true(hay: &str, key: &str) -> bool {
    let mut rest = hay;
    while let Some(at) = rest.find(key) {
        let before = rest[..at].chars().next_back();
        let boundary = before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if boundary {
            if let Some(v) = rest[at + key.len()..].trim_start().strip_prefix('=') {
                return v.trim_start().starts_with("true");
            }
        }
        rest = &rest[at + key.len()..];
    }
    false
}

/// The left-hand side of a `key = value` line, unquoted, or `None` when the line is not one.
fn split_kv(line: &str) -> Option<(String, &str)> {
    let (k, v) = line.split_once('=')?;
    let k = k.trim().trim_matches(['"', '\'']).trim();
    if k.is_empty() || k.contains(' ') || k.contains('[') {
        return None;
    }
    Some((k.to_string(), v))
}

/// ONE LINE WITH ITS BOM AND ITS TRAILING `#` COMMENT REMOVED, because Cargo removes both and a
/// reader that does not is a reader whose answer differs from the compiler's.
///
/// The comment is what a red team used: `[target.'cfg(all())'.dependencies] # extra` does not end
/// in `]`, so the header test failed, so the line was not a header — and the parser therefore STAYED
/// IN THE PREVIOUS SECTION and attributed every dependency under it to that one. A plane linked
/// into a wire was scored as a dev-dependency, on the strength of a comment.
///
/// Naive on quoting on purpose: a `#` inside a quoted `target.'cfg(…)'` key would be cut here. No
/// cfg expression Cargo accepts contains one, and the alternative — a reader that tracks quotes to
/// decide whether a comment is a comment — is a second parser to be wrong in a second way. Anything
/// this cut makes unreadable is reported by [`unreadable`] rather than skipped.
fn strip_comment(raw: &str) -> &str {
    let t = raw.trim_start_matches('\u{feff}').trim();
    match t.find('#') {
        Some(at) => t[..at].trim(),
        None => t,
    }
}

/// THE LINES THIS READER COULD NOT PARSE AND WOULD OTHERWISE HAVE SKIPPED.
///
/// A dependency table is the one thing in a manifest whose absence from this reader's answer is
/// indistinguishable from its absence from the build. So every line that LOOKS like a table header
/// and does not resolve to one, and every top-level dotted key whose first segment is a dependency
/// word (`target."cfg(unix)".dependencies.wire = { … }` sits under no `[section]` at all, and the
/// red team's version of it was caught only by the `Cargo.lock` cross-check), is handed back to the
/// caller to REPORT. A section header this reader could not parse is a refusal, not a skip.
pub fn unreadable(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let t = strip_comment(raw);
        if t.is_empty() {
            continue;
        }
        if t.starts_with('[') {
            if !t.ends_with(']') {
                out.push(format!(
                    "`{}` opens with `[` and does not close: this reader cannot tell which table \
                     the lines under it belong to, and it will not guess",
                    raw.trim()
                ));
            }
            continue;
        }
        let Some((key, _)) = t.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.contains('.') {
            continue;
        }
        let segs = header_segments(key);
        if segs.len() < 2 || !segs.iter().any(|s| DepTable::of_word(s).is_some()) {
            continue;
        }
        out.push(format!(
            "`{}` is a DOTTED KEY naming a dependency table from the top level of the file. It is \
             a real edge Cargo links and it sits under no `[section]` this reader recognises: write \
             it as a `[…dependencies]` table",
            raw.trim()
        ));
    }
    out
}

/// EVERY DEPENDENCY DECLARATION IN ONE MANIFEST, in every table and every spelling.
///
/// `[workspace.dependencies]` is NOT one of them: that table is the workspace's version pin list,
/// not a member's edges, and [`workspace_renames`] reads it for what it is.
pub fn dep_decls(text: &str) -> Vec<DepDecl> {
    let mut out: Vec<DepDecl> = Vec::new();
    // The section we are in: its header and its table; and, when the header IS one dependency's
    // own sub-table, the index in `out` of the declaration whose keys follow.
    let mut section: Option<(String, DepTable)> = None;
    let mut subtable: Option<usize> = None;

    for raw in text.lines() {
        let t = strip_comment(raw);
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let header = header.trim().trim_start_matches('[').trim_end_matches(']');
            section = None;
            subtable = None;
            let segs = header_segments(header);
            // The workspace's own pin table is not an edge of any member.
            if segs.first().map(String::as_str) == Some("workspace") {
                continue;
            }
            let Some(at) = segs.iter().position(|s| DepTable::of_word(s).is_some()) else {
                continue;
            };
            let table = DepTable::of_word(&segs[at]).expect("position found it");
            let head = segs[..=at].join(".");
            if at + 1 == segs.len() {
                section = Some((head, table));
            } else if at + 2 == segs.len() {
                // `[dependencies.foo]` — one declaration, whose keys follow.
                out.push(DepDecl {
                    pkg: segs[at + 1].clone(),
                    key: segs[at + 1].clone(),
                    table,
                    section: head,
                    renamed_here: false,
                    inherits: false,
                    path: None,
                });
                subtable = Some(out.len() - 1);
            }
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(i) = subtable {
            if let Some(p) = scalar_string(t, "package") {
                out[i].pkg = p;
                out[i].renamed_here = true;
            }
            if scalar_true(t, "workspace") {
                out[i].inherits = true;
            }
            if let Some(p) = scalar_string(t, "path") {
                out[i].path = Some(p);
            }
            continue;
        }
        let Some((section_name, table)) = section.clone() else {
            continue;
        };
        let Some((key, value)) = split_kv(t) else {
            continue;
        };
        let renamed = inline_package(value);
        out.push(DepDecl {
            pkg: renamed.clone().unwrap_or_else(|| key.clone()),
            key,
            table,
            section: section_name,
            renamed_here: renamed.is_some(),
            inherits: scalar_true(value, "workspace"),
            path: scalar_string(value, "path"),
        });
    }
    out
}

/// The renames `[workspace.dependencies]` states — `key -> package` — so a member that inherits
/// reaches the package the workspace named, not the word the member spelled.
pub fn workspace_renames(root_manifest: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut inside = false;
    let mut sub: Option<String> = None;
    for raw in root_manifest.lines() {
        let t = raw.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let segs = header_segments(header.trim());
            inside = segs.len() == 2 && segs[0] == "workspace" && segs[1] == "dependencies";
            sub = (segs.len() == 3 && segs[0] == "workspace" && segs[1] == "dependencies")
                .then(|| segs[2].clone());
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(key) = &sub {
            if let Some(p) = scalar_string(t, "package") {
                out.insert(key.clone(), p);
            }
            continue;
        }
        if !inside {
            continue;
        }
        let Some((key, value)) = split_kv(t) else {
            continue;
        };
        if let Some(p) = inline_package(value) {
            out.insert(key, p);
        }
    }
    out
}

/// The `[workspace] members = [ … ]` list, in declaration order.
///
/// A crate ON DISK and off this list is a crate `--workspace` never compiles, never tests, never
/// clippies and never denies — and a path dependency reaches it anyway, so it ships. That is the
/// hole `unmembered` is named for.
pub fn workspace_members(root_manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut collecting = false;
    for raw in root_manifest.lines() {
        let t = raw.trim();
        if let Some(header) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if !collecting {
                inside = header_segments(header.trim()) == ["workspace"];
                continue;
            }
        }
        if !inside {
            continue;
        }
        if !collecting {
            let Some((k, v)) = split_kv(t) else { continue };
            if k != "members" {
                continue;
            }
            collecting = true;
            for part in v.split(['[', ',']) {
                push_member(part, &mut out);
            }
            if v.contains(']') {
                collecting = false;
                inside = false;
            }
            continue;
        }
        for part in t.split(',') {
            push_member(part, &mut out);
        }
        if t.contains(']') {
            collecting = false;
            inside = false;
        }
    }
    out
}

fn push_member(part: &str, out: &mut Vec<String>) {
    let p = part.trim().trim_end_matches(']').trim();
    let p = p.trim_matches(['"', '\'']).trim();
    if !p.is_empty() && !p.starts_with('#') {
        out.push(p.to_string());
    }
}

/// Resolve every INHERITED declaration through the workspace's own renames. A declaration that
/// states its own `package =` is already final: the member's word wins over the workspace's.
pub fn resolve_inherited(decls: &mut [DepDecl], renames: &BTreeMap<String, String>) {
    for d in decls.iter_mut() {
        if d.renamed_here {
            continue;
        }
        if let Some(real) = renames.get(&d.key) {
            d.pkg = real.clone();
        }
    }
}

/// The SHIPPED dependency package names of one manifest, deduplicated — the shape the older
/// callers asked for, answered by the reader that sees every table.
pub fn shipped_dep_names(text: &str) -> Vec<String> {
    let mut out: Vec<String> = dep_decls(text)
        .into_iter()
        .filter(|d| d.table.shipped())
        .map(|d| d.pkg)
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = r#"
[package]
name = "busbar-transport-tcp"

[dependencies]
busbar-contract-transport = { workspace = true }
wire = { package = "busbar-plane-llm", path = "../busbar-plane-llm" }

[dependencies.explicit]
package = "busbar-plane-mcp"
path = "../busbar-plane-mcp"

[build-dependencies]
busbar-plane-a2a = { workspace = true }

[target.'cfg(unix)'.dependencies]
busbar-plane-streams = { workspace = true }

[dev-dependencies]
busbar-testkit = { workspace = true }

[features]
llm-serve = []
"#;

    #[test]
    fn every_table_and_every_rename_is_read() {
        let d = dep_decls(M);
        let shipped: Vec<&str> = d
            .iter()
            .filter(|x| x.table.shipped())
            .map(|x| x.pkg.as_str())
            .collect();
        assert!(shipped.contains(&"busbar-plane-llm"), "{shipped:?}");
        assert!(shipped.contains(&"busbar-plane-mcp"), "{shipped:?}");
        assert!(shipped.contains(&"busbar-plane-a2a"), "{shipped:?}");
        assert!(shipped.contains(&"busbar-plane-streams"), "{shipped:?}");
        // A feature name is not a dependency, and neither is a `[package]` key.
        assert!(!shipped.contains(&"llm-serve"), "{shipped:?}");
        assert!(!shipped.contains(&"name"), "{shipped:?}");
        let dev: Vec<&str> = d
            .iter()
            .filter(|x| !x.table.shipped())
            .map(|x| x.pkg.as_str())
            .collect();
        assert_eq!(dev, vec!["busbar-testkit"]);
    }

    #[test]
    fn the_section_a_declaration_came_from_is_kept() {
        let d = dep_decls(M);
        let target = d
            .iter()
            .find(|x| x.pkg == "busbar-plane-streams")
            .expect("the per-target dependency is read");
        assert_eq!(target.section, "target.cfg(unix).dependencies");
        assert_eq!(
            d.iter()
                .find(|x| x.pkg == "busbar-plane-a2a")
                .map(|x| x.section.as_str()),
            Some("build-dependencies")
        );
    }

    #[test]
    fn a_rename_cites_both_names() {
        let d = dep_decls(M);
        let renamed = d
            .iter()
            .find(|x| x.pkg == "busbar-plane-llm")
            .expect("the renamed dependency is read");
        assert_eq!(renamed.key, "wire");
        assert!(renamed.renamed_here);
        assert!(renamed.cite().contains("as `wire`"));
    }

    #[test]
    fn a_workspace_rename_reaches_the_package_it_names() {
        let root =
            "[workspace.dependencies]\nwire = { package = \"busbar-plane-llm\", path = \"x\" }\n";
        let mut d = dep_decls("[dependencies]\nwire = { workspace = true }\n");
        assert_eq!(d[0].pkg, "wire");
        assert!(d[0].inherits);
        resolve_inherited(&mut d, &workspace_renames(root));
        assert_eq!(d[0].pkg, "busbar-plane-llm");
    }

    #[test]
    fn the_member_list_is_read_in_both_layouts() {
        assert_eq!(
            workspace_members("[workspace]\nresolver = \"2\"\nmembers = [\n  \"crates/a\",\n  \"xtask\",\n]\n\n[workspace.dependencies]\nserde = \"1\"\n"),
            vec!["crates/a", "xtask"]
        );
        assert_eq!(
            workspace_members("[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n"),
            vec!["crates/a", "crates/b"]
        );
    }

    /// The workspace's own pin table is not an edge OF the workspace root.
    #[test]
    fn the_workspace_pin_table_is_not_a_dependency_section() {
        let d = dep_decls("[workspace.dependencies]\nserde = \"1\"\n");
        assert!(d.is_empty(), "{d:?}");
    }
}
