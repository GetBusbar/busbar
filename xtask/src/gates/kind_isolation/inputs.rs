//! `kind-isolation:build-inputs` — THE WAYS INTO A CRATE THAT ARE NOT A DEPENDENCY.
//!
//! > "it's not just planes, it's everything. core is core, plugins are plugins, transport,
//! > everything. HAS TO BE PERFECT AND CLEAN." — owner, 2026-09-08
//!
//! Every other row here reads a `[dependencies]` table or a `use` line. A red-team pass carried a
//! whole plane into a transport five times WITHOUT either, and every gate in the tree stayed green:
//!
//! * `#[path = "../../busbar-plane-llm/src/meta.rs"] pub mod smuggled;` — the transport compiles the
//!   plane's source into itself. The vocabulary rule could not see it because the path is a STRING
//!   LITERAL and `blank_literals` runs first, so this row reads the attribute off the RAW line,
//!   before anything is blanked.
//! * `[lib] path = "../busbar-plane-llm/src/lib.rs"` — the transport IS the plane at link time, with
//!   zero dependencies and zero source of its own.
//! * `include_str!("../busbar-plane-mcp/src/lib.rs")` in a `build.rs` — the plane's source is read
//!   at build time by a script nothing scans.
//! * a `Cargo.lock` naming an edge no manifest has. Nothing in the tree read the lock at all, so
//!   the file that says what actually gets COMPILED was never compared with the files that say what
//!   was asked for.
//! * `[features] llm-serve = []` in a transport — a feature name is a name, and it is the one part
//!   of a manifest no rule was reading. On the composition root this is BY DESIGN (`root-llm`,
//!   `root-voice-serve`), and that exemption is now a written rule with a green case rather than
//!   silence — it was equally silent on a transport.
//!
//! And one more, from the same pass: `plugins.yaml` files an out-of-tree plugin under a `kind:`,
//! and nothing checked that the kind is the one the crate's own name resolves to. A registry that
//! can say `store-mysql` is an `auth` plugin is a registry the loader will believe.
//!
//! WHAT "OUTSIDE" MEANS. Every path check resolves the path against the file that wrote it and asks
//! one question: does it leave the crate's own directory? A crate reaches another crate through
//! Cargo, where the edge is written down and scored — never by reading its files.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, WalkSpec};
use crate::ledger::Row;

use super::{banned_for, owning_dir, CrateInfo, MAKE_A_NEW_KIND, MIN_SOURCES};

pub const ROW_INPUTS: &str = "kind-isolation:build-inputs";

/// The registry of out-of-tree plugins, and the one file that files them under a kind.
const PLUGIN_REGISTRY: &str = "plugins.yaml";

/// THE REGISTRY'S KIND WORDS, each mapped onto the kind it names in this gate's table.
///
/// `plugins.yaml` says in its own header that a plugin is `store | auth | hook | secret` — the four
/// kinds the C ABI selects on — and it says `hook` where the table here says `hooks`. That is a
/// THIRD kind vocabulary beside this gate's and `qa/construction.toml`'s, and the way three
/// vocabularies stay one is that each is mapped, once, in the file that reads it. A word here that
/// maps onto nothing is that vocabulary starting to drift.
const REGISTRY_KIND_KEYS: &[(&str, &str)] = &[
    ("store", "store"),
    ("auth", "auth"),
    ("hook", "hooks"),
    ("secret", "secret"),
];

/// THE COMPOSITION ROOT'S FEATURES NAME PLANES BY DESIGN, and this is where that is written down.
///
/// `crates/busbar` carries `root-llm`, `root-mcp`, `root-voice-serve`: the root is the one place
/// the tree assembles a plane, so a feature that switches one on is the root doing its job. Every
/// other kind's features are its own vocabulary and may not name another kind's.
///
/// It is an EXEMPTION WITH A NUMBER ATTACHED, not a silence: `:matrix` counts every one of those
/// feature names against `[cell.busbar.plane]`, at an exact ceiling, so the root's plane words are
/// measured here as debt even while they are legal there.
const ROOT_KIND: &str = "root";

/// Normalise `base/rel` — the path a file at `base` writes — resolving `.` and `..`.
fn resolve(base: &str, rel: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in base.split('/').chain(rel.split('/')) {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// The directory part of a relative file path.
fn dir_of(rel: &str) -> String {
    rel.rsplit_once('/')
        .map_or(String::new(), |(d, _)| d.to_string())
}

/// Is `target` inside `dir`?
fn inside(dir: &str, target: &str) -> bool {
    target == dir || target.starts_with(&format!("{dir}/"))
}

/// The crate `target` belongs to, when that is ANOTHER crate AND `me` declares no dependency on it.
///
/// TWO NARROWINGS, and both are the rule rather than a softening of it.
///
/// A path that lands outside every crate is not this row's subject: a test that pins a table
/// against `qa/method-inventory.json`, or a doc example read out of `docs/`, is a crate reading a
/// repository ARTEFACT, not a crate reading another crate. There is no kind on the other end of it.
///
/// And a path into a crate this one already DEPENDS on is an edge that is written down: the
/// dependency ledger carries it, at its exact count, with its verdict — so `crates/busbar`'s tests
/// pinning a table against `busbar-mcp`'s own source are covered by the `root -> legacy` row that
/// already exists, not silent. What this row is for is the reach with NO edge at all: the transport
/// that compiles a plane's file into itself and declares nothing.
fn foreign_owner<'a>(
    by_dir: &BTreeMap<&str, &'a CrateInfo>,
    me: &CrateInfo,
    target: &str,
) -> Option<&'a CrateInfo> {
    if inside(&me.dir, target) {
        return None;
    }
    let theirs = by_dir.values().copied().find(|o| inside(&o.dir, target))?;
    let declared = me
        .deps
        .iter()
        .chain(me.dev_deps.iter())
        .any(|d| d.pkg == theirs.name);
    (!declared).then_some(theirs)
}

/// Every `key = "value"` string an attribute or macro call writes on one line, for the keys this
/// row reads. The line is RAW — never blanked — because the whole point is that these paths ARE
/// string literals and a rule that blanks them first is a rule that cannot see them.
fn quoted_after(line: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(marker) {
        let after = &rest[at + marker.len()..];
        if let Some(open) = after.find('"') {
            if let Some(close) = after[open + 1..].find('"') {
                out.push(after[open + 1..open + 1 + close].to_string());
            }
        }
        rest = after;
    }
    out
}

/// The `[lib]` / `[[bin]]` / `[[example]]` / `[[bench]]` / `[[test]]` target paths a manifest states.
fn target_paths(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(head) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = head.trim_matches('[').trim_matches(']').trim().to_string();
            continue;
        }
        if !matches!(
            section.as_str(),
            "lib" | "bin" | "example" | "bench" | "test"
        ) {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        if k.trim() == "path" {
            out.push((section.clone(), v.trim().trim_matches('"').to_string()));
        }
    }
    out
}

/// The `[features]` key names a manifest declares.
fn feature_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside_features = false;
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(head) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            inside_features = head.trim() == "features";
            continue;
        }
        if !inside_features || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some((k, _)) = t.split_once('=') {
            let k = k.trim().trim_matches('"');
            if !k.is_empty() {
                out.push(k.to_string());
            }
        }
    }
    out
}

/// One `[[package]]` of `Cargo.lock`: its name and the packages it names.
fn lock_packages(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut deps: BTreeSet<String> = BTreeSet::new();
    let mut in_deps = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t == "[[package]]" {
            if let Some(n) = name.take() {
                out.insert(n, std::mem::take(&mut deps));
            }
            deps.clear();
            in_deps = false;
            continue;
        }
        if t.starts_with('[') {
            in_deps = false;
            continue;
        }
        if in_deps {
            if t.starts_with(']') {
                in_deps = false;
                continue;
            }
            let d = t.trim_end_matches(',').trim().trim_matches('"');
            // `"name version (source)"` — the lock spells a disambiguated entry that way.
            if let Some(first) = d.split_whitespace().next() {
                if !first.is_empty() {
                    deps.insert(first.to_string());
                }
            }
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            match k.trim() {
                "name" => name = Some(v.trim().trim_matches('"').to_string()),
                "dependencies" if v.trim() == "[" => in_deps = true,
                _ => {}
            }
        }
    }
    if let Some(n) = name {
        out.insert(n, deps);
    }
    out
}

/// One `plugins.yaml` entry, as this row reads it: which kind it is filed under, and which crate.
fn registry_entries(text: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    let mut kind: Option<String> = None;
    let mut krate: Option<String> = None;
    let mut at = 0usize;
    let flush = |at: usize,
                 kind: &mut Option<String>,
                 krate: &mut Option<String>,
                 out: &mut Vec<(usize, String, String)>| {
        if let (Some(k), Some(c)) = (kind.take(), krate.take()) {
            out.push((at, k, c));
        }
        *kind = None;
        *krate = None;
    };
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(rest) = t.strip_prefix("- ") {
            flush(at, &mut kind, &mut krate, &mut out);
            at = i + 1;
            if let Some((k, v)) = rest.split_once(':') {
                match k.trim() {
                    "kind" => kind = Some(v.trim().to_string()),
                    "crate" => krate = Some(v.trim().to_string()),
                    _ => {}
                }
            }
            continue;
        }
        let Some((k, v)) = t.split_once(':') else {
            continue;
        };
        match k.trim() {
            "kind" => kind = Some(v.trim().to_string()),
            "crate" => krate = Some(v.trim().to_string()),
            _ => {}
        }
    }
    flush(at, &mut kind, &mut krate, &mut out);
    out
}

pub fn rule_inputs(cx: &Ctx, crates: &[CrateInfo], planes: &BTreeSet<String>) -> Row {
    let mut offenders: Vec<String> = Vec::new();
    let by_dir: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.dir.as_str(), c)).collect();
    let by_name: BTreeMap<&str, &CrateInfo> = crates.iter().map(|c| (c.name.as_str(), c)).collect();

    // ── 1 and 3. THE PATHS A SOURCE FILE WRITES ──────────────────────────────────────────────────
    let files = match cx.walk(&WalkSpec::new(["crates"]).ext("rs").min_files(MIN_SOURCES)) {
        Ok(f) => f,
        Err(e) => {
            return Row::fail(
                ROW_INPUTS,
                "the source walk for the build-input rule could not run",
                format!(
                    "{e} — a scan of no files finds no smuggled path, which is indistinguishable \
                     from a tree that has none."
                ),
            )
        }
    };
    let mut scanned = 0usize;
    for f in &files {
        let rel = f.rel_str();
        let Some(dir) = owning_dir(&rel) else {
            continue;
        };
        let Some(me) = by_dir.get(dir.as_str()) else {
            continue;
        };
        scanned += 1;
        let here = dir_of(&rel);
        for (line_no, raw) in f.text.lines().enumerate() {
            // THE ATTRIBUTE IS READ OFF THE RAW LINE. `blank_literals` would erase the very string
            // this rule is about — which is exactly why `#[path]` was invisible to `:vocab`.
            for (marker, label, what) in [
                ("#[path", "path-include", "a module compiled from"),
                (
                    "include_str!",
                    "build-script-reach",
                    "a file read at build time from",
                ),
                (
                    "include_bytes!",
                    "build-script-reach",
                    "bytes read at build time from",
                ),
            ] {
                for p in quoted_after(raw, marker) {
                    let target = resolve(&here, &p);
                    let Some(theirs) = foreign_owner(&by_dir, me, &target) else {
                        continue;
                    };
                    offenders.push(format!(
                        "{label}\t{rel}:{}\t{} is {what} `{target}` — {}'s own source, and {} \
                         declares no dependency on it in any table. A crate reaches another crate \
                         through Cargo, where the edge is written down and scored; reading its \
                         files compiles it in with no edge to score. {MAKE_A_NEW_KIND}",
                        line_no + 1,
                        me.name,
                        theirs.name,
                        me.name
                    ));
                }
            }
        }
    }
    if scanned == 0 {
        return Row::fail(
            ROW_INPUTS,
            "no crate source reached the build-input rule",
            "0 file(s) were scanned for smuggled paths, and zero files smuggle nothing."
                .to_string(),
        );
    }

    // ── 2 and 5. THE PATHS AND THE NAMES A MANIFEST WRITES ───────────────────────────────────────
    for c in crates {
        let Ok(text) = cx.read(&c.manifest) else {
            continue;
        };
        for (target, p) in target_paths(&text) {
            let resolved = resolve(&c.dir, &p);
            // A TARGET PATH IS NEVER ANOTHER CRATE'S FILE, dependency or not: `[lib] path` does not
            // LINK the other crate, it COMPILES its source as this crate's own body. There is no
            // edge that could make that a reach rather than an identity.
            if inside(&c.dir, &resolved) {
                continue;
            }
            let theirs = by_dir
                .values()
                .find(|o| inside(&o.dir, &resolved))
                .map(|o| format!("{} (kind {})", o.name, o.kind.unwrap_or("?")))
                .unwrap_or_else(|| "a path outside every crate in the census".to_string());
            offenders.push(format!(
                "foreign-lib-path\t{}\t`[{target}] path = \"{p}\"` compiles `{resolved}` as {}'s \
                 own target: {theirs}. At link time this crate IS that one, with no dependency \
                 edge to score and no source of its own. {MAKE_A_NEW_KIND}",
                c.manifest, c.name
            ));
        }

        // A FEATURE NAME IS A NAME. It is the one part of a manifest no rule was reading, and a
        // `[features] llm-serve = []` in a transport is that transport declaring a plane.
        //
        // THE COMPOSITION ROOT IS EXEMPT, IN WRITING. `root-llm`, `root-voice-serve`: the root is
        // the one place the tree assembles a plane, so a feature that switches one on is the root
        // doing its job. That is an exemption with a number attached rather than a silence —
        // `:matrix` counts every one of those words against the root's own cell, at an exact
        // ceiling — and the green case beside the red one is what makes it a rule.
        if c.kind == Some(ROOT_KIND) {
            continue;
        }
        let banned = banned_for(c.kind.unwrap_or(""), planes);
        for feat in feature_names(&text) {
            let lower = feat.to_lowercase();
            for (needle, why) in &banned {
                let hit = if needle.contains(':') || needle.ends_with('_') || needle.ends_with('-')
                {
                    lower.contains(needle.as_str())
                } else {
                    super::word_ci(&lower, needle)
                };
                if hit {
                    offenders.push(format!(
                        "feature-vocab\t{}\t`[features] {feat}` — {why} ({} crate). A feature is a \
                         NAME the whole tree reads, and this one names another kind's instance.",
                        c.manifest,
                        c.kind.unwrap_or("?")
                    ));
                }
            }
        }
    }

    // ── 4. THE LOCK AND THE MANIFESTS AGREE ──────────────────────────────────────────────────────
    match cx.read("Cargo.lock") {
        Ok(text) => {
            let locked = lock_packages(&text);
            for c in crates {
                let Some(in_lock) = locked.get(&c.name) else {
                    offenders.push(format!(
                        "lock-drift\tCargo.lock\t`{}` is a crate of this tree and has no \
                         [[package]] entry in the lock. What the lock says is what CARGO COMPILES; \
                         a crate it does not know is a crate nothing pinned.",
                        c.name
                    ));
                    continue;
                };
                let declared: BTreeSet<&str> = c
                    .deps
                    .iter()
                    .chain(c.dev_deps.iter())
                    .map(|d| d.pkg.as_str())
                    .filter(|n| by_name.contains_key(n))
                    .collect();
                for name in in_lock {
                    if by_name.contains_key(name.as_str()) && !declared.contains(name.as_str()) {
                        offenders.push(format!(
                            "lock-drift\tCargo.lock\tthe lock says `{}` depends on `{name}`, and \
                             no dependency table of {} declares it. The lock is what cargo \
                             COMPILES; an edge that lives only there is an edge no manifest asked \
                             for and no rule scored.",
                            c.name, c.manifest
                        ));
                    }
                }
                for name in &declared {
                    if !in_lock.contains(*name) {
                        offenders.push(format!(
                            "lock-drift\tCargo.lock\t{} declares a dependency on `{name}` and the \
                             lock's entry for `{}` does not carry it. The manifests and the lock \
                             disagree about what is compiled; regenerate the lock.",
                            c.manifest, c.name
                        ));
                    }
                }
            }
        }
        Err(e) => offenders.push(format!(
            "lock-drift\tCargo.lock\t{e} — the lock is what cargo compiles, and a lock that cannot \
             be read cannot be compared with the manifests that asked for it."
        )),
    }

    // ── 6. THE OUT-OF-TREE REGISTRY IS FILED UNDER THIS TREE'S KINDS ─────────────────────────────
    match cx.read(PLUGIN_REGISTRY) {
        Ok(text) => {
            let entries = registry_entries(&text);
            if entries.is_empty() {
                offenders.push(format!(
                    "no-registry-entries\t{PLUGIN_REGISTRY}\tthe plugin registry declares no \
                     entry this row can read. A registry that reads as empty files every plugin \
                     under no kind at all."
                ));
            }
            let mapped: BTreeMap<&str, &str> = REGISTRY_KIND_KEYS.iter().copied().collect();
            for (at, kind, krate) in entries {
                let Some(ours) = mapped.get(kind.as_str()) else {
                    offenders.push(format!(
                        "registry-unmapped-kind\t{PLUGIN_REGISTRY}:{at}\t`kind: {kind}` maps onto \
                         no kind in this gate's table. The registry and the gate are two kind \
                         vocabularies, and this is where they are held to one."
                    ));
                    continue;
                };
                // A crate name outside this tree's scheme resolves to nothing, and that is not a
                // mismatch — the out-of-tree plugins predate the naming rule. What IS a mismatch
                // is a name that resolves to a kind and is filed under a different one.
                let (resolved, remainder, _) = super::resolve_kind(&krate);
                let resolved = super::refine(resolved, &remainder);
                if let Some(resolved) = resolved {
                    if resolved != *ours {
                        offenders.push(format!(
                            "registry-kind-mismatch\t{PLUGIN_REGISTRY}:{at}\t`{krate}` is filed \
                             under `kind: {kind}` (this gate's `{ours}`) and its own name resolves \
                             to `{resolved}`. The registry is what the loader believes; a plugin \
                             filed under the wrong kind is handed the wrong ABI."
                        ));
                    }
                }
            }
        }
        Err(e) => offenders.push(format!(
            "unreadable\t{PLUGIN_REGISTRY}\t{e} — the registry files every out-of-tree plugin \
             under a kind, and one that cannot be read is one nobody compared."
        )),
    }

    offenders.sort();
    offenders.dedup();
    if offenders.is_empty() {
        return Row::pass(
            ROW_INPUTS,
            "no crate reaches another crate except through a dependency edge",
            format!(
                "{scanned} source file(s), {} manifest(s), the lock and {PLUGIN_REGISTRY}",
                crates.len()
            ),
        );
    }
    Row::fail(
        ROW_INPUTS,
        "a crate reaches another crate without a dependency edge",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_leaves_its_crate_or_it_does_not() {
        assert_eq!(
            resolve(
                "crates/busbar-transport-http/src",
                "../../busbar-plane-llm/src/meta.rs"
            ),
            "crates/busbar-plane-llm/src/meta.rs"
        );
        assert!(inside(
            "crates/busbar-transport-http",
            "crates/busbar-transport-http/src/raw.rs"
        ));
        assert!(!inside(
            "crates/busbar-transport-http",
            "crates/busbar-transport-https/src/raw.rs"
        ));
    }

    #[test]
    fn the_attribute_is_read_off_the_raw_line() {
        assert_eq!(
            quoted_after("#[path = \"../x/y.rs\"] pub mod smuggled;", "#[path"),
            vec!["../x/y.rs"]
        );
        assert_eq!(
            quoted_after("const S: &str = include_str!(\"../z.rs\");", "include_str!"),
            vec!["../z.rs"]
        );
    }

    #[test]
    fn the_lock_reads_as_a_package_graph() {
        let l = "[[package]]\nname = \"a\"\nversion = \"1\"\ndependencies = [\n \"b\",\n \"c 1.0 (registry+x)\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"1\"\n";
        let g = lock_packages(l);
        assert_eq!(
            g.get("a").map(|s| s.iter().cloned().collect::<Vec<_>>()),
            Some(vec!["b".to_string(), "c".to_string()])
        );
        assert!(g.contains_key("b"));
    }

    #[test]
    fn a_registry_entry_carries_its_kind_and_its_crate() {
        let y = "plugins:\n  - repo: store-mysql\n    kind: store\n    crate: busbar-store-mysql-plugin\n  - repo: auth-oidc\n    kind: auth\n    crate: busbar-auth-oidc-plugin\n";
        let e = registry_entries(y);
        assert_eq!(e.len(), 2, "{e:?}");
        assert_eq!(e[0].1, "store");
        assert_eq!(e[0].2, "busbar-store-mysql-plugin");
        assert_eq!(e[1].1, "auth");
    }

    #[test]
    fn a_feature_name_and_a_target_path_are_read() {
        let m = "[package]\nname = \"x\"\n\n[lib]\npath = \"../y/src/lib.rs\"\n\n[features]\nllm-serve = []\ndefault = [\"llm-serve\"]\n";
        assert_eq!(
            target_paths(m),
            vec![("lib".to_string(), "../y/src/lib.rs".to_string())]
        );
        assert_eq!(feature_names(m), vec!["llm-serve", "default"]);
    }
}
