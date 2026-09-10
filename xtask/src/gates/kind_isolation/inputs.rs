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
/// kinds the C ABI selects on — and it says `hook` where the table here says `hooks`.
///
/// `:truths` reconciles THREE places that name the kinds: `ARCHITECTURE.md`, the kind table here,
/// and `qa/construction.toml`. This is the FOURTH, and it is not one of that row's three because it
/// is a different KIND of file: the others describe the tree, and this one describes an out-of-tree
/// population the loader will act on. The way four vocabularies stay one is that each is mapped,
/// once, in the file that reads it; a word here that maps onto nothing is this one starting to
/// drift.
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
pub(super) const ROOT_KIND: &str = "root";

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

/// THE MODULE DIRECTORY of a source file — the directory a `mod x;` written inside it resolves
/// against.
///
/// A crate ROOT (`lib.rs`, `main.rs`, a `tests/`/`examples/`/`benches/`/`src/bin` binary,
/// `build.rs`) and a `mod.rs` both root their children in their OWN directory; every other file
/// roots them in a directory named after itself. Getting this wrong in either direction turns a
/// real module into an unresolvable one, so the two shapes are spelled out rather than guessed.
fn module_dir(rel: &str) -> String {
    let dir = dir_of(rel);
    let name = rel.rsplit('/').next().unwrap_or("");
    let parent = dir.rsplit('/').next().unwrap_or("");
    if matches!(name, "lib.rs" | "main.rs" | "mod.rs" | "build.rs")
        || matches!(parent, "tests" | "examples" | "benches" | "bin")
    {
        return dir;
    }
    let stem = name.strip_suffix(".rs").unwrap_or(name);
    if dir.is_empty() {
        stem.to_string()
    } else {
        format!("{dir}/{stem}")
    }
}

/// Every `mod NAME;` DECLARATION on one line — the ones that name a FILE, never the inline
/// `mod NAME { … }` that carries its own body.
///
/// Read off the raw line and anywhere in it, because `#[cfg(unix)] mod x;` is one line and a rule
/// that only reads the start of one would miss it.
fn mod_decls(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
        return out;
    }
    let b = line.as_bytes();
    let mut i = 0usize;
    while let Some(p) = line[i..].find("mod ") {
        let at = i + p;
        i = at + 4;
        let ok_before = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        if !ok_before {
            continue;
        }
        let rest = &line[at + 4..];
        let Some(semi) = rest.find(';') else { continue };
        let head = &rest[..semi];
        if head.contains('{') || head.contains('"') {
            continue;
        }
        let name = head.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.push(name.to_string());
        }
    }
    out
}

/// EVERY WAY A SOURCE FILE NAMES A PATH THE COMPILER WILL OPEN, with the finding each one earns.
///
/// `include!` was NOT on this list, and it is the strongest dual compile there is: `#[path]` at
/// least declares a module, while `include!("../../busbar-plane-llm/src/meta.rs")` splices another
/// crate's source into this one's body with no module, no dependency and no name. A red team walked
/// it through with every gate green. It reads as `path-include` because that is what it is.
const INCLUDE_MARKERS: &[(&str, &str, &str)] = &[
    ("#[path", "path-include", "a module compiled from"),
    ("include!", "path-include", "source spliced into it from"),
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
];

/// THE PATH ONE `marker` NAMES, resolved — or the splice this gate refuses to guess at.
///
/// `tail` is the file's text from just after the marker, NOT the line's: `include_str!(concat!(` is
/// a real spelling in this tree and its literals are two lines further down, so a line-shaped reader
/// sees an argument list that is not there.
///
/// THREE ANSWERS, and the middle one is the whole rule.
///
/// * A plain `"literal"` resolves against the file that wrote it.
/// * `concat!(env!("CARGO_MANIFEST_DIR"), "…")` resolves against the CRATE DIRECTORY, because that
///   is exactly what cargo sets that variable to. This is the idiom the tree already uses eight
///   times over, and it is also the spelling a red team used to reach
///   `"/../busbar-plane-mcp/src/lib.rs"` — so it is RESOLVED rather than refused, which is
///   strictly stronger than either reading it wrong or declining to read it.
/// * Anything else spliced — `format!`, `stringify!`, `option_env!`, a `concat!` of some other
///   variable — is an `Err`, and the caller reds on it. An input this gate cannot resolve is an
///   input it cannot score, and `quoted_after` took the FIRST literal, so
///   `concat!(env!("X"), "…")` used to resolve to a path inside the crate and be dropped.
fn include_targets(tail: &str, crate_dir: &str, here: &str) -> Vec<Result<String, String>> {
    let t = tail.trim_start();
    // `#[path = "…"]` — an `=` and a literal, never a call.
    let Some(rest) = t.strip_prefix('(') else {
        return match first_literal(t) {
            Some(p) => vec![Ok(resolve(here, &p))],
            None => Vec::new(),
        };
    };
    let rest = rest.trim_start();
    if rest.starts_with('"') {
        return match first_literal(rest) {
            Some(p) => vec![Ok(resolve(here, &p))],
            None => Vec::new(),
        };
    }
    let ident: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() || !rest[ident.len()..].starts_with('!') {
        return Vec::new();
    }
    let Some(inner) = balanced(&rest[ident.len() + 1..]) else {
        return vec![Err(format!("{ident}!(…)"))];
    };
    let lits = literals(inner);
    if ident == "concat" && lits.first().is_some_and(|l| l == "CARGO_MANIFEST_DIR") {
        let joined: String = lits[1..].concat();
        return vec![Ok(resolve(crate_dir, &joined))];
    }
    vec![Err(format!("{ident}!(…)"))]
}

/// The first `"…"` literal in `s`, unescaped only as far as this reader needs: a path.
fn first_literal(s: &str) -> Option<String> {
    let open = s.find('"')?;
    let close = s[open + 1..].find('"')?;
    Some(s[open + 1..open + 1 + close].to_string())
}

/// The text inside a `(…)` group that `s` opens, balanced.
fn balanced(s: &str) -> Option<&str> {
    let s = s.strip_prefix('(')?;
    let mut depth = 1i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every `"…"` literal in a fragment, in order.
fn literals(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

/// EVERY READ A BUILD SCRIPT MAKES THAT LEAVES ITS OWN CRATE DIRECTORY.
///
/// > "a build script that reads its siblings by directory walk, not by name" — the plant that went
/// > green
///
/// The marker loop above only reports a path that lands in ANOTHER CENSUSED CRATE, which is the
/// right narrowing for a library file and the wrong one for a build script. A `build.rs` that does
/// `read_dir("..")` and reads every `*/src/plane.rs` it finds names no crate at all, resolves to a
/// directory outside every crate, and was green everywhere — while compiling the whole tree's plane
/// sources into a transport's generated output. So a build script is held to the DIRECTORY rather
/// than to the name: a literal path that starts at `/` or climbs out through `..` is reported for
/// what it is, whatever it lands on. `build-script-reach` is also the needle a self-test has
/// expected since the row was written, and until now NO RULE EMITTED IT.
fn build_script_reach(
    by_dir: &BTreeMap<&str, &CrateInfo>,
    me: &CrateInfo,
    here: &str,
    rel: &str,
    line_no: usize,
    raw: &str,
) -> Vec<String> {
    const READS: &[(&str, &str)] = &[
        ("read_to_string", "reads"),
        ("read_dir", "walks"),
        ("File::open", "opens"),
        ("fs::read(", "reads"),
        ("include_str!", "reads"),
        ("include_bytes!", "reads"),
        ("include!", "compiles"),
    ];
    let mut out = Vec::new();
    for (marker, verb) in READS {
        for p in quoted_after(raw, marker) {
            if !(p.starts_with('/') || p.split('/').any(|s| s == "..")) {
                continue;
            }
            let target = resolve(here, &p);
            let lands = by_dir
                .values()
                .find(|o| inside(&o.dir, &target))
                .map(|o| format!("{} (kind {})", o.name, o.kind.unwrap_or("?")))
                .unwrap_or_else(|| "a path outside every crate in the census".to_string());
            out.push(format!(
                "build-script-reach\t{rel}:{}\t{}'s build script {verb} `{p}` — a path outside its \
                 own crate directory, resolving to `{target}`: {lands}. A build script runs with \
                 the whole checkout under it and writes into the crate it builds, so a read that \
                 climbs out is another crate's source compiled in with no edge to score, and a \
                 `read_dir` that climbs out names no crate at all and so is reported by the \
                 DIRECTORY rather than by what it happens to find. {MAKE_A_NEW_KIND}",
                line_no + 1,
                me.name
            ));
        }
    }
    out
}

/// The name of an INLINE `mod NAME { … }` opened on this line — the shape that makes a DIRECTORY
/// for every child module declared inside it.
fn inline_mod(code: &str) -> Option<String> {
    let b = code.as_bytes();
    let mut i = 0usize;
    while let Some(p) = code[i..].find("mod ") {
        let at = i + p;
        i = at + 4;
        if at != 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let rest = code[at + 4..].trim_start();
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        if rest[name.len()..].trim_start().starts_with('{') {
            return Some(name);
        }
    }
    None
}

/// EVERY FILE THIS CRATE COMPILES, AS THE SOURCE ITSELF NAMES IT — one entry per `mod`/`#[path]`
/// declaration, resolved to the path the compiler will open.
#[derive(Clone)]
struct Compiled {
    /// The file that wrote the declaration, and the line it is on.
    at: String,
    /// How it was written, for the finding.
    how: String,
    /// Every path the compiler would accept for it. A plain `mod x;` has two.
    candidates: Vec<String>,
}

/// THE COMPILED SET AGAINST THE SCANNED SET.
///
/// > "nothing plane-specific anywhere; kinds never cross-contaminate; make it so hard it catches
/// > false positives." — owner
///
/// Every rule in this gate that reads source reads the SCANNED SET: `crates/**` as the walker
/// yields it, minus any directory named `target` and minus anything `git check-ignore` claims. A
/// red team walked a whole plane through the gap between that set and the set the COMPILER reads:
/// `crates/store-memory/src/target/leak.rs`, naming `busbar-plane-llm` and defining `fn mc p_hook`,
/// reached by `#[path = "target/leak.rs"] pub mod leak;` in `lib.rs`. Live, linked, shipped code
/// naming another kind's instance — and invisible twice over, because the walker skips any
/// directory called `target` and `.gitignore` carries a bare `target/`.
///
/// So the two sets are compared, by name, and a compiled file that is not in the scanned set is
/// reported whatever the reason. A `git check-ignore` hit on a compiled path is reported as well
/// and in its own words, because that is the same hole reachable from a file nobody has to name:
/// one line in a `.gitignore` retires a source file from every scanner in this gate at once.
fn hidden_sources(
    cx: &Ctx,
    scanned: &BTreeSet<String>,
    files: &[crate::ctx::SourceFile],
) -> Vec<String> {
    let mut compiled: Vec<Compiled> = Vec::new();
    for f in files {
        compiled.extend(compiled_in(&f.rel_str(), &f.text).iter().cloned());
    }

    // ONE `check-ignore` FOR THE WHOLE COMPILED SET. A tracked path is never reported by git, so
    // what comes back is exactly the dangerous population: a file the compiler opens and no scanner
    // in this repository will ever be handed.
    let asked: Vec<String> = compiled
        .iter()
        .flat_map(|c| c.candidates.iter().cloned())
        .collect();
    let ignored = cx.ignored(&asked);

    let mut out = Vec::new();
    for c in &compiled {
        for cand in &c.candidates {
            if ignored.contains(cand) {
                out.push(format!(
                    "hidden-source\t{}\t`{}` compiles `{cand}`, and `git check-ignore` claims that \
                     path. An ignored file is a file every scanner in this gate is handed a tree \
                     without — the walker drops it — while the compiler links it in. One line in a \
                     `.gitignore` retires a source file from the whole gate, and this is that line \
                     doing it. {MAKE_A_NEW_KIND}",
                    c.at, c.how
                ));
            }
        }
        if c.candidates.iter().any(|p| scanned.contains(p)) {
            continue;
        }
        out.push(format!(
            "hidden-source\t{}\t`{}` compiles a file that is in no scan this gate runs: {}. Every \
             rule here reads the SCANNED SET; the compiler reads the COMPILED SET, and a file in \
             the second and not the first is source code no rule in this repository has ever \
             looked at. Move it under a directory the walker reads, or delete it. {MAKE_A_NEW_KIND}",
            c.at,
            c.how,
            c.candidates
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
    }
    out
}

/// THE COMPILED SET OF ONE FILE, MEMOISED — a pure function of its path and its bytes.
///
/// The reasoning is `matrix.rs`'s, and so is the arithmetic: every planted case re-runs the whole
/// gate, a plant changes ONE file, and re-lexing 1 600 of them for each of 120 plants is the
/// difference between a battery that runs in minutes and one nobody waits for. The key is the path
/// and the text, because the answer depends on nothing else.
fn compiled_in(rel: &str, text: &str) -> std::sync::Arc<Vec<Compiled>> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    rel.hash(&mut h);
    text.hash(&mut h);
    let key = h.finish();
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<u64, std::sync::Arc<Vec<Compiled>>>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Some(hit) = memo.lock().ok().and_then(|m| m.get(&key).cloned()) {
        return hit;
    }
    let built = std::sync::Arc::new(read_compiled(rel, text));
    if let Ok(mut m) = memo.lock() {
        m.insert(key, built.clone());
    }
    built
}

fn read_compiled(rel: &str, text: &str) -> Vec<Compiled> {
    let mut compiled: Vec<Compiled> = Vec::new();
    {
        let root_dir = module_dir(rel);
        let file_dir = dir_of(rel);
        // AN INLINE `mod x { … }` IS A DIRECTORY. `pub mod a2a { pub mod anomaly; }` in a `lib.rs`
        // compiles `src/a2a/anomaly.rs`, not `src/anomaly.rs`, and a `#[path]` written inside one
        // resolves against that same directory. So the nesting is tracked, by brace depth, over
        // text the lexer has already blanked — the counter this crate has exactly one of.
        let mut st = crate::scan::LexState::default();
        let mut depth = 0i32;
        let mut open_mods: Vec<(String, i32)> = Vec::new();
        let mut pending: Option<String> = None;
        for (line_no, raw) in text.lines().enumerate() {
            let code = crate::scan::blank_code(raw, &mut st);
            let at = format!("{rel}:{}", line_no + 1);
            let here = if open_mods.is_empty() {
                root_dir.clone()
            } else {
                format!(
                    "{root_dir}/{}",
                    open_mods
                        .iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join("/")
                )
            };
            // THE ATTRIBUTE IS READ OFF THE RAW LINE and GATED ON THE BLANKED ONE: the path is a
            // string literal the blanker would erase, and a `#[path = "…"]` quoted inside a comment
            // is not a declaration. `busbar-core`'s own header describes the shims it deleted in
            // exactly that shape, and reading it would have re-declared them.
            let on_this_line = if code.contains("#[path") {
                quoted_after(raw, "#[path").into_iter().next()
            } else {
                None
            };
            let names = mod_decls(&code);
            let attr = on_this_line.clone().or_else(|| pending.clone());
            for name in &names {
                match &attr {
                    // A `#[path]` OUTSIDE AN INLINE BLOCK IS RELATIVE TO THE FILE'S OWN DIRECTORY,
                    // and INSIDE one it is relative to the module directory — the language's rule,
                    // and the difference between reading `src/tests/auth_tests.rs` (which exists,
                    // sixty times over in this tree) and `src/auth/tests/auth_tests.rs` (which does
                    // not). A rule that got this backwards would report every one of them.
                    Some(p) => compiled.push(Compiled {
                        at: at.clone(),
                        how: format!("#[path = \"{p}\"] mod {name};"),
                        candidates: vec![resolve(
                            if open_mods.is_empty() {
                                &file_dir
                            } else {
                                &here
                            },
                            p,
                        )],
                    }),
                    None => compiled.push(Compiled {
                        at: at.clone(),
                        how: format!("mod {name};"),
                        candidates: vec![
                            resolve(&here, &format!("{name}.rs")),
                            resolve(&here, &format!("{name}/mod.rs")),
                        ],
                    }),
                }
            }
            // A `#[path]` AND ITS `mod` ARE RARELY ADJACENT. `#[cfg(…)]`, `#[allow(dead_code)]` and
            // a doc line all sit between them in this tree, so the attribute survives anything that
            // is itself an attribute, a comment or blank, and nothing else.
            let t = code.trim();
            pending = match on_this_line {
                Some(p) => Some(p),
                None if !names.is_empty() => None,
                None if t.is_empty() || t.starts_with("#[") || t.starts_with("#!") => pending,
                None if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') => pending,
                None => None,
            };

            if let Some(name) = inline_mod(&code) {
                open_mods.push((name, depth));
            }
            depth += crate::scan::delta(&code, '{', '}');
            while open_mods.last().is_some_and(|(_, d)| depth <= *d) {
                open_mods.pop();
            }
        }
    }
    compiled
}

/// The table headers that redirect what cargo compiles, and the files that may carry them.
const REDIRECT_HEADS: &[&str] = &["patch", "replace", "source"];

/// EVERY `[patch]`, `[replace]` AND `[source]` TABLE IN THE REPOSITORY, held to the named rows.
///
/// Read off the raw header lines rather than through a TOML value model on purpose: the claim is
/// about the FILE, and a reader that has to resolve the table to see it is a reader with a place to
/// be wrong. A header this reader cannot close (`[patch.crates-io` with no `]`) is reported too,
/// because a line that opens a redirect and does not close is a line whose scope nobody can state.
fn redirect_findings(cx: &Ctx, reg: &super::KindRegistry) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let files = match cx.walk(&WalkSpec::new(["."]).ext("toml")) {
        Ok(f) => f,
        Err(e) => {
            return vec![format!(
                "redirect-scan	.\t{e} — a scan of no manifests finds no `[patch]`, which is \
                 indistinguishable from a tree that has none."
            )]
        }
    };
    for f in &files {
        let rel = f.rel_str();
        let name = rel.rsplit('/').next().unwrap_or(&rel);
        let is_cargo_toml = name == "Cargo.toml";
        let is_cargo_config = name == "config.toml" && rel.contains(".cargo/");
        if !is_cargo_toml && !is_cargo_config {
            continue;
        }
        for (i, raw) in f.text.lines().enumerate() {
            let t = raw.trim().trim_start_matches('\u{feff}');
            let t = match t.split_once('#') {
                Some((head, _)) => head.trim(),
                None => t,
            };
            let Some(head) = t.strip_prefix('[') else {
                continue;
            };
            let head = head.trim_end_matches(']').trim_start_matches('[');
            let first = head.split('.').next().unwrap_or(head).trim();
            if !REDIRECT_HEADS.contains(&first) {
                continue;
            }
            let entry = head.trim();
            if reg
                .patch_allows
                .iter()
                .any(|a| a.file == rel && a.entry == entry)
            {
                continue;
            }
            out.push(format!(
                "redirect\t{rel}:{}\t`[{entry}]` substitutes one crate for another AFTER every \
                 manifest in this tree has been read: the census, the edge ledger, the matrix and \
                 the lock cross-check are all downstream of a decision none of them can see. It is \
                 allowed by a `[[patch]]` row naming this file and this entry, or by nothing.",
                i + 1
            ));
        }
    }
    // A ROW THAT COVERS NOTHING IS A STANDING HOLE. The allowance expires with the entry it names.
    for a in &reg.patch_allows {
        let live = files.iter().any(|f| {
            f.rel_str() == a.file
                && f.text.lines().any(|l| {
                    let t = l.trim();
                    t.starts_with('[') && t.trim_matches(['[', ']']).trim() == a.entry
                })
        });
        if !live {
            out.push(format!(
                "dead-patch-row	{}\t`[[patch]] file = \"{}\" entry = \"{}\"` covers nothing: no \
                 such table exists. Strike the row ({}).",
                a.file, a.file, a.entry, a.reason
            ));
        }
    }
    out
}

pub fn rule_inputs(
    cx: &Ctx,
    crates: &[CrateInfo],
    planes: &BTreeSet<String>,
    reg: &super::KindRegistry,
) -> Row {
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
        let mut line_start = 0usize;
        for (line_no, raw) in f.text.lines().enumerate() {
            // THE ATTRIBUTE IS READ OFF THE RAW LINE. `blank_literals` would erase the very string
            // this rule is about — which is exactly why `#[path]` was invisible to `:vocab`.
            if rel.ends_with("build.rs") {
                offenders.extend(build_script_reach(&by_dir, me, &here, &rel, line_no, raw));
            }
            for (marker, label, what) in INCLUDE_MARKERS {
                let mut cut = 0usize;
                while let Some(p) = raw[cut..].find(marker) {
                    let at = line_start + cut + p + marker.len();
                    cut += p + marker.len();
                    // THE ARGUMENT, NOT THE REST OF THE FILE. Far enough to cross the two or three
                    // lines a wrapped `concat!(` spans, and no further, so a marker that carries no
                    // argument cannot borrow a literal from the next function.
                    let end = (at + 400..=f.text.len())
                        .find(|i| f.text.is_char_boundary(*i))
                        .unwrap_or(f.text.len());
                    for target in include_targets(&f.text[at..end], &me.dir, &here) {
                        // A PATH THIS GATE CANNOT RESOLVE IS RED, NOT SKIPPED. Splicing is not a
                        // spelling this row is allowed to read past: an input it cannot resolve is
                        // one it cannot score, and the softest possible failure of the rule that
                        // matters most is to resolve a path the compiler never opens and say
                        // nothing about the one it does.
                        let target = match target {
                            Ok(t) => t,
                            Err(built_with) => {
                                offenders.push(format!(
                                    "unresolvable-include\t{rel}:{}\t{} builds a `{marker}` path \
                                     with `{built_with}`, which this gate cannot resolve. An input \
                                     it cannot resolve is an input it cannot score, and the first \
                                     literal inside a splice is not the path. Write the path, or \
                                     splice it from `env!(\"CARGO_MANIFEST_DIR\")`, which resolves \
                                     to this crate's own directory and IS scored. \
                                     {MAKE_A_NEW_KIND}",
                                    line_no + 1,
                                    me.name
                                ));
                                continue;
                            }
                        };
                        let Some(theirs) = foreign_owner(&by_dir, me, &target) else {
                            continue;
                        };
                        offenders.push(format!(
                            "{label}\t{rel}:{}\t{} is {what} `{target}` — {}'s own source, and {} \
                             declares no dependency on it in any table. A crate reaches another \
                             crate through Cargo, where the edge is written down and scored; \
                             reading its files compiles it in with no edge to score. \
                             {MAKE_A_NEW_KIND}",
                            line_no + 1,
                            me.name,
                            theirs.name,
                            me.name
                        ));
                    }
                }
            }
            line_start += raw.len() + 1;
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

    // ── 1b. THE COMPILED SET IS THE SCANNED SET ──────────────────────────────────────────────────
    let scan_set: BTreeSet<String> = files.iter().map(|f| f.rel_str()).collect();
    offenders.extend(hidden_sources(cx, &scan_set, &files));

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

    // ── 7. NOTHING REDIRECTS WHAT CARGO COMPILES ─────────────────────────────────────────────────
    //
    // `[patch]`, `[replace]` and `.cargo/config.toml`'s `[source] replace-with` substitute one
    // crate for another AFTER every manifest in this tree has been read and agreed with. The
    // census, the edge ledger, the matrix and the lock cross-check are all downstream of a
    // decision none of them can see: `[patch.crates-io] busbar-plane-llm = { path = "…" }` links a
    // different plane into every crate in the workspace with no finding anywhere. Nothing in this
    // gate read those tables at all -- `grep '\[patch' xtask/src` returned nothing.
    //
    // So EVERY one of them is red unless a `[[patch]]` row names the exact file and the exact
    // entry and says why. There is no allowance in this source and no default: the tree has none
    // today, so the measured ceiling is zero and the ledger's table is empty.
    offenders.extend(redirect_findings(cx, reg));

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
