//! WHERE THIS LINT LOOKS — and the two rules that fail when the tree stops answering.
//!
//! Every row in every other family names the root it governs THROUGH this module, so a crate move
//! is a one-value flip rather than 46 silently stale paths. That is not a convenience: a rule
//! pointed at a directory that moved scans nothing, prints nothing, and reads exactly like a clean
//! tree — zero is the passing answer to every ban in this gate.
//!
//! * `CORE`/`BIN` — the library/binary seam. Each row's choice between them is a signed decision
//!   about which side of the seam that invariant watches.
//! * `SUBSTRATE`/`SUBSTRATE_VALUES` — where the plane-neutral machinery and the value families went
//!   in 1.6.0. A census row whose symbol moved gains the scope so it FOLLOWS the symbol rather than
//!   reading zero.
//! * The PROTOCOL CRATES, the PLANE ROOTS and the TREE-WIDE SCOPE are DERIVED, not spelled,
//!   because a constant is a thing to remember on the day a dialect lands and the failure of
//!   forgetting is the silent one.
//!
//! ## What "derived" means here, measured against the three things that had forgotten a plane
//!
//! This header said the above while `PLANES` was the literal `["mcp", "a2a"]`, `proto_root_of`
//! knew four crate shapes and not the `busbar-plane-*` one fold #39 created, and `tree()` was seven
//! prefixes out of forty-nine crates (items 183, 184, 224). Each is now read off the tree:
//!
//! * THE PLANES are every production `pub const PLANE_DECL` DECLARATION (column 0 — the hot lane's
//!   indented ABI symbol name and every doc comment quoting the grammar are not declarations) plus
//!   the canonical roster [`crate::planes::PLANE_KEYS`]. The roster is READ, not restated, and it is
//!   there for the other direction: a plane the roster names that no longer declares itself is
//!   PLANE-ROOT-MISSING, where a derivation alone would simply stop listing it. A plane that
//!   declares itself and is on no roster (the fifth, `decision`) is scanned anyway — being found is
//!   what a derivation is for.
//! * THE PROTOCOL CRATES gain `busbar-plane-*`, the wire dialects the `-codec` halves dissolved into.
//! * THE TREE-WIDE SCOPE is every `crates/<crate>/src/` that holds a source file. A crate created
//!   tomorrow is in the census and the axis bans on the day it is created, which is the only day
//!   that matters; the axis rows keep their ARMS as the allowed prefixes, so widening the scope
//!   widens what is judged, never what is legitimate.
//!
//! BOTH DERIVATIONS ARE RUN OVER THE WALK rather than over `std::fs`, and that is what makes them
//! provable: a self-test can empty a protocol crate, or take the grammar out of a plane's `mod.rs`,
//! and watch the rule go red. The shell's globs asked `[ -d ]`, which no overlay can answer — and a
//! directory holding no Rust contributes nothing to any scan below, so "has a source file in it" is
//! the same question asked honestly (it is the question the plane resolver in `xtask/src/planes.rs`
//! — the Rust port of the deleted `scripts/plane-roots.sh` — already had to add).

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, WalkSpec};
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;
use crate::planes::{PlaneRootError, PlaneRoots, PLANE_GRAMMAR, PLANE_KEYS};

pub const ROW_PROTO_ROOTS: &str = "structure-lint:proto-roots";
pub const ROW_PLANE_ROOTS: &str = "structure-lint:plane-roots";

// `busbar-core` was absorbed INTO `busbar-kernel` (W4 core-absorption) and `busbar-substrate`'s
// plane-neutral machinery was folded into the same crate (W4.b P2), so the library seam and the
// substrate machinery now share one home. A row's choice between `CORE` and `SUBSTRATE` still
// records which invariant watches which surface; both address the engine crate today.
pub const CORE: &str = "crates/busbar-kernel/src";
pub const BIN: &str = "crates/busbar/src";
pub const SUBSTRATE: &str = "crates/busbar-kernel/src";
pub const SUBSTRATE_VALUES: &str = "crates/busbar-substrate-values/src";

/// The root every walk in this gate starts from.
pub const CRATES: &str = "crates";

/// FIVE SHAPES, because the naming is not uniform and pretending it is would silently drop a whole
/// protocol from the scan. `busbar-llm` is the LLM protocol's plugin (six dialect modules under one
/// crate — one plugin per PROTOCOL, not per dialect); `busbar-mcp` is the MCP protocol's plugin;
/// `busbar-proto-*` is the older per-protocol naming; `busbar-*-codec` is the newest, each protocol
/// plugin's pure half. A fifth protocol under any of them is scanned without editing this.
pub fn proto_root_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix("crates/")?;
    let (crate_name, tail) = rest.split_once('/')?;
    if !tail.starts_with("src/") {
        return None;
    }
    let matches = crate_name == "busbar-llm"
        || crate_name == "busbar-mcp"
        || (crate_name.starts_with("busbar-") && crate_name.ends_with("-codec"))
        || crate_name.starts_with("busbar-proto-")
        // THE FIFTH SHAPE, and the one this function had forgotten: fold #39 dissolved the
        // `-codec` halves into `busbar-plane-<key>` (the dialect to the plane crate), so a
        // protocol's wire arm now lives under this name and was in no scan and no allowed arm.
        || crate_name.starts_with("busbar-plane-");
    matches.then(|| format!("crates/{crate_name}/src/"))
}

/// The resolved addresses this run's rows are written against.
#[derive(Debug, Clone)]
pub struct Addresses {
    pub core: String,
    pub bin: String,
    pub substrate: String,
    pub substrate_values: String,
    /// Every protocol crate's `src/`, each with its trailing `/`, sorted.
    pub proto_roots: Vec<String>,
    /// Every `crates/<crate>/src/` that holds a source file, each with its trailing `/`, sorted —
    /// the tree-wide scope, derived so a new crate is in it without anybody remembering.
    pub src_roots: Vec<String>,
    /// Every plane this tree declares or the roster names, in roster order then by key, each
    /// resolved to its home (or to an address nothing matches, with the finding recorded).
    pub planes: Vec<Plane>,
    pub mcp: String,
    pub a2a: String,
}

/// One plane and the directory that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plane {
    pub key: String,
    pub home: String,
}

impl Addresses {
    /// The scan roots for every TREE-WIDE rule (the census and the axis ledger): EVERY crate's
    /// `src/`, plus `CORE + BIN`, the plane homes and the protocol crates.
    ///
    /// It was `CORE + BIN + mcp + a2a + proto_roots` — seven prefixes of forty-nine crates — and
    /// `busbar-contract`, every `busbar-kernel-*` crate (the money path among them), the voice
    /// plane and every `busbar-plane-*` crate were outside the two axis bans and the census that
    /// call themselves tree-wide (items 183, 224). The named roots are still listed: while they
    /// sit inside a crate's `src/` they are redundant and cost nothing, and the day one of them
    /// does not (a plane home outside `src/`) they are the reason it stays covered.
    pub fn tree(&self) -> Vec<String> {
        let mut out = vec![format!("{}/", self.core), format!("{}/", self.bin)];
        out.extend(self.planes.iter().map(|p| format!("{}/", p.home)));
        out.extend(self.proto_roots.iter().cloned());
        out.extend(self.src_roots.iter().cloned());
        let mut seen = BTreeSet::new();
        out.retain(|p| seen.insert(p.clone()));
        out
    }

    /// The home of one plane, or the unresolvable address if the tree gave it none.
    pub fn plane(&self, key: &str) -> String {
        self.planes
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.home.clone())
            .unwrap_or_else(|| Addresses::unresolved(key))
    }

    /// A plane whose root could not be resolved still has to spell SOMETHING into the rows that
    /// name it, and that something must be a path nothing matches — never a prefix that would
    /// silently widen a ban or narrow it onto the wrong tree.
    fn unresolved(plane: &str) -> String {
        format!("PLANE-ROOT-UNRESOLVED/{plane}")
    }
}

/// Resolve the addresses, recording the two "the tree stopped answering" findings as it goes.
pub fn resolve(cx: &Ctx, f: &mut Findings) -> Addresses {
    let files = cx
        .walk(&WalkSpec::new([CRATES]).ext("rs"))
        .unwrap_or_default();

    let proto_roots: BTreeSet<String> = files
        .iter()
        .filter_map(|s| proto_root_of(&s.rel_str()))
        .collect();
    if proto_roots.is_empty() {
        f.proto_roots.push(finding_proto_roots());
    }

    let src_roots: BTreeSet<String> = files
        .iter()
        .filter_map(|s| src_root_of(&s.rel_str()))
        .collect();

    // THE OWNERSHIP RULE, over the SAME file list: a plane's home is the directory holding its
    // DECLARATION — not a directory that merely shares its name. The wire-codec split gives a plane
    // a second same-named directory (`busbar-plane-a2a/src/a2a/`) that holds bytes-on-the-wire and
    // declares nothing, and the LLM and voice planes live in a crate's `src/` with no directory
    // named after them at all, which is why the old name-first rule could only ever find two.
    let mut homes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in &files {
        let rel = s.rel_str();
        if rel.contains("/tests/") || !declares_plane(&s.text) {
            continue;
        }
        if let Some((key, home)) = declaration_home(&rel) {
            homes.entry(key).or_default().insert(home);
        }
    }
    // A home must hold a source file: the composition root's declaration names a plane crate, and
    // a plane crate with nothing in it is a plane every rule would scan zero files of.
    let holds_source = |home: &str| {
        let prefix = format!("{home}/");
        files.iter().any(|s| s.rel_str().starts_with(&prefix))
    };

    let mut roster: Vec<String> = PLANE_KEYS.iter().map(|k| (*k).to_string()).collect();
    for key in homes.keys() {
        if !roster.contains(key) {
            roster.push(key.clone());
        }
    }

    let roots = PlaneRoots::at(cx.abs(CRATES));
    let mut planes = Vec::new();
    for key in &roster {
        let owned: Vec<std::path::PathBuf> = homes
            .get(key)
            .into_iter()
            .flatten()
            .filter(|h| holds_source(h))
            .map(std::path::PathBuf::from)
            .collect();
        let home = match roots.judge(key, owned) {
            Ok(dir) => dir.display().to_string(),
            Err(e) => {
                f.plane_roots.push(finding_plane_root(&e));
                Addresses::unresolved(key)
            }
        };
        planes.push(Plane {
            key: key.clone(),
            home,
        });
    }

    let mut a = Addresses {
        core: CORE.to_string(),
        bin: BIN.to_string(),
        substrate: SUBSTRATE.to_string(),
        substrate_values: SUBSTRATE_VALUES.to_string(),
        proto_roots: proto_roots.into_iter().collect(),
        src_roots: src_roots.into_iter().collect(),
        planes,
        mcp: String::new(),
        a2a: String::new(),
    };
    a.mcp = a.plane("mcp");
    a.a2a = a.plane("a2a");
    a
}

/// `crates/<crate>/src/`, for any source under one.
fn src_root_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix("crates/")?;
    let (crate_name, tail) = rest.split_once('/')?;
    tail.starts_with("src/")
        .then(|| format!("crates/{crate_name}/src/"))
}

/// A plane DECLARES itself with the grammar at column 0 of a production line. Column 0 is the
/// line between a declaration and everything that merely quotes it: the hot lane's
/// `    pub const PLANE_DECL: &[u8]` is the loader's ABI symbol name, indented inside a module, and
/// every doc comment that says "`PLANE_DECL`" is prose.
pub fn declares_plane(text: &str) -> bool {
    if !text.contains(PLANE_GRAMMAR) {
        return false;
    }
    crate::scan::test_scope(text)
        .iter()
        .any(|l| !l.gated && !l.is_comment && l.raw.starts_with(PLANE_GRAMMAR))
}

/// The plane a declaration at `rel` is for, and the directory that owns it. Three shapes, each
/// read off the path the tree put the declaration at:
///
/// * `crates/busbar/src/root/plane_<key>.rs` — THE COMPOSITION ROOT declares a pure plane whose
///   crate may not name the kernel type (`busbar-plane-decision`, DECISIONS #40). The file names
///   the plane; the plane's code is its crate, `crates/busbar-plane-<key>/src`.
/// * `crates/<crate>/src/<file>.rs` — a plane that IS its crate (`busbar-llm`, `busbar-voice`):
///   the key is the crate name without `busbar-`, the home is the crate's `src`.
/// * anything deeper — a plane that is a module (`busbar-mcp/src/mcp/`): the key is the
///   directory's own name and the home is that directory.
pub fn declaration_home(rel: &str) -> Option<(String, String)> {
    let rest = rel.strip_prefix("crates/")?;
    let (crate_name, tail) = rest.split_once('/')?;
    let (dir, file) = rel.rsplit_once('/')?;
    let stem = file.strip_suffix(".rs")?;
    if crate_name == "busbar" {
        let key = stem
            .strip_prefix("plane_")
            .unwrap_or(stem)
            .replace('_', "-");
        return Some((key.clone(), format!("crates/busbar-plane-{key}/src")));
    }
    let last = dir.rsplit('/').next()?;
    if tail.split('/').count() == 2 && last == "src" {
        let key = crate_name
            .strip_prefix("busbar-plane-")
            .or_else(|| crate_name.strip_prefix("busbar-"))
            .unwrap_or(crate_name);
        return Some((key.to_string(), dir.to_string()));
    }
    Some((last.to_string(), dir.to_string()))
}

/// The offender, spelled once. The legacy translator reads the plane and the verdict off the
/// script's own lines and calls THIS, so a parity diff can only be about which plane failed.
fn finding_plane_root(e: &PlaneRootError) -> String {
    match e {
        PlaneRootError::Missing { plane, .. } => finding_plane_missing(plane),
        PlaneRootError::Ambiguous { plane, candidates } => {
            finding_plane_ambiguous(plane, candidates.len())
        }
    }
}

pub fn finding_proto_roots() -> String {
    "PROTO-ROOTS-MISSING: no `crates/busbar-llm/src`, `crates/busbar-mcp/src`, \
     `crates/busbar-*-codec/src`, `crates/busbar-proto-*/src` or `crates/busbar-plane-*/src` holds \
     a source file. The operation \
     and transport axis bans are scoped over the protocol crates, so this is a ban scanning \
     NOTHING, and zero is the passing answer to a ban."
        .to_string()
}

pub fn finding_plane_missing(plane: &str) -> String {
    format!(
        "PLANE-ROOT-MISSING: nothing under crates/ carries the `{plane}` plane's `{PLANE_GRAMMAR}` \
         declaration, so every rule that names this plane is scanning NOTHING"
    )
}

pub fn finding_plane_ambiguous(plane: &str, n: usize) -> String {
    format!(
        "PLANE-ROOT-AMBIGUOUS: `{plane}` resolves to {n} directories that each declare its grammar \
         — a half-finished move or a duplicated plane, and no caller can say which pair of trees it \
         just compared"
    )
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_PROTO_ROOTS,
            "the protocol crates are where the axis rows scope over them",
            "the protocol crates cannot be located, so the axis bans scan nothing",
            &f.proto_roots,
        ),
        row(
            ROW_PLANE_ROOTS,
            "every plane resolves to exactly one home",
            "a plane resolves to no home or to two",
            &f.plane_roots,
        ),
    ]
}
