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
//! * The PROTOCOL CRATES and the PLANE ROOTS are DERIVED, not spelled, because a constant is a
//!   thing to remember on the day a dialect lands and the failure of forgetting is the silent one.
//!
//! BOTH DERIVATIONS ARE RUN OVER THE WALK rather than over `std::fs`, and that is what makes them
//! provable: a self-test can empty a protocol crate, or take the grammar out of a plane's `mod.rs`,
//! and watch the rule go red. The shell's globs asked `[ -d ]`, which no overlay can answer — and a
//! directory holding no Rust contributes nothing to any scan below, so "has a source file in it" is
//! the same question asked honestly (it is the question `plane-roots.sh` already had to add).

use std::collections::BTreeSet;

use crate::ctx::{Ctx, WalkSpec};
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;
use crate::planes::{PlaneRootError, PlaneRoots, PLANE_GRAMMAR};

pub const ROW_PROTO_ROOTS: &str = "structure-lint:proto-roots";
pub const ROW_PLANE_ROOTS: &str = "structure-lint:plane-roots";

pub const CORE: &str = "crates/busbar-core/src";
pub const BIN: &str = "crates/busbar/src";
pub const SUBSTRATE: &str = "crates/busbar-substrate/src";
pub const SUBSTRATE_VALUES: &str = "crates/busbar-substrate-values/src";

/// The planes whose roots every plane-scoped row is written against.
pub const PLANES: [&str; 2] = ["mcp", "a2a"];

/// The root every walk in this gate starts from.
pub const CRATES: &str = "crates";

/// FOUR SHAPES, because the naming is not uniform and pretending it is would silently drop a whole
/// protocol from the scan. `busbar-llm` is the LLM protocol's plugin (six dialect modules under one
/// crate — one plugin per PROTOCOL, not per dialect); `busbar-mcp` is the MCP protocol's plugin;
/// `busbar-proto-*` is the older per-protocol naming; `busbar-*-codec` is the newest, each protocol
/// plugin's pure half. A fifth protocol under any of them is scanned without editing this.
fn proto_root_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix("crates/")?;
    let (crate_name, tail) = rest.split_once('/')?;
    if !tail.starts_with("src/") {
        return None;
    }
    let matches = crate_name == "busbar-llm"
        || crate_name == "busbar-mcp"
        || (crate_name.starts_with("busbar-") && crate_name.ends_with("-codec"))
        || crate_name.starts_with("busbar-proto-");
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
    pub mcp: String,
    pub a2a: String,
}

impl Addresses {
    /// The scan roots for every TREE-WIDE rule (the census and the axis ledger): `CORE + BIN` plus
    /// the plane roots plus the protocol crates.
    ///
    /// The plane roots are listed EXPLICITLY rather than assumed to be inside `CORE`. While they
    /// are, the extra prefixes are redundant and cost nothing; the day a plane becomes its own
    /// crate they are the only reason the MCP wire-word census rows and the two axis bans keep
    /// covering it. Without them a census row over `"mcp-protocol-version"` would go from 1 to 0
    /// the moment the constant left core, which reads as MISSING — loud, but loud AFTER the fact.
    pub fn tree(&self) -> Vec<String> {
        let mut out = vec![
            format!("{}/", self.core),
            format!("{}/", self.bin),
            format!("{}/", self.mcp),
            format!("{}/", self.a2a),
        ];
        out.extend(self.proto_roots.iter().cloned());
        out
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

    // The ownership rule, over the SAME file list: a candidate directory is named after the plane
    // AND directly holds a source that declares the plane's grammar. A name match is not an
    // ownership claim — the wire-codec split gives a plane a second same-named directory that holds
    // bytes-on-the-wire and declares nothing.
    let roots = PlaneRoots::at(cx.abs(CRATES));
    let mut resolved = Vec::new();
    for plane in PLANES {
        let owned: Vec<std::path::PathBuf> = {
            let mut dirs: BTreeSet<String> = BTreeSet::new();
            for s in &files {
                let rel = s.rel_str();
                let Some((dir, _)) = rel.rsplit_once('/') else {
                    continue;
                };
                if dir.rsplit('/').next() != Some(plane) {
                    continue;
                }
                if s.text.contains(PLANE_GRAMMAR) {
                    dirs.insert(dir.to_string());
                }
            }
            dirs.into_iter().map(std::path::PathBuf::from).collect()
        };
        match roots.judge(plane, owned) {
            Ok(dir) => resolved.push(dir.display().to_string()),
            Err(e) => {
                f.plane_roots.push(finding_plane_root(&e));
                resolved.push(Addresses::unresolved(plane));
            }
        }
    }

    Addresses {
        core: CORE.to_string(),
        bin: BIN.to_string(),
        substrate: SUBSTRATE.to_string(),
        substrate_values: SUBSTRATE_VALUES.to_string(),
        proto_roots: proto_roots.into_iter().collect(),
        mcp: resolved[0].clone(),
        a2a: resolved[1].clone(),
    }
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
     `crates/busbar-*-codec/src` or `crates/busbar-proto-*/src` holds a source file. The operation \
     and transport axis bans are scoped over the protocol crates, so this is a ban scanning \
     NOTHING, and zero is the passing answer to a ban."
        .to_string()
}

pub fn finding_plane_missing(plane: &str) -> String {
    format!(
        "PLANE-ROOT-MISSING: no directory named `{plane}` under crates/ carries its `{PLANE_GRAMMAR}` \
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
