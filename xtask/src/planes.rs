//! THE PLANE-KEYS / PLANE-ROOTS CONTRACT — `scripts/plane-keys.sh` (WHICH planes exist) and WHERE
//! a plane lives, as one Rust module, so no gate restates the plane set or guesses its addresses.
//! This module is the ONLY home of the roots half: its shell twin `scripts/plane-roots.sh` was
//! sourced by nothing and was deleted in eec209ae4 (item 549).
//!
//! The resolution rule is deliberately mechanical and unchanged: a plane's root is the directory
//! that OWNS it — found by name, then narrowed by ownership. A name match is not an ownership
//! claim, because the wire-codec split gives a plane a second same-named directory
//! (`busbar-plane-a2a/src/a2a/` beside `busbar-a2a/src/a2a/`) that holds bytes-on-the-wire and
//! never declares the plane. A candidate must directly contain a `*.rs` carrying the grammar
//! (`pub const PLANE_DECL`) to count. Three answers, one of which is a pass:
//!
//! * exactly one — that is the home, wherever the tree put it.
//! * none — [`PlaneRootError::Missing`]. NOT a skip: a plane nothing can locate is a plane every
//!   rule is scanning zero files of, and zero is the passing answer to every ban.
//! * more than one — [`PlaneRootError::Ambiguous`], naming both claimants. A half-finished move or
//!   a duplicated plane; picking whichever sorts first would freeze one home and quietly un-freeze
//!   the other.
//!
//! A DOOR-ONLY PLANE (P3 DEL-MCP, ARCHITECT 2026-10-05): a plane whose legacy engine is deleted and
//! which is served through its memory-ABI door alone carries no `pub const PLANE_DECL` anywhere —
//! its declaration is its DOOR ROW in the composition root's manifest
//! (`crates/busbar/Cargo.toml`: a `[package.metadata.busbar.linked]` row naming a
//! `busbar-plane-<key>` crate whose `[package.metadata.busbar.linked-axes]` row carries the
//! `plane-door` axis, e.g. `plane-mcp-door`). Its home is that crate's `src`, read by
//! [`door_planes`]. The door is consulted ONLY for a plane no grammar declaration claims, so a
//! plane that still has its engine beside a door row (`llm-on-driver`) keeps the engine as its
//! home; a door row that names no crate on disk is still `Missing`, never a pass. This is the same
//! reading `gates::config_schema::declared` gives a door-only plane's Statement.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The canonical order is the doctrine order: the three original protocols, then voice (Plane 4).
///
/// THE LEGACY-ENGINE ROSTER: every consumer reads a key as a `crates/busbar-<key>` directory (see
/// [`plane_src_roots`]). `mcp` IS STRUCK (P3 DEL-MCP, ARCHITECT 2026-10-05; its shell twin
/// `scripts/plane-keys.sh` says the same in the same commit): `crates/busbar-mcp` is deleted and the
/// mcp plane is plane-kind only, its door crate `busbar-plane-mcp` — scanned by the plane-kind regime
/// and located by its door row ([`door_planes`]) wherever a gate resolves the plane's home.
pub const PLANE_KEYS: [&str; 3] = ["llm", "a2a", "voice"];

/// The default ownership grammar. Overridable for a fixture tree, the way
/// `PLANE_ROOTS_GRAMMAR` is in the shell.
pub const PLANE_GRAMMAR: &str = "pub const PLANE_DECL";

/// The composition root's manifest, relative to the `crates/` search root: where a door-only
/// plane's door row is declared.
pub const DOOR_MANIFEST: &str = "busbar/Cargo.toml";

/// The `linked-axes` axis that makes a linked row a plane's memory-ABI DOOR (`root::linked`).
pub const PLANE_DOOR_AXIS: &str = "plane-door";

/// The `key = "value"` rows of one `[table]` of a manifest, in file order — the reading
/// `crates/busbar/src/linked_gen.rs` gives `build.rs` (one row per line, both sides optionally
/// quoted, `#` starts a comment). An absent table is no rows.
fn manifest_rows(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let mut inside = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            inside = code == header;
            continue;
        }
        if let (true, Some((k, v))) = (inside, code.split_once('=')) {
            rows.push((
                k.trim().trim_matches('"').to_string(),
                v.trim().trim_matches('"').to_string(),
            ));
        }
    }
    rows
}

/// THE DOOR PLANES the composition root's manifest declares: plane key -> the crate its door row
/// links. A row counts when its `linked-axes` row carries [`PLANE_DOOR_AXIS`] and the crate it
/// links is a `busbar-plane-<key>` crate (the plane kind's naming, the one
/// `structure_lint::roots::declaration_home` reads a plane crate's key off). A door row linking a
/// crate of any other name declares no plane key here — it stays unlocatable, which is the loud
/// answer.
pub fn door_planes(manifest: &str) -> BTreeMap<String, String> {
    let doors: Vec<String> = manifest_rows(manifest, "package.metadata.busbar.linked-axes")
        .into_iter()
        .filter(|(_, axes)| axes.split_whitespace().any(|a| a == PLANE_DOOR_AXIS))
        .map(|(feature, _)| feature)
        .collect();
    manifest_rows(manifest, "package.metadata.busbar.linked")
        .into_iter()
        .filter(|(feature, _)| doors.contains(feature))
        .filter_map(|(_, krate)| {
            let key = krate.strip_prefix("busbar-plane-")?.to_string();
            Some((key, krate))
        })
        .collect()
}

/// Every plane key EXCEPT `llm` — `busbar-llm` owns the LLM dialect names and is never scanned as
/// a plane key by the grep gate, which bans the dialects there instead. Derived from
/// [`PLANE_KEYS`], so adding a plane in one place flows here.
pub fn plane_keys_protocol() -> Vec<&'static str> {
    PLANE_KEYS.iter().copied().filter(|k| *k != "llm").collect()
}

/// `crates/busbar-<k>/src` for every plane key, plus the `-codec` halves that still exist. The gate
/// scans SOURCES, not manifests, so a split that moved the bulk of a plane's files must be named
/// here or that bulk stops being scanned — which is the failure mode a split invites.
///
/// MCP HAS NO ROOT HERE AT ALL since P3 DEL-MCP (ARCHITECT 2026-10-05): the engine crate is deleted
/// and `mcp` left [`PLANE_KEYS`]. The paragraph below is the history of its `-codec` half.
///
/// MCP HAS NO `-codec` ROOT ANY MORE, and that is a decision rather than an omission.
/// `busbar-mcp-codec` dissolved (#39: no `busbar-*-codec` crate). Its `ProtocolDecl` and two
/// operation cells stayed with the engine at `crates/busbar-mcp/src/codec/`, which the
/// `crates/busbar-mcp/src` root above already walks. Its WIRE DIALECT went to
/// `crates/busbar-plane-mcp/src`, which is NOT listed here on purpose: a `busbar-plane-*` crate is
/// scanned by the PLANE-KIND regime instead — `gate.plugin_kinds.plane` in qa/construction.toml,
/// `plane_pricing_blindness::PLANE_CRATES`, kind-isolation's closure wall, and the crate's own
/// `tests/purity.rs` — which is strictly stronger than this legacy-engine needle list. Nothing went
/// unscanned; it changed which gate reads it.
///
/// LLM HAS NO `-codec` ROOT ANY MORE EITHER (owner ruling R7, 2026-09-27, #39): `busbar-llm-codec`
/// dissolved into `busbar-plane-llm`'s own `codec` module, a pure move. `crates/busbar-plane-llm/src`
/// is NOT listed here for the same reason `crates/busbar-plane-mcp/src` is not: it is scanned by the
/// PLANE-KIND regime instead, which already walks the whole crate directory, `codec` module
/// included.
///
/// VOICE HAS NO `-codec` ROOT ANY MORE EITHER, same ruling: `busbar-voice-codec` dissolved into
/// `busbar-plane-streaming`'s own `codec` module. `crates/busbar-plane-streaming/src` is NOT listed
/// here for the same reason — the PLANE-KIND regime already walks it whole.
pub fn plane_src_roots() -> Vec<String> {
    PLANE_KEYS
        .iter()
        .map(|k| format!("crates/busbar-{k}/src"))
        .collect()
}

/// The NEUTRAL (ABI-side) src roots — the crates a plane must never leak into and that must still
/// compile with every plane crate removed.
///
/// REMOVING A ROOT IS A NAMED CHANGE, NEVER A SILENT ONE. A root that is listed but absent means
/// the gate scans zero files of it and reports the passing answer to every ban, which is why the
/// walk refuses a missing root rather than narrowing itself.
/// ── WIDENED 2026-09-23: "THE NEUTRAL CRATES" WAS THREE OF FORTY-NINE ────────────────────────────
///
/// This list read `busbar-kernel`, `busbar-substrate-values`, `api` — and it is the denominator for
/// `plane-purity` (9 rows), `plane-transport-neutrality` (3 rows) and `plane-purity-strict`'s
/// ceilings. Two gates print the words "the neutral crates" and read three directories.
///
/// The 1.6.0 gate blind-spot census planted the identical line
/// `let _ = busbar_mcp::Thing;` in six crates and only the one in `busbar-kernel` was found; it then
/// planted `let rtp_port = 1;` in the same six and found one again. **`busbar-contract` was not on
/// the list** — the plugin-visible capability surface, the crate whose neutrality is the entire
/// promise of the plane ABI — and neither was `busbar-kernel-ledger`, which is the money path.
/// `docs/design/BUSBAR-1.6.0.md:2988` names this exactly: *a crate that is in no list is in no
/// gate.*
///
/// THE MEMBERSHIP RULE, so the next reader can decide an entry rather than copy one. A crate is
/// NEUTRAL when it must still compile with every plane crate deleted and must never name a protocol
/// by name. That admits the kernel and every crate it decomposed into, the ABI and contract crates,
/// the loader and the SDK, and the compiled-in cleanliness crates. It excludes, each for a reason
/// that is a property of the crate and not a preference:
///
/// * the five `busbar-plane-*` crates — the plane kind itself, scanned by the REVERSE side of
///   `plane-purity` through `kind_isolation::plane_kind_src_roots`;
/// * `busbar-llm`, `busbar-mcp`, `busbar-a2a`, `busbar-voice` and the two surviving `-codec` halves
///   — the legacy engines: naming a protocol is what they are for, and [`plane_src_roots`] is the
///   list that scans them;
/// * the plugin INSTANCES (`busbar-transport-*`, `store-*`, `secret-*`, `auth-*`, `hook*`,
///   `export-*`, `plane-example`) — an instance crate names its own protocol by definition;
/// * `crates/busbar` — the composition root constructs planes BY NAME (`root/plane_decisions.rs`),
///   which is the one place in the tree where naming one is the job.
///
/// STILL AN EXPLICIT LIST, AND THAT IS STILL A GAP. Deriving this by exclusion from the directories
/// on disk would close the enrolment hole for good — a new neutral crate would be in the gate on the
/// day it is created rather than on the day somebody remembers this function. It is not done here
/// because the [`crate::gates::plane_purity`] and [`crate::gates::plane_transport_neutrality`]
/// `:roots` rows are built on this list being a LIST: they refuse a listed root that is not on disk,
/// and a list derived from disk can never fail that way, which would trade one blind spot for a row
/// that cannot go red. PARK for the owner: derive-by-exclusion plus a separate census row that every
/// `crates/*/src` is either neutral or named non-neutral, so neither property is lost.
///
/// REMOVING A ROOT IS A NAMED CHANGE, NEVER A SILENT ONE. A root that is listed but absent means
/// the gate scans zero files of it and reports the passing answer to every ban, which is why the
/// walk refuses a missing root rather than narrowing itself.
pub fn neutral_src_roots() -> Vec<String> {
    [
        // The kernel and the crates it decomposed into. `busbar-core` was absorbed into
        // `busbar-kernel` (W4.a, 673ecdaaa); `busbar-substrate`'s engine followed it (W4.b P2,
        // 5fa320208) while its value leaves live in `busbar-substrate-values`. Both former roots
        // are gone from disk — scanning them now would read zero files and pass every ban silently.
        "crates/busbar-kernel/src",
        "crates/busbar-kernel-audit/src",
        "crates/busbar-kernel-breaker/src",
        "crates/busbar-kernel-egress/src",
        "crates/busbar-kernel-identity/src",
        // THE MONEY PATH. `plane-purity`'s claim is that a plane's name does not reach a neutral
        // crate; the one-book ledger is where a plane's name reaching in would become a price keyed
        // by plugin, which #77(1) bans outright.
        "crates/busbar-kernel-ledger/src",
        "crates/busbar-kernel-scope/src",
        "crates/busbar-kernel-wal/src",
        // THE ABI AND CONTRACT SURFACES. `busbar-contract` is the crate the census's demonstration
        // was about: it is what a plugin author compiles against, so a protocol noun in it is a
        // protocol noun in the published ABI.
        // (The plugin ABI and its SDK, the former `busbar-plugin` / `busbar-plugin-sdk`, are
        // `busbar-contract/src/abi` since the #84 merge, so this root covers them.)
        "crates/busbar-contract/src",
        // THE LOADER AND THE SDK — the TCB crates BUSBAR-1.6.0.md excuses by name from the plugin
        // KINDS, which is not the same as excusing them from neutrality: the loader dlopens every
        // kind and the SDK is what an author writes against.
        "crates/plugin-loader/src",
        // THE COMPILED-IN CLEANLINESS CRATES (DECISIONS #4/#5: admin and oauth2 are not a `control`
        // kind) and the remaining neutral leaves.
        "crates/busbar-core-admin/src",
        "crates/busbar-core-connector/src",
        "crates/busbar-core-oauth2/src",
        // `crates/busbar-unit-transport-key/src` is STRUCK (fold F14): the crate folded into
        // `busbar-kernel-identity` (`src/transport_key/`, #36/#40), and that module is deleted in
        // turn (TRANSPORT-STACK: TLS is core's connection security, `busbar-core-connector`, listed
        // above).
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[derive(Debug, Clone)]
pub enum PlaneRootError {
    Missing {
        plane: String,
        search_root: PathBuf,
        grammar: String,
    },
    Ambiguous {
        plane: String,
        candidates: Vec<PathBuf>,
    },
}

impl fmt::Display for PlaneRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlaneRootError::Missing {
                plane,
                search_root,
                grammar,
            } => write!(
                f,
                "PLANE-ROOT-MISSING: no directory named `{plane}` under {}/ carries its `{grammar}` \
                 declaration, and no `{PLANE_DOOR_AXIS}` row in {}/{DOOR_MANIFEST} links a \
                 `busbar-plane-{plane}` crate on disk (a door-only plane's declaration). Every rule \
                 that names this plane is now scanning NOTHING, and zero is the passing answer to a \
                 ban. If the plane legitimately moved somewhere this rule cannot see it, fix the \
                 search — do not delete the rows or lower a scan floor.",
                search_root.display(),
                search_root.display()
            ),
            PlaneRootError::Ambiguous { plane, candidates } => write!(
                f,
                "PLANE-ROOT-AMBIGUOUS: `{plane}` resolves to {} directories that each declare its \
                 grammar: {}. Two homes for one plane's declaration is a half-finished move or a \
                 duplicated plane; either way no caller can say which pair of trees it just \
                 compared. Resolve the tree.",
                candidates.len(),
                candidates
                    .iter()
                    .map(|c| c.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// The resolver, drivable over a throwaway tree — the search root and the grammar are both
/// parameters, so the refusals above are proven on purpose rather than as an import-time side
/// effect of whichever lint happened to source the file.
#[derive(Debug, Clone)]
pub struct PlaneRoots {
    search_root: PathBuf,
    grammar: String,
}

impl PlaneRoots {
    pub fn at(search_root: impl Into<PathBuf>) -> PlaneRoots {
        PlaneRoots {
            search_root: search_root.into(),
            grammar: PLANE_GRAMMAR.to_string(),
        }
    }

    pub fn grammar(mut self, grammar: impl Into<String>) -> PlaneRoots {
        self.grammar = grammar.into();
        self
    }

    pub fn resolve(&self, plane: &str) -> Result<PathBuf, PlaneRootError> {
        let mut named = Vec::new();
        find_dirs_named(&self.search_root, plane, &mut named);
        named.sort();
        named.dedup();

        let mut owned: Vec<PathBuf> = named
            .into_iter()
            .filter(|d| declares_here(d, &self.grammar))
            .collect();
        // A DOOR-ONLY PLANE: no grammar declaration claims it, so its door row is its declaration.
        if owned.is_empty() {
            owned.extend(self.door_home(plane));
        }
        self.judge(plane, owned)
    }

    /// The `src` of the crate the manifest's door row for `plane` links, when it is on disk and
    /// directly holds a source file. `None` for no door row, or a door row naming nothing here.
    pub fn door_home(&self, plane: &str) -> Option<PathBuf> {
        let manifest = std::fs::read_to_string(self.search_root.join(DOOR_MANIFEST)).ok()?;
        let krate = door_planes(&manifest).remove(plane)?;
        let src = self.search_root.join(krate).join("src");
        holds_source(&src).then_some(src)
    }

    /// The three-answers rule, over candidates somebody else located. THE SAME judgement the disk
    /// resolver reaches, called from both — a gate reading the tree through an overlay cannot use
    /// the `std::fs` walk above, and a second copy of "zero homes and two homes are both failures"
    /// is exactly the drift this module exists to end.
    pub fn judge(&self, plane: &str, owned: Vec<PathBuf>) -> Result<PathBuf, PlaneRootError> {
        match owned.len() {
            1 => Ok(owned.into_iter().next().expect("len == 1")),
            0 => Err(PlaneRootError::Missing {
                plane: plane.to_string(),
                search_root: self.search_root.clone(),
                grammar: self.grammar.clone(),
            }),
            _ => Err(PlaneRootError::Ambiguous {
                plane: plane.to_string(),
                candidates: owned,
            }),
        }
    }

    /// Resolve every key, collecting each failure rather than stopping at the first — the caller
    /// wants to see every unlocatable plane in one run.
    pub fn resolve_all(&self, planes: &[&str]) -> (Vec<(String, PathBuf)>, Vec<PlaneRootError>) {
        let mut ok = Vec::new();
        let mut errs = Vec::new();
        for p in planes {
            match self.resolve(p) {
                Ok(dir) => ok.push(((*p).to_string(), dir)),
                Err(e) => errs.push(e),
            }
        }
        (ok, errs)
    }
}

fn find_dirs_named(dir: &Path, name: &str, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if base == "target" || base == ".git" {
            continue;
        }
        if base == name {
            out.push(path.clone());
        }
        find_dirs_named(&path, name, out);
    }
}

/// A directory DIRECTLY holding a `*.rs` — a door crate's `src` with its `lib.rs`.
fn holds_source(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|rd| {
        rd.filter_map(|e| e.ok())
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
    })
}

/// A candidate must DIRECTLY hold a `*.rs` declaring the grammar — not merely reference it three
/// directories over.
fn declares_here(dir: &Path, grammar: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if std::fs::read_to_string(&path)
            .map(|s| s.contains(grammar))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "[package.metadata.busbar.linked]\n\
        proto-llm = \"busbar-llm\"\n\
        llm-on-driver = \"busbar-plane-llm\"\n\
        plane-mcp-door = \"busbar-plane-mcp\"\n\
        transport-tcp = \"busbar-transport-tcp\"\n\n\
        [package.metadata.busbar.linked-axes]\n\
        proto-llm = \"plane claims\"\n\
        llm-on-driver = \"plane-door\"\n\
        plane-mcp-door = \"plane-door\" # the door\n\
        transport-tcp = \"transport transport-door\"\n";

    /// A door row is read by its axis, and its key off the plane crate's name; a row on any other
    /// axis (`transport-door` included) declares no plane.
    #[test]
    fn a_plane_door_row_declares_its_plane_crate() {
        let doors = door_planes(MANIFEST);
        assert_eq!(
            doors.get("mcp").map(String::as_str),
            Some("busbar-plane-mcp")
        );
        assert_eq!(
            doors.get("llm").map(String::as_str),
            Some("busbar-plane-llm")
        );
        assert_eq!(doors.len(), 2, "{doors:?}");
    }

    /// The same row without the `plane-door` axis is no declaration.
    #[test]
    fn a_row_off_the_door_axis_declares_nothing() {
        let off = MANIFEST.replace(
            "plane-mcp-door = \"plane-door\"",
            "plane-mcp-door = \"plane\"",
        );
        assert!(!door_planes(&off).contains_key("mcp"));
    }
}
