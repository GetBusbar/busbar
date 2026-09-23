//! THE PLANE-KEYS / PLANE-ROOTS CONTRACT — `scripts/plane-keys.sh` (WHICH planes exist) and
//! `scripts/plane-roots.sh` (WHERE a plane lives) as one Rust module, so no gate restates the plane
//! set or guesses its addresses.
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

use std::fmt;
use std::path::{Path, PathBuf};

/// The canonical order is the doctrine order: the three original protocols, then voice (Plane 4).
pub const PLANE_KEYS: [&str; 4] = ["llm", "mcp", "a2a", "voice"];

/// The default ownership grammar. Overridable for a fixture tree, the way
/// `PLANE_ROOTS_GRAMMAR` is in the shell.
pub const PLANE_GRAMMAR: &str = "pub const PLANE_DECL";

/// Every plane key EXCEPT `llm` — `busbar-llm` owns the LLM dialect names and is never scanned as
/// a plane key by the grep gate, which bans the dialects there instead. Derived from
/// [`PLANE_KEYS`], so adding a plane in one place flows here.
pub fn plane_keys_protocol() -> Vec<&'static str> {
    PLANE_KEYS.iter().copied().filter(|k| *k != "llm").collect()
}

/// The PROTOCOL keys except `self`, canonical order.
pub fn plane_keys_other(self_key: &str) -> Vec<&'static str> {
    plane_keys_protocol()
        .into_iter()
        .filter(|k| *k != self_key)
        .collect()
}

/// `crates/busbar-<k>/src` for every plane key, plus the `-codec` halves that still exist. The gate
/// scans SOURCES, not manifests, so a split that moved the bulk of a plane's files must be named
/// here or that bulk stops being scanned — which is the failure mode a split invites.
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
pub fn plane_src_roots() -> Vec<String> {
    let mut out: Vec<String> = PLANE_KEYS
        .iter()
        .map(|k| format!("crates/busbar-{k}/src"))
        .collect();
    out.push("crates/busbar-llm-codec/src".to_string());
    out.push("crates/busbar-voice-codec/src".to_string());
    out
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
/// The census in `docs/design/1.6.0-gate-blindspots.md` planted the identical line
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
/// * `crates/busbar` — the composition root constructs planes BY NAME (`root/plane_decision.rs`),
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
        "crates/busbar-kernel-budget/src",
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
        "crates/busbar-contract/src",
        "crates/busbar-plugin/src",
        "crates/busbar-substrate-values/src",
        "crates/api/src",
        // THE LOADER AND THE SDK — the TCB crates ARCHITECTURE.md excuses by name from the plugin
        // KINDS, which is not the same as excusing them from neutrality: the loader dlopens every
        // kind and the SDK is what an author writes against.
        "crates/plugin-loader/src",
        "crates/plugin-sdk/src",
        // THE COMPILED-IN CLEANLINESS CRATES (DECISIONS #4/#5: admin and oauth2 are not a `control`
        // kind) and the remaining neutral leaves.
        "crates/busbar-core-admin/src",
        "crates/busbar-core-connsec/src",
        "crates/busbar-oauth2/src",
        "crates/busbar-timing/src",
        "crates/busbar-unit-transport-key/src",
        "crates/secret-ref/src",
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
                 declaration. Every rule that names this plane is now scanning NOTHING, and zero is \
                 the passing answer to a ban. If the plane legitimately moved somewhere this rule \
                 cannot see it, fix the search — do not delete the rows or lower a scan floor.",
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

        let owned: Vec<PathBuf> = named
            .into_iter()
            .filter(|d| declares_here(d, &self.grammar))
            .collect();
        self.judge(plane, owned)
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
