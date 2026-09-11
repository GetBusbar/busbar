//! THE PLANE-KEYS / PLANE-ROOTS CONTRACT — `scripts/plane-keys.sh` (WHICH planes exist) and
//! `scripts/plane-roots.sh` (WHERE a plane lives) as one Rust module, so no gate restates the plane
//! set or guesses its addresses.
//!
//! The resolution rule is deliberately mechanical and unchanged: a plane's root is the directory
//! that OWNS it — found by name, then narrowed by ownership. A name match is not an ownership
//! claim, because the wire-codec split gives a plane a second same-named directory
//! (`busbar-a2a-codec/src/a2a/` beside `busbar-a2a/src/a2a/`) that holds bytes-on-the-wire and
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

/// `crates/busbar-<k>/src` for every plane key, plus the `-codec` halves. The gate scans SOURCES,
/// not manifests, so a split that moved the bulk of a plane's files must be named here or that
/// bulk stops being scanned — which is the failure mode a split invites.
pub fn plane_src_roots() -> Vec<String> {
    let mut out: Vec<String> = PLANE_KEYS
        .iter()
        .map(|k| format!("crates/busbar-{k}/src"))
        .collect();
    out.push("crates/busbar-llm-codec/src".to_string());
    out.push("crates/busbar-mcp-codec/src".to_string());
    out.push("crates/busbar-a2a-codec/src".to_string());
    out.push("crates/busbar-voice-codec/src".to_string());
    out
}

/// The NEUTRAL (ABI-side) src roots — the crates a plane must never leak into and that must still
/// compile with every plane crate removed.
///
/// REMOVING A ROOT IS A NAMED CHANGE, NEVER A SILENT ONE. A root that is listed but absent means
/// the gate scans zero files of it and reports the passing answer to every ban, which is why the
/// walk refuses a missing root rather than narrowing itself.
///
/// THE KERNEL AND THE UNITS ARE NEUTRAL TOO, and this list did not say so. The four roots below the
/// kernel are the RETIRING crates — the ones a plane must not leak into on the way out. The kernel
/// and the fourteen `busbar-unit-*` crates are what those crates are being retired INTO, and they
/// are the strictest neutral surface in the tree: the kernel knows its plugin KINDS and nothing
/// past them, and every core step is served once by a kind-neutral unit. A gate that scanned the
/// crates on their way out and not the crates they were landing in was watching the wrong end of
/// the move, and it printed green the whole way.
pub fn neutral_src_roots() -> Vec<String> {
    let mut out = vec![
        "crates/busbar-core/src".to_string(),
        "crates/busbar-substrate/src".to_string(),
        "crates/busbar-substrate-values/src".to_string(),
        "crates/api/src".to_string(),
        "crates/busbar-kernel/src".to_string(),
    ];
    out.extend(
        UNIT_KEYS
            .iter()
            .map(|k| format!("crates/busbar-unit-{k}/src")),
    );
    out
}

/// The units whose sources this gate scans, by the segment that names the step each answers.
///
/// Spelled out rather than globbed for the reason the roots above are: a glob that stops matching
/// is a scan that quietly narrows, and the walk can only refuse a root it was told to expect.
///
/// TWO OF THE FOURTEEN ARE NOT HERE YET, AND THIS IS WHERE THEY ARE OWED. `busbar-unit-trust` and
/// `busbar-unit-ledger` carry vendor-named FIXTURE strings in their test code — a vendor hostname
/// a host-normaliser is judged against, a vendor meter label a migration is keyed on. Measured on
/// this tree they are worth seven DIALECT hits and seven KEY hits in the `--strict` (test-scope)
/// pass, which is seven and seven above ceilings that only go down. Adding the two roots before
/// those fixtures are neutral would force both ceilings UP, which is the move the ratchet exists to
/// refuse. Neutralising the fixtures is a landing in those crates, not in this one; the two lines
/// go in here on the commit that makes them.
const UNIT_KEYS: [&str; 12] = [
    "admission",
    "audit",
    "auth",
    "breaker",
    "cost",
    "egress",
    "egress-auth",
    "scope",
    "transport-key",
    "usage",
    "verbs",
    "wal",
];

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
