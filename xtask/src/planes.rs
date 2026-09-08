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

/// THE PLANE KEYS THE DIRECTORY-RESOLVED GREP GATES SCAN, IN ONE PLACE.
///
/// `blocking-ffi`, `response-header` and `settings-leak` each add the plane homes to a fixed root
/// list before scanning. This list used to be written out three times — plus a fourth copy as
/// `structure_lint::roots::PLANES` — so adding a plane meant editing four independent lists, and
/// missing three of them left those gates reporting CLEAN over a scan set that never contained the
/// new plane. Zero files is the passing answer to every ban, so the drift is silent and it is a
/// false green.
///
/// WHY THIS IS NOT [`plane_keys_protocol`]. A key only belongs here if [`PlaneRoots::resolve`] can
/// find its home, and that search wants a DIRECTORY NAMED FOR THE KEY holding a `.rs` that declares
/// the grammar. `mcp` and `a2a` have one (`busbar-mcp/src/mcp`, `busbar-a2a/src/a2a`); `llm` and
/// `voice` declare `PLANE_DECL` in their crate's `src/lib.rs`, whose directory is `src`, so they
/// resolve to `Missing`. Adding either here without giving it such a directory turns all three
/// gates red — which is why the case in `xtask/tests/infra.rs` puts every entry to the tree rather
/// than trusting the list.
pub const PLANE_SCAN_KEYS: &[&str] = &["mcp", "a2a"];

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
pub fn neutral_src_roots() -> Vec<String> {
    vec![
        "crates/busbar-core/src".to_string(),
        "crates/busbar-substrate/src".to_string(),
        "crates/busbar-substrate-values/src".to_string(),
        "crates/api/src".to_string(),
    ]
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
    /// A directory in the search could not be read, so the candidate count is a floor rather than a
    /// count. Every read behind that count used to be discarded, and every one of those discards
    /// UNDERCOUNTS — which is the one direction that turns a refusal into a pass, because two homes
    /// minus one unreadable candidate answers `Ok(one home)`.
    Unreadable {
        plane: String,
        path: PathBuf,
        message: String,
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
            PlaneRootError::Unreadable {
                plane,
                path,
                message,
            } => write!(
                f,
                "PLANE-ROOT-UNREADABLE: resolving `{plane}` could not read {} ({message}). The \
                 answer to this search is a COUNT of the directories that declare the plane, and a \
                 candidate nobody could read only ever lowers it — two homes minus one unreadable \
                 candidate reads as one home, and the ambiguity that should have been reported \
                 resolves silently. Fix the permissions or the tree; a count taken over an \
                 incomplete search is not a count.",
                path.display()
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
        let unreadable = |path: &Path, message: String| PlaneRootError::Unreadable {
            plane: plane.to_string(),
            path: path.to_path_buf(),
            message,
        };
        let mut named = Vec::new();
        find_dirs_named(&self.search_root, plane, &mut named)
            .map_err(|(p, m)| unreadable(&p, m))?;
        named.sort();
        named.dedup();

        let mut owned: Vec<PathBuf> = Vec::new();
        for d in named {
            if declares_here(&d, &self.grammar).map_err(|(p, m)| unreadable(&p, m))? {
                owned.push(d);
            }
        }
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

/// THE SCAN ROOTS FOR A DIRECTORY-RESOLVED GREP GATE: the caller's fixed roots plus the resolved
/// plane homes, relative to the workspace root.
///
/// This body was written out three times, byte for byte, in `blocking_ffi`, `response_header` and
/// `settings_leak`. Three copies of a resolver is three chances for one of them to be updated and
/// the others not, and the failure that produces is a gate that keeps reporting clean over a scan
/// set that quietly stopped including a plane.
///
/// IT TAKES PATHS, NOT A `Ctx`. This module has no `use crate::` line and is the one every gate
/// imports; making it depend on a gate-facing type would invert that. The two things the body
/// wanted from the context were `cx.abs("crates")` and `cx.root()`, so it takes those.
pub fn resolved_scan_roots(
    crates_dir: &Path,
    workspace_root: &Path,
    fixed: &[&str],
    keys: &[&str],
) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = fixed.iter().map(|r| (*r).to_string()).collect();
    let (ok, errs) = PlaneRoots::at(crates_dir).resolve_all(keys);
    if !errs.is_empty() {
        return Err(errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    for (_, dir) in ok {
        let rel = dir
            .strip_prefix(workspace_root)
            .map_err(|_| format!("{} is not under the workspace root", dir.display()))?;
        out.push(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(out)
}

/// The failure both searches below report: the path that could not be read, and why.
type ReadFailure = (PathBuf, String);

/// EVERY READ HERE IS A REFUSAL WHEN IT FAILS, because every one of them feeds a COUNT and every
/// discarded read lowers that count. `Missing` and `Ambiguous` are both decided by counting, so an
/// undercount reads as "fewer homes than there are" — which turns the two-home refusal into a
/// silent single answer and the no-home refusal into nothing at all.
fn find_dirs_named(dir: &Path, name: &str, out: &mut Vec<PathBuf>) -> Result<(), ReadFailure> {
    let rd = std::fs::read_dir(dir).map_err(|e| (dir.to_path_buf(), e.to_string()))?;
    for entry in rd {
        let entry = entry.map_err(|e| (dir.to_path_buf(), e.to_string()))?;
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
        find_dirs_named(&path, name, out)?;
    }
    Ok(())
}

/// A candidate must DIRECTLY hold a `*.rs` declaring the grammar — not merely reference it three
/// directories over.
///
/// An unreadable candidate is NOT "a candidate that does not declare the plane". `false` here is a
/// claim about the file's contents, and a file nobody read supports no claim about its contents.
fn declares_here(dir: &Path, grammar: &str) -> Result<bool, ReadFailure> {
    let rd = std::fs::read_dir(dir).map_err(|e| (dir.to_path_buf(), e.to_string()))?;
    for entry in rd {
        let entry = entry.map_err(|e| (dir.to_path_buf(), e.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| (path.clone(), e.to_string()))?;
        if text.contains(grammar) {
            return Ok(true);
        }
    }
    Ok(false)
}
