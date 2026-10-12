//! THE NEUTRAL SIDE OF THE CRATE CENSUS — the twin of [`super::plane_kind_src_roots`].
//!
//! Read by `plane-transport-neutrality`, whose scanned population this is.

use std::collections::{BTreeMap, BTreeSet};

use super::{census, is_tree_crate, CrateInfo, Family, NEUTRAL_LEGACY};
use crate::ctx::{Ctx, WalkSpec};

/// THE NEUTRAL SIDE OF THE CENSUS: every crate of this tree (`crates/<dir>`), sorted into the
/// three answers the kind table can give about it. See [`neutral_census`].
#[derive(Debug, Clone, Default)]
pub struct NeutralCensus {
    /// `crates/<dir>/src` of every crate whose kind is [`Family::Neutral`] (and the
    /// [`NEUTRAL_LEGACY`] crate), sorted — the neutral population a neutrality scan reads.
    pub neutral: Vec<String>,
    /// The entries of [`Self::neutral`] that hold no file on disk: a census-neutral crate whose
    /// manifest is present and whose source is not. Scanned, it would be zero files.
    pub sourceless: Vec<String>,
    /// `(crates/<dir>, family)` for every crate the kind table names NON-neutral: the plane family
    /// (planes and the retiring legacy engines) and the transports.
    pub non_neutral: Vec<(String, &'static str)>,
    /// `(crates/<dir>, why)` for every crate the census cannot classify: a `crates/<dir>/src` no
    /// manifest with a package name governs, a name that resolves to no kind, or a name two kinds
    /// claim at one precedence. Such a crate is in NO population, so it is in no scan.
    pub unclassified: Vec<(String, String)>,
}

/// THE NEUTRAL CRATE POPULATION, DERIVED FROM THE KIND TABLE — the twin of
/// [`super::plane_kind_src_roots`] on the other side of the plane ABI.
///
/// `planes::neutral_src_roots` is a hand list, and a new neutral crate was in no neutrality scan
/// until somebody remembered it. Here the census answers instead: every directory `crates/<dir>`
/// that carries a manifest of this tree, or a `src/` with any file in it, is read off the kind
/// table, and is either NEUTRAL (scanned), NAMED non-neutral by its family (plane, transport), or
/// UNCLASSIFIED — which a caller must refuse, because a crate in no population is a crate in no
/// gate. A neutral crate named tomorrow is scanned tomorrow.
///
/// Read through the context, so a planted manifest and a planted `src/` count exactly as real ones.
/// Pinned plugin checkouts are not mounted here: the population is the tree's own `crates/`.
pub fn neutral_census(cx: &Ctx) -> Result<NeutralCensus, String> {
    let crates = census(cx)?;
    // Every `crates/<dir>` that holds any file under `src/`, overlay included.
    let listed = cx
        .list(&WalkSpec::new(["crates"]).allow_empty())
        .map_err(|e| e.to_string())?;
    let mut with_src: BTreeSet<String> = BTreeSet::new();
    for p in &listed {
        let s = p.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() >= 4 && parts[0] == "crates" && parts[2] == "src" {
            with_src.insert(format!("crates/{}", parts[1]));
        }
    }
    let mut by_dir: BTreeMap<String, &CrateInfo> = BTreeMap::new();
    for c in crates.iter().filter(|c| is_tree_crate(&c.manifest)) {
        by_dir.insert(c.dir.clone(), c);
    }
    let mut dirs: BTreeSet<String> = by_dir.keys().cloned().collect();
    dirs.extend(with_src.iter().cloned());

    let mut out = NeutralCensus::default();
    for dir in dirs {
        let Some(c) = by_dir.get(&dir) else {
            out.unclassified.push((
                dir.clone(),
                format!(
                    "{dir}/src holds source but no `{dir}/Cargo.toml` with a [package] name \
                     governs it, so the census cannot classify it"
                ),
            ));
            continue;
        };
        if c.kind.is_none() && c.name != NEUTRAL_LEGACY {
            let why = if c.ambiguous.is_empty() {
                format!(
                    "`{}` resolves to no kind in the kind table, so the census cannot classify it",
                    c.name
                )
            } else {
                format!(
                    "`{}` is claimed by {} kinds at one precedence ({}), so the census cannot \
                     classify it",
                    c.name,
                    c.ambiguous.len(),
                    c.ambiguous.join(", ")
                )
            };
            out.unclassified.push((dir, why));
            continue;
        }
        match c.family {
            Family::Neutral => {}
            Family::Plane if c.name == NEUTRAL_LEGACY => {}
            Family::Plane => {
                out.non_neutral.push((dir, "plane"));
                continue;
            }
            Family::Transport => {
                out.non_neutral.push((dir, "transport"));
                continue;
            }
        }
        let root = format!("{dir}/src");
        if !with_src.contains(&dir) {
            out.sourceless.push(root.clone());
        }
        out.neutral.push(root);
    }
    Ok(out)
}

/// The census-neutral source roots alone — [`neutral_census`]'s `neutral`. `Err` when the census
/// classes no crate neutral, since an empty population is the passing answer to every ban.
pub fn neutral_kind_src_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let out = neutral_census(cx)?.neutral;
    if out.is_empty() {
        return Err(
            "no crate under crates/ resolves to a neutral-family kind — the neutral population is \
             empty, and an empty population is the passing answer to every ban"
                .to_string(),
        );
    }
    Ok(out)
}
