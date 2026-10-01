//! THE MAINTENANCE DIFF between two locks of one dialect: paths REMOVED and ADDED, a PROBABLE RENAME
//! where a removed path and an added path share a parent and a type (its children follow it and
//! are folded into the one line), and enum values or union tags gained or lost.

use std::collections::{BTreeMap, BTreeSet};

use super::walk::Entry;
use super::Lock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Removed {
        id: String,
        ty: String,
    },
    Added {
        id: String,
        ty: String,
    },
    Rename {
        id: String,
        to: String,
        ty: String,
        children: usize,
    },
    Type {
        id: String,
        from: String,
        to: String,
    },
    /// `what` is `enum` or `tags`; `gained` says which way.
    Values {
        id: String,
        what: &'static str,
        gained: bool,
        values: Vec<String>,
    },
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::Removed { id, ty } => write!(f, "REMOVED  {id}  ({ty})"),
            Change::Added { id, ty } => write!(f, "ADDED    {id}  ({ty})"),
            Change::Rename {
                id,
                to,
                ty,
                children,
            } => write!(
                f,
                "RENAME?  {id} -> {to}  ({ty}, same parent; {children} child path(s) moved with it)"
            ),
            Change::Type { id, from, to } => write!(f, "TYPE     {id}  {from} -> {to}"),
            Change::Values {
                id,
                what,
                gained,
                values,
            } => write!(
                f,
                "{}{}  {id}  {}",
                if *what == "enum" { "ENUM" } else { "TAGS" },
                if *gained { "+   " } else { "-   " },
                values.join(", ")
            ),
        }
    }
}

/// The parent of `path` among `keys`: the longest proper prefix that is itself a path and ends at
/// a segment boundary (`.`, `[`, `{`). Union tags may contain dots (`type=response.created`), so
/// the parent is found by membership, not by splitting.
pub fn parent<'k>(path: &str, keys: &'k BTreeSet<&str>) -> &'k str {
    let mut best = "";
    for (i, c) in path.char_indices() {
        if matches!(c, '.' | '[' | '{') {
            if let Some(k) = keys.get(&path[..i]) {
                best = *k;
            }
        }
    }
    best
}

fn value_texts(e: &Entry) -> BTreeSet<String> {
    e.enums.iter().map(|v| v.to_string()).collect()
}

fn set_change(
    out: &mut Vec<Change>,
    id: &str,
    what: &'static str,
    old: &BTreeSet<String>,
    new: &BTreeSet<String>,
) {
    let gained: Vec<String> = new.difference(old).cloned().collect();
    let lost: Vec<String> = old.difference(new).cloned().collect();
    if !gained.is_empty() {
        out.push(Change::Values {
            id: id.to_string(),
            what,
            gained: true,
            values: gained,
        });
    }
    if !lost.is_empty() {
        out.push(Change::Values {
            id: id.to_string(),
            what,
            gained: false,
            values: lost,
        });
    }
}

fn under(path: &str, root: &str) -> Option<String> {
    let rest = path.strip_prefix(root)?;
    rest.starts_with(['.', '[', '{']).then(|| rest.to_string())
}

pub fn diff(old: &Lock, new: &Lock) -> Vec<Change> {
    let empty = BTreeMap::new();
    let mut out = Vec::new();
    let dirs: BTreeSet<&String> = old.dirs.keys().chain(new.dirs.keys()).collect();
    for dir in dirs {
        let a = old.dirs.get(dir).unwrap_or(&empty);
        let b = new.dirs.get(dir).unwrap_or(&empty);
        let id = |p: &str| format!("{}/{dir}/{p}", new.dialect);
        let a_keys: BTreeSet<&str> = a.keys().map(String::as_str).collect();
        let b_keys: BTreeSet<&str> = b.keys().map(String::as_str).collect();
        let mut removed: BTreeSet<&str> = a_keys.difference(&b_keys).copied().collect();
        let mut added: BTreeSet<&str> = b_keys.difference(&a_keys).copied().collect();

        // PROBABLE RENAMES: a removed path with exactly one unpaired added sibling of its type.
        let candidates: Vec<&str> = removed.iter().copied().collect();
        for r in candidates {
            if !removed.contains(r) {
                continue;
            }
            let rp = parent(r, &a_keys);
            let same: Vec<&str> = added
                .iter()
                .copied()
                .filter(|x| parent(x, &b_keys) == rp && b[*x].ty == a[r].ty)
                .collect();
            let [to] = same.as_slice() else { continue };
            let to = *to;
            let moved: Vec<(&str, String)> = removed
                .iter()
                .filter_map(|c| under(c, r).map(|rest| (*c, format!("{to}{rest}"))))
                .filter(|(_, t)| added.contains(t.as_str()))
                .collect();
            for (c, t) in &moved {
                removed.remove(c);
                added.remove(t.as_str());
            }
            removed.remove(r);
            added.remove(to);
            out.push(Change::Rename {
                id: id(r),
                to: to.to_string(),
                ty: a[r].ty.clone(),
                children: moved.len(),
            });
        }
        out.extend(removed.iter().map(|p| Change::Removed {
            id: id(p),
            ty: a[*p].ty.clone(),
        }));
        out.extend(added.iter().map(|p| Change::Added {
            id: id(p),
            ty: b[*p].ty.clone(),
        }));
        for p in a_keys.intersection(&b_keys).copied() {
            let (x, y) = (&a[p], &b[p]);
            if x.ty != y.ty {
                out.push(Change::Type {
                    id: id(p),
                    from: x.ty.clone(),
                    to: y.ty.clone(),
                });
            }
            set_change(&mut out, &id(p), "enum", &value_texts(x), &value_texts(y));
            let (tx, ty): (BTreeSet<String>, BTreeSet<String>) = (
                x.tags.iter().cloned().collect(),
                y.tags.iter().cloned().collect(),
            );
            set_change(&mut out, &id(p), "tags", &tx, &ty);
        }
    }
    out
}
