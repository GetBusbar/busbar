//! The pure `(method, path) -> verb` match over the closed verb table in [`crate::verb`].
//!
//! The rows (the 66 of the pinned 1.5.5 `openapi-1.5.5.json` fixture, the 11 new 1.6.0 verbs, the
//! five ledger views and the three audit-chain reads) live in [`crate::verb::TABLE`]; this module
//! only matches request lines against them. Five verbs the design once named left 1.6.0 by the
//! owner's 2026-09-08 ruling, and four more by #77(9) (owner answer Q71(1)); none has a row: their
//! paths are unmounted.

use crate::verb::{admin_rows, VerbRow, VerbScope};
use busbar_contract::ids::OpClassId;

/// The operation class every read-only verb prices under.
///
/// The design's admin row prices every verb the same (a flat, zero-priced `count` class, itself
/// kernel-reserved), so the read/write split exists only to keep the audit step's
/// dispute check meaningful (a verb whose scope tier changed between resolution and audit is a real
/// finding, not noise) and to mirror the closed 34/32 `ReadOnly`/`Full` split the design pins.
pub(crate) const OP_READ: OpClassId = OpClassId::new("admin_read");
/// The operation class every mutating verb prices under. See [`OP_READ`].
pub(crate) const OP_WRITE: OpClassId = OpClassId::new("admin_write");

/// Whether a concrete path segment satisfies a template segment, capturing the template's `{name}`
/// against the concrete value when it is a variable segment.
///
/// An EMPTY concrete segment never satisfies a `{name}`: `/keys/` is not `/keys/{id}` with an empty
/// id, it is a path the router this surface has always been mounted on does not carry at all.
fn segment_matches<'p>(
    template: &'static str,
    concrete: &'p str,
) -> Option<Option<(&'static str, &'p str)>> {
    if let Some(name) = template.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        if concrete.is_empty() {
            return None;
        }
        Some(Some((name, concrete)))
    } else if template == concrete {
        Some(None)
    } else {
        None
    }
}

/// Match a concrete path against a `{param}`-templated path, returning the captured parameters in
/// template order when every segment matches and the segment counts are equal (this plane's paths
/// never use a trailing wildcard, so a length mismatch is always a non-match).
///
/// An empty segment is a SEGMENT, and the split keeps it. Dropping empties normalised
/// `/api/v1/admin/keys/abc/` and `/api/v1//admin/keys/abc` onto the row for
/// `/api/v1/admin/keys/{id}` — so a trailing slash decoded as a revoke on a surface whose own
/// router answers neither path. What the table declares is the only thing it answers.
fn match_path<'p>(
    template: &'static str,
    concrete: &'p str,
) -> Option<Vec<(&'static str, &'p str)>> {
    let mut params = Vec::new();
    let mut t_segs = template.split('/');
    let mut c_segs = concrete.split('/');
    loop {
        match (t_segs.next(), c_segs.next()) {
            (None, None) => return Some(params),
            (Some(t), Some(c)) => {
                if let Some(pair) = segment_matches(t, c)? {
                    params.push(pair);
                }
            }
            _ => return None,
        }
    }
}

/// The part of a request target that names an operation: everything before the first `?` or `#`.
///
/// A query string and a fragment are arguments TO an operation, never part of its identity, so the
/// cut belongs at the one place every caller reaches rather than at each of them. It lived at
/// `resolve` alone for a release, which meant a second caller matched a paged read's raw target
/// against the templates and found no row at all.
fn operation_target(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// Find the verb a method and concrete path resolve to, and the path parameters it carries.
///
/// Total over the closed table: a linear scan of its rows, each a handful of segment
/// comparisons. This is a cost paid once per admin unit, not a hot per-byte path.
pub(crate) fn find_verb<'p>(
    method: &str,
    path: &'p str,
) -> Option<(&'static VerbRow, Vec<(&'static str, &'p str)>)> {
    let path = operation_target(path);
    admin_rows().find_map(|entry| {
        if entry.method != method {
            return None;
        }
        match_path(entry.path, path).map(|params| (entry, params))
    })
}

/// One row of the closed table, as the composition root reads it.
///
/// The table's own [`VerbRow`] is entitled to change how it stores a row; what a root binds against
/// is what a row MEANS. Four fields, all `&'static`: the
/// operation's name, the method and templated path it was extracted under, and which side of the
/// closed read-only/full split it falls on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedVerb {
    /// The operation name — the snake-case `operationId` of the pinned tag for the 66, and the
    /// design's own spelling for the 8.
    pub verb: &'static str,
    /// The HTTP method the table row was extracted under.
    pub method: &'static str,
    /// The templated path, `{param}` segments and all.
    pub template: &'static str,
    /// Whether the operation is on the read-only side of the closed split.
    pub read_only: bool,
}

impl ResolvedVerb {
    /// The row a table entry resolves to.
    fn of(entry: &VerbRow) -> Self {
        Self {
            verb: entry.name,
            method: entry.method,
            template: entry.path,
            read_only: entry.scope == VerbScope::ReadOnly,
        }
    }

    /// The operation class this row prices under.
    #[must_use]
    pub fn op_class(&self) -> OpClassId {
        if self.read_only {
            OP_READ
        } else {
            OP_WRITE
        }
    }
}

/// Resolve a concrete request line to the closed table's row for it.
///
/// THE ONE ENTRY POINT. This is how the administrative listener's mount asks which row a method
/// and path name — twice per request, once to decide whether the closed table declares the pair at
/// all (a pair it does not declare goes straight to the surface that already answers it, never to
/// the loop) and once, at the admin units' own decode step, to name the kernel verb the unit is a
/// destination for. A query string is not part of the operation's identity — `GET /audit?limit=4`
/// and `GET /audit` are one row — so [`find_verb`] cuts it before the match rather than carrying it
/// in.
///
/// `None` means the table does not declare the pair, which is this surface's answer for an
/// unsupported operation and never an invitation to guess one.
#[must_use]
pub fn resolve(method: &str, path: &str) -> Option<ResolvedVerb> {
    find_verb(method, path).map(|(entry, _params)| ResolvedVerb::of(entry))
}

/// The rung the operation NAMED `name` requires, or `None` when the closed table names no such
/// operation — the per-verb allow-list's vocabulary (#77(9), OWNER-LOCKED,
/// `docs/design/BUSBAR-1.6.0.md` l.2279: `role_bindings.<provider>.<role>.verbs: [ … ]` names
/// operations by exactly the name a row carries here). Handed to the kernel through
/// `busbar_kernel::admin::seam::AdminVerbTable`, which validation and the admin gate read.
#[must_use]
pub fn named_rung(name: &str) -> Option<busbar_contract::authz::Scope> {
    use busbar_contract::authz::Scope;
    admin_rows().find(|entry| entry.name == name).map(|entry| {
        if entry.scope == VerbScope::ReadOnly {
            Scope::ReadOnly
        } else {
            Scope::Full
        }
    })
}

/// The operation NAME a request line resolves to — [`resolve`]'s row, by the name an allow-list
/// spells it with (see [`named_rung`]).
#[must_use]
pub fn name_at(method: &str, path: &str) -> Option<&'static str> {
    resolve(method, path).map(|resolved| resolved.verb)
}

/// Every row the closed table declares, in the order the table holds them.
///
/// The generated 1.5.5 rows first, then the 1.6.0 additions — so a caller counting them sees the
/// 66, the 9 and the 5 as three runs rather than as one undifferentiated list.
#[must_use]
pub fn table() -> Vec<ResolvedVerb> {
    admin_rows().map(ResolvedVerb::of).collect()
}

#[cfg(test)]
#[path = "tests/verbs.rs"]
mod tests;
