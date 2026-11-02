//! The pure `(method, path) -> verb` match over the closed verb table in [`crate::verb`].

use crate::verb::{admin_rows, VerbRow, VerbScope};
use busbar_contract::ids::OpClassId;

/// The operation class every read-only verb prices under.

pub(crate) const OP_READ: OpClassId = OpClassId::new("admin_read");
/// The operation class every mutating verb prices under. See [`OP_READ`].
pub(crate) const OP_WRITE: OpClassId = OpClassId::new("admin_write");

/// Whether a concrete path segment satisfies a template segment, capturing the template's `{name}`

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

fn operation_target(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// Find the verb a method and concrete path resolve to, and the path parameters it carries.

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

#[must_use]
pub fn resolve(method: &str, path: &str) -> Option<ResolvedVerb> {
    find_verb(method, path).map(|(entry, _params)| ResolvedVerb::of(entry))
}

/// The rung the operation NAMED `name` requires, or `None` when the closed table names no such

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

#[must_use]
pub fn name_at(method: &str, path: &str) -> Option<&'static str> {
    resolve(method, path).map(|resolved| resolved.verb)
}

/// Every row the closed table declares, in the order the table holds them.

#[must_use]
pub fn table() -> Vec<ResolvedVerb> {
    admin_rows().map(ResolvedVerb::of).collect()
}

#[cfg(test)]
#[path = "tests/verbs.rs"]
mod tests;
