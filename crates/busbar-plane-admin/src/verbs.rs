//! The closed 66+17+5 kernel-verb table, and the pure `(method, path) -> verb` match this plane runs.
//!
//! The 66 come from `generated::verb_table_1_5_5` — mechanically extracted from the pinned
//! `openapi-1.5.5.json` fixture, treated as ground truth and never regenerated here. The 17 are the
//! 1.6.0-additive money-governance verbs the design names by name only (`verify`, `plane_facts`,
//! `plane_record_write`, `set_operator_key`, `set_escrow`, `chain_break`, `store_restore`,
//! `reseal_epoch_floor`, `set_dual_control`, `set_overdraft_ceiling`, `set_dispute_max_age`,
//! `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust`, `export_keyset`, `approve`) with
//! no HTTP method or path of their own — they are new admin-API surface, not part of the 1.5.5 tag.
//!
//! **Judgment call, flagged for review**: the design does not state an HTTP binding for the 17. This
//! module assigns each one a `POST /api/v1/admin/<kebab-case-verb>` binding — the same shape every
//! other mutating admin operation in the 1.5.5 table uses — purely so this plane has *something*
//! coherent to decode against in the closed-loop tests below. `verify` and `plane_facts` are marked
//! read-only (they are checks/introspection, not mutations); every other 1.6.0 verb is marked `full`,
//! matching the design's statement that the irreducible/dual-controlled set is entirely mutating.
//! If the real HTTP binding differs, only this table's literals need to change — the codec logic
//! (`find_verb`, path-pattern matching) does not know these are synthetic.

use crate::generated::verb_table_1_5_5::VERB_TABLE_1_5_5;
use busbar_contract::control::ControlRoute;
use busbar_contract::ids::OpClassId;

/// The 17 1.6.0-additive verbs, with their synthetic HTTP binding (see the module doc comment).
const NEW_VERBS_1_6_0: &[ControlRoute] = &[
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/verify",
        operation: "verify",
        read_only: true,
    },
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/plane-facts",
        operation: "plane_facts",
        read_only: true,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/plane-record-write",
        operation: "plane_record_write",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/operator-key",
        operation: "set_operator_key",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/escrow",
        operation: "set_escrow",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/chain-break",
        operation: "chain_break",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/store-restore",
        operation: "store_restore",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/reseal-epoch-floor",
        operation: "reseal_epoch_floor",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/dual-control",
        operation: "set_dual_control",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/overdraft-ceiling",
        operation: "set_overdraft_ceiling",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/dispute-max-age",
        operation: "set_dispute_max_age",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/commit-upgrade",
        operation: "commit_upgrade",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/disputes/resolve",
        operation: "resolve_dispute",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/slices/resolve",
        operation: "resolve_slice",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/adjust",
        operation: "adjust",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/export-keyset",
        operation: "export_keyset",
        read_only: false,
    },
    ControlRoute {
        method: "POST",
        path: "/api/v1/admin/approve",
        operation: "approve",
        read_only: false,
    },
];

/// The five 1.6.0 ledger views, mounted under one sub-prefix of the admin surface.
///
/// Unlike the 17 above, these paths are NOT a judgment call. `/api/v1/admin/ledger/*` is the prefix
/// the design names for them, and `/api/v1/admin/ledger/openapi.json` is the path it names for the
/// document that describes the 1.6.0 operations — a document beside the 1.5.5 one rather than
/// inside it, because the 1.5.5 document's bytes are pinned and an additive path is not a byte.
///
/// Every one is a `GET` and every one is read-only, which is what puts them on the same rung as the
/// legacy `GET /usage`: the same credential that may read what a bucket spent may read what the
/// ledger posted for it, and neither may write anything.
const LEDGER_VERBS_1_6_0: &[ControlRoute] = &[
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/ledger/totals",
        operation: "get_ledger_totals",
        read_only: true,
    },
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/ledger/checkpoints",
        operation: "get_ledger_checkpoints",
        read_only: true,
    },
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/ledger/reconciliation",
        operation: "get_ledger_reconciliation",
        read_only: true,
    },
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/ledger/migration",
        operation: "get_ledger_migration",
        read_only: true,
    },
    ControlRoute {
        method: "GET",
        path: "/api/v1/admin/ledger/openapi.json",
        operation: "get_ledger_openapi_json",
        read_only: true,
    },
];

/// How many rows the closed table declares: 66 from the pinned 1.5.5 tag, the 17 1.6.0
/// money-governance verbs, and the 5 1.6.0 ledger views.
pub(crate) const VERB_COUNT: usize = 66 + 17 + 5;

/// The verb the `openapi.json` blob is served under, where `encode_response` applies the one
/// documented exception (an `info.version` substitution over an otherwise verbatim body).
pub(crate) const VERB_OPENAPI_JSON: &str = "get_openapi_json";

/// The operation class every read-only verb prices under.
///
/// The design's admin row prices every verb the same (a flat, zero-priced `count` class, itself
/// kernel-reserved — see `meta.rs`), so the read/write split exists only to keep the audit step's
/// dispute check meaningful (a verb whose scope tier changed between decode and audit is a real
/// finding, not noise) and to mirror the closed 34/32 `ReadOnly`/`Full` split the design pins.
pub(crate) const OP_READ: OpClassId = OpClassId::new("admin_read");
/// The operation class every mutating verb prices under. See [`OP_READ`].
pub(crate) const OP_WRITE: OpClassId = OpClassId::new("admin_write");

/// THE ONE DECLARED CLAIM: every operation this surface answers, in one static table.
///
/// The generated 1.5.5 rows first, then the 17 money-governance verbs, then the 5 ledger views.
/// It is a `const` rather than a lazily-concatenated `Vec` because it is what
/// [`ControlMeta::ROUTES`](busbar_contract::control::ControlMeta::ROUTES) hands back, and a
/// declaration a surface builds at first use is a declaration that is not a declaration: the kind's
/// open vocabulary is read ONCE, at registration, and sealed. The concatenation runs in a `const fn`
/// so the three sources stay three sources — the generated artefact is never edited to hold rows it
/// was not generated with.
const fn declared_routes() -> [ControlRoute; VERB_COUNT] {
    // A filler row, overwritten by every one of the `VERB_COUNT` writes below. The array has to be
    // initialised before it can be indexed, and a `const fn` has no `MaybeUninit` this crate would
    // be allowed to use anyway (`#![forbid(unsafe_code)]`).
    let mut out = [ControlRoute {
        method: "",
        path: "",
        operation: "",
        read_only: true,
    }; VERB_COUNT];
    let mut n = 0;
    let mut i = 0;
    while i < VERB_TABLE_1_5_5.len() {
        let (method, path, operation, read_only) = VERB_TABLE_1_5_5[i];
        out[n] = ControlRoute {
            method,
            path,
            operation,
            read_only,
        };
        i += 1;
        n += 1;
    }
    i = 0;
    while i < NEW_VERBS_1_6_0.len() {
        out[n] = NEW_VERBS_1_6_0[i];
        i += 1;
        n += 1;
    }
    i = 0;
    while i < LEDGER_VERBS_1_6_0.len() {
        out[n] = LEDGER_VERBS_1_6_0[i];
        i += 1;
        n += 1;
    }
    // The count is the declaration's own arithmetic, and this is where it is checked: a table that
    // does not fill its own array is a table whose count and whose rows disagree.
    assert!(n == VERB_COUNT);
    out
}

/// The declared table, as one static value the face hands back by reference.
static ROUTES: [ControlRoute; VERB_COUNT] = declared_routes();

/// The declaration, by reference — what `ControlMeta::ROUTES` is.
pub(crate) const fn declared() -> &'static [ControlRoute] {
    &ROUTES
}

/// Every operation this surface answers. One reading of the one declaration.
pub(crate) fn all_verbs() -> &'static [ControlRoute] {
    declared()
}

/// The table row a verb NAME belongs to.
///
/// This is how a step after the loop's resolve gets back to the static row: the draft's fact map
/// carries the operation the loop resolved, and this turns that name into the one row that owns it.
/// A lookup in one closed table, not a second reading of the body's bytes.
pub(crate) fn verb_named(verb: &str) -> Option<&'static ControlRoute> {
    all_verbs().iter().find(|e| e.operation == verb)
}

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
/// cut belongs at the one place both callers reach rather than at each of them. It lived at
/// `resolve` alone for a release, which meant the plane's own decode matched a paged read's raw
/// target against the templates and found no row at all.
fn operation_target(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// Find the verb a method and concrete path decode to, and the path parameters it carries.
///
/// Total over the closed table: a linear scan of at most [`VERB_COUNT`] rows, each a handful of segment
/// comparisons. This is a decode-time cost paid once per admin unit, not a hot per-byte path.
pub(crate) fn find_verb<'p>(
    method: &str,
    path: &'p str,
) -> Option<(&'static ControlRoute, Vec<(&'static str, &'p str)>)> {
    let path = operation_target(path);
    all_verbs().iter().find_map(|entry| {
        if entry.method != method {
            return None;
        }
        match_path(entry.path, path).map(|params| (entry, params))
    })
}

/// One row of the closed table, as the composition root reads it.
///
/// The declared [`ControlRoute`] carries the surface's own spelling of a row; what a root binds
/// against is what a row MEANS. Four fields, all `&'static`: the
/// operation's name, the method and templated path it was extracted under, and which side of the
/// closed read-only/full split it falls on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedVerb {
    /// The operation name — the snake-case `operationId` of the pinned tag for the 66, and the
    /// design's own spelling for the 17.
    pub verb: &'static str,
    /// The HTTP method the table row was extracted under.
    pub method: &'static str,
    /// The templated path, `{param}` segments and all.
    pub template: &'static str,
    /// Whether the operation is on the read-only side of the closed split.
    pub read_only: bool,
}

impl ResolvedVerb {
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
/// The same lookup [`find_verb`] runs at decode, exposed for the one caller entitled to ask it
/// outside a decode: the composition root, which has to know which kernel verb a unit is a
/// destination for before the unit's own decode has produced a draft. A query string is not part of
/// the operation's identity — `GET /audit?limit=4` and `GET /audit` are one row — so [`find_verb`]
/// cuts it before the match rather than carrying it in, for this caller and for the plane's own
/// decode alike.
///
/// `None` means the table does not declare the pair, which is the plane's own answer for an
/// unsupported operation and never an invitation to guess one.
#[must_use]
pub fn resolve(method: &str, path: &str) -> Option<ResolvedVerb> {
    find_verb(method, path).map(|(entry, _params)| ResolvedVerb {
        verb: entry.operation,
        method: entry.method,
        template: entry.path,
        read_only: entry.read_only,
    })
}

/// Every row the closed table declares, in the order the plane holds them.
///
/// The generated 1.5.5 rows first, then the 1.6.0 additions — so a caller counting them sees the
/// 66, the 17 and the 5 as three runs rather than as one undifferentiated list.
#[must_use]
pub fn table() -> Vec<ResolvedVerb> {
    all_verbs()
        .iter()
        .map(|entry| ResolvedVerb {
            verb: entry.operation,
            method: entry.method,
            template: entry.path,
            read_only: entry.read_only,
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/verbs.rs"]
mod tests;
