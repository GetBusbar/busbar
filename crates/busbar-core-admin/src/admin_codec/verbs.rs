//! The closed 66+18+5+3 kernel-verb table, and the pure `(method, path) -> verb` match over it.
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
//! other mutating admin operation in the 1.5.5 table uses — purely so the table has *something*
//! coherent to resolve against in the closed-loop tests below. `verify` and `plane_facts` are marked
//! read-only (they are checks/introspection, not mutations); every other 1.6.0 verb is marked `full`,
//! matching the design's statement that the irreducible/dual-controlled set is entirely mutating.
//! If the real HTTP binding differs, only this table's literals need to change — the match logic
//! (`find_verb`, path-pattern matching) does not know these are synthetic.

use crate::admin_codec::generated::verb_table_1_5_5::VERB_TABLE_1_5_5;
use crate::verb::KernelVerb;
use busbar_contract::ids::OpClassId;

/// One row of the closed verb table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerbEntry {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) verb: &'static str,
    pub(crate) read_only: bool,
}

/// The 18 1.6.0-additive money-governance verbs. The first seventeen carry the synthetic HTTP
/// binding flagged in the module doc; the eighteenth, `amend_rate_history`, carries the
/// design's own binding under `/ledger/`.
const NEW_VERBS_1_6_0: &[VerbEntry] = &[
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/verify",
        verb: "verify",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/plane-facts",
        verb: "plane_facts",
        read_only: true,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/plane-record-write",
        verb: "plane_record_write",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/operator-key",
        verb: "set_operator_key",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/escrow",
        verb: "set_escrow",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/chain-break",
        verb: "chain_break",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/store-restore",
        verb: "store_restore",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/reseal-epoch-floor",
        verb: "reseal_epoch_floor",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/dual-control",
        verb: "set_dual_control",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/overdraft-ceiling",
        verb: "set_overdraft_ceiling",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/dispute-max-age",
        verb: "set_dispute_max_age",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/commit-upgrade",
        verb: "commit_upgrade",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/disputes/resolve",
        verb: "resolve_dispute",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/slices/resolve",
        verb: "resolve_slice",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/adjust",
        verb: "adjust",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/export-keyset",
        verb: "export_keyset",
        read_only: false,
    },
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/approve",
        verb: "approve",
        read_only: false,
    },
    // `amend_rate_history`: unlike the seventeen above, its path is NOT a judgment call. The
    // dated rate-card-history design binds it at `POST /api/v1/admin/ledger/amend-rate-history` —
    // under the `/ledger/` prefix the five views share, because it is the one write among them — and
    // `full` + irreducible, because it corrects what the past cost.
    VerbEntry {
        method: "POST",
        path: "/api/v1/admin/ledger/amend-rate-history",
        verb: "amend_rate_history",
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
const LEDGER_VERBS_1_6_0: &[VerbEntry] = &[
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/ledger/totals",
        verb: "get_ledger_totals",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/ledger/checkpoints",
        verb: "get_ledger_checkpoints",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/ledger/reconciliation",
        verb: "get_ledger_reconciliation",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/ledger/migration",
        verb: "get_ledger_migration",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/ledger/openapi.json",
        verb: "get_ledger_openapi_json",
        read_only: true,
    },
];

/// THE THREE AUDIT-CHAIN READS, and their paths are not a judgment call either.
///
/// A chain that is signed but that nobody outside can fetch is a chain only we can check, which is
/// a claim rather than evidence. These three are how somebody else checks it: where the chain is
/// now, what is in a window of it, and which keys signed it.
///
/// PULL, NEVER PUSH. The node ANSWERS these; it opens no outbound connection, holds no cloud
/// credential and phones nobody. That is what lets an airgapped operator `curl` their own evidence
/// and a firewalled node be audited at all. The counter-signing and publishing half is a separate
/// product, definitionally — a node cannot anchor to itself.
///
/// All three are `GET` and all three are read-only, which puts them on the same rung as the legacy
/// `GET /audit` they sit beside: the credential that may read what the admin chain recorded may
/// read what the record chain sealed, and neither may write anything. A full-scope gate here would
/// mean the only party who can check the evidence is the party the evidence is about.
///
/// The range read takes its window as a query string (`?from=&to=`) rather than as path segments,
/// because a query names ARGUMENTS to an operation and `from`/`to` are arguments — the same reason
/// `GET /audit?limit=4` and `GET /audit` are one row here (see [`operation_target`]).
const AUDIT_VERBS_1_6_0: &[VerbEntry] = &[
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/audit/head",
        verb: "get_audit_head",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/audit/range",
        verb: "get_audit_range",
        read_only: true,
    },
    VerbEntry {
        method: "GET",
        path: "/api/v1/admin/audit/keys",
        verb: "get_audit_keys",
        read_only: true,
    },
];

/// How many rows the closed table declares: 66 from the pinned 1.5.5 tag, the 18 1.6.0
/// money-governance verbs (the seventeen plus `amend_rate_history`), the 5 1.6.0 ledger
/// views, and the 3 audit-chain reads.
pub(crate) const VERB_COUNT: usize = 66 + 18 + 5 + 3;

// ── THE ROWS AND THEIR NAMES CANNOT DRIFT, AND THE COMPILER IS WHAT SAYS SO ────────────────────
//
// A 1.6.0 row is declared HERE, as a string; the verb it names is declared in [`crate::verb`], as
// an enumeration variant; and the two are joined by [`crate::verb::verb_name`]. Until 1.6.0 that
// join ran through a `_ => ""` arm in the composition root, so a row nobody wrote a name for
// resolved to the empty string, matched nothing, and the verb REFUSED — with no compile error and
// no test naming the cause. `docs/design/BUSBAR-1.6.0.md:2064` names the shape: "a list that must
// agree with code, with nothing forcing the agreement", and `:2020` names the rule it breaks — A
// GAP AND A FAILURE MUST NEVER BE THE SAME OUTPUT.
//
// So the agreement is forced, at compile time, in BOTH directions and over all three tables: every
// row has a verb that names it, every verb has a row that carries its name, and the two lists are
// the same length (which is what catches a row added twice with one of its pair missing). A table
// and a name list that disagree do not produce a red test; they produce no binary at all.

/// Two `&str`s compared where `==` is not available — a `const` context.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether any verb in `verbs` is the one [`crate::verb::verb_name`] spells `name`.
const fn some_verb_is_named(verbs: &[KernelVerb], name: &str) -> bool {
    let mut i = 0;
    while i < verbs.len() {
        if let Some(spelling) = crate::verb::verb_name(verbs[i]) {
            if str_eq(spelling, name) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Whether any row in `rows` carries `name`.
const fn some_row_carries(rows: &[VerbEntry], name: &str) -> bool {
    let mut i = 0;
    while i < rows.len() {
        if str_eq(rows[i].verb, name) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether one table's rows and one list's verbs name exactly each other.
const fn rows_and_names_agree(rows: &[VerbEntry], verbs: &[KernelVerb]) -> bool {
    if rows.len() != verbs.len() {
        return false;
    }
    let mut i = 0;
    while i < rows.len() {
        if !some_verb_is_named(verbs, rows[i].verb) {
            return false;
        }
        i += 1;
    }
    let mut j = 0;
    while j < verbs.len() {
        match crate::verb::verb_name(verbs[j]) {
            None => return false,
            Some(name) => {
                if !some_row_carries(rows, name) {
                    return false;
                }
            }
        }
        j += 1;
    }
    true
}

const _: () = assert!(
    rows_and_names_agree(NEW_VERBS_1_6_0, crate::verb::NEW_VERBS),
    "NEW_VERBS_1_6_0 and crate::verb::NEW_VERBS disagree: a row here has no `verb_name` arm in \
     crates/busbar-core-admin/src/verb.rs, or an arm there has no row here. Add both."
);

const _: () = assert!(
    rows_and_names_agree(LEDGER_VERBS_1_6_0, crate::verb::LEDGER_VERBS),
    "LEDGER_VERBS_1_6_0 and crate::verb::LEDGER_VERBS disagree: a row here has no `verb_name` arm \
     in crates/busbar-core-admin/src/verb.rs, or an arm there has no row here. Add both."
);

const _: () = assert!(
    rows_and_names_agree(AUDIT_VERBS_1_6_0, crate::verb::AUDIT_VERBS),
    "AUDIT_VERBS_1_6_0 and crate::verb::AUDIT_VERBS disagree: a row here has no `verb_name` arm in \
     crates/busbar-core-admin/src/verb.rs, or an arm there has no row here. Add both."
);

/// The declared count is the count of what is actually declared. A row added without bumping this
/// used to be a runtime assertion in one test; it is now a condition of the crate existing.
const _: () = assert!(
    VERB_COUNT
        == VERB_TABLE_1_5_5.len()
            + NEW_VERBS_1_6_0.len()
            + LEDGER_VERBS_1_6_0.len()
            + AUDIT_VERBS_1_6_0.len(),
    "VERB_COUNT does not equal the number of rows the closed table declares"
);

/// The operation class every read-only verb prices under.
///
/// The design's admin row prices every verb the same (a flat, zero-priced `count` class, itself
/// kernel-reserved — see `meta.rs`), so the read/write split exists only to keep the audit step's
/// dispute check meaningful (a verb whose scope tier changed between resolution and audit is a real
/// finding, not noise) and to mirror the closed 34/32 `ReadOnly`/`Full` split the design pins.
pub(crate) const OP_READ: OpClassId = OpClassId::new("admin_read");
/// The operation class every mutating verb prices under. See [`OP_READ`].
pub(crate) const OP_WRITE: OpClassId = OpClassId::new("admin_write");

/// Every verb the admin surface declares, generated rows first, then the 1.6.0 additions.
///
/// A `const fn`-free concatenation would need `[T; N]` const generics arithmetic this table does not
/// need to pay for: the table is built once, at first use, by `std::sync::LazyLock`, which keeps the
/// combined list a single flat slice for every lookup while declaring its true source in one place.
pub(crate) fn all_verbs() -> &'static [VerbEntry] {
    static TABLE: std::sync::OnceLock<Vec<VerbEntry>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut v = Vec::with_capacity(VERB_COUNT);
        v.extend(
            VERB_TABLE_1_5_5
                .iter()
                .map(|&(method, path, verb, ro)| VerbEntry {
                    method,
                    path,
                    verb,
                    read_only: ro,
                }),
        );
        v.extend_from_slice(NEW_VERBS_1_6_0);
        v.extend_from_slice(LEDGER_VERBS_1_6_0);
        v.extend_from_slice(AUDIT_VERBS_1_6_0);
        v
    })
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
/// cut belongs at the one place every caller reaches rather than at each of them. It lived at
/// `resolve` alone for a release, which meant a second caller matched a paged read's raw target
/// against the templates and found no row at all.
fn operation_target(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or(target)
}

/// Find the verb a method and concrete path resolve to, and the path parameters it carries.
///
/// Total over the closed table: a linear scan of at most [`VERB_COUNT`] rows, each a handful of segment
/// comparisons. This is a cost paid once per admin unit, not a hot per-byte path.
pub(crate) fn find_verb<'p>(
    method: &str,
    path: &'p str,
) -> Option<(&'static VerbEntry, Vec<(&'static str, &'p str)>)> {
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
/// This module's own [`VerbEntry`] stays crate-private because the table is entitled to change how
/// it stores a row; what a root binds against is what a row MEANS. Four fields, all `&'static`: the
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
    find_verb(method, path).map(|(entry, _params)| ResolvedVerb {
        verb: entry.verb,
        method: entry.method,
        template: entry.path,
        read_only: entry.read_only,
    })
}

/// Every row the closed table declares, in the order the table holds them.
///
/// The generated 1.5.5 rows first, then the 1.6.0 additions — so a caller counting them sees the
/// 66, the 17 and the 5 as three runs rather than as one undifferentiated list.
#[must_use]
pub fn table() -> Vec<ResolvedVerb> {
    all_verbs()
        .iter()
        .map(|entry| ResolvedVerb {
            verb: entry.verb,
            method: entry.method,
            template: entry.path,
            read_only: entry.read_only,
        })
        .collect()
}

#[cfg(test)]
#[path = "tests/verbs.rs"]
mod tests;
