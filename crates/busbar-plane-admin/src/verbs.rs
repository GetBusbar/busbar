//! The closed 66+18+5 kernel-verb table, and the pure `(method, path) -> verb` match this plane runs.
//!
//! The 66 come from `generated::verb_table_1_5_5` — mechanically extracted from the pinned
//! `openapi-1.5.5.json` fixture, treated as ground truth and never regenerated here. Seventeen of
//! the eighteen are the 1.6.0-additive money-governance verbs the design names by name only
//! (`verify`, `plane_facts`, `plane_record_write`, `set_operator_key`, `set_escrow`, `chain_break`,
//! `store_restore`, `reseal_epoch_floor`, `set_dual_control`, `set_overdraft_ceiling`,
//! `set_dispute_max_age`, `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust`,
//! `export_keyset`, `approve`) with no HTTP method or path of their own — they are new admin-API
//! surface, not part of the 1.5.5 tag. The eighteenth, `amend_rate_history`, is the exception: the
//! rate-card-history design names its method AND its path, so its row below is transcribed rather
//! than chosen.
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
use busbar_contract::ids::OpClassId;

/// One row of the closed verb table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerbEntry {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) verb: &'static str,
    pub(crate) read_only: bool,
}

/// The 18 1.6.0-additive verbs, with their synthetic HTTP binding (see the module doc comment).
/// The eighteenth, `amend_rate_history`, is the exception the module doc's judgment call does not
/// cover: its path IS named by the design.
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
    // The eighteenth, and the ONE row in this list whose path is not a judgment call: the design
    // names `POST /api/v1/admin/ledger/amend-rate-history` outright, under the same `/ledger/`
    // sub-prefix its reads are mounted at, because an amendment is a write to what the ledger
    // reports and belongs beside the figures it moves. It is the only non-read this plane decodes
    // under that prefix, which is exactly why the method matters here more than anywhere else in
    // the table: bound as a `GET`, a route that reprices an already-invoiced window would carry a
    // read's scope and a read's rate class, and a read-only credential would reach it.
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

/// How many rows the closed table declares: 66 from the pinned 1.5.5 tag, the 18 1.6.0
/// money-governance verbs, and the 5 1.6.0 ledger views.
///
/// The 66 is the number that must never move — it is the pinned tag's own count, proved against the
/// fixture below. The other two are the additive surface, and the first of them moved once: the
/// dated rate-card history added the signed `amend_rate_history` write. The two reads that history
/// also owes (`rate-history`, `repricings`) are not rows yet, for the reason the verbs unit's own
/// list gives — a row that decodes to an operation with no body to render is a surface that exists
/// and does not answer.
pub(crate) const VERB_COUNT: usize = 66 + 18 + 5;

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

/// Every verb this plane decodes, generated rows first, then the 1.6.0 additions.
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
        v
    })
}

/// The table row a verb NAME belongs to.
///
/// This is how a step after `decode_ingress` gets back to the static row: the draft's fact map
/// carries the verb the decode step resolved, and this turns that name into the one row that owns
/// it. A lookup in one closed table, not a second reading of the body's bytes.
pub(crate) fn verb_named(verb: &str) -> Option<&'static VerbEntry> {
    all_verbs().iter().find(|e| e.verb == verb)
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
/// The plane's own [`VerbEntry`] stays crate-private because the plane is entitled to change how it
/// stores a row; what a root binds against is what a row MEANS. Four fields, all `&'static`: the
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
        verb: entry.verb,
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
            verb: entry.verb,
            method: entry.method,
            template: entry.path,
            read_only: entry.read_only,
        })
        .collect()
}

/// The representative body fields this plane extracts into `Facts` for the documented subset of
/// mutation verbs — key-management, group, config, hook, identity-provider and export operations.
/// See the crate-root doc comment for the honest boundary: this is ONE representative field per
/// listed verb, not full per-field schema validation of every body every operation accepts. Any
/// verb absent from this table still decodes correctly (method+path -> verb+path-params always
/// works); it simply carries no extra body-derived fact, which is a safe, visible omission rather
/// than a silently wrong one — nothing downstream trusts a body fact that decode did not set.
///
/// Every field named here is a member the pinned `openapi-1.5.5.json` request schema for that
/// operation actually declares, and the test below reads the fixture to say so. Seven rows used to
/// name a member no schema had (`parent` on `PutGroupsName`, `url` on `PutHooksName`, `issuer`,
/// `sink`, `module`, `filename`, and `settings` on a body that is a free-form object): a fact key
/// that can never be populated is a promise decode cannot keep, so those rows are either corrected
/// to the member the schema does declare or dropped where the schema declares no named member at
/// all (`PutConfigSettings`, `PutIdentityProvidersName`, `PutExportName` all take an open object).
pub(crate) fn documented_body_field(verb: &str) -> Option<&'static str> {
    Some(match verb {
        "post_keys" => "name",
        "patch_keys_id" => "group",
        "post_groups" => "name",
        "put_groups_name" => "config",
        "patch_groups_name" => "parent",
        "post_config_apply" => "config",
        "post_config_rollback" => "version",
        "post_hooks" => "name",
        "put_hooks_name" => "config",
        "patch_hooks_name_settings" => "settings",
        "patch_identity_providers_name_settings" => "settings",
        "patch_export_name_settings" => "settings",
        "put_admin_auth" => "admin_auth",
        "post_plugins" => "file",
        "post_plugins_rollback" => "file",
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/verbs.rs"]
mod tests;
