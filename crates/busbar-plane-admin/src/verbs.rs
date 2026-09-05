//! The closed 66+17 kernel-verb table, and the pure `(method, path) -> verb` match this plane runs.
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
use busbar_contract::ids::OpClassId;

/// One row of the closed verb table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VerbEntry {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) verb: &'static str,
    pub(crate) read_only: bool,
}

/// The 17 1.6.0-additive verbs, with their synthetic HTTP binding (see the module doc comment).
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
];

/// How many rows the closed table declares: 66 from the pinned 1.5.5 tag plus the 17 1.6.0 additions.
pub(crate) const VERB_COUNT: usize = 66 + 17;

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
/// 83-row list a single flat slice for every lookup while declaring its true source in one place.
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
        v
    })
}

/// The table row a verb NAME belongs to.
///
/// This is how a step after `decode_ingress` gets back to the static row: the draft's fact map
/// carries the verb the decode step resolved, and this turns that name into the one row that owns
/// it. A lookup in a closed 83-row table, not a second reading of the body's bytes.
pub(crate) fn verb_named(verb: &str) -> Option<&'static VerbEntry> {
    all_verbs().iter().find(|e| e.verb == verb)
}

/// Whether a concrete path segment satisfies a template segment, capturing the template's `{name}`
/// against the concrete value when it is a variable segment.
fn segment_matches<'p>(
    template: &'static str,
    concrete: &'p str,
) -> Option<Option<(&'static str, &'p str)>> {
    if let Some(name) = template.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
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
fn match_path<'p>(
    template: &'static str,
    concrete: &'p str,
) -> Option<Vec<(&'static str, &'p str)>> {
    let t_segs: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    let c_segs: Vec<&str> = concrete.split('/').filter(|s| !s.is_empty()).collect();
    if t_segs.len() != c_segs.len() {
        return None;
    }
    let mut params = Vec::new();
    for (t, c) in t_segs.iter().zip(c_segs.iter()) {
        if let Some(pair) = segment_matches(t, c)? {
            params.push(pair);
        }
    }
    Some(params)
}

/// Find the verb a method and concrete path decode to, and the path parameters it carries.
///
/// Total over the closed table: a linear scan of at most 83 rows, each a handful of segment
/// comparisons. This is a decode-time cost paid once per admin unit, not a hot per-byte path.
pub(crate) fn find_verb<'p>(
    method: &str,
    path: &'p str,
) -> Option<(&'static VerbEntry, Vec<(&'static str, &'p str)>)> {
    all_verbs().iter().find_map(|entry| {
        if entry.method != method {
            return None;
        }
        match_path(entry.path, path).map(|params| (entry, params))
    })
}

/// The representative body fields this plane extracts into `Facts` for the documented subset of
/// mutation verbs — key-management, group, config, hook, identity-provider and export operations.
/// See the crate-root doc comment for the honest boundary: this is ONE representative field per
/// listed verb, not full per-field schema validation of every body every operation accepts. Any
/// verb absent from this table still decodes correctly (method+path -> verb+path-params always
/// works); it simply carries no extra body-derived fact, which is a safe, visible omission rather
/// than a silently wrong one — nothing downstream trusts a body fact that decode did not set.
pub(crate) fn documented_body_field(verb: &str) -> Option<&'static str> {
    Some(match verb {
        "post_keys" => "name",
        "patch_keys_id" => "group",
        "post_groups" => "name",
        "put_groups_name" => "parent",
        "patch_groups_name" => "parent",
        "post_config_apply" => "config",
        "put_config_settings" => "settings",
        "post_config_rollback" => "version",
        "post_hooks" => "name",
        "put_hooks_name" => "url",
        "patch_hooks_name_settings" => "settings",
        "put_identity_providers_name" => "issuer",
        "patch_identity_providers_name_settings" => "settings",
        "put_export_name" => "sink",
        "patch_export_name_settings" => "settings",
        "put_admin_auth" => "module",
        "post_plugins" => "filename",
        "post_plugins_rollback" => "file",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_exactly_83_rows() {
        assert_eq!(all_verbs().len(), VERB_COUNT);
    }

    #[test]
    fn matches_a_templated_path_and_captures_the_param() {
        let params = match_path("/api/v1/admin/keys/{id}", "/api/v1/admin/keys/abc123").unwrap();
        assert_eq!(params, vec![("id", "abc123")]);
    }

    #[test]
    fn rejects_a_wrong_segment_count() {
        assert!(match_path("/api/v1/admin/keys/{id}", "/api/v1/admin/keys").is_none());
    }

    #[test]
    fn find_verb_resolves_a_concrete_request() {
        let (entry, params) = find_verb("GET", "/api/v1/admin/keys/xyz").expect("matches");
        assert_eq!(entry.verb, "get_keys_id");
        assert_eq!(params, vec![("id", "xyz")]);
    }

    /// Mechanically converts a `PascalCase` `operationId` (`GetKeysIdUsage`) to this crate's own
    /// `snake_case` verb name (`get_keys_id_usage`), so the fixture test below can compute the
    /// expected verb name rather than hand-transcribing a second copy of the 66-row mapping.
    fn snake_case(operation_id: &str) -> String {
        let mut out = String::new();
        for (i, c) in operation_id.chars().enumerate() {
            if c.is_uppercase() {
                if i != 0 {
                    out.push('_');
                }
                out.extend(c.to_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// The table test required by the crate's design brief: for every one of the 66 operations the
    /// pinned `testing/shadow-oracle/fixtures/openapi-1.5.5.json` fixture declares, `find_verb`
    /// resolves the right verb name and the right (`read_only`) scope. This is the boundary check
    /// that the closed table in this module (transcribed by hand from the same fixture) has not
    /// drifted from it.
    #[test]
    fn every_1_5_5_fixture_operation_resolves_to_the_right_verb_and_scope() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
        ));
        let doc: serde_json::Value = serde_json::from_str(fixture).expect("fixture is valid JSON");
        let paths = doc["paths"].as_object().expect("paths is an object");

        let mut checked = 0usize;
        for (path, methods) in paths {
            let methods = methods.as_object().expect("path item is an object");
            for (method, op) in methods {
                let method = method.to_uppercase();
                let operation_id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
                let expected_verb = snake_case(operation_id);
                let expected_read_only = method == "GET"
                    || method == "HEAD"
                    || path == "/api/v1/admin/config/validate"
                    || path == "/api/v1/admin/plugins/inspect";

                let (entry, _) = find_verb(&method, path).unwrap_or_else(|| {
                    panic!("no table row matches fixture operation {method} {path}")
                });
                assert_eq!(
                    entry.verb, expected_verb,
                    "{method} {path}: table verb does not match the fixture's operationId"
                );
                assert_eq!(
                    entry.read_only, expected_read_only,
                    "{method} {path}: table scope does not match required_scope(method, path)"
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked, 66,
            "the pinned fixture must declare exactly 66 operations"
        );
    }
}
