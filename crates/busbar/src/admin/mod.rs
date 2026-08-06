// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Virtual-key management API. Admin CRUD over `/api/v1/admin/keys`, guarded by the
//! configured admin token (enforced in `auth_middleware`, not here). Mutations refresh the
//! `GovState` cache. Responses never include a key's `generation_hash`; the plaintext secret is returned
//! exactly once, on creation.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

/// Deserialize a field as a "double option" so the three JSON intents stay distinguishable:
/// - field ABSENT: the `#[serde(default)]` on the field supplies the OUTER `None`.
/// - field present `null`: this fn is invoked and yields `Some(None)` (an explicit clear).
/// - field present value: this fn is invoked and yields `Some(Some(v))` (an explicit set).
///
/// Serde calls a field's deserializer ONLY when the key is present, so the absent case never reaches
/// here (it is covered by the field default). This is the standard `double_option` pattern; it lets
/// PATCH express "clear this cap back to unlimited" (`null`) distinctly from "leave it unchanged"
/// (omit), which a single `Option<T>` cannot represent.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

use crate::admin::v1::contract::taxonomy::Cond;
use crate::admin::v1::contract::AdminError;
use crate::governance::{NewKeySpec, VirtualKey};

/// Process-wide gate serializing the existence-sensitive critical sections of the key store.
///
/// `delete_key` is the only operation that flips a key from existing to absent, but its check-then-act
/// (`usage_for` lookup → `delete_key`) and `update_key`'s check-then-act (the store's `get_key` →
/// `put_key` UPSERT) BOTH read existence and then write, with no rows-affected signal from the store
/// to make either atomic. Two hazards follow, and BOTH are closed by serializing every such section
/// behind this one async mutex:
/// - Two concurrent DELETEs of one id would otherwise both observe `Some` and both return 200 (the
///   second SQL delete no-ops) — a misleading audit trail of two revocations of one row.
/// - A PATCH interleaved with a DELETE would otherwise RESURRECT the revoked key: the PATCH reads
///   the row (exists), the DELETE removes it, then the PATCH's `put_key` UPSERT re-inserts it. Under
///   this gate the PATCH's lookup→put runs to completion before any DELETE (so the row is gone
///   afterward), or after it (so the PATCH's `get_key` returns `None` → 404 and never re-puts).
///
/// The proper store-layer fix is an UPDATE-ONLY `put`/`update` (`UPDATE … WHERE id=?` that affects 0
/// rows when absent, never an upsert) used by `update_key`, which would need no lock at all — but that
/// method lives in `governance.rs` and does not exist yet. This gate is the admin-side guard that
/// closes the resurrection race from the admin surface. Both ops are admin-only and rare, so a
/// single global lock has no meaningful cost.
///
/// CANCELLATION SAFETY: this is a `std::sync::Mutex`, NOT a `tokio::sync::Mutex`, and the guard
/// is acquired INSIDE each operation's `spawn_blocking` closure — bound to the SYNCHRONOUS store
/// mutation, not to the async handler future. An earlier design held an async guard across the
/// cancellable outer `.await`; if the client dropped the request, the guard was dropped while the
/// already-scheduled (and thus uncancellable) `spawn_blocking` closure kept running its lookup→write,
/// re-opening the very resurrection / double-revoke races this gate closes. Acquiring the lock inside
/// the blocking closure means the gate is held for the entire lookup→write regardless of any
/// outer-future drop: `spawn_blocking`, once scheduled, runs to completion. A `std::sync::Mutex` is
/// used precisely because the lock is taken on a blocking thread with no async runtime in scope.
/// A poisoned lock (a panic in another holder while the gate was held) is recovered with
/// `into_inner()` — the guarded data is `()`, so there is no inconsistent state to fear, and refusing
/// to serialize would be worse than proceeding.
static EXISTENCE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `POST /keys` body (1.5.0 signed-token keys): PURE AUTH + a signed expiring token. A minted
/// key is a busbar-signed `{sub, exp, kid}` token, returned ONCE. No rpm/tpm/budget on a key - all
/// enforcement flows through the bound `group`. `#[serde(deny_unknown_fields)]` so the removed
/// 1.4.x fields (max_budget_cents/rpm_limit/tpm_limit/budget_period) fail loudly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct CreateKeyReq {
    name: String,
    /// The `groups:` bucket this key binds to (at most one). A key with NO group is authed +
    /// unlimited (access only). If the named group EXISTS, the key binds to it. If it does NOT
    /// exist, the mint 400s UNLESS `parent` is given, in which case it is AUTO-PROVISIONED as a leaf under
    /// `parent` (self-service; see `parent`).
    #[serde(default)]
    group: Option<String>,
    /// AUTO-PROVISION target: the EXISTING parent group under which to create
    /// `group` as a leaf when `group` does not yet exist: the first-self-mint materialization of a
    /// `user:<sub>` personal budget bucket. The new leaf's limits come from the nearest-ancestor
    /// `child_default` template (inherit-only when none up the chain), created through the same
    /// validate-at-the-door path as `POST /groups`. If `group` ALREADY exists, `parent` must equal
    /// its actual parent (else 409); a mint never re-homes an existing group. Ignored when `group`
    /// is absent (a key with no group has nothing to provision).
    #[serde(default)]
    parent: Option<String>,
    /// Pools this key may target. OMITTED = ALL pools; an explicit `[]` = NO pools.
    #[serde(default)]
    allowed_pools: Option<Vec<String>>,
    /// Optional mint-time labels echoed onto this key's metric series; never interpreted by
    /// enforcement.
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
    /// Token lifetime as a duration string (`7d`, `24h`, `30m`, `3600s`) - the token's `exp` is
    /// `now + expires_in`. Mutually exclusive with `expires_at`. Absent (and no `expires_at`) => a
    /// sane long default (see `DEFAULT_KEY_TTL_SECS`).
    #[serde(default)]
    expires_in: Option<String>,
    /// Token expiry as an absolute Unix-seconds timestamp. Mutually exclusive with `expires_in`.
    #[serde(default)]
    expires_at: Option<u64>,
    /// When true, ALSO issue an AWS-style access-key-id + secret access key (the MinIO/S3-compatible
    /// model) so a Bedrock-SDK client can authenticate via inbound SigV4. Both are returned ONCE.
    #[serde(default)]
    issue_aws_credential: bool,
}

/// The default signed-token lifetime when the mint body specifies neither `expires_in` nor
/// `expires_at`: 90 days. Long enough that routine use does not churn, short enough that a leaked
/// token is not valid forever (the 1.x posture: keys never expired).
pub(crate) const DEFAULT_KEY_TTL_SECS: u64 = 90 * 86_400;

/// Parse a duration string (`<n><unit>`, unit in s|m|h|d) to seconds. Bounded so an absurd value
/// cannot overflow the `exp` computation.
pub(crate) fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| "duration needs a unit (s|m|h|d), e.g. 7d".to_string())?,
    );
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}': expected <number><s|m|h|d>"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => return Err(format!("invalid duration unit '{other}': use s|m|h|d")),
    };
    n.checked_mul(mult)
        .filter(|v| *v <= 10 * 365 * 86_400)
        .ok_or_else(|| "duration is too large (max 10 years)".to_string())
}

#[cfg(test)]
mod parse_duration_secs_tests {
    use super::parse_duration_secs;

    /// Unit multiplication is correct for each accepted suffix.
    #[test]
    fn each_unit_multiplies_correctly() {
        assert_eq!(parse_duration_secs("30s"), Ok(30));
        assert_eq!(parse_duration_secs("5m"), Ok(300));
        assert_eq!(parse_duration_secs("2h"), Ok(7200));
        assert_eq!(parse_duration_secs("3d"), Ok(259_200));
    }

    /// The max-duration bound is exactly 10 * 365 * 86_400 seconds (3650 days) — the boundary
    /// itself must be accepted, and one day past it must be rejected. A mutated bound (e.g.
    /// `10 + 365 * 86_400` instead of `10 * 365 * 86_400`) would reject values far below the real
    /// 10-year limit, or accept values far above it, depending on the mutation.
    #[test]
    fn max_duration_boundary_is_exactly_ten_years() {
        assert_eq!(parse_duration_secs("3650d"), Ok(10 * 365 * 86_400));
        assert!(
            parse_duration_secs("3651d").is_err(),
            "one day past the 10-year bound must be rejected"
        );
    }
}

/// Error-type taxonomy strings shared with the forward/OpenAI-family DATA-plane vocabulary, aliased
/// from their canonical home in `proto::openai_family` so the banks cannot drift. `main.rs`
/// references them via `crate::admin::ERR_TYPE_*`.
///
/// The admin API itself no longer has an error vocabulary of its own: every admin error — keys
/// included — is an [`AdminError`] projected by `key_err`/`err_json` (design D route 2). The
/// `internal_error`/`conflict_error`/`version_conflict_error` tokens that used to be re-mapped onto
/// the frozen `code` enum in a second place are gone with it.
pub(crate) const ERR_TYPE_NOT_FOUND: &str = crate::proto::openai_family::ERR_TYPE_NOT_FOUND;
pub(crate) const ERR_TYPE_INVALID_REQUEST: &str =
    crate::proto::openai_family::ERR_TYPE_INVALID_REQUEST;

/// Maximum byte lengths for admin-API path / body fields (defense-in-depth DB/log-bloat guards).
/// A real minted key id is `vk_` + 16 hex chars (19 chars); 64 is generous headroom.
/// 256 chars for a key name is far past any reasonable label.
const MAX_KEY_NAME_LEN: usize = 256;
const MAX_KEY_ID_LEN: usize = 64;

// SCRAPE BREAK: mint-time `labels` are echoed VERBATIM as Prometheus label names on every
// key metric series (metrics.rs `base_labels`). An unvalidated map is a scrape-integrity hole:
// - a label named `key`/`bucket`/`model`/`tier` (the RESERVED names busbar itself attaches)
// duplicates a label on the series, which breaks the WHOLE /metrics exposition (a duplicate
// label name is invalid Prometheus text -> every scrape fails, not just this key);
// - a name that is not a valid Prometheus label name (`^[a-zA-Z_][a-zA-Z0-9_]*$`) is rejected by
// the exposition encoder for the same all-or-nothing effect;
// - an unbounded count / length bloats every scrape and the store row.
// So validate at the mint ingress (the one write path) and 400 anything unsafe.
/// Label names busbar itself attaches to key metric series - an operator label may not shadow them.
const RESERVED_METRIC_LABELS: &[&str] = &["key", "bucket", "model", "tier"];
const MAX_LABEL_COUNT: usize = 16;
const MAX_LABEL_NAME_LEN: usize = 64;
const MAX_LABEL_VALUE_LEN: usize = 256;

/// Validate the mint-time `labels` map. Returns `Err(message)` (a 400 body) for a reserved/invalid
/// name, an over-count map, or an over-long name/value. `Ok(())` when every label is scrape-safe.
fn validate_mint_labels(labels: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    if labels.len() > MAX_LABEL_COUNT {
        return Err(format!(
            "too many labels: {} (max {MAX_LABEL_COUNT})",
            labels.len()
        ));
    }
    for (name, value) in labels {
        if RESERVED_METRIC_LABELS.contains(&name.as_str()) {
            return Err(format!(
                "label name '{name}' is reserved (busbar attaches it to metric series); \
                 reserved names are {RESERVED_METRIC_LABELS:?}"
            ));
        }
        if name.len() > MAX_LABEL_NAME_LEN {
            return Err(format!(
                "label name is {} chars; must be <= {MAX_LABEL_NAME_LEN}",
                name.len()
            ));
        }
        if !is_valid_label_name(name) {
            return Err(format!(
                "label name '{name}' is not a valid Prometheus label name \
                 (must match ^[a-zA-Z_][a-zA-Z0-9_]*$)"
            ));
        }
        if value.len() > MAX_LABEL_VALUE_LEN {
            return Err(format!(
                "label '{name}' value is {} chars; must be <= {MAX_LABEL_VALUE_LEN}",
                value.len()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod validate_mint_labels_tests {
    use super::{validate_mint_labels, MAX_LABEL_COUNT};

    /// The count boundary is exact: `MAX_LABEL_COUNT` labels is fine; one more is rejected. A
    /// mutated `>` → `>=` would reject the boundary count itself as "too many".
    #[test]
    fn label_count_boundary_is_exact() {
        let at_cap: std::collections::BTreeMap<String, String> = (0..MAX_LABEL_COUNT)
            .map(|i| (format!("l{i}"), "v".to_string()))
            .collect();
        assert!(
            validate_mint_labels(&at_cap).is_ok(),
            "exactly MAX_LABEL_COUNT labels must be accepted"
        );

        let mut over_cap = at_cap;
        over_cap.insert("one_more".to_string(), "v".to_string());
        assert!(
            validate_mint_labels(&over_cap).is_err(),
            "MAX_LABEL_COUNT + 1 labels must be rejected"
        );
    }
}

/// A valid Prometheus label name: `^[a-zA-Z_][a-zA-Z0-9_]*$` (non-empty, ASCII-alnum + underscore,
/// never leading with a digit). Hand-rolled to avoid a regex dependency on the mint path.
fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false, // empty or bad first char
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        body.to_string(),
    )
        .into_response()
}

/// Project an [`AdminError`] onto the frozen v1 wire, NAMING the taxonomy CONDITION it came from.
/// This is the keys surface's ONLY error door, and it is the SAME `err_json` every other v1 handler
/// funnels through — so keys and non-keys emit the identical envelope, the identical `code` for the
/// same condition, and are seen by the identical drift machinery.
///
/// It replaces a SECOND vocabulary (`error_response(status, ERR_TYPE_*, msg)`), which re-derived the
/// frozen `code` enum from `*_error` tokens in a second place. That split made the keys responses
/// invisible to the OpenAPI projection and let the two banks drift; naming a `Cond`
/// here is what makes each keys emission observable to `contract::taxonomy` (design D route 2).
/// This enum names WHO IS REFUSING, so the ONE error door can also be the ONE audit door.
///
/// `POST /keys` wrote `key.create`/`applied` on success and NOTHING on any refusal
/// — the anti-sprawl cap 409 included — while `key.patch`/`key.delete`/
/// `key.rotate`/`key.revoke` each wrote `rejected` by hand at the arms someone remembered. A refused
/// mint is precisely the event a reviewer needs (someone tried to issue a credential and was
/// stopped), and it was the one event with no row.
///
/// The fix is not "add the missing calls": it is to make the refusal seam UNABLE to emit without a
/// decision. `key_err` now takes this, so every present and future refusal on the keys surface must
/// say whether it is a mutation (→ a `rejected` row, written here, once) or a read (→ nothing, since
/// a refused GET changed nothing). There is no third option and no way to skip the question.
#[derive(Clone, Copy)]
pub(crate) enum KeyAudit<'a> {
    /// A READ refusal. Nothing was mutated, so nothing is recorded.
    Read,
    /// A MUTATION refusal: records `(verb, resource)`/`rejected` for `actor`. `resource` is
    /// `key:<id>` where an id exists and [`KEY_RESOURCE_NONE`] on a mint that never got one.
    Mutation {
        verb: &'static str,
        resource: &'a str,
        actor: &'a str,
    },
}

/// The `resource` for a MINT that was refused before any key existed — there is no id to name, and
/// inventing one would put a row in the log for a key that never was.
pub(crate) const KEY_RESOURCE_NONE: &str = "key:-";

/// Project an [`AdminError`] onto the frozen v1 wire, NAMING the taxonomy CONDITION it came from,
/// and — for a mutating operation — writing that operation's `rejected` audit row.
/// This is the keys surface's ONLY error door, and it is the SAME `err_json` every other v1 handler
/// funnels through — so keys and non-keys emit the identical envelope, the identical `code` for the
/// same condition, and are seen by the identical drift machinery.
///
/// It replaces a SECOND vocabulary (`error_response(status, ERR_TYPE_*, msg)`), which re-derived the
/// frozen `code` enum from `*_error` tokens in a second place. That split made the keys responses
/// invisible to the OpenAPI projection and let the two banks drift; naming a `Cond`
/// here is what makes each keys emission observable to `contract::taxonomy` (design D route 2).
///
/// Folding the audit row in here is the same move for the same reason: one door, one row, no
/// per-arm remembering. See [`KeyAudit`].
fn key_err(who: KeyAudit<'_>, e: &AdminError, cond: Cond) -> Response {
    record_key_refusal(who);
    crate::admin::v1::json::err_json_cond(e, cond)
}

/// The audit half of [`key_err`], usable on its own by the one refusal door that cannot name a
/// [`Cond`]: a failed transaction is `AdminError::Internal`, which `taxonomy::err_kind_of`
/// classifies as ALGORITHMIC, so there is nothing to declare — but the mutation was still refused.
fn record_key_refusal(who: KeyAudit<'_>) {
    if let KeyAudit::Mutation {
        verb,
        resource,
        actor,
    } = who
    {
        audit::AUDIT.record_by(verb, resource, audit::OUTCOME_REJECTED, actor);
    }
}

/// 500 for an internal store/DB failure. The detailed error (which may embed raw SQL fragments,
/// column/table names, or paths from the store backend) is logged server-side via `tracing::error!`;
/// the HTTP body carries only a generic message so internal storage details are never disclosed to
/// the client (even an authenticated admin). `op` names the operation for log correlation.
fn internal_error(op: &str, e: &crate::governance::StoreError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store operation failed");
    crate::admin::v1::json::err_json(&AdminError::Internal)
}

#[cfg(test)]
mod internal_error_tests {
    use super::internal_error;
    use crate::governance::StoreError;

    /// `internal_error` must project `AdminError::Internal` onto the real error envelope — a 500
    /// with the frozen `{"error":{"code":"internal",...}}` body — never `Response::default()`
    /// (which axum resolves to a bare `200 OK` with an EMPTY body, disguising a store failure as a
    /// success to the client).
    #[tokio::test]
    async fn projects_a_500_internal_error_envelope() {
        let resp = internal_error("test_op", &StoreError("boom".to_string()));
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "a store failure must answer 500, not the 200 `Response::default()` would give"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.is_empty(),
            "the body must carry the error envelope, not be empty like `Response::default()`"
        );
        let v: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON body");
        assert_eq!(v["error"]["code"], "internal");
    }
}

// ── Admin API (the FROZEN surface — /api/v1/admin/*) ─────────────────────────────────────────────────
//
// Built engine + swappable layers, VERSION-FIRST: each API version (`v1`, later `v2`)
// is a self-contained unit under its own directory holding that version's CONTRACT (typed views +
// stable error codes), its SERVICE (typed operations over the shared engine), and its TRANSPORT wire
// adapters (`json`, later `graphql`). The transport PORT (`AdminTransport` in `transport`) is shared
// across versions and transports. Releasing v2 is a LAYER copy of `v1/`, not a rewrite; v1 never
// breaks. The keys handlers below are mounted ONLY at the canonical `/api/v1/admin/keys*` routes
// (via the JsonV1 router — the pre-release `/admin/keys` alias is gone), and speak the ONE frozen
// v1 contract: the `{error:{code,message}}` envelope with the stable code enum. Keys
// are a first-class v1 resource served by these handlers until they migrate into the versioned
// service module.
pub(crate) mod audit;
pub(crate) mod rate;
pub(crate) mod restart;
pub(crate) mod transport;
pub(crate) mod v1;
pub(crate) mod versions;

pub(crate) use v1::json::JsonV1;
pub(crate) use v1::service::mark_start;

/// Key metadata for API responses — deliberately omits `generation_hash`.
/// A key record's ETag: a short digest of its mutable metadata. Changes whenever any PATCHable
/// field changes, so `If-Match` detects a concurrent modification (409, no lost update).
fn key_etag(k: &VirtualKey) -> String {
    let meta = key_meta(k);
    crate::sigv4::sha256_hex(meta.to_string().as_bytes())[..16].to_string()
}

/// Parse the optional `If-Match` header for a KEY mutation (PATCH/DELETE `/keys/{id}`): the key's
/// own ETag from a prior GET (16 lowercase hex chars — see `key_etag`), quotes/weak-prefix
/// stripped. `*` (RFC 7232: "any current representation") matches any existing key, i.e. no guard —
/// `Ok(None)`. Anything that cannot be a key ETag is a 400 `invalid_request` — the SAME terminal
/// the config-plane parser gives a malformed guard, never a retriable-looking 409 that a client
/// with a header bug would re-read and retry forever. Shared by PATCH and DELETE so
/// the two verbs can never diverge on grammar.
#[allow(clippy::result_large_err)] // Err = the ready-to-return 400 Response (callers just return it)
fn parse_key_if_match(
    who: KeyAudit<'_>,
    headers: &axum::http::HeaderMap,
) -> Result<Option<String>, Response> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    let bare = s.strip_prefix("W/").unwrap_or(s).trim_matches('"');
    if bare.len() == 16 && bare.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(Some(bare.to_string()))
    } else {
        Err(key_err(
            who,
            &AdminError::Validation(
                "malformed If-Match: expected the key's ETag (16 hex chars, quoted) or *".into(),
            ),
            Cond::MalformedIfMatch,
        ))
    }
}

fn key_meta(k: &VirtualKey) -> Value {
    // 1.5.0 keys are PURE AUTH bindings: id / name / allowed_pools / group / labels. Keys carry no
    // limits (all enforcement flows through the bound group). `allowed_pools` keeps the intent:
    // JSON `null` = all pools; `[]` = no pools.
    json!({
        "id": k.id,
        "name": k.name,
        "allowed_pools": k.allowed_scopes.as_ref().map(|list| {
            list.iter().map(|s| s.value.as_str()).collect::<Vec<_>>()
        }),
        "group": k.group,
        "enabled": k.enabled,
        "created_at": k.created_at,
        "labels": k.labels,
    })
}

/// `enabled` alone cannot distinguish a reversible PAUSE (`PATCH {enabled:false}`) from either
/// of the two PERMANENT states (`revoke`, `delete`) — all three land on `enabled == false`. This
/// derives the disambiguating value from the same internal state the engine already tracks, in
/// tombstone-first priority (a tombstoned row is also denylisted, by `revoke`-then-delete, so the
/// checks must not be reordered):
/// - `deleted_at.is_some()`  → **tombstoned** (`DELETE /keys/{id}`: denylisted + hard-deleted; the row
///   is kept only so billing/audit attribution keeps resolving).
/// - else `gov.is_revoked()` → **revoked** (`POST /keys/{id}/revoke`: denylisted, permanent, binding
///   row kept).
/// - else `!enabled`          → **disabled** (`PATCH {enabled:false}`: reversible, not denylisted).
/// - else                     → **active**.
fn key_state(k: &VirtualKey, gov: &crate::governance::GovState) -> &'static str {
    if k.deleted_at.is_some() {
        "tombstoned"
    } else if gov.is_revoked(&k.id) {
        "revoked"
    } else if !k.enabled {
        "disabled"
    } else {
        "active"
    }
}

/// Governance-off semantics: ONE rule across the keys surface, chosen so no
/// status is ambiguous —
/// - collection READS (`GET /keys`) answer 200 with an EMPTY page (`disabled_empty_list`): with
///   governance off the keyspace is truthfully empty, and a 404 on a collection reads as a
///   mount/path error to every REST client;
/// - single-resource READS keep 404 `not_found` (also truthful — no such key exists);
/// - WRITES (create/patch/delete/rotate/revoke) answer 409 `conflict` (`disabled_write`): the request
///   conflicts with the server's configured state, with an actionable message. Previously every
///   handler returned 404 — making `not_found` mean two different things forever.
fn disabled_write(who: KeyAudit<'_>) -> Response {
    key_err(
        who,
        &AdminError::Conflict(
            "governance is not enabled on this server; enable `governance:` in config.yaml to \
             manage virtual keys"
                .into(),
        ),
        Cond::GovernanceOff,
    )
}

/// `GET /keys` with governance off: the truthful empty page in the standard cursor envelope.
fn disabled_empty_list() -> Response {
    json_response(
        StatusCode::OK,
        json!({ "items": [], "next_cursor": serde_json::Value::Null }),
    )
}

/// Single-resource read with governance off: no key can exist, so `not_found` is truthful.
fn disabled_read() -> Response {
    key_err(
        KeyAudit::Read,
        &AdminError::not_found_because("key", "governance is not enabled on this server"),
        Cond::GovernanceOff,
    )
}

/// Bound a path `id` (the virtual-key id from `/api/v1/admin/keys/{id}`). Admin-gated, but an unbounded id
/// flows into a store lookup / log lines — cap it as defense-in-depth (DB/log-bloat guard). A real
/// minted id is `vk_` + 16 hex chars (19 chars), so [`MAX_KEY_ID_LEN`] is generous headroom. Returns
/// a 400 response when too long, `None` when acceptable.
fn reject_overlong_id(who: KeyAudit<'_>, id: &str) -> Option<Response> {
    if id.len() > MAX_KEY_ID_LEN {
        Some(key_err(
            who,
            &AdminError::Validation("id must be <= 64 characters".into()),
            Cond::Overlong,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod reject_overlong_id_tests {
    use super::{reject_overlong_id, KeyAudit, MAX_KEY_ID_LEN};

    /// The bound is exact: an id of exactly `MAX_KEY_ID_LEN` chars is acceptable (`None`); one char
    /// past it is rejected (`Some`). A mutated `>` → `>=` would reject the boundary length itself,
    /// which a real minted id (`vk_` + 16 hex = 19 chars) never reaches but a caller passing exactly
    /// the documented max legitimately could.
    #[test]
    fn id_length_boundary_is_exact() {
        let at_max = "a".repeat(MAX_KEY_ID_LEN);
        assert!(
            reject_overlong_id(KeyAudit::Read, &at_max).is_none(),
            "an id of exactly MAX_KEY_ID_LEN chars must be accepted"
        );

        let over_max = "a".repeat(MAX_KEY_ID_LEN + 1);
        assert!(
            reject_overlong_id(KeyAudit::Read, &over_max).is_some(),
            "an id one char past MAX_KEY_ID_LEN must be rejected"
        );
    }
}

/// 500 for a `spawn_blocking` task that failed to run to completion (cancelled or panicked). The
/// blocking store closures here don't panic in normal operation, but a `JoinError` must NOT
/// propagate as an `unwrap()` on the request path — map it to a generic 500 (details logged).
fn join_error(op: &str, e: &tokio::task::JoinError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store task failed to join");
    crate::admin::v1::json::err_json(&AdminError::Internal)
}

/// The request header carrying a client-chosen idempotency token on the two replayable admin
/// mutations (key mint + key rotate).
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// Replay window (seconds, ~10 min) for the idempotency cache; stale entries are swept on use.
const IDEMPOTENCY_TTL_SECS: u64 = 600;

/// The three states an idempotency reservation's lifecycle actually has. A plain bool ("committed
/// or not") conflated two meanings: "safe to clear because nothing irreversible ran" and "unsafe to
/// clear because an uncancellable blocking task might already have committed" — the latter only
/// applies once the mint has been handed to `spawn_blocking`/`config_transaction`'s blocking half,
/// which (per `txn.rs`) keeps running to completion even after the handler future that awaits it is
/// DROPPED (a client disconnect/timeout). Collapsing those two into one bool meant a disconnect
/// mid-mint cleared the sentinel while the mint was still landing, so a client retry saw an empty
/// slot and minted a SECOND key — the exact double-mint the reservation exists to prevent.
#[derive(PartialEq, Eq)]
enum IdemState {
    /// Reserved, nothing irreversible has happened yet. A drop here MUST clear the sentinel — a
    /// parse/validation refusal must not leave a stuck in-flight key.
    Reserved,
    /// The mint has been handed to the uncancellable blocking task. A drop here is a CLIENT
    /// DISCONNECT, and the mint may already have committed — dropping the sentinel would let the
    /// client's retry mint a SECOND key. Leave it; it expires with the 10-min window, and until
    /// then a retry gets the honest 409 "already in flight".
    InFlight,
    /// The response was built and cached. Nothing to clear.
    Committed,
}

/// An in-flight idempotency RESERVATION. `create_key`/`rotate_key` insert a `Null`-body sentinel
/// under the cache lock the instant they decide to mint (atomic with the "already cached?" check),
/// so a concurrent retry with the same `Idempotency-Key` sees the reservation and is rejected instead
/// of double-minting. This guard clears that sentinel on drop only while [`IdemState::Reserved`] — see
/// its variants for why the other two states must NOT clear on drop.
struct IdemReservation {
    #[allow(clippy::type_complexity)]
    cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), (u64, serde_json::Value)>>,
    >,
    key: (String, String),
    state: IdemState,
}

impl IdemReservation {
    /// Explicitly clear the sentinel from a POST-AWAIT failure exit that is one of the transaction's
    /// OWN fail-closed outcomes (a store error, a cap rejection, a not-found) — never reached on
    /// genuine cancellation, so we KNOW nothing committed and it is safe to free the key for retry
    /// even though `state` is `InFlight` by this point.
    fn clear(&mut self) {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(c.get(&self.key), Some((_, v)) if v.is_null()) {
            c.remove(&self.key);
        }
        self.state = IdemState::Committed; // nothing left for Drop to do
    }
}

impl Drop for IdemReservation {
    fn drop(&mut self) {
        if self.state != IdemState::Reserved {
            return;
        }
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        // Only remove if it is STILL the pending sentinel — never clobber a real committed body
        // (a success path that already replaced it).
        if matches!(c.get(&self.key), Some((_, v)) if v.is_null()) {
            c.remove(&self.key);
        }
    }
}

/// The label a cap rejection uses for the UNBOUND (no `group:`) key bucket.
const UNBOUND_BUCKET_LABEL: &str = "(no group)";

/// THE `limits.max_keys_per_principal` CHOKE POINT — the one place any path that can add a key to a
/// principal's bucket asks "is this bucket already full?". Called by the MINT (`POST /keys`) and by
/// the REBIND (`PATCH /keys/{id}`), both from inside their `EXISTENCE_GATE`d blocking section, so
/// the count and the write that follows it are one atomic critical region. A store failure
/// propagates and the caller FAILS CLOSED — never admit past a ceiling we could not verify.
///
/// `group` names the bucket: `Some(g)` for a bound key, `None` for the UNBOUND bucket (which is
/// capped too — see below). `exclude_id` is the key being MOVED, so a rebind does not count the
/// mover twice; `None` on the mint path (nothing to exclude). Returns `Some((bucket_label, n))`
/// when the bucket is at or over `cap`. `cap == 0` = unlimited (the default) and short-circuits.
///
/// Two defect classes die here rather than at N call sites:
///
/// * The count is of LIVE keys only: a disabled or revoked key holds no usable credential,
///   so counting it forever made the cap a ONE-WAY RATCHET (a principal that revoked ten keys
///   could never mint again, and the documented remedy "revoke or delete an existing key" was
///   simply false for `revoke`). Enabled + not-denylisted is exactly "can still authenticate".
/// * The UNBOUND bucket is counted. A groupless key escapes the whole limit tree, so
///   exempting it from the key-count cap as well made the ceiling evadable by omitting one field.
fn check_key_cap(
    gov: &crate::governance::GovState,
    cap: usize,
    group: Option<&str>,
    exclude_id: Option<&str>,
) -> crate::governance::StoreResult<Option<(String, usize)>> {
    if cap == 0 {
        return Ok(None); // unlimited
    }
    let n = gov
        .all_keys()?
        .iter()
        .filter(|k| k.group.as_deref() == group)
        .filter(|k| Some(k.id.as_str()) != exclude_id)
        // SELF-SERVE keys (`user:<sub>`) are EXCLUDED: a principal always has exactly one (the
        // token-exchange mint is an idempotent upsert on the current epoch), so it must never
        // consume an admin `max_keys_per_principal` ceiling. See `SELF_KEY_GROUP_PREFIX`.
        .filter(|k| {
            k.group
                .as_deref()
                .map(|g| !g.starts_with(crate::governance::SELF_KEY_GROUP_PREFIX))
                .unwrap_or(true)
        })
        .filter(|k| k.enabled && !gov.is_revoked(&k.id))
        .count();
    if n >= cap {
        return Ok(Some((group.unwrap_or(UNBOUND_BUCKET_LABEL).to_string(), n)));
    }
    Ok(None)
}

/// POST /api/v1/admin/keys — mint a virtual key. Returns the plaintext secret ONCE.
pub(crate) async fn create_key(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<crate::state::AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // A fresh snapshot for the mint's pool/group READS; the auto-provision path (below) swaps
    // through `handle` and re-loads inside its own lock, so binding always sees the provisioned leaf.
    let app = handle.load();
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let who = KeyAudit::Mutation {
        verb: "key.create",
        resource: KEY_RESOURCE_NONE,
        actor: &actor,
    };
    // IDEMPOTENT MINT (optional `Idempotency-Key`): a retried POST with the same key inside the
    // ~10min window returns the FIRST response verbatim (including the once-shown secret — the
    // standard idempotency contract: a retry is the same request, not a second mint) instead of
    // double-creating. Bounded: stale entries are swept on every use.
    let idem_key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    // The idempotency key is scoped to the PRINCIPAL: (actor, header). A different admin's identical
    // Idempotency-Key value must never replay this principal's response (which carries a secret).
    let idem_ckey: Option<(String, String)> = idem_key.as_ref().map(|k| (actor.clone(), k.clone()));
    if let Some(ref ck) = idem_ckey {
        let now = crate::store::now();
        let mut cache = app
            .idempotency_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (t, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match cache.get(ck) {
            // A COMPLETED prior mint (the real 201 object): replay it verbatim.
            Some((_, cached)) if !cached.is_null() => {
                return json_response(StatusCode::CREATED, cached.clone());
            }
            // An IN-FLIGHT reservation (Null sentinel): a concurrent request with the same key is
            // still minting. Reject rather than double-mint (the TOCTOU a separate check+insert
            // allowed); the client's retry succeeds once the first completes or the reservation
            // expires.
            Some(_) => {
                return key_err(
                    who,
                    &AdminError::Conflict(
                        "a request with this Idempotency-Key is already in flight".into(),
                    ),
                    Cond::IdempotencyInFlight,
                );
            }
            // First time: RESERVE under this SAME lock hold, so a concurrent request observes the
            // reservation instead of an empty slot.
            None => {
                cache.insert(ck.clone(), (now, serde_json::Value::Null));
            }
        }
    }
    // Clears the reservation if we return before committing (parse / validation / mint failure);
    // disarmed on success, where the real body replaces the sentinel.
    let mut idem_reservation = idem_ckey.as_ref().map(|ck| IdemReservation {
        cache: app.idempotency_cache.clone(),
        key: ck.clone(),
        state: IdemState::Reserved,
    });
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    // Parse the body via the depth-guarded `crate::json` seam, NOT axum's stock `Json<T>` extractor,
    // whose `JsonRejection` body echoes the raw serde `Display` — a fragment of the offending input.
    // This body carries SECRETS (an AWS secret_access_key, the bearer being minted), so any parse
    // failure maps to a GENERIC 400, logging only the byte length via `parse_err_log` (never the raw
    // error, never an input fragment).
    let req: CreateKeyReq = match crate::json::parse(&body) {
        Ok(req) => req,
        Err(_) => {
            tracing::warn!("create_key: {}", crate::json::parse_err_log(body.len()));
            return key_err(
                who,
                &AdminError::Validation("invalid JSON".into()),
                Cond::MalformedBody,
            );
        }
    };
    // Bound the key name. It is admin-gated, but an unbounded `name` persists verbatim into the
    // store (DB-bloat / log-line-bloat vector) — cap it as defense-in-depth. MAX_KEY_NAME_LEN chars
    // is far past any reasonable label.
    if req.name.len() > MAX_KEY_NAME_LEN {
        return key_err(
            who,
            &AdminError::Validation("name must be <= 256 characters".into()),
            Cond::Overlong,
        );
    }
    // Labels are echoed verbatim as Prometheus label NAMES on this key's metric series; an
    // unsafe name (reserved, or not a valid label name) or an oversized map breaks the WHOLE scrape.
    // Reject at the mint ingress (see `validate_mint_labels`).
    if let Err(msg) = validate_mint_labels(&req.labels) {
        return key_err(who, &AdminError::Validation(msg), Cond::InvalidLabels);
    }
    // SIGNED-TOKEN keys require a signing key. Without one, mint cannot issue a token - fail
    // loud rather than persist a binding no token can be issued for.
    if !gov.signing_enabled() {
        return key_err(
            who,
            &AdminError::Conflict(
                "signed-token minting is unavailable: no signing key is configured (set \
             auth.signing_key - busbar no longer auto-generates one; run \
             `busbar --generate-signing-key`)"
                    .into(),
            ),
            Cond::NoSigningKey,
        );
    }
    // `expires_in` and `expires_at` are mutually exclusive; resolve the token expiry (Unix secs).
    let now = crate::store::now();
    let exp = match (req.expires_in.as_deref(), req.expires_at) {
        (Some(_), Some(_)) => {
            return key_err(
                who,
                &AdminError::Validation(
                    "expires_in and expires_at are mutually exclusive; set at most one".into(),
                ),
                Cond::KeyExpiryFields,
            );
        }
        (Some(dur), None) => match parse_duration_secs(dur) {
            Ok(secs) => now.saturating_add(secs),
            Err(msg) => return key_err(who, &AdminError::Validation(msg), Cond::KeyExpiryFields),
        },
        (None, Some(at)) => {
            if at <= now {
                return key_err(
                    who,
                    &AdminError::Validation("expires_at is in the past".into()),
                    Cond::KeyExpiryFields,
                );
            }
            at
        }
        (None, None) => now.saturating_add(DEFAULT_KEY_TTL_SECS),
    };
    // `allowed_pools` (intent carried INTACT into the binding): OMITTED = all pools (`None`);
    // an explicit `[]` = NO pools; a list scopes it. NON-FATAL typo diagnostic on each named pool.
    let allowed_pools = req.allowed_pools;
    for pool in allowed_pools.iter().flatten() {
        if !app.pools.contains_key(pool) {
            tracing::warn!(
                pool = %pool,
                key_name = %req.name,
                "create_key: allowed_pools entry names no configured pool (possible typo; \
                 key still created - configure the pool later to activate this entry)"
            );
        }
    }
    // ── THE MINT TRANSACTION ─────────────────────────────────────────────────────────────────────
    // Group resolution, the auto-provision swap, the anti-sprawl cap and the key's store write are
    // ONE `config_transaction` section. Three defect classes die here by construction:
    //
    // * The bound group's existence check and the key's store write share ONE continuous lock hold.
    // The old shape resolved the group under the mutation lock, RELEASED it on return, then
    // re-acquired the lock and re-verified the group BY HAND — a copied prose contract a third
    // bind path would have had to copy again. There is nothing left to re-verify: the lock is
    // never released between the check and the bind, so a concurrent group DELETE either lands
    // first (this body sees the group gone → fail closed) or is blocked until the key is bound
    // (then DELETE's bound-key guard sees it → 409).
    // * `max_keys_per_principal` is read from `txn.app()` — the FRESH post-lock snapshot — not from
    // the pre-lock extractor `app`. A settings apply landing between the request's snapshot and
    // this enforcement can no longer make the mint enforce a stale ceiling: there is no older
    // snapshot in scope to read.
    // * The cap COUNT and the mint run together in ONE `spawn_blocking` closure under
    // `EXISTENCE_GATE`, so N concurrent callers at the boundary are serialized — each sees the
    // writes of those before it and only the first `cap - current` mints succeed. `>= cap` is a
    // `409` (a retry can't fix it without deleting a key), and a store failure counting keys
    // FAILS CLOSED — never mint past a ceiling we could not verify.
    //
    // LOCK ORDER: `config_transaction` holds the async config lock across the whole section and
    // takes `EXISTENCE_GATE` (a std Mutex) only INSIDE the blocking closure, never across an await —
    // one global acquisition order, no cycle.
    if req.group.is_none() && req.parent.is_some() {
        // `parent` without `group` has nothing to root — a loud 400 beats silently ignoring it.
        return key_err(
            who,
            &AdminError::Validation(
                "`parent` was given without `group`; `parent` names the group to auto-provision \
             `group` under, so `group` is required with it"
                    .into(),
            ),
            Cond::ParentWithoutGroup,
        );
    }
    // (1.5.2 scope collapse: the delegated-mint-must-bind refusal is GONE. Only a `full` credential
    // can reach `POST /keys` now — there is no narrower `mint` scope to hand out uncapped keys — so
    // an operator minting an unbound key is a legitimate act by the tree's owner, no longer gated.)
    /// What the mint's blocking half produced: the key (bearer-only or with AWS credentials), or the
    /// anti-sprawl ceiling it hit.
    enum MintOutcome {
        Bearer(Box<(crate::governance::VirtualKey, String)>),
        Aws(Box<(crate::governance::VirtualKey, String, String, String)>),
        AtCap { group: String, n: usize, cap: usize },
    }
    // Keys carry NO inline limits; enforcement flows through the bound group.
    let spec = NewKeySpec {
        name: req.name,
        allowed_pools,
        group: req.group.clone(),
        labels: req.labels,
    };
    let issue_aws = req.issue_aws_credential;
    let want_group = req.group.clone();
    let want_parent = req.parent.clone();
    let gov = gov.clone();
    let txn_actor = actor.clone();
    // The mint is about to be handed to `config_transaction`'s uncancellable blocking half — from
    // here on, a dropped handler future (client disconnect) must NOT clear the sentinel, since the
    // mint may already be landing. See `IdemState::InFlight`.
    if let Some(r) = idem_reservation.as_mut() {
        r.state = IdemState::InFlight;
    }
    let res = crate::admin::v1::json::config_transaction(&handle, move |txn| {
        let current = txn.app();
        // MINT-TIME group resolution (self-service): a bound `group` must exist NOW — a dangling
        // binding would make every request on the new key fail closed at admission. When it does not
        // exist AND `parent` is given, AUTO-PROVISION it as a leaf under `parent` (materializing the
        // `user:<sub>` personal budget bucket on first self-mint) through the SAME
        // validate-at-the-door group-write path, so validation / cost rebuild / overlay persistence
        // hold. When it exists and `parent` is given, `parent` must match the actual parent (409
        // otherwise). A key with NO group is authed + unlimited — nothing to resolve.
        let provisioned = match want_group.as_deref() {
            Some(group) => {
                crate::admin::v1::json::plan_mint_group(
                    current,
                    group,
                    want_parent.as_deref(),
                    &txn_actor,
                )?
            }
            None => None,
        };
        // ANTI-SPRAWL CAP — see `check_key_cap` for what counts. Read from the FRESH snapshot, so a
        // concurrent apply cannot leave this mint enforcing a stale cap.
        let cap = current.max_keys_per_principal;
        // The BUCKET this mint lands in. `None` is the UNBOUND bucket, capped too — a groupless key
        // escapes the limit tree entirely, so leaving it uncapped makes the cap evadable by simply
        // omitting `group`.
        let cap_group = spec.group.clone();
        let did_provision = provisioned.is_some();
        // WHAT THE AUTO-PROVISION COMMITTED, carried INTO the post-commit step. The provision is
        // recorded at COMMIT time, not after the whole transaction succeeds: once the swap is
        // visible to in-flight requests there is no honest compensation (un-persisting is itself
        // fallible), so a mint that fails downstream must still leave an audited, version-bumped
        // group — the same state an explicit `POST /groups` + failed `POST /keys` leaves, and the
        // retry then simply binds to it. `config_version` comes from the committed snapshot itself,
        // not a post-lock-release `handle.load()` that a concurrent mutation could have moved.
        let provision_record = provisioned.as_ref().map(|installed| {
            (
                installed.clone(),
                want_group.clone().unwrap_or_default(),
                want_parent.clone().unwrap_or_default(),
                txn_actor.clone(),
            )
        });
        // The blocking half: cap count + mint, one `spawn_blocking`, one `EXISTENCE_GATE` hold.
        let mint = move || {
            // RUNS AFTER the commit-and-swap (it is `commit_then`'s follow-on step) and BEFORE the
            // fallible mint below, so the record exists whatever the mint does.
            if let Some((installed, group, parent, actor)) = provision_record {
                audit::AUDIT.record_by(
                    "group.provision",
                    &format!("group:{group}"),
                    audit::OUTCOME_APPLIED,
                    &actor,
                );
                installed.versions.record(
                    installed.config_version,
                    &actor,
                    &format!("group.provision group:{group} (auto, parent {parent})"),
                    &installed.hook_registry,
                    &installed.global_hooks,
                );
            }
            let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
            let minted = (|| -> crate::governance::StoreResult<MintOutcome> {
                if let Some((group, n)) = check_key_cap(&gov, cap, cap_group.as_deref(), None)? {
                    return Ok(MintOutcome::AtCap { group, n, cap });
                }
                if issue_aws {
                    // Issues the AccessKeyId + secret access key alongside the bearer secret.
                    gov.mint_signed_with_aws(spec, exp, now)
                        .map(|m| MintOutcome::Aws(Box::new(m)))
                } else {
                    gov.mint_signed(spec, exp, now)
                        .map(|m| MintOutcome::Bearer(Box::new(m)))
                }
            })()
            .map_err(|e| {
                tracing::error!(operation = "create_key", error = %e, "admin store operation failed");
                AdminError::Internal
            })?;
            Ok(crate::admin::v1::json::Outcome::Value((
                minted,
                did_provision,
            )))
        };
        match provisioned {
            // Auto-provision: PERSIST-then-SWAP the new leaf, THEN bind the key to it — both inside
            // this one guard, so the leaf cannot be deleted between being created and being bound.
            Some(installed) => {
                let group = want_group.clone().unwrap_or_default();
                Ok(crate::admin::v1::json::Outcome::commit_then(
                    installed.clone(),
                    crate::admin::v1::json::persist_provisioned_group(
                        installed,
                        group,
                        txn_actor.clone(),
                    ),
                    mint,
                ))
            }
            None => Ok(txn.store_write(mint)),
        }
    })
    .await;
    let (minted, provisioned_group) = match res {
        Ok(v) => v,
        // Fail-closed: an auto-provision that was rejected leaves nothing behind, and a mint that
        // failed after one committed is reported here. `group.provision`'s own REJECTED row is
        // written at the two sites that used to write it (a failed build, a failed persist).
        //
        // The refusal row is written HERE rather than via `key_err`, because everything arriving at
        // this door is either `AdminError::Internal` or a refusal raised inside the transaction —
        // neither carries a `Cond`, so the envelope stays untagged.
        Err(e) => {
            record_key_refusal(who);
            // The transaction's OWN fail-closed outcome — reached only when the `.await` completed
            // normally, never on genuine cancellation — so nothing committed and the reservation is
            // safe to free for a legitimate retry.
            if let Some(r) = idem_reservation.as_mut() {
                r.clear();
            }
            return crate::admin::v1::json::err_json(&e);
        }
    };
    // NOTE: the `group.provision` audit + version records are written INSIDE the transaction, at
    // commit time (see `provision_record` above) — not here. Writing them here made them
    // conditional on the mint that follows the commit ALSO succeeding, which is exactly how a
    // committed config change ended up with no trail.
    let (key, token, aws) = match minted {
        MintOutcome::AtCap { group, n, cap } => {
            // Same reasoning as the `Err(e)` arm above: the transaction committed (if it
            // auto-provisioned) but the mint itself was refused by the cap check — a fail-closed
            // outcome of the completed await, not a cancellation. Safe to free the reservation.
            if let Some(r) = idem_reservation.as_mut() {
                r.clear();
            }
            return key_err(
                who,
                &AdminError::Conflict(format!(
                    "group '{group}' already has {n} live key(s), at the \
                     `limits.max_keys_per_principal` cap of {cap}; revoke or delete an existing \
                     key before minting another",
                )),
                Cond::AtKeyCap,
            );
        }
        MintOutcome::Bearer(b) => {
            let (key, token) = *b;
            (key, token, None)
        }
        MintOutcome::Aws(b) => {
            let (key, token, access_key_id, secret_access_key) = *b;
            (key, token, Some((access_key_id, secret_access_key)))
        }
    };
    audit::AUDIT.record_by(
        "key.create",
        &format!("key:{}", key.id),
        audit::OUTCOME_APPLIED,
        &actor,
    );
    let mut body = key_meta(&key);
    // A freshly minted key is deterministically "active" — `mint_signed`/
    // `mint_signed_with_aws` always set `enabled: true` and `deleted_at: None`, and the id is a fresh
    // CSPRNG draw that cannot already be on the revocation denylist. No `gov.is_revoked` round-trip
    // needed (and `gov` is not in scope here — moved into the mint closure above).
    body["state"] = json!("active");
    // The busbar-SIGNED token IS the key credential, shown exactly once.
    body["token"] = json!(token);
    body["expires_at"] = json!(exp);
    // Tell the caller whether this mint AUTO-PROVISIONED its group leaf (self-service), so a
    // portal can distinguish "bound to an existing bucket" from "created your personal bucket + bound".
    body["group_provisioned"] = json!(provisioned_group);
    if let Some((access_key_id, secret_access_key)) = aws {
        // The AccessKeyId is NOT secret (it travels in plaintext in the SigV4 header); the AWS SECRET
        // access key is shown ONCE here only, mirroring the token.
        body["aws_access_key_id"] = json!(access_key_id);
        body["aws_secret_access_key"] = json!(secret_access_key);
    }
    if let Some(ref ck) = idem_ckey {
        app.idempotency_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ck.clone(), (crate::store::now(), body.clone()));
    }
    if let Some(g) = idem_reservation.as_mut() {
        g.state = IdemState::Committed;
    }
    json_response(StatusCode::CREATED, body)
}

/// Partial update to an existing key. Keys are PURE AUTH (1.5.0), so the mutable surface is
/// auth-shaped only. Every field is optional; only the present ones change. The credential, name,
/// allowed-pools, and labels are immutable here (rotate/recreate for those).
///
/// `group` is THREE-STATE via serde double-option (`Option<Option<String>>`):
/// - absent (`#[serde(default)]` -> outer `None`): leave the binding unchanged.
/// - JSON `null` (`Some(None)`): UNBIND to no group (authed + unlimited).
/// - a value (`Some(Some(name))`): REBIND to that group (must exist; mint-parity check).
///
/// A single `Option<T>` could not tell absent from present-null, so a binding could never be
/// cleared once set. `enabled` is a plain `Option<bool>` (a bool has no clear state). The 1.4.x
/// cap fields (`rpm_limit`/`tpm_limit`/`max_budget_cents`) are GONE: limits live on the group.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct UpdateKeyReq {
    #[serde(default)]
    enabled: Option<bool>,
    /// Rebind or UNBIND the key's group. Absent = unchanged; `null` = unbind. The double `Option`
    /// is what distinguishes those two, so the schema describes it as a nullable string.
    #[serde(default, deserialize_with = "double_option")]
    #[cfg_attr(feature = "openapi-schema", schemars(with = "Option<String>"))]
    group: Option<Option<String>>,
}

/// PATCH /api/v1/admin/keys/{id}: enable/disable a key or rebind/unbind its group. `enabled` is
/// the primary use (disabling a key WITHOUT destroying its usage history, which `DELETE` would).
/// Admin-gated by the auth middleware (every `/admin/*` path requires the admin token). A rebind
/// target is validated to EXIST (mint parity): otherwise PATCH would be a back door minting a
/// dangling binding that fails every request closed. 404 if the key is absent.
pub(crate) async fn update_key(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<crate::state::AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.patch",
        resource: &resource,
        actor: &actor,
    };
    // Fast-fail BEFORE parsing the body if governance is off (the authoritative re-check happens under
    // the config-mutation lock below, against the live App).
    if handle.load().governance.is_none() {
        return disabled_write(who);
    }
    if let Some(resp) = reject_overlong_id(who, &id) {
        return resp;
    }
    // OPTIMISTIC CONCURRENCY (optional `If-Match`): the caller's ETag is compared against the
    // CURRENT record — a stale tag is a 409, never a lost update. The compare must be ATOMIC with
    // the write, so it is deferred INTO the gated write closure below (a separate pre-read here
    // would leave a window in which a concurrent PATCH mutates the row between the check and this
    // write, defeating the guard). Absent header = the transitional unguarded path.
    let if_match = match parse_key_if_match(who, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Parse via the depth-guarded `crate::json` seam, not axum's `Json<T>` (whose rejection body
    // echoes the raw serde error / an input fragment). Any failure maps to a GENERIC 400, logging
    // only the byte length via `parse_err_log` — no raw error, no input fragment.
    let req: UpdateKeyReq = match crate::json::parse(&body) {
        Ok(req) => req,
        Err(_) => {
            tracing::warn!("update_key: {}", crate::json::parse_err_log(body.len()));
            return key_err(
                who,
                &AdminError::Validation("invalid JSON".into()),
                Cond::MalformedBody,
            );
        }
    };
    // MINT-PARITY validation: a rebind target must exist in the top-level groups block NOW - a
    // dangling binding would fail every request on this key closed at admission. Only a present
    // VALUE is checked (`Some(Some(name))`); a present `null` (unbind) and an absent field need no
    // check.
    //
    // The existence check and the store write are ONE `config_transaction` section, so a group
    // cannot be DELETED between validating it and persisting the binding: group create/DELETE run
    // through the SAME choke point (and DELETE refuses while keys are still bound), and the check
    // reads the FRESH post-lock snapshot rather than the extractor's (possibly pre-swap) one.
    // Serialized this way a rebind and a group delete cannot interleave: either the rebind lands
    // first (then DELETE sees the bound key → 409) or the delete lands first (then this check sees
    // the group gone → 400).
    //
    // RESURRECTION RACE: `update_key` is a check-then-act (`get_key` → `put_key`, and `put_key`
    // UPSERTs on the PRIMARY KEY, so it INSERTs a missing row rather than no-opping). A PATCH that
    // reads an extant key, then has a concurrent DELETE remove the row before its `put_key` runs,
    // would re-create the just-revoked key. The blocking closure holds the same `EXISTENCE_GATE`
    // `delete_key` uses across the whole lookup→put section so PATCH and DELETE cannot interleave.
    //
    // CANCELLATION SAFETY: the gate is locked INSIDE the blocking closure so its lifetime is bound
    // to the synchronous `gov.update_key` mutation, not to this cancellable async handler. If the
    // client drops the request the already-scheduled closure still runs to completion holding the
    // gate — a dropped outer future can never release it mid-write. The If-Match compare and the
    // write run TOGETHER under the gate, so the record the ETag was checked against is the same
    // record that gets updated.
    enum UpdateOutcome {
        /// The updated row plus its `state`, computed INSIDE the gated closure below (where
        /// `gov` — and therefore `gov.is_revoked`, needed to tell a disabled key from a revoked one —
        /// is in scope; the outer `match` below is outside the transaction closure and has no `gov`).
        Updated(Box<crate::governance::VirtualKey>, &'static str),
        NotFound,
        EtagStale,
        /// The destination bucket (rebind target, or the key's own group on a re-enable) is
        /// already at `limits.max_keys_per_principal`.
        AtCap {
            group: String,
            n: usize,
            cap: usize,
        },
    }
    let res = crate::admin::v1::json::config_transaction(&handle, move |txn| {
        let current = txn.app();
        let Some(gov) = current.governance.clone() else {
            // Unreachable in practice — governance is process-lifetime and is reused across every
            // swap, so the pre-parse fast-fail above already answered. Fail closed anyway.
            return Err(AdminError::Conflict(
                "governance is not enabled on this server; enable `governance:` in config.yaml to \
                 manage virtual keys"
                    .into(),
            ));
        };
        if let Some(Some(group)) = req.group.as_ref() {
            if !current.groups_registry.contains_key(group.as_str()) {
                return Err(AdminError::Validation(format!(
                    "group '{group}' does not exist in the top-level groups block; configure it \
                     first (e.g. {group}: {{ limits: [ {{ budget: 0, per: month }} ] }})"
                )));
            }
        }
        let (enabled, group) = (req.enabled, req.group);
        // The anti-sprawl ceiling, read from the FRESH post-lock snapshot exactly as the mint does.
        let cap = current.max_keys_per_principal;
        Ok(txn.store_write(move || {
            let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
            let outcome = (|| -> crate::governance::StoreResult<UpdateOutcome> {
                // ONE read of the pre-image, inside the gate: it answers If-Match staleness,
                // existence, AND the cap guard below, so the three cannot disagree about which
                // record they are talking about.
                // O(1) row lookup instead of a full-table `all_keys()` scan filtered by id: this
                // runs under `EXISTENCE_GATE`, where a fresh single-row store read is exactly what
                // the If-Match compare below needs (see `Store::get_key`).
                let Some(before) = gov.store().get_key(&id)? else {
                    return Ok(UpdateOutcome::NotFound);
                };
                if let Some(tag) = &if_match {
                    if key_etag(&before) != *tag {
                        return Ok(UpdateOutcome::EtagStale);
                    }
                }
                // ANTI-SPRAWL CAP ON EVERY PATCH THAT ADDS A LIVE KEY TO A BUCKET.
                // `max_keys_per_principal` was enforced only at MINT,
                // so a PATCH could walk a principal past its own ceiling one rebind at a time —
                // mint N keys under an empty group, then rebind them all onto the capped one.
                //
                // Guarding only the REBIND left the same ratchet hole open on the OTHER field:
                // `check_key_cap` counts LIVE keys (enabled + not denylisted, by design so a
                // revoke frees a slot), so `PATCH {"enabled": false}` × N followed by N fresh mints
                // and then `PATCH {"enabled": true}` × N walks the bucket to 2N with every
                // individual request passing the guard. RE-ENABLING is an admission, exactly like a
                // rebind, and is gated here as one.
                //
                // The predicate is the general one both cases are instances of: check the cap iff
                // this PATCH would ADD a live key to its destination bucket — i.e. the key is live
                // afterwards AND was not already counted in that bucket (it was dead, or it was
                // live in a different bucket). A no-op re-save, a disable, and a rebind of an
                // already-dead key are all untouched, so an at-cap bucket stays editable. The mover
                // is excluded from the count for the same reason.
                let revoked = gov.is_revoked(&before.id);
                let dest_group = match group.as_ref() {
                    Some(g) => g.clone(),
                    None => before.group.clone(),
                };
                let was_counted = before.enabled && !revoked;
                let will_be_counted = enabled.unwrap_or(before.enabled) && !revoked;
                if will_be_counted && (!was_counted || dest_group != before.group) {
                    if let Some((g, n)) =
                        check_key_cap(&gov, cap, dest_group.as_deref(), Some(id.as_str()))?
                    {
                        return Ok(UpdateOutcome::AtCap { group: g, n, cap });
                    }
                }
                Ok(match gov.update_key(&id, enabled, group)? {
                    Some(key) => {
                        let state = key_state(&key, &gov);
                        UpdateOutcome::Updated(Box::new(key), state)
                    }
                    None => UpdateOutcome::NotFound,
                })
            })()
            .map_err(|e| {
                tracing::error!(operation = "update_key", error = %e, "admin store operation failed");
                AdminError::Internal
            })?;
            Ok(crate::admin::v1::json::Outcome::Value(outcome))
        }))
    })
    .await;
    match res {
        Ok(UpdateOutcome::Updated(key, state)) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_APPLIED, &actor);
            let mut body = key_meta(&key);
            body["state"] = json!(state);
            json_response(StatusCode::OK, body)
        }
        Ok(UpdateOutcome::EtagStale) => {
            key_err(who,
                &AdminError::VersionConflict(
                    "If-Match ETag is stale: the key changed since you read it (re-read and retry)"
                        .into(),
                ),
                Cond::StaleIfMatch,
            )
        }
        Ok(UpdateOutcome::NotFound) => {
            key_err(who, &AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(UpdateOutcome::AtCap { group, n, cap }) => {
            key_err(who,
                &AdminError::Conflict(format!(
                    "group '{group}' already has {n} live key(s), at the \
                     `limits.max_keys_per_principal` cap of {cap}; revoke or delete one of its keys \
                     before rebinding or re-enabling another into it",
                )),
                Cond::AtKeyCap,
            )
        }
        // The only 400 this body can raise is the dangling rebind target; anything else is the
        // generic store failure, which carries no condition of its own.
        Err(e @ AdminError::Validation(_)) => key_err(who, &e, Cond::RebindTargetMissing),
        Err(e @ AdminError::Conflict(_)) => key_err(who, &e, Cond::GovernanceOff),
        Err(e) => crate::admin::v1::json::err_json(&e),
    }
}

/// GET /api/v1/admin/keys — list key metadata (no secrets/hashes). Optional filters:
/// `?enabled=true|false` (by enabled state), `?prefix=vk_ab` (by key-id prefix),
/// `?group=<name>` (keys bound to that group: a `user:<sub>` leaf's keys are one person's
/// keys; a team group's are the team's; the customer's self-service tool re-scopes from here).
pub(crate) async fn list_keys(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Strict query parsing FIRST: a malformed filter/cursor is a loud 400 on every
    // server — governance-off must not fork the validation behavior (200-empty only for a VALID
    // query).
    // An unparseable filter value is a loud 400, never a silently-dropped filter (which would
    // return MORE keys than the caller asked for).
    let enabled = match q.get("enabled") {
        None => None,
        Some(v) => match v.parse::<bool>() {
            Ok(b) => Some(b),
            Err(_) => {
                return key_err(
                    KeyAudit::Read,
                    &AdminError::Validation("invalid `enabled` filter: expected true|false".into()),
                    Cond::InvalidQueryValue,
                )
            }
        },
    };
    let prefix = q.get("prefix").cloned();
    // Group filter: exact bound-group match. No existence check against the registry — a key can
    // reference a group another node's config no longer has, and listing "keys of `g`" must still
    // find them (that dangling state is exactly what an operator would be hunting).
    let group = q.get("group").cloned();
    // PAGINATION: the ONE cursor envelope shared by every admin list —
    // `?limit=` bounds the page, `?cursor=` (opaque) resumes after the prior one, and the response is
    // `{items, next_cursor}` (next_cursor present iff more rows remain). No `total`, no `?offset=` —
    // one pagination grammar across keys/audit/versions/topology.
    // Default 200 / hard cap 1000 — the SAME limit policy as the audit/versions lists (one
    // pagination grammar, one limit policy; an unbounded default response is exactly what
    // pagination exists to prevent).
    let limit = match q.get("limit") {
        None => crate::admin::v1::contract::LIST_LIMIT_DEFAULT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n.clamp(1, crate::admin::v1::contract::LIST_LIMIT_MAX),
            Err(_) => {
                return key_err(
                    KeyAudit::Read,
                    &AdminError::Validation(format!(
                        "invalid `limit`: expected an integer (max {})",
                        crate::admin::v1::contract::LIST_LIMIT_MAX
                    )),
                    Cond::InvalidQueryValue,
                )
            }
        },
    };
    let start = match q.get("cursor") {
        Some(c) => match crate::admin::v1::contract::decode_offset_cursor(c) {
            Some(n) => n,
            None => {
                return key_err(
                    KeyAudit::Read,
                    &AdminError::Validation("invalid or foreign pagination cursor".into()),
                    Cond::MalformedCursor,
                )
            }
        },
        None => 0,
    };
    // Secondary point: a tombstoned key otherwise vanishes from this list with no marker —
    // "it is gone" and "it never existed" looked the same. `?include=tombstoned` opts in to seeing
    // them (each row's now-additive `state` reads `"tombstoned"`); default behaviour (their
    // continued silent omission from a plain `GET /keys`) is unchanged, so this is purely additive.
    let include_tombstoned = match q.get("include") {
        None => false,
        Some(v) if v == "tombstoned" => true,
        Some(_) => {
            return key_err(
                KeyAudit::Read,
                &AdminError::Validation("invalid `include` filter: expected `tombstoned`".into()),
                Cond::InvalidQueryValue,
            )
        }
    };
    let Some(gov) = &app.governance else {
        return disabled_empty_list();
    };
    let gov = gov.clone();
    let res = tokio::task::spawn_blocking(move || {
        let keys = gov.all_keys()?;
        // `state` is derived HERE, on the blocking pool, where `gov` — and therefore
        // `gov.is_revoked` — is in scope; the outer match below is past the `.await` and has no
        // `gov` of its own (it was moved into this closure).
        Ok::<_, crate::governance::StoreError>(
            keys.into_iter()
                .map(|k| {
                    let state = key_state(&k, &gov);
                    (k, state)
                })
                .collect::<Vec<_>>(),
        )
    })
    .await;
    match res {
        Ok(Ok(keys)) => {
            let mut filtered: Vec<_> = keys
                .iter()
                // TOMBSTONE (1.5.0): `gov.all_keys()` -> `Store::list_keys` is deliberately
                // unfiltered (billing/audit attribution needs tombstoned rows to keep resolving by
                // id) — the admin LISTING is the caller responsible for filtering live-only by
                // default, same as every other "does this key exist" surface on this handler set.
                // `?include=tombstoned` opts back in.
                .filter(|(k, _)| include_tombstoned || k.deleted_at.is_none())
                .filter(|(k, _)| enabled.is_none_or(|e| k.enabled == e))
                .filter(|(k, _)| prefix.as_deref().is_none_or(|p| k.id.starts_with(p)))
                .filter(|(k, _)| {
                    group
                        .as_deref()
                        .is_none_or(|g| k.group.as_deref() == Some(g))
                })
                .collect();
            // Deterministic page boundaries: sort by id (the store's iteration order is not a
            // pagination contract).
            filtered.sort_by(|(a, _), (b, _)| a.id.cmp(&b.id));
            let total = filtered.len();
            let page: Vec<_> = filtered
                .into_iter()
                .skip(start)
                .take(limit)
                .map(|(k, state)| {
                    let mut v = key_meta(k);
                    v["state"] = json!(state);
                    v
                })
                .collect();
            // More rows past this page → hand back the next opaque cursor; else None (end of list).
            let end = start.saturating_add(page.len());
            let next_cursor =
                (end < total).then(|| crate::admin::v1::contract::encode_offset_cursor(end));
            json_response(
                StatusCode::OK,
                json!({ "items": page, "next_cursor": next_cursor }),
            )
        }
        Ok(Err(e)) => internal_error("list_keys", &e),
        Err(e) => join_error("list_keys", &e),
    }
}

/// POST /api/v1/admin/keys/{id}/rotate — re-issue an existing key's CREDENTIAL in place: the id (and
/// with it budgets, rate windows, usage, audit attribution) is unchanged, the PREVIOUS credential
/// stops authenticating immediately and fleet-wide, and the new one is returned exactly once,
/// exactly like mint. 404 for an unknown id. An attached AWS SigV4 credential is not touched
/// (separate lifecycle).
///
/// A 1.5.0 signed-token key answers with `{token, expires_at}` (a fresh token at a new binding
/// generation — every previously-issued token for the subject is now rejected); a legacy
/// hashed-secret key answers with `{secret}`. Rotation NEVER converts the former into the latter:
/// arming a hashed bearer secret on a signed-token key would add a second, weaker, non-expiring
/// credential to a key deliberately minted without one.
pub(crate) async fn rotate_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.rotate",
        resource: &resource,
        actor: &actor,
    };
    // IDEMPOTENT ROTATE (optional `Idempotency-Key`): rotate is the one other
    // destructive, secret-bearing POST — a network-level retry without this mints TWICE and the
    // first (lost) response's secret is silently dead. Same mechanics as create's idempotent mint
    // (principal-scoped cache + in-flight reservation), with the cache key additionally scoped by
    // operation + key id so a create and a rotate sharing a header value can never replay each
    // other's response.
    let idem_ckey: Option<(String, String)> = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|k| (actor.clone(), format!("rotate:{id}:{k}")));
    if let Some(ref ck) = idem_ckey {
        let now = crate::store::now();
        let mut cache = app
            .idempotency_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.retain(|_, (t, _)| now.saturating_sub(*t) < IDEMPOTENCY_TTL_SECS);
        match cache.get(ck) {
            Some((_, cached)) if !cached.is_null() => {
                return json_response(StatusCode::OK, cached.clone());
            }
            Some(_) => {
                return key_err(
                    who,
                    &AdminError::Conflict(
                        "a request with this Idempotency-Key is already in flight".into(),
                    ),
                    Cond::IdempotencyInFlight,
                );
            }
            None => {
                cache.insert(ck.clone(), (now, serde_json::Value::Null));
            }
        }
    }
    let mut idem_reservation = idem_ckey.as_ref().map(|ck| IdemReservation {
        cache: app.idempotency_cache.clone(),
        key: ck.clone(),
        state: IdemState::Reserved,
    });
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    let gov = gov.clone();
    let gid = id.clone();
    // rotate is a check-then-act (get_key → mint → put_key over the UPSERT primitive), so it must
    // hold EXISTENCE_GATE for the same reason update_key/delete_key do: without it a concurrent
    // delete that lands between rotate's read and write is clobbered by rotate's put — RESURRECTING
    // a revoked key with a fresh secret. Gate acquired INSIDE the closure for cancellation safety
    // (a scheduled spawn_blocking runs to completion even if the handler future is dropped).
    // The re-minted signed token gets the SAME default lifetime a mint with no `expires_in` /
    // `expires_at` would receive (rotate takes no body today).
    let exp = crate::store::now().saturating_add(DEFAULT_KEY_TTL_SECS);
    // The rotate is about to be handed to `spawn_blocking`'s uncancellable task — from here on, a
    // dropped handler future (client disconnect) must NOT clear the sentinel. See `IdemState::InFlight`.
    if let Some(r) = idem_reservation.as_mut() {
        r.state = IdemState::InFlight;
    }
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        // `state` is derived HERE (where `gov` is in scope, moved into this closure) rather
        // than after the `.await` below — a rotated key can still be `disabled` or `revoked` (rotate
        // does not touch `enabled` or the denylist, only tombstoned keys refuse to rotate at all, see
        // `GovState::rotate_key`), so `gov.is_revoked` is genuinely needed, not just `enabled`.
        gov.rotate_key(&gid, exp)
            .map(|opt| opt.map(|rotated| (key_state(&rotated.key, &gov), rotated)))
    })
    .await;
    match res {
        Ok(Ok(Some((state, rotated)))) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_APPLIED, &actor);
            let mut body = key_meta(&rotated.key);
            body["state"] = json!(state);
            // Shown exactly once, exactly like mint. 1.5.0 has exactly one bearer-credential shape,
            // so rotation always re-issues a signed token.
            body["token"] = json!(rotated.token);
            body["expires_at"] = json!(rotated.exp);
            // COMMIT the idempotency slot with the real response (replaces the reservation) and
            // disarm the drop-guard — a retry inside the window replays THIS body verbatim.
            if let Some(ref ck) = idem_ckey {
                let mut cache = app
                    .idempotency_cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                cache.insert(ck.clone(), (crate::store::now(), body.clone()));
                if let Some(r) = idem_reservation.as_mut() {
                    r.state = IdemState::Committed;
                }
            }
            json_response(StatusCode::OK, body)
        }
        // All three arms below are the transaction's OWN fail-closed outcomes, reached only after
        // the `.await` completed normally (never on genuine cancellation) — safe to free the
        // reservation for a legitimate retry.
        Ok(Ok(None)) => {
            if let Some(r) = idem_reservation.as_mut() {
                r.clear();
            }
            key_err(who, &AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Err(e)) => {
            if let Some(r) = idem_reservation.as_mut() {
                r.clear();
            }
            internal_error("rotate_key", &e)
        }
        Err(e) => {
            if let Some(r) = idem_reservation.as_mut() {
                r.clear();
            }
            join_error("rotate_key", &e)
        }
    }
}

/// POST /api/v1/admin/keys/{id}/revoke - REVOKE a signed-token key WITHOUT deleting its binding /
/// usage history (1.5.0). Adds the subject to the durable revocation denylist so every outstanding
/// token for it is rejected immediately (stateless verify + denylist read), while `GET /keys/{id}`
/// still shows the (now-revoked) binding for the record. Idempotent - revoking an already-revoked
/// key is 200. `DELETE /keys/{id}` is the revoke-AND-forget variant.
pub(crate) async fn revoke_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.revoke",
        resource: &resource,
        actor: &actor,
    };
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    if let Some(resp) = reject_overlong_id(who, &id) {
        return resp;
    }
    let gov = gov.clone();
    let id_for_task = id.clone();
    // The subject must name an existing binding (a revoke for a nonexistent key is a 404, not a
    // silent denylist entry for a typo'd id). Then denylist it durably.
    let res = tokio::task::spawn_blocking(move || -> crate::governance::StoreResult<bool> {
        // Hold EXISTENCE_GATE across the existence check and the denylist write, matching
        // update_key/rotate_key/delete_key. Without it, a concurrent `delete_key` can dispose of the
        // key in the window between this check-then-act, producing a phantom `key.revoke APPLIED`
        // audit record for a key another operation already fully disposed of (audit non-repudiation).
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        // O(1) row lookup instead of a full-table `all_keys()` scan filtered by id.
        let exists = gov.store().get_key(&id_for_task)?.is_some();
        if !exists {
            return Ok(false);
        }
        gov.revoke(&id_for_task, "revoked via admin API")?;
        Ok(true)
    })
    .await;
    match res {
        Ok(Ok(true)) => {
            audit::AUDIT.record_by("key.revoke", &resource, audit::OUTCOME_APPLIED, &actor);
            json_response(StatusCode::OK, json!({ "revoked": id }))
        }
        Ok(Ok(false)) => key_err(who, &AdminError::not_found("key"), Cond::UnknownResource),
        Ok(Err(e)) => internal_error("revoke_key", &e),
        Err(e) => join_error("revoke_key", &e),
    }
}

/// POST /api/v1/admin/signing-key/rotate - ROTATE the busbar key-signing key. Rotation is
/// REVOKE-ALL by design: a new signing key means every token minted under the OLD key stops
/// verifying (its `kid`/signature no longer matches), so every outstanding key must be re-minted.
/// 1.5.0 is single-key, so this reports the intent and the current kid; the actual key swap is an
/// operator action (replace `auth.signing_key` / the persisted key file and restart or reload) so
/// that a fleet rotates in lockstep. Returns the current kid and the revoke-all warning; a future
/// keyset makes this a live in-process swap.
pub(crate) async fn rotate_signing_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let who = KeyAudit::Mutation {
        verb: "signing_key.report",
        resource: "signing-key",
        actor: &actor,
    };
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    let Some(kid) = gov.signing_kid() else {
        return key_err(
            who,
            &AdminError::Conflict("no signing key is configured; nothing to rotate".into()),
            Cond::NothingToRotate,
        );
    };
    // `signing_key.report`, not `signing_key.rotate`: this endpoint rotates NOTHING. It reads the
    // current kid and returns the operator instructions below. Recording it as `rotate`/`applied`
    // told anyone reading the log that every outstanding token had been revoked.
    //
    // The row stays, rather than being dropped as a non-mutation, because the log exists so a
    // credential probing the surface leaves a trail — and a valid admin token calling this
    // repeatedly is exactly that. Dropping it would also make this the only `KeyAudit::Mutation`
    // verb in the file that audits its refusals but not its successes.
    audit::AUDIT.record_by(
        "signing_key.report",
        "signing-key",
        audit::OUTCOME_APPLIED,
        &actor,
    );
    json_response(
        StatusCode::OK,
        json!({
            "current_kid": kid,
            "revoke_all": true,
            "message": "rotating the signing key REVOKES ALL outstanding keys (every token must be \
                        re-minted). 1.5.0 is single-key: replace auth.signing_key (or the persisted \
                        signing-key file) with fresh material and restart/reload every node in \
                        lockstep, then re-mint keys."
        }),
    )
}

/// GET /api/v1/admin/keys/{id} — one key's metadata (id/name/pools/budgets/limits/enabled; never the
/// secret or generation_hash). 404 when no key with `id` exists. Fills the single-key read gap in the key
/// surface; it stays on the legacy `{type}` envelope + `key_meta` shape so
/// it is consistent with the sibling key routes (the full `{code}`-envelope migration is a follow-up).
pub(crate) async fn get_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(KeyAudit::Read, &id) {
        return resp;
    }
    let gov = gov.clone();
    let id2 = id.clone();
    // The synchronous store read runs on the blocking pool (the SQLite backend is sync). O(1) row
    // lookup via `Store::get_key`, not a full-table `all_keys()` scan filtered by id.
    // `state` is derived HERE too, alongside the read — `gov.is_revoked` needs `gov`, which is
    // moved into this closure and unavailable after the `.await` below.
    let res = tokio::task::spawn_blocking(move || {
        gov.store()
            .get_key(&id2)
            .map(|opt| opt.map(|k| (key_state(&k, &gov), k)))
    })
    .await;
    match res {
        Ok(Ok(Some((state, k)))) => {
            let etag = key_etag(&k);
            // ETag lives ONLY in the HTTP `ETag` header (RFC 7232), not duplicated into the JSON
            // body — one authoritative surface, matching how config/hooks/auth expose their
            // concurrency token.
            let mut meta = key_meta(&k);
            meta["state"] = json!(state);
            let mut resp = json_response(StatusCode::OK, meta);
            if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
                resp.headers_mut().insert(axum::http::header::ETAG, v);
            }
            resp
        }
        Ok(Ok(None)) => key_err(
            KeyAudit::Read,
            &AdminError::not_found("key"),
            Cond::UnknownResource,
        ),
        Ok(Err(e)) => internal_error("get_key", &e),
        Err(e) => join_error("get_key", &e),
    }
}

/// GET /api/v1/admin/keys/{id}/usage — the key's BUDGET-window counters (the enforcement view:
/// spend/tokens/requests against its own budget window; the fleet FinOps series lives on `/usage`)
/// plus `rate_headroom`: the fraction `[0,1]` of the tightest `requests`/`tokens` limit across
/// the key's group chain still available in each limit's own window (`null` when the chain has no
/// such limit): a client can back off BEFORE hitting a 429 instead of discovering the cap by
/// tripping it (key-06).
pub(crate) async fn key_usage(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(KeyAudit::Read, &id) {
        return resp;
    }
    let now = crate::store::now();
    let gov2 = gov.clone();
    let id2 = id.clone();
    // One blocking hop fetches BOTH the usage counters and the key record (the record feeds the
    // in-memory `rate_headroom` read, which needs the configured caps).
    let cost = app.cost.clone();
    let res = tokio::task::spawn_blocking(move || {
        // DERIVED at read time: spend_cents = ledger x CURRENT rate card (+ fee x requests) - a
        // rate-card correction changes this number on the very next read (tokens are the truth).
        let usage = gov2.usage_for(&cost, &id2, now)?;
        // O(1) row lookup instead of a full-table `all_keys()` scan filtered by id.
        let key = gov2.store().get_key(&id2)?;
        // TOMBSTONE (1.5.0): `get_key` (and `usage_for`, which may still find a residual/derived
        // bucket) can both still answer for a deleted key — attribution rows survive on purpose.
        // The admin-facing "does this key exist" surface must not, though: a tombstoned key reads
        // as absent here, same as an unknown id, so DELETE stays a real removal from every reader's
        // point of view.
        if key.as_ref().is_some_and(|k| k.deleted_at.is_some()) {
            return Ok::<_, crate::governance::StoreError>(None);
        }
        Ok::<_, crate::governance::StoreError>(usage.map(|u| (u, key)))
    })
    .await;
    match res {
        Ok(Ok(Some((u, key)))) => {
            // Headroom derives from the key's GROUP CHAIN (keys carry no caps of their own):
            // the tightest requests/tokens limit across the chain, `null` when unlimited.
            // Pool-less read: a per-pool cap is not a property of the key as a whole, so
            // pool-scoped buckets are excluded from this overview figure.
            let headroom = key
                .as_ref()
                .and_then(|k| gov.rate_headroom(&app.cost, k, None, now));
            // Label the numbers: a key's attribution bucket accrues in the ALL-TIME
            // window (its limits, if any, live on the bound group's own windows), plus when the
            // read was taken, so a consumer can cache, align, and reset-detect without guessing.
            json_response(
                StatusCode::OK,
                json!({
                    "id": id,
                    "budget_period": crate::governance::WINDOW_TOTAL,
                    "window_start": 0,
                    "as_of": now,
                    "group": key.as_ref().and_then(|k| k.group.clone()),
                    "spend_cents": u.spend_cents,
                    "tokens": u.tokens,
                    "requests": u.requests,
                    "rate_headroom": headroom,
                }),
            )
        }
        Ok(Ok(None)) => key_err(
            KeyAudit::Read,
            &AdminError::not_found("key"),
            Cond::UnknownResource,
        ),
        Ok(Err(e)) => internal_error("key_usage", &e),
        Err(e) => join_error("key_usage", &e),
    }
}

/// DELETE /api/v1/admin/keys/{id} — revoke a key. Returns 404 when no key with `id` exists (REST/OpenAPI
/// contract), so a typo'd or already-deleted id is distinguishable from an actual revocation rather
/// than masquerading as a spurious 200.
pub(crate) async fn delete_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The ONE audit identity for this operation: `key_err` writes the `rejected` row from it, so a
    // refusal cannot be shaped without being recorded. See `KeyAudit`.
    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.delete",
        resource: &resource,
        actor: &actor,
    };
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    if let Some(resp) = reject_overlong_id(who, &id) {
        return resp;
    }
    // Optimistic concurrency (optional `If-Match` — every mutation verb on the surface honors
    // it): the caller's ETag is compared against the CURRENT record inside the gated critical
    // section below, so the delete only lands on the exact record state the caller last read.
    let if_match = match parse_key_if_match(who, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Existence check before delete: the key RECORD is looked up first and `None` means not-found
    // (the store's `delete_key` silently no-ops a zero-row delete, so we cannot rely on it to signal
    // not-found). Use the public GovState API rather than reaching into the store. The record (not a
    // bare existence bit) is needed anyway: the optional If-Match guard compares its ETag.
    //
    // Both store calls (the lookup and the delete) run on ONE `spawn_blocking` task so neither
    // blocks a Tokio worker thread, matching the request-path discipline. Running them on the same
    // task also keeps the lookup→delete pair tighter than two separately-scheduled awaits would.
    //
    // TOCTOU: `GovState`/store expose no rows-affected signal, so a *bare* check-then-act would let
    // two concurrent DELETEs of the same id both observe `Some` and both return 200 (the second SQL
    // delete no-ops) — a misleading audit trail implying two revocations of one row. The store-layer
    // `changes()` signal does not exist, so the race is closed here instead: serialize
    // every delete's lookup→delete critical section behind the process-wide `EXISTENCE_GATE`. The same
    // gate also serializes `update_key`'s lookup→put, so a PATCH cannot resurrect a key this DELETE
    // removes (see `EXISTENCE_GATE`). The loser of a delete race observes `Ok(None)` and correctly
    // returns 404. Deletes are admin-only and rare, so a single global lock has no meaningful cost.
    //
    // CANCELLATION SAFETY: the gate is locked INSIDE the `spawn_blocking` closure, so the whole
    // lookup→delete runs under the lock on the blocking thread. `spawn_blocking` is uncancellable once
    // scheduled, so even if the client drops this request the critical section completes while still
    // holding the gate — the gate can never be released mid-sequence by an outer-future drop.
    /// The three delete outcomes the gated critical section distinguishes.
    enum DeleteOutcome {
        Deleted,
        NotFound,
        EtagStale,
    }
    let gov = gov.clone();
    let id_for_task = id.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        // The key RECORD (not just existence) is read under the gate: the If-Match compare must be
        // atomic with the delete, exactly like PATCH's compare-and-put. O(1) row lookup instead of
        // a full-table `all_keys()` scan filtered by id.
        let key = gov.store().get_key(&id_for_task)?;
        match key {
            None => Ok(DeleteOutcome::NotFound),
            // TOMBSTONE (1.5.0): `get_key` returns a deleted key's row forever (billing/admin
            // attribution needs it to), so a second DELETE — or N concurrent ones — must not treat
            // an already-tombstoned row as "found, proceed": that is exactly what made every
            // concurrent delete report 204 and made a second delete report 204 instead of 404.
            Some(k) if k.deleted_at.is_some() => Ok(DeleteOutcome::NotFound),
            Some(k) => {
                if let Some(expected) = &if_match {
                    if key_etag(&k) != *expected {
                        return Ok(DeleteOutcome::EtagStale);
                    }
                }
                // REVOKE-THEN-DELETE (1.5.0): add the subject to the denylist BEFORE removing the
                // binding, so a signed token for this key is rejected even in the window between
                // the denylist write and the binding removal (and stays rejected via the durable
                // denylist even if a stale in-memory binding lingered on another node). A denylist
                // write failure is fatal to the delete (fail-closed: never report a delete that did
                // not durably revoke).
                gov.revoke(&id_for_task, "key deleted")?;
                gov.delete_key(&id_for_task)
                    .map(|()| DeleteOutcome::Deleted)
            }
        }
    })
    .await;
    match res {
        Ok(Ok(DeleteOutcome::Deleted)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // 204 No Content — the SAME success shape as `DELETE /api/v1/admin/hooks/{name}` (was a
            // bespoke `200 {"deleted": id}` found nowhere else on the surface). (contract H4.)
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(DeleteOutcome::NotFound)) => {
            key_err(who, &AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Ok(DeleteOutcome::EtagStale)) => key_err(
            who,
            &AdminError::VersionConflict(
                "If-Match ETag is stale: the key changed since you read it (re-read and retry)"
                    .into(),
            ),
            Cond::StaleIfMatch,
        ),
        Ok(Err(e)) => internal_error("delete_key", &e),
        Err(e) => join_error("delete_key", &e),
    }
}

/// THE KEY-CAP CHOKE POINT, class-level. Every path that can add
/// a key to a principal's bucket — the mint and the rebind — asks `check_key_cap`, so these cases
/// pin the shared predicate rather than one call site.
#[cfg(test)]
mod key_cap_tests {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    use std::sync::Arc;

    fn gov() -> Arc<GovState> {
        Arc::new(GovState::new(Arc::new(MemoryStore::new()), Some("t".into())).unwrap())
    }

    fn mint(gov: &GovState, name: &str, group: Option<&str>) -> crate::governance::VirtualKey {
        gov.create_key(
            NewKeySpec {
                name: name.into(),
                allowed_pools: None,
                group: group.map(str::to_string),
                labels: Default::default(),
            },
            0,
        )
        .expect("mint")
        .0
    }

    /// `cap == 0` is unlimited, and a bucket under its ceiling admits.
    #[test]
    fn zero_cap_is_unlimited_and_under_cap_admits() {
        let g = gov();
        for i in 0..5 {
            mint(&g, &format!("k{i}"), Some("team"));
        }
        assert!(super::check_key_cap(&g, 0, Some("team"), None)
            .unwrap()
            .is_none());
        assert!(super::check_key_cap(&g, 6, Some("team"), None)
            .unwrap()
            .is_none());
        let hit = super::check_key_cap(&g, 5, Some("team"), None)
            .unwrap()
            .expect("at cap");
        assert_eq!(hit, ("team".to_string(), 5));
    }

    /// The cap counts LIVE keys only. A revoked or disabled key holds no usable credential, so
    /// counting it forever made the ceiling a ONE-WAY RATCHET — and made the rejection's own advice
    /// ("revoke or delete an existing key") false for `revoke`.
    #[test]
    fn revoked_and_disabled_keys_do_not_hold_a_cap_slot() {
        let g = gov();
        let a = mint(&g, "a", Some("team"));
        let b = mint(&g, "b", Some("team"));
        mint(&g, "c", Some("team"));
        assert!(
            super::check_key_cap(&g, 3, Some("team"), None)
                .unwrap()
                .is_some(),
            "three live keys fill a cap of 3"
        );

        // REVOKE one: its credential is dead, so its slot must come back.
        g.revoke(&a.id, "test").expect("revoke");
        assert!(
            super::check_key_cap(&g, 3, Some("team"), None)
                .unwrap()
                .is_none(),
            "a revoked key must not hold a cap slot forever"
        );

        // DISABLE another: same reasoning.
        g.update_key(&b.id, Some(false), None).expect("disable");
        assert!(
            super::check_key_cap(&g, 2, Some("team"), None)
                .unwrap()
                .is_none(),
            "a disabled key must not hold a cap slot"
        );
    }

    /// The UNBOUND bucket is capped too. A groupless key escapes the limit tree entirely, so
    /// exempting it from the key-count ceiling made the ceiling evadable by omitting one field.
    #[test]
    fn the_unbound_bucket_is_counted_too() {
        let g = gov();
        mint(&g, "a", None);
        mint(&g, "b", None);
        let hit = super::check_key_cap(&g, 2, None, None)
            .unwrap()
            .expect("the no-group bucket is capped");
        assert_eq!(hit, (super::UNBOUND_BUCKET_LABEL.to_string(), 2));
        // Bound keys live in their own bucket and do not spend the unbound one's slots.
        mint(&g, "c", Some("team"));
        assert_eq!(
            super::check_key_cap(&g, 2, None, None).unwrap(),
            Some((super::UNBOUND_BUCKET_LABEL.to_string(), 2)),
            "buckets are independent"
        );
    }

    /// The REBIND path excludes the key being MOVED, so re-PATCHing a key onto the group it
    /// is already bound to is not spuriously refused — while a genuine move into a full bucket is.
    #[test]
    fn rebind_excludes_the_mover_but_still_refuses_a_full_target() {
        let g = gov();
        let a = mint(&g, "a", Some("team"));
        mint(&g, "b", Some("team"));
        // `a` re-bound onto its OWN group: excluding the mover leaves 1 < 2, so it admits.
        assert!(
            super::check_key_cap(&g, 2, Some("team"), Some(&a.id))
                .unwrap()
                .is_none(),
            "a no-op rebind of an at-cap bucket onto itself must not 409"
        );
        // A key from elsewhere moving IN sees 2 >= 2 and is refused.
        let outsider = mint(&g, "c", None);
        assert!(
            super::check_key_cap(&g, 2, Some("team"), Some(&outsider.id))
                .unwrap()
                .is_some(),
            "a rebind must not walk a principal past its ceiling"
        );
    }
}

// The admin-surface e2e tests authenticate through the `admin-tokens` module; a
// `--no-default-features` binary compiles it OUT, which DISABLES the admin API wholesale (the
// admin_auth chain all-Passes ⇒ denied) — so this module only applies when the module exists.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/tests.rs"]
mod tests;

// The auto-provision POST-COMMIT FAILURE branch. Drives the
// handler directly (no HTTP), so it needs no admin-token module.
#[cfg(test)]
#[path = "tests/provision_tests.rs"]
mod provision_tests;
