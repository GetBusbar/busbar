// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Virtual-key management API. Admin CRUD over `/api/v1/admin/keys`, guarded by the
//! configured admin token (enforced in `auth_middleware`, not here). Mutations refresh the
//! `GovState` cache. Responses never include a key's `key_hash`; the plaintext secret is returned
//! exactly once, on creation.

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

/// Deserialize a field as a "double option" so the three JSON intents stay distinguishable:
///   - field ABSENT: the `#[serde(default)]` on the field supplies the OUTER `None`.
///   - field present `null`: this fn is invoked and yields `Some(None)` (an explicit clear).
///   - field present value: this fn is invoked and yields `Some(Some(v))` (an explicit set).
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
///   - Two concurrent DELETEs of one id would otherwise both observe `Some` and both return 200 (the
///     second SQL delete no-ops) — a misleading audit trail of two revocations of one row.
///   - A PATCH interleaved with a DELETE would otherwise RESURRECT the revoked key: the PATCH reads
///     the row (exists), the DELETE removes it, then the PATCH's `put_key` UPSERT re-inserts it. Under
///     this gate the PATCH's lookup→put runs to completion before any DELETE (so the row is gone
///     afterward), or after it (so the PATCH's `get_key` returns `None` → 404 and never re-puts).
///
/// The proper store-layer fix is an UPDATE-ONLY `put`/`update` (`UPDATE … WHERE id=?` that affects 0
/// rows when absent, never an upsert) used by `update_key`, which would need no lock at all — but that
/// method lives in `governance.rs`, outside this unit's owned files. This gate is the admin-side guard
/// that closes the resurrection race with the surface we own. Both ops are admin-only and rare, so a
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

/// `POST /keys` body (1.5.0 signed-token keys, S1): PURE AUTH + a signed expiring token. A minted
/// key is a busbar-signed `{sub, exp, kid}` token, returned ONCE. No rpm/tpm/budget on a key - all
/// enforcement flows through the bound `group`. `#[serde(deny_unknown_fields)]` so the removed
/// 1.4.x fields (max_budget_cents/rpm_limit/tpm_limit/budget_period) fail loudly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKeyReq {
    name: String,
    /// The `groups:` bucket this key binds to (at most one). A key with NO group is authed +
    /// unlimited (access only). If the named group EXISTS, the key binds to it. If it does NOT
    /// exist, the mint 400s UNLESS `parent` is given — then it is AUTO-PROVISIONED as a leaf under
    /// `parent` (self-service D2; see `parent`).
    #[serde(default)]
    group: Option<String>,
    /// AUTO-PROVISION target (self-service §6a, D2): the EXISTING parent group under which to create
    /// `group` as a leaf when `group` does not yet exist — the first-self-mint materialization of a
    /// `user:<sub>` personal budget bucket. The new leaf's limits come from the nearest-ancestor
    /// `child_default` template (inherit-only when none up the chain), created through the same
    /// validate-at-the-door path as `POST /groups`. If `group` ALREADY exists, `parent` must equal
    /// its actual parent (else 409) — a mint never re-homes an existing group. Ignored when `group`
    /// is absent (a key with no group has nothing to provision).
    #[serde(default)]
    parent: Option<String>,
    /// Pools this key may target. OMITTED = ALL pools; an explicit `[]` = NO pools (C6).
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
const DEFAULT_KEY_TTL_SECS: u64 = 90 * 86_400;

/// Parse a duration string (`<n><unit>`, unit in s|m|h|d) to seconds. Bounded so an absurd value
/// cannot overflow the `exp` computation.
fn parse_duration_secs(s: &str) -> Result<u64, String> {
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

// M6/F2 (scrape break): mint-time `labels` are echoed VERBATIM as Prometheus label names on every
// key metric series (metrics.rs `base_labels`). An unvalidated map is a scrape-integrity hole:
//   - a label named `key`/`bucket`/`model`/`tier` (the RESERVED names busbar itself attaches)
//     duplicates a label on the series, which breaks the WHOLE /metrics exposition (a duplicate
//     label name is invalid Prometheus text -> every scrape fails, not just this key);
//   - a name that is not a valid Prometheus label name (`^[a-zA-Z_][a-zA-Z0-9_]*$`) is rejected by
//     the exposition encoder for the same all-or-nothing effect;
//   - an unbounded count / length bloats every scrape and the store row.
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
/// invisible to the OpenAPI projection (design D §1.2) and let the two banks drift; naming a `Cond`
/// here is what makes each keys emission observable to `contract::taxonomy` (design D route 2).
fn key_err(e: &AdminError, cond: Cond) -> Response {
    crate::admin::v1::json::err_json_cond(e, cond)
}

/// 500 for an internal store/DB failure. The detailed error (which may embed raw SQL fragments,
/// column/table names, or paths from the store backend) is logged server-side via `tracing::error!`;
/// the HTTP body carries only a generic message so internal storage details are never disclosed to
/// the client (even an authenticated admin). `op` names the operation for log correlation.
fn internal_error(op: &str, e: &crate::governance::StoreError) -> Response {
    tracing::error!(operation = op, error = %e, "admin store operation failed");
    crate::admin::v1::json::err_json(&AdminError::Internal)
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
// v1 contract: the `{error:{code,message}}` envelope with the stable code enum (contract H1). Keys
// are a first-class v1 resource served by these handlers until they migrate into the versioned
// service module.
pub(crate) mod audit;
pub(crate) mod rate;
pub(crate) mod transport;
pub(crate) mod v1;
pub(crate) mod versions;

pub(crate) use v1::json::JsonV1;
pub(crate) use v1::service::mark_start;

/// Key metadata for API responses — deliberately omits `key_hash`.
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
/// with a header bug would re-read and retry forever (re-audit M4). Shared by PATCH and DELETE so
/// the two verbs can never diverge on grammar.
#[allow(clippy::result_large_err)] // Err = the ready-to-return 400 Response (callers just return it)
fn parse_key_if_match(headers: &axum::http::HeaderMap) -> Result<Option<String>, Response> {
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
            &AdminError::Validation(
                "malformed If-Match: expected the key's ETag (16 hex chars, quoted) or *".into(),
            ),
            Cond::MalformedIfMatch,
        ))
    }
}

fn key_meta(k: &VirtualKey) -> Value {
    // 1.5.0 keys are PURE AUTH bindings: id / name / allowed_pools / group / labels. Keys carry no
    // limits (all enforcement flows through the bound group). `allowed_pools` keeps the C6 intent:
    // JSON `null` = all pools; `[]` = no pools.
    json!({
        "id": k.id,
        "name": k.name,
        "allowed_pools": k.allowed_pools,
        "group": k.group,
        "enabled": k.enabled,
        "created_at": k.created_at,
        "labels": k.labels,
    })
}

/// Governance-off semantics (re-audit HIGH-2): ONE rule across the keys surface, chosen so no
/// status is ambiguous —
/// - collection READS (`GET /keys`) answer 200 with an EMPTY page (`disabled_empty_list`): with
///   governance off the keyspace is truthfully empty, and a 404 on a collection reads as a
///   mount/path error to every REST client;
/// - single-resource READS keep 404 `not_found` (also truthful — no such key exists);
/// - WRITES (create/patch/delete/rotate/revoke) answer 409 `conflict` (`disabled_write`): the request
///   conflicts with the server's configured state, with an actionable message. Previously every
///   handler returned 404 — making `not_found` mean two different things forever.
fn disabled_write() -> Response {
    key_err(
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
        &AdminError::not_found_because("key", "governance is not enabled on this server"),
        Cond::GovernanceOff,
    )
}

/// Bound a path `id` (the virtual-key id from `/api/v1/admin/keys/{id}`). Admin-gated, but an unbounded id
/// flows into a store lookup / log lines — cap it as defense-in-depth (DB/log-bloat guard). A real
/// minted id is `vk_` + 16 hex chars (19 chars), so [`MAX_KEY_ID_LEN`] is generous headroom. Returns
/// a 400 response when too long, `None` when acceptable.
fn reject_overlong_id(id: &str) -> Option<Response> {
    if id.len() > MAX_KEY_ID_LEN {
        Some(key_err(
            &AdminError::Validation("id must be <= 64 characters".into()),
            Cond::Overlong,
        ))
    } else {
        None
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

/// An in-flight idempotency RESERVATION. `create_key` inserts a `Null`-body sentinel under the
/// cache lock the instant it decides to mint (atomic with the "already cached?" check), so a
/// concurrent retry with the same `Idempotency-Key` sees the reservation and is rejected instead
/// of double-minting. This guard clears that sentinel on drop UNLESS the mint committed — so a
/// request that fails after reserving frees the key for a legitimate retry, while a successful
/// mint (which replaced the sentinel with its real 201 body and disarmed the guard) keeps it.
struct IdemReservation {
    #[allow(clippy::type_complexity)]
    cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(String, String), (u64, serde_json::Value)>>,
    >,
    key: (String, String),
    committed: bool,
}

impl Drop for IdemReservation {
    fn drop(&mut self) {
        if self.committed {
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
        committed: false,
    });
    let Some(gov) = &app.governance else {
        return disabled_write();
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
            &AdminError::Validation("name must be <= 256 characters".into()),
            Cond::Overlong,
        );
    }
    // M6/F2: labels are echoed verbatim as Prometheus label NAMES on this key's metric series; an
    // unsafe name (reserved, or not a valid label name) or an oversized map breaks the WHOLE scrape.
    // Reject at the mint ingress (see `validate_mint_labels`).
    if let Err(msg) = validate_mint_labels(&req.labels) {
        return key_err(&AdminError::Validation(msg), Cond::InvalidLabels);
    }
    // SIGNED-TOKEN keys require a signing key (S2). Without one, mint cannot issue a token - fail
    // loud rather than persist a binding no token can be issued for.
    if !gov.signing_enabled() {
        return key_err(
            &AdminError::Conflict(
                "signed-token minting is unavailable: no signing key is configured (set \
             auth.signing_key, or let busbar generate one on first boot)"
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
                &AdminError::Validation(
                    "expires_in and expires_at are mutually exclusive; set at most one".into(),
                ),
                Cond::KeyExpiryFields,
            );
        }
        (Some(dur), None) => match parse_duration_secs(dur) {
            Ok(secs) => now.saturating_add(secs),
            Err(msg) => return key_err(&AdminError::Validation(msg), Cond::KeyExpiryFields),
        },
        (None, Some(at)) => {
            if at <= now {
                return key_err(
                    &AdminError::Validation("expires_at is in the past".into()),
                    Cond::KeyExpiryFields,
                );
            }
            at
        }
        (None, None) => now.saturating_add(DEFAULT_KEY_TTL_SECS),
    };
    // `allowed_pools` (C6, intent carried INTACT into the binding): OMITTED = all pools (`None`);
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
    //  * The bound group's existence check and the key's store write share ONE continuous lock hold.
    //    The old shape resolved the group under the mutation lock, RELEASED it on return, then
    //    re-acquired the lock and re-verified the group BY HAND — a copied prose contract a third
    //    bind path would have had to copy again. There is nothing left to re-verify: the lock is
    //    never released between the check and the bind, so a concurrent group DELETE either lands
    //    first (this body sees the group gone → fail closed) or is blocked until the key is bound
    //    (then DELETE's bound-key guard sees it → 409).
    //  * `max_keys_per_principal` is read from `txn.app()` — the FRESH post-lock snapshot — not from
    //    the pre-lock extractor `app`. A settings apply landing between the request's snapshot and
    //    this enforcement can no longer make the mint enforce a stale ceiling: there is no older
    //    snapshot in scope to read.
    //  * The cap COUNT and the mint run together in ONE `spawn_blocking` closure under
    //    `EXISTENCE_GATE`, so N concurrent callers at the boundary are serialized — each sees the
    //    writes of those before it and only the first `cap - current` mints succeed. `>= cap` is a
    //    `409` (a retry can't fix it without deleting a key), and a store failure counting keys
    //    FAILS CLOSED — never mint past a ceiling we could not verify.
    //
    // LOCK ORDER: `config_transaction` holds the async config lock across the whole section and
    // takes `EXISTENCE_GATE` (a std Mutex) only INSIDE the blocking closure, never across an await —
    // one global acquisition order, no cycle.
    if req.group.is_none() && req.parent.is_some() {
        // `parent` without `group` has nothing to root — a loud 400 beats silently ignoring it.
        return key_err(
            &AdminError::Validation(
                "`parent` was given without `group`; `parent` names the group to auto-provision \
             `group` under, so `group` is required with it"
                    .into(),
            ),
            Cond::ParentWithoutGroup,
        );
    }
    /// What the mint's blocking half produced: the key (bearer-only or with AWS credentials), or the
    /// anti-sprawl ceiling it hit.
    enum MintOutcome {
        Bearer(Box<(crate::governance::VirtualKey, String)>),
        Aws(Box<(crate::governance::VirtualKey, String, String, String)>),
        AtCap { group: String, n: usize, cap: usize },
    }
    /// Count the keys bound to `group` and report the ceiling hit. Runs on a blocking thread under
    /// `EXISTENCE_GATE`, atomically with the mint that follows it. A store failure FAILS CLOSED.
    fn check_cap(
        gov: &crate::governance::GovState,
        cap_group: &Option<String>,
        cap: usize,
    ) -> crate::governance::StoreResult<Option<(String, usize)>> {
        if let Some(group) = cap_group.as_deref() {
            let n = gov
                .all_keys()?
                .iter()
                .filter(|k| k.group.as_deref() == Some(group))
                .count();
            if n >= cap {
                return Ok(Some((group.to_string(), n)));
            }
        }
        Ok(None)
    }
    // Keys carry NO inline limits (S1); enforcement flows through the bound group.
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
    let res = crate::admin::v1::json::config_transaction(&handle, move |txn| {
        let current = txn.app();
        // MINT-TIME group resolution (self-service D2): a bound `group` must exist NOW — a dangling
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
        // ANTI-SPRAWL CAP (audit gap 7 / self-service §6a): `limits.max_keys_per_principal` bounds
        // how many keys may bind to ONE group. Since a `user:<sub>` leaf IS the principal (§5), this
        // caps a self-issuing dev's key count. `0` = unlimited (skip). Only meaningful for a bound
        // key. An auto-provisioned leaf is brand-new (0 keys), so a group's FIRST self-mint always
        // passes. READ FROM THE FRESH SNAPSHOT — this is the stale-cap fix.
        let cap = current.max_keys_per_principal;
        let cap_group = if cap > 0 { spec.group.clone() } else { None };
        let did_provision = provisioned.is_some();
        // The blocking half: cap count + mint, one `spawn_blocking`, one `EXISTENCE_GATE` hold.
        let mint = move || {
            let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
            let minted = (|| -> crate::governance::StoreResult<MintOutcome> {
                if let Some((group, n)) = check_cap(&gov, &cap_group, cap)? {
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
        // written at the two sites that used to write it (a failed build, a failed persist), so the
        // audit trail is byte-for-byte what the hand-rolled path produced.
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    if provisioned_group {
        // The leaf was created + persisted inside the transaction — audited + versioned exactly like
        // an explicit `POST /groups`.
        let group = req.group.clone().unwrap_or_default();
        audit::AUDIT.record_by(
            "group.provision",
            &format!("group:{group}"),
            audit::OUTCOME_APPLIED,
            &actor,
        );
        let live = handle.load();
        live.versions.record(
            live.config_version,
            &actor,
            &format!(
                "group.provision group:{group} (auto, parent {})",
                req.parent.clone().unwrap_or_default()
            ),
            &live.hook_registry,
            &live.global_hooks,
        );
    }
    let (key, token, aws) = match minted {
        MintOutcome::AtCap { group, n, cap } => {
            return key_err(
                &AdminError::Conflict(format!(
                    "group '{group}' already has {n} key(s), at the \
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
    // The busbar-SIGNED token IS the key credential (S1), shown exactly once.
    body["token"] = json!(token);
    body["expires_at"] = json!(exp);
    // Tell the caller whether this mint AUTO-PROVISIONED its group leaf (self-service D2), so a
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
        g.committed = true;
    }
    json_response(StatusCode::CREATED, body)
}

/// Partial update to an existing key. Keys are PURE AUTH (1.5.0, S1), so the mutable surface is
/// auth-shaped only. Every field is optional; only the present ones change. The credential, name,
/// allowed-pools, and labels are immutable here (rotate/recreate for those).
///
/// `group` is THREE-STATE via serde double-option (`Option<Option<String>>`):
///   - absent (`#[serde(default)]` -> outer `None`): leave the binding unchanged.
///   - JSON `null` (`Some(None)`): UNBIND to no group (authed + unlimited).
///   - a value (`Some(Some(name))`): REBIND to that group (must exist; mint-parity check).
///
/// A single `Option<T>` could not tell absent from present-null, so a binding could never be
/// cleared once set. `enabled` is a plain `Option<bool>` (a bool has no clear state). The 1.4.x
/// cap fields (`rpm_limit`/`tpm_limit`/`max_budget_cents`) are GONE: limits live on the group.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateKeyReq {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
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
    // Fast-fail BEFORE parsing the body if governance is off (the authoritative re-check happens under
    // the config-mutation lock below, against the live App).
    if handle.load().governance.is_none() {
        return disabled_write();
    }
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    // OPTIMISTIC CONCURRENCY (optional `If-Match`): the caller's ETag is compared against the
    // CURRENT record — a stale tag is a 409, never a lost update. The compare must be ATOMIC with
    // the write, so it is deferred INTO the gated write closure below (a separate pre-read here
    // would leave a window in which a concurrent PATCH mutates the row between the check and this
    // write, defeating the guard). Absent header = the transitional unguarded path.
    let if_match = match parse_key_if_match(&headers) {
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
        Updated(Box<crate::governance::VirtualKey>),
        NotFound,
        EtagStale,
    }
    let resource = format!("key:{id}");
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
        Ok(txn.store_write(move || {
            let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
            let outcome = (|| -> crate::governance::StoreResult<UpdateOutcome> {
                if let Some(tag) = &if_match {
                    match gov.all_keys()?.into_iter().find(|k| k.id == id) {
                        Some(k) if key_etag(&k) != *tag => return Ok(UpdateOutcome::EtagStale),
                        None => return Ok(UpdateOutcome::NotFound),
                        Some(_) => {}
                    }
                }
                Ok(match gov.update_key(&id, enabled, group)? {
                    Some(key) => UpdateOutcome::Updated(Box::new(key)),
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
        Ok(UpdateOutcome::Updated(key)) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_APPLIED, &actor);
            json_response(StatusCode::OK, key_meta(&key))
        }
        Ok(UpdateOutcome::EtagStale) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(
                &AdminError::VersionConflict(
                    "If-Match ETag is stale: the key changed since you read it (re-read and retry)"
                        .into(),
                ),
                Cond::StaleIfMatch,
            )
        }
        Ok(UpdateOutcome::NotFound) => {
            audit::AUDIT.record_by("key.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(&AdminError::not_found("key"), Cond::UnknownResource)
        }
        // The only 400 this body can raise is the dangling rebind target; anything else is the
        // generic store failure, which carries no condition of its own.
        Err(e @ AdminError::Validation(_)) => key_err(&e, Cond::RebindTargetMissing),
        Err(e @ AdminError::Conflict(_)) => key_err(&e, Cond::GovernanceOff),
        Err(e) => crate::admin::v1::json::err_json(&e),
    }
}

/// GET /api/v1/admin/keys — list key metadata (no secrets/hashes). Optional filters (design-admin-api-v1
/// §2.1): `?enabled=true|false` (by enabled state), `?prefix=vk_ab` (by key-id prefix),
/// `?group=<name>` (keys bound to that group — §6d: a `user:<sub>` leaf's keys are one person's
/// keys; a team group's are the team's; the customer's self-service tool re-scopes from here).
pub(crate) async fn list_keys(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Strict query parsing FIRST (re-audit L6): a malformed filter/cursor is a loud 400 on every
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
    // PAGINATION (design-admin-api-v1 §0.4): the ONE cursor envelope shared by every admin list —
    // `?limit=` bounds the page, `?cursor=` (opaque) resumes after the prior one, and the response is
    // `{items, next_cursor}` (next_cursor present iff more rows remain). No `total`, no `?offset=` —
    // one pagination grammar across keys/audit/versions/topology.
    // Default 200 / hard cap 1000 — the SAME limit policy as the audit/versions lists (one
    // pagination grammar, one limit policy; an unbounded default response is exactly what
    // pagination exists to prevent — re-audit M9).
    let limit = match q.get("limit") {
        None => crate::admin::v1::contract::LIST_LIMIT_DEFAULT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n.min(crate::admin::v1::contract::LIST_LIMIT_MAX),
            Err(_) => {
                return key_err(
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
                    &AdminError::Validation("invalid or foreign pagination cursor".into()),
                    Cond::MalformedCursor,
                )
            }
        },
        None => 0,
    };
    let Some(gov) = &app.governance else {
        return disabled_empty_list();
    };
    let gov = gov.clone();
    let res = tokio::task::spawn_blocking(move || gov.all_keys()).await;
    match res {
        Ok(Ok(keys)) => {
            let mut filtered: Vec<_> = keys
                .iter()
                .filter(|k| enabled.is_none_or(|e| k.enabled == e))
                .filter(|k| prefix.as_deref().is_none_or(|p| k.id.starts_with(p)))
                .filter(|k| {
                    group
                        .as_deref()
                        .is_none_or(|g| k.group.as_deref() == Some(g))
                })
                .collect();
            // Deterministic page boundaries: sort by id (the store's iteration order is not a
            // pagination contract).
            filtered.sort_by(|a, b| a.id.cmp(&b.id));
            let total = filtered.len();
            let page: Vec<_> = filtered
                .into_iter()
                .skip(start)
                .take(limit)
                .map(key_meta)
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
/// credential to a key deliberately minted without one (audit round-5 HIGH-6).
pub(crate) async fn rotate_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    // IDEMPOTENT ROTATE (optional `Idempotency-Key`, re-audit M10): rotate is the one other
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
        committed: false,
    });
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    let gov = gov.clone();
    let gid = id.clone();
    // rotate is a check-then-act (get_key → mint → put_key over the UPSERT primitive), so it must
    // hold EXISTENCE_GATE for the same reason update_key/delete_key do: without it a concurrent
    // delete that lands between rotate's read and write is clobbered by rotate's put — RESURRECTING
    // a revoked key with a fresh secret. Gate acquired INSIDE the closure for cancellation safety
    // (a scheduled spawn_blocking runs to completion even if the handler future is dropped).
    // (found: audit c1r6 — rotate was the one key-mutator missing the gate.)
    // The re-minted signed token gets the SAME default lifetime a mint with no `expires_in` /
    // `expires_at` would receive (rotate takes no body today).
    let exp = crate::store::now().saturating_add(DEFAULT_KEY_TTL_SECS);
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.lock().unwrap_or_else(|e| e.into_inner());
        gov.rotate_key(&gid, exp)
    })
    .await;
    let resource = format!("key:{id}");
    match res {
        Ok(Ok(Some(rotated))) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_APPLIED, &actor);
            let mut body = key_meta(rotated.key());
            // Shown exactly once, exactly like mint — the field names the credential the key
            // actually carries (a signed-token binding is never handed a legacy bearer secret).
            match rotated {
                crate::governance::RotatedCredential::Token { token, exp, .. } => {
                    body["token"] = json!(token);
                    body["expires_at"] = json!(exp);
                }
                crate::governance::RotatedCredential::Secret { secret, .. } => {
                    body["secret"] = json!(secret);
                }
            }
            // COMMIT the idempotency slot with the real response (replaces the reservation) and
            // disarm the drop-guard — a retry inside the window replays THIS body verbatim.
            if let Some(ref ck) = idem_ckey {
                let mut cache = app
                    .idempotency_cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                cache.insert(ck.clone(), (crate::store::now(), body.clone()));
                if let Some(r) = idem_reservation.as_mut() {
                    r.committed = true;
                }
            }
            json_response(StatusCode::OK, body)
        }
        Ok(Ok(None)) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(&AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Err(e)) => internal_error("rotate_key", &e),
        Err(e) => join_error("rotate_key", &e),
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
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    if let Some(resp) = reject_overlong_id(&id) {
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
        let exists = gov.all_keys()?.iter().any(|k| k.id == id_for_task);
        if !exists {
            return Ok(false);
        }
        gov.revoke(&id_for_task, "revoked via admin API")?;
        Ok(true)
    })
    .await;
    let resource = format!("key:{id}");
    match res {
        Ok(Ok(true)) => {
            audit::AUDIT.record_by("key.revoke", &resource, audit::OUTCOME_APPLIED, &actor);
            json_response(StatusCode::OK, json!({ "revoked": id }))
        }
        Ok(Ok(false)) => {
            audit::AUDIT.record_by("key.revoke", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(&AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Err(e)) => internal_error("revoke_key", &e),
        Err(e) => join_error("revoke_key", &e),
    }
}

/// POST /api/v1/admin/signing-key/rotate - ROTATE the busbar key-signing key (S2). Rotation is
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
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    let Some(kid) = gov.signing_kid() else {
        return key_err(
            &AdminError::Conflict("no signing key is configured; nothing to rotate".into()),
            Cond::NothingToRotate,
        );
    };
    audit::AUDIT.record_by(
        "signing_key.rotate",
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
/// secret or key_hash). 404 when no key with `id` exists. Fills the single-key read gap in the key
/// surface (design-admin-api-v1 §2.1); it stays on the legacy `{type}` envelope + `key_meta` shape so
/// it is consistent with the sibling key routes (the full `{code}`-envelope migration is a follow-up).
pub(crate) async fn get_key(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    let gov = gov.clone();
    let id2 = id.clone();
    // The synchronous store read runs on the blocking pool (the SQLite backend is sync). Read via
    // `all_keys` + find (the same accessor the list handler uses) — admin scale, no hot path.
    let res = tokio::task::spawn_blocking(move || {
        gov.all_keys()
            .map(|keys| keys.into_iter().find(|k| k.id == id2))
    })
    .await;
    match res {
        Ok(Ok(Some(k))) => {
            let etag = key_etag(&k);
            // ETag lives ONLY in the HTTP `ETag` header (RFC 7232), not duplicated into the JSON
            // body — one authoritative surface, matching how config/hooks/auth expose their
            // concurrency token. (contract H4.)
            let meta = key_meta(&k);
            let mut resp = json_response(StatusCode::OK, meta);
            if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{etag}\"")) {
                resp.headers_mut().insert(axum::http::header::ETAG, v);
            }
            resp
        }
        Ok(Ok(None)) => key_err(&AdminError::not_found("key"), Cond::UnknownResource),
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
    if let Some(resp) = reject_overlong_id(&id) {
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
        let key = gov2.all_keys()?.into_iter().find(|k| k.id == id2);
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
            // Label the numbers (re-audit L): a key's attribution bucket accrues in the ALL-TIME
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
        Ok(Ok(None)) => key_err(&AdminError::not_found("key"), Cond::UnknownResource),
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
    let Some(gov) = &app.governance else {
        return disabled_write();
    };
    if let Some(resp) = reject_overlong_id(&id) {
        return resp;
    }
    // Optimistic concurrency (optional `If-Match`, H3 — every mutation verb on the surface honors
    // it): the caller's ETag is compared against the CURRENT record inside the gated critical
    // section below, so the delete only lands on the exact record state the caller last read.
    let if_match = match parse_key_if_match(&headers) {
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
    // `changes()` fix is out of this unit's owned files, so we close the race here instead: serialize
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
        // atomic with the delete, exactly like PATCH's compare-and-put.
        let key = gov.all_keys()?.into_iter().find(|k| k.id == id_for_task);
        match key {
            None => Ok(DeleteOutcome::NotFound),
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
    let resource = format!("key:{id}");
    match res {
        Ok(Ok(DeleteOutcome::Deleted)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // 204 No Content — the SAME success shape as `DELETE /api/v1/admin/hooks/{name}` (was a
            // bespoke `200 {"deleted": id}` found nowhere else on the surface). (contract H4.)
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Ok(DeleteOutcome::NotFound)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(&AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Ok(DeleteOutcome::EtagStale)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            key_err(
                &AdminError::VersionConflict(
                    "If-Match ETag is stale: the key changed since you read it (re-read and retry)"
                        .into(),
                ),
                Cond::StaleIfMatch,
            )
        }
        Ok(Err(e)) => internal_error("delete_key", &e),
        Err(e) => join_error("delete_key", &e),
    }
}

// The admin-surface e2e tests authenticate through the `admin-tokens` module; a
// `--no-default-features` binary compiles it OUT, which DISABLES the admin API wholesale (the
// admin_auth chain all-Passes ⇒ denied) — so this module only applies when the module exists.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/tests.rs"]
mod tests;
