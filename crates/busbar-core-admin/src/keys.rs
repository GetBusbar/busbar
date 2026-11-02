// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::redacted::Secret;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

use crate::admin_state::AppAdmin as _;
use crate::idempotency::durable::{self, Claim, Refused, Settled};
use crate::idempotency::Probe;
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use busbar_kernel::audit_ring as audit;
use busbar_kernel::config::parse::parse_duration_secs;
use busbar_kernel::diagnostics::{
    diag_debug, diag_error, ADMIN_CREATEKEY_MALFORMED_BODY, ADMIN_STORE_OPERATION_FAILED,
    ADMIN_STORE_TASK_JOIN_FAILED, ADMIN_UPDATEKEY_MALFORMED_BODY, CREATEKEY_UNKNOWN_POOL,
};
use busbar_kernel::governance::claims::ClaimSet;
use busbar_kernel::governance::{NewKeySpec, VirtualKey};

static EXISTENCE_GATE: ClaimSet<String> = ClaimSet::new();

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

use busbar_kernel::governance::mint_policy::{MintRequest, DEFAULT_KEY_TTL_SECS};

#[cfg(test)]
#[path = "tests/parse_duration_secs_tests.rs"]
mod parse_duration_secs_tests;

const MAX_KEY_NAME_LEN: usize = 256;
const MAX_KEY_ID_LEN: usize = 64;

const RESERVED_METRIC_LABELS: &[&str] = &["key", "bucket", "model", "tier"];
const MAX_LABEL_COUNT: usize = 16;
const MAX_LABEL_NAME_LEN: usize = 64;
const MAX_LABEL_VALUE_LEN: usize = 256;

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
#[path = "tests/validate_mint_labels_tests.rs"]
mod validate_mint_labels_tests;

fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
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

pub(crate) const KEY_RESOURCE_NONE: &str = "key:-";

fn key_err(who: KeyAudit<'_>, e: &AdminError, cond: Cond) -> Response {
    record_key_refusal(who);
    crate::v1::json::err_json_cond(e, cond)
}

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

fn internal_error(op: &str, e: &busbar_kernel::governance::RecordStoreError) -> Response {
    diag_error!(ADMIN_STORE_OPERATION_FAILED, operation = op, error = %e, "admin store operation failed");
    crate::v1::json::err_json(&AdminError::Internal)
}

#[cfg(test)]
#[path = "tests/internal_error_tests.rs"]
mod internal_error_tests;

fn key_etag(k: &VirtualKey) -> String {
    let meta = key_meta(k);
    busbar_contract::sha256_hex(meta.to_string().as_bytes())[..16].to_string()
}

#[allow(clippy::result_large_err)]
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
    let mut meta = json!({
        "id": k.id,
        "name": k.name,
        "allowed_pools": k.allowed_scopes.as_ref().map(|list| {
            list.iter()
                .filter(|s| s.kind == "pool")
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>()
        }),
        "group": k.group,
        "enabled": k.enabled,
        "created_at": k.created_at,
        "labels": k.labels,
    });

    let mut by_kind: std::collections::BTreeMap<String, Vec<&str>> =
        std::collections::BTreeMap::new();
    for s in k
        .allowed_scopes
        .iter()
        .flatten()
        .filter(|s| s.kind != "pool")
    {
        by_kind
            .entry(busbar_contract::records::scope_kinds::wire_field_for(
                &s.kind,
            ))
            .or_default()
            .push(s.value.as_str());
    }
    for (field, values) in by_kind {
        meta[field] = json!(values);
    }
    meta
}

fn lift_plane_grants(
    body: Value,
) -> Option<(Value, Option<Vec<busbar_contract::records::ScopeRef>>)> {
    let Value::Object(mut fields) = body else {
        return Some((body, None));
    };
    let grant_fields: Vec<(String, String)> = fields
        .keys()
        .filter_map(|field| {
            busbar_kernel::governance::plane_grant_kind(field).map(|kind| (field.clone(), kind))
        })
        .collect();
    let mut plane: Option<Vec<busbar_contract::records::ScopeRef>> = None;
    for (field, kind) in grant_fields {
        let value = fields.remove(&field)?;
        if !busbar_kernel::governance::plane_declares_kind(&kind) {
            return None;
        }
        if value.is_null() {
            continue;
        }
        let names = value.as_array()?;
        let list = plane.get_or_insert_with(Vec::new);
        for name in names {
            list.push(busbar_contract::records::ScopeRef {
                kind: kind.clone(),
                value: name.as_str()?.to_string(),
            });
        }
    }
    Some((Value::Object(fields), plane))
}

fn key_state(k: &VirtualKey, gov: &busbar_kernel::governance::GovState) -> &'static str {
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

fn disabled_empty_list() -> Response {
    json_response(
        StatusCode::OK,
        json!({ "items": [], "next_cursor": serde_json::Value::Null }),
    )
}

fn disabled_read() -> Response {
    key_err(
        KeyAudit::Read,
        &AdminError::not_found_because("key", "governance is not enabled on this server"),
        Cond::GovernanceOff,
    )
}

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
#[path = "tests/reject_overlong_id_tests.rs"]
mod reject_overlong_id_tests;

fn join_error(op: &str, e: &tokio::task::JoinError) -> Response {
    diag_error!(ADMIN_STORE_TASK_JOIN_FAILED, operation = op, error = %e, "admin store task failed to join");
    crate::v1::json::err_json(&AdminError::Internal)
}

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub type KeyReplayCache = crate::idempotency::IdempotencyCache<Value>;

async fn complete_key_mutation(
    op: &'static str,
    mutation: impl std::future::Future<Output = Response> + Send + 'static,
) -> Response {
    match tokio::spawn(mutation).await {
        Ok(response) => response,
        Err(error) => join_error(op, &error),
    }
}

async fn claim_in_store(
    store: std::sync::Arc<dyn busbar_kernel::governance::RecordStore>,
    key: (String, String),
) -> Result<Claim, Refused> {
    let now = busbar_kernel::store::now();
    tokio::task::spawn_blocking(move || durable::claim(&*store, &key, now))
        .await
        .unwrap_or_else(|e| Err(Refused::Unavailable(format!("the claim did not run: {e}"))))
}

async fn settle_in_store(
    store: std::sync::Arc<dyn busbar_kernel::governance::RecordStore>,
    claim: Option<Claim>,
    settled: Settled,
) {
    let Some(claim) = claim else {
        return;
    };
    let now = busbar_kernel::store::now();
    let kept =
        tokio::task::spawn_blocking(move || durable::settle(&*store, &claim, now, &settled)).await;
    let why = match kept {
        Ok(Ok(())) => return,
        Ok(Err(why)) => why,
        Err(e) => e.to_string(),
    };
    diag_error!(ADMIN_STORE_OPERATION_FAILED, operation = "idempotency.settle", error = %why, "the store did not keep an Idempotency-Key's outcome; a retry is refused as in flight until the claim lapses");
}

fn claim_refused(who: KeyAudit<'_>, refused: Refused) -> Response {
    let ran = match refused {
        Refused::InFlight | Refused::Retained(_) => {
            return key_err(
                who,
                &AdminError::Conflict(
                    "a request with this Idempotency-Key is already in flight".into(),
                ),
                Cond::IdempotencyInFlight,
            )
        }
        Refused::Unavailable(why) => {
            diag_error!(ADMIN_STORE_OPERATION_FAILED, operation = "idempotency.claim", error = %why, "admin store operation failed");
            record_key_refusal(who);
            return crate::v1::json::err_json(&AdminError::Unavailable(
                "the store could not record this Idempotency-Key; nothing was done".into(),
            ));
        }
        Refused::Applied(what) => what,
        Refused::Answer(_) => "an earlier request".to_string(),
    };
    key_err(
        who,
        &AdminError::Conflict(format!(
            "a request with this Idempotency-Key already ran ({ran}); its once-shown secret is not \
             kept, so it cannot be replayed here"
        )),
        Cond::IdempotencyInFlight,
    )
}

const UNBOUND_BUCKET_LABEL: &str = "(no group)";

fn check_key_cap(
    gov: &busbar_kernel::governance::GovState,
    cap: usize,
    group: Option<&str>,
    exclude_id: Option<&str>,
) -> busbar_kernel::governance::RecordStoreResult<Option<(String, usize)>> {
    if cap == 0 {
        return Ok(None);
    }
    let n = gov
        .all_keys()?
        .iter()
        .filter(|k| k.group.as_deref() == group)
        .filter(|k| Some(k.id.as_str()) != exclude_id)
        .filter(|k| {
            k.group
                .as_deref()
                .map(|g| !g.starts_with(busbar_kernel::governance::SELF_KEY_GROUP_PREFIX))
                .unwrap_or(true)
        })
        .filter(|k| k.enabled && !gov.is_revoked(&k.id))
        .count();
    if n >= cap {
        return Ok(Some((group.unwrap_or(UNBOUND_BUCKET_LABEL).to_string(), n)));
    }
    Ok(None)
}

pub(crate) async fn create_key(
    axum::extract::State(handle): axum::extract::State<
        std::sync::Arc<busbar_kernel::state::AppHandle>,
    >,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,

    axum::Extension(replays): axum::Extension<std::sync::Arc<KeyReplayCache>>,
    body: Bytes,
) -> Response {
    complete_key_mutation(
        "create_key",
        create_key_owned(handle, principal, headers, replays, body),
    )
    .await
}

async fn create_key_owned(
    handle: std::sync::Arc<busbar_kernel::state::AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    headers: axum::http::HeaderMap,
    replays: std::sync::Arc<KeyReplayCache>,
    body: Bytes,
) -> Response {
    let app = handle.load();
    let actor = principal.actor_id().to_string();

    let who = KeyAudit::Mutation {
        verb: "key.create",
        resource: KEY_RESOURCE_NONE,
        actor: &actor,
    };

    let idem_key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    let idem_ckey: Option<(String, String)> = idem_key
        .as_ref()
        .map(|k| (actor.clone(), crate::idempotency::create_replay_key(k)));
    let mut idem_reservation: Option<crate::idempotency::Reservation<'_, Value>> = None;
    if let Some(ref ck) = idem_ckey {
        match replays.probe(ck.clone(), busbar_kernel::store::now()) {
            Probe::NoKey => {}

            Probe::Replay(cached) => return json_response(StatusCode::CREATED, cached),

            Probe::InFlight => {
                return key_err(
                    who,
                    &AdminError::Conflict(
                        "a request with this Idempotency-Key is already in flight".into(),
                    ),
                    Cond::IdempotencyInFlight,
                );
            }

            Probe::Reserved(r) => idem_reservation = Some(r),
        }
    }
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };

    let parsed = busbar_kernel::json::parse::<Value>(&body)
        .ok()
        .and_then(lift_plane_grants)
        .and_then(|(rest, plane)| {
            serde_json::from_value::<CreateKeyReq>(rest)
                .ok()
                .map(|req| (req, plane))
        });
    let (req, plane_scopes) = match parsed {
        Some(req) => req,
        None => {
            diag_debug!(
                ADMIN_CREATEKEY_MALFORMED_BODY,
                "create_key: {}",
                busbar_kernel::json::parse_err_log(body.len())
            );
            return key_err(
                who,
                &AdminError::Validation("invalid JSON".into()),
                Cond::MalformedBody,
            );
        }
    };

    if req.name.len() > MAX_KEY_NAME_LEN {
        return key_err(
            who,
            &AdminError::Validation("name must be <= 256 characters".into()),
            Cond::Overlong,
        );
    }

    if let Err(msg) = validate_mint_labels(&req.labels) {
        return key_err(who, &AdminError::Validation(msg), Cond::InvalidLabels);
    }

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

    if req.issue_aws_credential && !gov.at_rest_enabled() {
        return key_err(
            who,
            &AdminError::Conflict(busbar_kernel::governance::at_rest::NO_KEY_REFUSAL.to_string()),
            Cond::NoSigningKey,
        );
    }

    let now = busbar_kernel::store::now();
    let (exp, explicit) = match (req.expires_in.as_deref(), req.expires_at) {
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
            Ok(secs) => (now.saturating_add(secs), true),
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
            (at, true)
        }
        (None, None) => (now.saturating_add(DEFAULT_KEY_TTL_SECS), false),
    };

    let requested_ttl = exp.saturating_sub(now);
    let caller_roles: &[String] = principal.0.as_ref().map_or(&[], |p| p.roles.as_slice());

    let requested_binding_mode = busbar_kernel::governance::SELF_KEY_BINDING_MODE_APP;

    let (requested_pools, grants_other_kinds) =
        busbar_kernel::governance::mint_policy::requested_grant(
            busbar_kernel::governance::grant_scopes(
                req.allowed_pools.clone(),
                plane_scopes.clone(),
            )
            .as_deref(),
        );
    let mint_req = MintRequest {
        roles: caller_roles,
        requested_pools: requested_pools.as_deref(),
        grants_other_kinds,
        requested_ttl_secs: requested_ttl,
        explicit_ttl: explicit,
        requested_mode: Some(requested_binding_mode),
    };
    let exp = match app.mint_policy.check_mint(&mint_req) {
        Ok(ttl) => now.saturating_add(ttl),
        Err(msg) => return key_err(who, &AdminError::Validation(msg), Cond::KeyExpiryFields),
    };

    let allowed_pools = req.allowed_pools;
    for pool in allowed_pools.iter().flatten() {
        if !app
            .engine_tables_view()
            .pools()
            .iter()
            .any(|(n, _)| *n == pool.as_str())
        {
            diag_debug!(
                CREATEKEY_UNKNOWN_POOL,
                pool = %pool,
                key_name = %req.name,
                "create_key: allowed_pools entry names no configured pool (possible typo; \
                 key still created - configure the pool later to activate this entry)"
            );
        }
    }

    if req.group.is_none() && req.parent.is_some() {
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

    enum MintOutcome {
        TokenOnly(Box<(busbar_kernel::governance::VirtualKey, Secret<String>)>),
        Aws(
            Box<(
                busbar_kernel::governance::VirtualKey,
                Secret<String>,
                String,
                Secret<String>,
            )>,
        ),
        AtCap {
            group: String,
            n: usize,
            cap: usize,
        },
    }

    let spec = NewKeySpec {
        name: req.name,
        allowed_pools,
        plane_scopes,
        group: req.group.clone(),
        labels: req.labels,
        minted_by: Some(actor.clone()),
        binding_mode: Some(requested_binding_mode.to_string()),
    };

    let issued = req
        .issue_aws_credential
        .then(|| app.auth.issued_credential());
    let want_group = req.group.clone();
    let want_parent = req.parent.clone();
    let gov = gov.clone();
    let txn_actor = actor.clone();

    let replay_store = gov.store();
    let claim = match idem_reservation.as_ref() {
        Some(r) => {
            match claim_in_store(std::sync::Arc::clone(&replay_store), r.key().clone()).await {
                Ok(claim) => Some(claim),
                Err(refused) => return claim_refused(who, refused),
            }
        }
        None => None,
    };

    if let Some(r) = idem_reservation.as_mut() {
        r.in_flight();
    }
    let res = crate::v1::json::config_transaction(&handle, move |txn| {
        let current = txn.app();







        let provisioned = match want_group.as_deref() {
            Some(group) => {
                crate::v1::json::plan_mint_group(
                    current,
                    group,
                    want_parent.as_deref(),
                    &txn_actor,
                )?
            }
            None => None,
        };


        let cap = current.max_keys_per_principal;



        let cap_group = spec.group.clone();
        let did_provision = provisioned.is_some();







        let provision_record = provisioned.as_ref().map(|installed| {
            (
                installed.clone(),
                want_group.clone().unwrap_or_default(),
                want_parent.clone().unwrap_or_default(),
                txn_actor.clone(),
            )
        });

        let mint = move || {


            if let Some((installed, group, parent, actor)) = provision_record {
                audit::AUDIT.record_by(
                    "group.provision",
                    &format!("group:{group}"),
                    audit::OUTCOME_APPLIED,
                    &actor,
                );
                installed.record_version(&actor, &format!("group.provision group:{group} (auto, parent {parent})"));
            }
            let minted = (|| -> busbar_kernel::governance::RecordStoreResult<MintOutcome> {
                if let Some((group, n)) = check_key_cap(&gov, cap, cap_group.as_deref(), None)? {
                    return Ok(MintOutcome::AtCap { group, n, cap });
                }
                if let Some(issued) = &issued {



                    let Some((kind, shape)) = issued else {
                        return Err(busbar_kernel::governance::RecordStoreError(
                            "no linked auth plugin states the shape of the credential to issue"
                                .to_string(),
                        ));
                    };
                    gov.mint_signed_with_credential(spec, exp, now, kind, shape)
                        .map(|m| MintOutcome::Aws(Box::new(m)))
                } else {
                    gov.mint_signed(spec, exp, now)
                        .map(|m| MintOutcome::TokenOnly(Box::new(m)))
                }
            })()
            .map_err(|e| {
                diag_error!(ADMIN_STORE_OPERATION_FAILED, operation = "create_key", error = %e, "admin store operation failed");
                AdminError::Internal
            })?;
            Ok(crate::v1::json::Outcome::Value((
                minted,
                did_provision,
            )))
        };
        match provisioned {


            Some(installed) => {
                let group = want_group.clone().unwrap_or_default();
                Ok(crate::v1::json::Outcome::commit_then(
                    installed.clone(),
                    crate::v1::json::persist_provisioned_group(
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

        Err(e) => {
            record_key_refusal(who);
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }

            if !matches!(e, AdminError::Internal) {
                settle_in_store(replay_store, claim, Settled::Released).await;
            }
            return crate::v1::json::err_json(&e);
        }
    };

    let (key, token, aws) = match minted {
        MintOutcome::AtCap { group, n, cap } => {
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }
            settle_in_store(replay_store, claim, Settled::Released).await;
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
        MintOutcome::TokenOnly(b) => {
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

    body["state"] = json!("active");

    body["token"] = json!(token.expose(&busbar_kernel::seal::lend()));
    body["expires_at"] = json!(exp);

    body["group_provisioned"] = json!(provisioned_group);
    if let Some((access_key_id, secret_access_key)) = aws {
        body["aws_access_key_id"] = json!(access_key_id);
        body["aws_secret_access_key"] =
            json!(secret_access_key.expose(&busbar_kernel::seal::lend()));
    }
    if let Some(r) = idem_reservation.take() {
        r.commit(body.clone(), busbar_kernel::store::now());
    }
    settle_in_store(
        replay_store,
        claim,
        Settled::Applied(format!("key:{}", key.id)),
    )
    .await;
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

pub(crate) async fn update_key(
    axum::extract::State(handle): axum::extract::State<
        std::sync::Arc<busbar_kernel::state::AppHandle>,
    >,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    complete_key_mutation(
        "update_key",
        update_key_owned(handle, principal, id, headers, body),
    )
    .await
}

async fn update_key_owned(
    handle: std::sync::Arc<busbar_kernel::state::AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    id: String,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();

    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.patch",
        resource: &resource,
        actor: &actor,
    };

    if handle.load().governance.is_none() {
        return disabled_write(who);
    }
    if let Some(resp) = reject_overlong_id(who, &id) {
        return resp;
    }

    let if_match = match parse_key_if_match(who, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let req: UpdateKeyReq = match busbar_kernel::json::parse(&body) {
        Ok(req) => req,
        Err(_) => {
            diag_debug!(
                ADMIN_UPDATEKEY_MALFORMED_BODY,
                "update_key: {}",
                busbar_kernel::json::parse_err_log(body.len())
            );
            return key_err(
                who,
                &AdminError::Validation("invalid JSON".into()),
                Cond::MalformedBody,
            );
        }
    };

    enum UpdateOutcome {
        Updated(Box<busbar_kernel::governance::VirtualKey>, &'static str),
        NotFound,
        EtagStale,

        AtCap { group: String, n: usize, cap: usize },
    }
    let res = crate::v1::json::config_transaction(&handle, move |txn| {
        let current = txn.app();
        let Some(gov) = current.governance.clone() else {


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

        let cap = current.max_keys_per_principal;
        Ok(txn.store_write(move || {
            let _existence_guard = EXISTENCE_GATE.claim(id.clone());
            let outcome = (|| -> busbar_kernel::governance::RecordStoreResult<UpdateOutcome> {






                let Some(before) = gov.store().get_key(&id)? else {
                    return Ok(UpdateOutcome::NotFound);
                };
                if let Some(tag) = &if_match {
                    if key_etag(&before) != *tag {
                        return Ok(UpdateOutcome::EtagStale);
                    }
                }


















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
                diag_error!(ADMIN_STORE_OPERATION_FAILED, operation = "update_key", error = %e, "admin store operation failed");
                AdminError::Internal
            })?;
            Ok(crate::v1::json::Outcome::Value(outcome))
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


        Err(e @ AdminError::Validation(_)) => key_err(who, &e, Cond::RebindTargetMissing),
        Err(e @ AdminError::Conflict(_)) => key_err(who, &e, Cond::GovernanceOff),
        Err(e) => {
            record_key_refusal(who);
            crate::v1::json::err_json(&e)
        }
    }
}

pub(crate) async fn list_keys(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
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

    let group = q.get("group").cloned();

    let limit = match q.get("limit") {
        None => crate::v1::contract::LIST_LIMIT_DEFAULT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n.clamp(1, crate::v1::contract::LIST_LIMIT_MAX),
            Err(_) => {
                return key_err(
                    KeyAudit::Read,
                    &AdminError::Validation(format!(
                        "invalid `limit`: expected an integer (max {})",
                        crate::v1::contract::LIST_LIMIT_MAX
                    )),
                    Cond::InvalidQueryValue,
                )
            }
        },
    };
    let start = match q.get("cursor") {
        Some(c) => match crate::v1::contract::decode_offset_cursor(c) {
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

        Ok::<_, busbar_kernel::governance::RecordStoreError>(
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
                .filter(|(k, _)| include_tombstoned || k.deleted_at.is_none())
                .filter(|(k, _)| enabled.is_none_or(|e| k.enabled == e))
                .filter(|(k, _)| prefix.as_deref().is_none_or(|p| k.id.starts_with(p)))
                .filter(|(k, _)| {
                    group
                        .as_deref()
                        .is_none_or(|g| k.group.as_deref() == Some(g))
                })
                .collect();

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

            let end = start.saturating_add(page.len());
            let next_cursor = (end < total).then(|| crate::v1::contract::encode_offset_cursor(end));
            json_response(
                StatusCode::OK,
                json!({ "items": page, "next_cursor": next_cursor }),
            )
        }
        Ok(Err(e)) => internal_error("list_keys", &e),
        Err(e) => join_error("list_keys", &e),
    }
}

enum RotateOutcome {
    Rotated(
        &'static str,
        Box<busbar_kernel::governance::RotatedCredential>,
    ),

    Unknown,

    PastCeiling(String),
}

pub(crate) async fn rotate_key(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,

    axum::Extension(replays): axum::Extension<std::sync::Arc<KeyReplayCache>>,
) -> Response {
    complete_key_mutation(
        "rotate_key",
        rotate_key_owned(app, principal, id, headers, replays),
    )
    .await
}

async fn rotate_key_owned(
    app: std::sync::Arc<busbar_kernel::state::App>,
    principal: busbar_kernel::auth::AuthPrincipal,
    id: String,
    headers: axum::http::HeaderMap,
    replays: std::sync::Arc<KeyReplayCache>,
) -> Response {
    let actor = principal.actor_id().to_string();

    let resource = format!("key:{id}");
    let who = KeyAudit::Mutation {
        verb: "key.rotate",
        resource: &resource,
        actor: &actor,
    };
    if let Some(resp) = reject_overlong_id(who, &id) {
        return resp;
    }

    let idem_ckey: Option<(String, String)> = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(|k| (actor.clone(), crate::idempotency::rotate_replay_key(&id, k)));
    let mut idem_reservation: Option<crate::idempotency::Reservation<'_, Value>> = None;
    if let Some(ref ck) = idem_ckey {
        match replays.probe(ck.clone(), busbar_kernel::store::now()) {
            Probe::NoKey => {}
            Probe::Replay(cached) => return json_response(StatusCode::OK, cached),
            Probe::InFlight => {
                return key_err(
                    who,
                    &AdminError::Conflict(
                        "a request with this Idempotency-Key is already in flight".into(),
                    ),
                    Cond::IdempotencyInFlight,
                );
            }
            Probe::Reserved(r) => idem_reservation = Some(r),
        }
    }
    let Some(gov) = &app.governance else {
        return disabled_write(who);
    };
    let gov = gov.clone();
    let gid = id.clone();

    let now = busbar_kernel::store::now();
    let caller_roles: Vec<String> = principal
        .0
        .as_ref()
        .map_or_else(Vec::new, |p| p.roles.clone());
    let policy = std::sync::Arc::clone(&app.mint_policy);

    let replay_store = gov.store();
    let claim = match idem_reservation.as_ref() {
        Some(r) => {
            match claim_in_store(std::sync::Arc::clone(&replay_store), r.key().clone()).await {
                Ok(claim) => Some(claim),
                Err(refused) => return claim_refused(who, refused),
            }
        }
        None => None,
    };

    if let Some(r) = idem_reservation.as_mut() {
        r.in_flight();
    }
    let res = tokio::task::spawn_blocking(
        move || -> Result<RotateOutcome, busbar_kernel::governance::RecordStoreError> {
            let _existence_guard = EXISTENCE_GATE.claim(gid.clone());

            let Some(key) = gov
                .store()
                .get_key(&gid)?
                .filter(|k| k.deleted_at.is_none())
            else {
                return Ok(RotateOutcome::Unknown);
            };
            let (pools, grants_other_kinds) =
                busbar_kernel::governance::mint_policy::requested_grant(
                    key.allowed_scopes.as_deref(),
                );
            let ttl = match policy.check_mint(&MintRequest {
                roles: &caller_roles,
                requested_pools: pools.as_deref(),
                grants_other_kinds,
                requested_ttl_secs: DEFAULT_KEY_TTL_SECS,
                explicit_ttl: false,
                requested_mode: key.binding_mode.as_deref(),
            }) {
                Ok(ttl) => ttl,
                Err(msg) => return Ok(RotateOutcome::PastCeiling(msg)),
            };

            Ok(match gov.rotate_key(&gid, now.saturating_add(ttl))? {
                Some(rotated) => {
                    RotateOutcome::Rotated(key_state(&rotated.key, &gov), Box::new(rotated))
                }
                None => RotateOutcome::Unknown,
            })
        },
    )
    .await;
    match res {
        Ok(Ok(RotateOutcome::Rotated(state, rotated))) => {
            audit::AUDIT.record_by("key.rotate", &resource, audit::OUTCOME_APPLIED, &actor);
            let mut body = key_meta(&rotated.key);
            body["state"] = json!(state);

            body["token"] = json!(rotated.token.expose(&busbar_kernel::seal::lend()));
            body["expires_at"] = json!(rotated.exp);

            if let Some(r) = idem_reservation.take() {
                r.commit(body.clone(), busbar_kernel::store::now());
            }
            settle_in_store(replay_store, claim, Settled::Applied(resource.clone())).await;
            json_response(StatusCode::OK, body)
        }

        Ok(Ok(RotateOutcome::Unknown)) => {
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }
            settle_in_store(replay_store, claim, Settled::Released).await;
            key_err(who, &AdminError::not_found("key"), Cond::UnknownResource)
        }
        Ok(Ok(RotateOutcome::PastCeiling(msg))) => {
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }
            settle_in_store(replay_store, claim, Settled::Released).await;
            key_err(who, &AdminError::Validation(msg), Cond::KeyExpiryFields)
        }
        Ok(Err(e)) => {
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }

            record_key_refusal(who);
            internal_error("rotate_key", &e)
        }

        Err(e) => {
            if let Some(r) = idem_reservation.take() {
                r.clear();
            }
            record_key_refusal(who);
            join_error("rotate_key", &e)
        }
    }
}

pub(crate) async fn revoke_key(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(id): Path<String>,
) -> Response {
    complete_key_mutation("revoke_key", revoke_key_owned(app, principal, id)).await
}

async fn revoke_key_owned(
    app: std::sync::Arc<busbar_kernel::state::App>,
    principal: busbar_kernel::auth::AuthPrincipal,
    id: String,
) -> Response {
    let actor = principal.actor_id().to_string();

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

    let res = tokio::task::spawn_blocking(
        move || -> busbar_kernel::governance::RecordStoreResult<bool> {
            let _existence_guard = EXISTENCE_GATE.claim(id_for_task.clone());

            let exists = gov.store().get_key(&id_for_task)?.is_some();
            if !exists {
                return Ok(false);
            }
            gov.revoke(&id_for_task, "revoked via admin API")?;
            Ok(true)
        },
    )
    .await;
    match res {
        Ok(Ok(true)) => {
            audit::AUDIT.record_by("key.revoke", &resource, audit::OUTCOME_APPLIED, &actor);
            json_response(StatusCode::OK, json!({ "revoked": id }))
        }
        Ok(Ok(false)) => key_err(who, &AdminError::not_found("key"), Cond::UnknownResource),
        Ok(Err(e)) => {
            record_key_refusal(who);
            internal_error("revoke_key", &e)
        }
        Err(e) => {
            record_key_refusal(who);
            join_error("revoke_key", &e)
        }
    }
}

pub(crate) async fn rotate_signing_key(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();

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

pub(crate) async fn get_key(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
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

    let res = tokio::task::spawn_blocking(move || {
        gov.store()
            .get_key(&id2)
            .map(|opt| opt.map(|k| (key_state(&k, &gov), k)))
    })
    .await;
    match res {
        Ok(Ok(Some((state, k)))) => {
            let etag = key_etag(&k);

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

pub(crate) async fn key_usage(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    Path(id): Path<String>,
) -> Response {
    let Some(gov) = &app.governance else {
        return disabled_read();
    };
    if let Some(resp) = reject_overlong_id(KeyAudit::Read, &id) {
        return resp;
    }
    let now = busbar_kernel::store::now();
    let gov2 = gov.clone();
    let id2 = id.clone();

    let cost = app.cost.clone();
    let res = tokio::task::spawn_blocking(move || {
        let key = gov2.store().get_key(&id2)?;

        let Some(key) = key.filter(|k| k.deleted_at.is_none()) else {
            return Ok::<_, busbar_kernel::governance::RecordStoreError>(None);
        };

        let usage = gov2.derived_bucket_usage_priced(
            &cost,
            &id2,
            busbar_kernel::governance::WINDOW_TOTAL,
            true,
            now,
        )?;
        Ok::<_, busbar_kernel::governance::RecordStoreError>(Some((usage, Some(key))))
    })
    .await;
    match res {
        Ok(Ok(Some((Err(refused), _)))) => crate::v1::json::err_json_cond(
            &crate::v1::service::usage_refusal("key_usage", &refused),
            Cond::Unpriced,
        ),
        Ok(Ok(Some((Ok(u), key)))) => {
            let headroom = key
                .as_ref()
                .and_then(|k| gov.rate_headroom(&app.cost, k, None, now));

            json_response(
                StatusCode::OK,
                json!({
                    "id": id,
                    "budget_period": busbar_kernel::governance::WINDOW_TOTAL,
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

pub(crate) async fn delete_key(
    busbar_kernel::state::CurrentApp(app): busbar_kernel::state::CurrentApp,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    complete_key_mutation("delete_key", delete_key_owned(app, principal, id, headers)).await
}

async fn delete_key_owned(
    app: std::sync::Arc<busbar_kernel::state::App>,
    principal: busbar_kernel::auth::AuthPrincipal,
    id: String,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();

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

    let if_match = match parse_key_if_match(who, &headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    enum DeleteOutcome {
        Deleted,
        NotFound,
        EtagStale,
    }
    let gov = gov.clone();
    let id_for_task = id.clone();
    let task_actor = actor.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _existence_guard = EXISTENCE_GATE.claim(id_for_task.clone());

        let key = gov.store().get_key(&id_for_task)?;
        match key {
            None => Ok(DeleteOutcome::NotFound),

            Some(k) if k.deleted_at.is_some() => Ok(DeleteOutcome::NotFound),
            Some(k) => {
                if let Some(expected) = &if_match {
                    if key_etag(&k) != *expected {
                        return Ok(DeleteOutcome::EtagStale);
                    }
                }

                gov.revoke(&id_for_task, "key deleted")?;
                match gov.delete_key(&id_for_task) {
                    Ok(()) => Ok(DeleteOutcome::Deleted),
                    Err(error) => {
                        audit::AUDIT.record_by(
                            "key.revoke",
                            &format!("key:{id_for_task}"),
                            audit::OUTCOME_APPLIED,
                            &task_actor,
                        );
                        Err(error)
                    }
                }
            }
        }
    })
    .await;
    match res {
        Ok(Ok(DeleteOutcome::Deleted)) => {
            audit::AUDIT.record_by("key.delete", &resource, audit::OUTCOME_APPLIED, &actor);

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
        Ok(Err(e)) => {
            record_key_refusal(who);
            internal_error("delete_key", &e)
        }
        Err(e) => {
            record_key_refusal(who);
            join_error("delete_key", &e)
        }
    }
}

#[cfg(test)]
#[path = "tests/key_cap_tests.rs"]
mod key_cap_tests;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/provision_tests.rs"]
mod provision_tests;

#[cfg(test)]
#[path = "tests/key_custody_tests.rs"]
mod key_custody_tests;
