// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use busbar_core_admin::GovernanceError;
use busbar_kernel::host_services::{KernelServices, Resolution, TrustRefused};
use busbar_kernel::trust::book::{KeyRow, Ruling};

use super::{AdminAnswer, AmendmentJournal, AuditView, LedgerView};

pub(crate) type PlaneLookup = Arc<dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync>;

#[must_use]
pub(crate) fn no_planes() -> PlaneLookup {
    Arc::new(|_| None)
}

#[derive(Debug)]
pub(crate) enum PlaneWriteFailure {
    /// Native refusal or conflict proves this submission did not publish.
    Unapplied,
    /// The exact native attempt remains held; never replan it from the record.
    Unknown(Option<[u8; 16]>),
}

pub(crate) type PlaneRecordSink = Arc<
    dyn for<'a> Fn(
            &'a PlaneDeclaration,
            &'a PlaneRecord,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), PlaneWriteFailure>> + Send + 'a>,
        > + Send
        + Sync,
>;

/// The operation already sealed, or submitted with an unknown Store outcome. These bytes and
/// metadata belong to the first request; reconciliation must never reconstruct them from a retry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum EffectReceipt {
    CommitUpgrade {
        node: u64,
        seq: u64,
        hash: [u8; 32],
        body: Vec<u8>,
    },
    PlaneRecordWrite {
        record: PlaneRecord,
        #[serde(default)]
        pending: Option<[u8; 16]>,
    },
    /// A trust decision whose durable write has an unknown outcome (TRUST-ADMIN-PRODUCER-DESIGN r3
    /// §4.6): the attempt's identity and outcome only, never pin material. `version` 1 is the only
    /// layout this build reads back.
    TrustDecision {
        version: u16,
        attempt_op_id: [u8; 16],
        key: String,
        ruling: String,
        decided_at: u64,
        operation: Option<String>,
    },
}

/// The one receipt layout of [`EffectReceipt::TrustDecision`] this build reads back.
const TRUST_RECEIPT_VERSION: u16 = 1;

/// Whether an answered write definitely did nothing, completed, or still owns an effect receipt.
#[derive(Debug, Clone)]
enum EffectDisposition {
    Unapplied,
    Applied,
    /// A sealed journal operation is waiting for acknowledgement.
    Pending(EffectReceipt),
    /// Store submission crossed the boundary but its outcome is unknown.
    Unknown(EffectReceipt),
}

#[derive(Debug, Clone)]
pub(crate) struct EffectAnswer {
    pub(crate) answer: AdminAnswer,
    disposition: EffectDisposition,
}

impl EffectAnswer {
    pub(crate) fn applied(answer: AdminAnswer) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Applied,
        }
    }

    pub(super) fn unapplied(answer: AdminAnswer) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Unapplied,
        }
    }

    fn pending(answer: AdminAnswer, receipt: EffectReceipt) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Pending(receipt),
        }
    }

    fn unknown(answer: AdminAnswer, receipt: EffectReceipt) -> Self {
        Self {
            answer,
            disposition: EffectDisposition::Unknown(receipt),
        }
    }
}

impl std::ops::Deref for EffectAnswer {
    type Target = AdminAnswer;

    fn deref(&self) -> &AdminAnswer {
        &self.answer
    }
}

fn refused_effect(status: u16, code: &str, message: &str) -> EffectAnswer {
    EffectAnswer::unapplied(refused(status, code, message))
}

pub(crate) const COMMIT_UPGRADE_RECORD_TAG: &str = "busbar/commit-upgrade/v1";

pub(crate) const RUNNING_RELEASE: &str = env!("CARGO_PKG_VERSION");

fn refused(status: u16, code: &str, message: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(code, message).into_bytes(),
    }
}

pub(crate) fn journal_unavailable(why: &str) -> AdminAnswer {
    refused(503, "service_unavailable", why)
}

fn answer(value: &json::Value) -> Result<AdminAnswer, GovernanceError> {
    json::to_vec(value)
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store)
}

pub(crate) async fn verify_effect(
    ledger: &dyn LedgerView,
    audit: Option<&dyn AuditView>,
    journal: Option<&busbar_kernel_audit::amend::NodeAmendments>,
) -> Result<AdminAnswer, GovernanceError> {
    let priced = ledger.priced().await.map_err(|why| {
        tracing::warn!(why = %why, "verify could not read the ledger's counts");
        GovernanceError::Store
    })?;
    let identity_holds = priced.refused.is_empty();
    let mut findings: Vec<String> = priced
        .refused
        .iter()
        .map(|row| {
            format!(
                "refused counts: {} in the window opening at {}: {}",
                row.bucket, row.day, row.refusal
            )
        })
        .collect();

    if let Some(audit) = audit {
        findings.extend(
            audit
                .restart_findings()
                .into_iter()
                .map(|finding| format!("restart: {finding}")),
        );
    }

    if let Some(Err(broken)) = journal.map(crate::root::durability::verify_held) {
        findings.push(format!("amendment chain: {broken}"));
    }
    if let Some(audit) = audit {
        findings.extend(
            audit
                .retained_audit_findings()
                .into_iter()
                .map(|finding| format!("audit chain: {finding}")),
        );

        findings.extend(
            audit
                .stored_chain_findings()
                .await
                .into_iter()
                .map(|finding| format!("stored chain: {finding}")),
        );
    }
    answer(&json::json!({
        "checkpoints": 0,
        "since": null,
        "book_verified": false,
        "findings": findings,
        "identity_holds": identity_holds,
        "discrepancies": 0,
        "ok": findings.is_empty() && identity_holds,
    }))
}

pub(crate) async fn plane_record_write_effect(
    body: &[u8],
    at: u64,
    planes: &(dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync),
    sink: Option<&PlaneRecordSink>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(&key)
            .and_then(json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
    };
    let Some(plane) = text("plane") else {
        return Ok(refused_effect(400, "invalid_request", "plane is required"));
    };
    let Some(kind) = text("kind") else {
        return Ok(refused_effect(400, "invalid_request", "kind is required"));
    };
    let Some(id) = text("id") else {
        return Ok(refused_effect(400, "invalid_request", "id is required"));
    };
    let row = match obj.get(&"body") {
        Some(row) if !row.is_null() => row,
        _ => {
            return Ok(refused_effect(400, "invalid_request", "body is required"));
        }
    };
    let parent = match obj.get(&"parent") {
        None => None,
        Some(p) if p.is_null() => None,
        Some(p) if p.as_str().is_some_and(|p| !p.trim().is_empty()) => {
            p.as_str().map(str::to_string)
        }
        Some(_) => {
            return Ok(refused_effect(
                400,
                "invalid_request",
                "parent must be a non-empty string or null",
            ));
        }
    };
    let terminal = match obj.get(&"terminal") {
        None => false,
        Some(b) if b.is_null() => false,
        Some(b) if b.is_boolean() => b.as_bool() == Some(true),
        Some(_) => {
            return Ok(refused_effect(
                400,
                "invalid_request",
                "terminal must be a boolean",
            ));
        }
    };
    let Some(decl) = planes(plane) else {
        return Ok(refused_effect(
            404,
            "not_found",
            &format!("plane `{plane}` not found"),
        ));
    };

    if !busbar_contract::plane::declares_record_kind(&decl, kind) {
        return Ok(refused_effect(
            403,
            "forbidden",
            &format!("plane `{plane}` may not write record kind `{kind}`"),
        ));
    }

    if busbar_kernel::store::plane_view::KERNEL_RECORD_KINDS.contains(&kind) {
        busbar_kernel::diagnostics::diag_warn!(
            busbar_kernel::diagnostics::PLANE_RECORD_WRITE_KERNEL_KIND,
            plane = %plane,
            kind = %kind,
            "an admin plane record write named a record kind the kernel keeps its own records \
             under: refused, nothing written"
        );
        return Ok(refused_effect(
            403,
            "forbidden",
            &format!(
                "record kind `{kind}` is kept by the kernel: plane `{plane}` may not write it"
            ),
        ));
    }

    let Some(owned) = busbar_kernel::store::plane_view::plane_owned_kind(plane, kind) else {
        return Ok(refused_effect(
            400,
            "invalid_request",
            "plane and kind must not hold a control character",
        ));
    };
    let sink = sink.ok_or(GovernanceError::Store)?;
    let record = PlaneRecord {
        kind: owned,
        id: id.to_string(),
        parent,
        seq: 0,
        ts: at,
        disposition: if terminal {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: json::to_vec(row).map_err(|_| GovernanceError::Validation)?,
    };

    let applied = answer(&json::json!({
        "plane": plane,
        "kind": kind,
        "id": record.id,
        "parent": record.parent,
        "terminal": terminal,
        "written_at": at,
    }))?;
    match sink(&decl, &record).await {
        Ok(()) => Ok(EffectAnswer::applied(applied)),
        Err(PlaneWriteFailure::Unapplied) => Ok(EffectAnswer::unapplied(journal_unavailable(
            "the store refused this record write; nothing was published",
        ))),
        Err(PlaneWriteFailure::Unknown(pending)) => {
            tracing::error!(
                "the plane record write has an unknown outcome; its exact record and native attempt remain in custody"
            );
            Ok(EffectAnswer::unknown(
                journal_unavailable(
                    "the store did not acknowledge this record write; its outcome is unknown; do not re-submit",
                ),
                EffectReceipt::PlaneRecordWrite { record, pending },
            ))
        }
    }
}

pub(crate) async fn commit_upgrade_effect(
    body: &[u8],
    at: u64,
    principal: &str,
    journal: Option<&AmendmentJournal>,
) -> Result<EffectAnswer, GovernanceError> {
    let doc: json::Value = json::parse_value(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(version) = obj
        .get(&"version")
        .and_then(json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(refused_effect(
            400,
            "invalid_request",
            "version is required",
        ));
    };
    if version != RUNNING_RELEASE {
        return Ok(refused_effect(
            409,
            "conflict",
            &format!("this node runs `{RUNNING_RELEASE}`; it cannot commit `{version}`"),
        ));
    }
    let journal = journal.ok_or(GovernanceError::Store)?;
    if let Err(why) = journal.admit().await {
        return Ok(EffectAnswer::unapplied(journal_unavailable(&why)));
    }
    let mut record = busbar_kernel_wal::BodyWriter::new();
    record.text(COMMIT_UPGRADE_RECORD_TAG);
    record.text(version);
    record.num(at);
    record.text(principal);
    let body = record.finish();
    let node = journal
        .book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .node();
    let (node_seq, hash) = journal.seal_policy(body.clone(), at)?;
    let receipt = EffectReceipt::CommitUpgrade {
        node,
        seq: node_seq,
        hash,
        body,
    };
    if let Err(why) = journal.acked(node_seq).await {
        return Ok(EffectAnswer::pending(
            journal_unavailable(&format!(
                "the commit is sealed at journal position {node_seq} and not yet kept by the store: \
             {why}; do not re-submit"
            )),
            receipt,
        ));
    }
    match answer(&json::json!({
        "committed": version,
        "committed_at": at,
        "seq": node_seq,
        "hash": hex::encode(hash),
    })) {
        Ok(answer) => Ok(EffectAnswer::applied(answer)),
        Err(_) => Ok(EffectAnswer::pending(
            journal_unavailable(
                "the commit is sealed but its answer could not be encoded; do not re-submit",
            ),
            receipt,
        )),
    }
}

/// The response header that classifies every trust decision answer (TRUST-ADMIN-PRODUCER-DESIGN
/// r3 §4.5). Host-created; audit never reads it (§5.2).
pub(crate) const TRUST_EFFECT_HEADER: &str = "x-busbar-trust-effect";

/// The marker on every answer [`replayable`] replays instead of running the effect (r3 §4.6).
pub(crate) const REPLAYED_HEADER: &str = "idempotent-replayed";

/// An admin error envelope with the raiser's closed `reason` and typed `details` (r5 §1.2).
fn refused_with(
    status: u16,
    code: &str,
    reason: &str,
    message: &str,
    details: &json::Value,
) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_kernel::admin::gate::admin_envelope_body_details(
            code,
            Some(reason),
            message,
            details,
        )
        .into_bytes(),
    }
}

/// [`refused_with`] for a closed reason, its code and status read from the reason table.
fn refused_reason(reason: &str, message: &str, details: &json::Value) -> AdminAnswer {
    let (status, code) = busbar_kernel::admin::reasons::row(reason)
        .map_or((500, "internal"), |row| (row.http, row.code));
    refused_with(status, code, reason, message, details)
}

fn no_details() -> json::Value {
    json::Value::from(json::Map::new())
}

fn trust_effect(mut answer: AdminAnswer, effect: &str) -> AdminAnswer {
    answer
        .headers
        .push((TRUST_EFFECT_HEADER.to_string(), effect.to_string()));
    answer
}

fn ruling_word(ruling: Ruling) -> &'static str {
    match ruling {
        Ruling::Approve => "approve",
        Ruling::Revoke => "revoke",
    }
}

/// The decided key as `TrustKeyView`: the one projection `GET /trust` and the views use (r3 §3.1).
fn trust_key_answer(row: &KeyRow) -> Result<AdminAnswer, GovernanceError> {
    json::to_vec(&busbar_core_admin::trust_inventory::key_row(row))
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store)
}

/// `GET /trust` (r3 §3.1): served from the serving kernel's trust book through the one
/// projection; 503 when no native trust custody is installed, never an empty success (§6).
pub(crate) fn trust_list_effect(
    kernel: Option<&Arc<KernelServices>>,
) -> Result<AdminAnswer, GovernanceError> {
    let readout = kernel
        .cloned()
        .map(busbar_kernel::trust::TrustReadout::over);
    match busbar_core_admin::trust_inventory::trust_list_body(readout.as_ref()) {
        Ok(body) => Ok(super::json_answer(body)),
        Err(why) => Ok(refused_reason("service_unavailable", &why.0, &no_details())),
    }
}

/// The trust arms run only for a resolved principal (r3 §4.3): never the unresolved fallback.
pub(crate) fn trust_actor_unresolved(verb: busbar_core_admin::KernelVerb) -> AdminAnswer {
    trust_effect(
        refused_reason(
            "scope_insufficient",
            "a trust decision needs a resolved principal",
            &json::json!({
                "needed_scope": "full",
                "needed_verb": busbar_core_admin::verb_name(verb),
            }),
        ),
        "not_applied",
    )
}

/// The request's `Idempotency-Key`, as [`replayable`] keys it: the operation a decision records.
pub(crate) fn idempotency_key(request: &super::AdminRequest) -> Option<&str> {
    request
        .header(IDEMPOTENCY_KEY_HEADER)
        .filter(|value| !value.is_empty())
}

/// The closed admin decision body (r3 §4.1): `{key, expected_digest}`, both present.
enum TrustBody<'a> {
    Decide {
        key: &'a str,
        reviewed: busbar_kernel::trust::book::Reviewed<'a>,
    },
    Refused(AdminAnswer),
}

fn trust_body(doc: &json::Value) -> TrustBody<'_> {
    let malformed = |message: &str| {
        TrustBody::Refused(refused_reason("malformed_body", message, &no_details()))
    };
    let Some(object) = doc.as_object() else {
        return malformed("the body must be an object `{key, expected_digest}`");
    };
    if let Some((member, _)) = object
        .iter()
        .find(|(member, _)| !matches!(*member, "key" | "expected_digest"))
    {
        return malformed(&format!(
            "unknown member `{member}`: the body is `{{key, expected_digest}}`"
        ));
    }
    let Some(key) = object
        .get(&"key")
        .and_then(json::Value::as_str)
        .filter(|key| !key.trim().is_empty())
    else {
        return malformed("key is required");
    };
    let reviewed = match object.get(&"expected_digest") {
        None => {
            return TrustBody::Refused(refused_reason(
                "reviewed_digest_required",
                "expected_digest is required: send the digest reviewed from GET /trust, or null \
                 for a key never sighted",
                &no_details(),
            ));
        }
        Some(digest) if digest.is_null() => busbar_kernel::trust::book::Reviewed::Unsighted,
        Some(digest) => match digest.as_str().filter(|d| !d.trim().is_empty()) {
            Some(digest) => busbar_kernel::trust::book::Reviewed::Seen(digest),
            None => {
                return malformed("expected_digest must be a non-empty string or null");
            }
        },
    };
    TrustBody::Decide { key, reviewed }
}

/// The message of a refused decision, by its closed reason and case (r3 §4.5).
fn trust_refusal_message(key: &str, refused: &TrustRefused) -> String {
    match refused {
        TrustRefused::NoSuchKey => format!("trust key `{key}` not found"),
        TrustRefused::Ambiguous => format!(
            "trust key `{key}` names more than one trust row; a registration name containing `/` \
             makes it ambiguous, so rename the registration"
        ),
        TrustRefused::NothingSighted => format!("trust key `{key}` was never sighted"),
        TrustRefused::Unverified => format!(
            "trust key `{key}` was last sighted unverified: its document failed verification, so \
             there is nothing to approve"
        ),
        TrustRefused::Rootless => format!("trust key `{key}` has no authenticity root"),
        TrustRefused::Earlier => format!(
            "an earlier decision on trust key `{key}` is still settling; nothing was submitted"
        ),
        TrustRefused::Unavailable => {
            "native trust custody cannot keep decisions on this node; nothing was decided"
                .to_string()
        }
        TrustRefused::Store(_) => {
            "the store did not keep the decision; nothing was decided".to_string()
        }
        refused => match refused.reason() {
            "reviewed_digest_stale" => format!(
                "trust key `{key}` changed since it was reviewed; read it again and review its \
                 current digest"
            ),
            "decision_in_progress" => {
                format!("trust key `{key}` has another decision in progress; retry")
            }
            reason => format!("trust key `{key}` was not decided: {reason}"),
        },
    }
}

/// `POST /trust/approve|revoke` (r3 §4): parse the closed body, decide through the serving
/// kernel's one decision function, and answer per §4.5. `audited` reports to the walk whether the
/// kernel wrote this request's typed audit row (condition A-C4b).
pub(crate) async fn trust_decide_effect(
    body: &[u8],
    ruling: Ruling,
    kernel: Option<&KernelServices>,
    actor: &str,
    operation: Option<&str>,
    audited: &AtomicBool,
) -> Result<EffectAnswer, GovernanceError> {
    let unapplied =
        |answer: AdminAnswer| Ok(EffectAnswer::unapplied(trust_effect(answer, "not_applied")));
    let Ok(doc) = json::parse_value(body) else {
        return unapplied(refused_reason(
            "malformed_body",
            "the body must be JSON `{key, expected_digest}`",
            &no_details(),
        ));
    };
    let (key, reviewed) = match trust_body(&doc) {
        TrustBody::Decide { key, reviewed } => (key, reviewed),
        TrustBody::Refused(answer) => return unapplied(answer),
    };
    let Some(kernel) = kernel else {
        return unapplied(refused_reason(
            "service_unavailable",
            "native trust custody is not installed on this node",
            &no_details(),
        ));
    };
    let decided = kernel
        .trust_rule_by(key, ruling, reviewed, actor, operation)
        .await;
    audited.store(decided.audited, Ordering::SeqCst);
    match decided.result {
        Ok(row) => Ok(EffectAnswer::applied(trust_effect(
            trust_key_answer(&row)?,
            "applied",
        ))),
        Err(TrustRefused::Unknown { op_id, decided_at }) => {
            tracing::error!(key = %key, "a trust decision's durable write has an unknown outcome; its attempt is retained");
            let answer = refused_reason(
                "service_unavailable",
                "outcome unknown; do not re-submit with this key; needs operator investigation \
                 (read the key's state)",
                &json::json!({
                    "key": key,
                    "ruling": ruling_word(ruling),
                    "decided_at": decided_at,
                    "decided_by": {"kind": "principal", "id": actor},
                    "operation": operation,
                }),
            );
            Ok(EffectAnswer::unknown(
                trust_effect(answer, "unknown"),
                EffectReceipt::TrustDecision {
                    version: TRUST_RECEIPT_VERSION,
                    attempt_op_id: op_id,
                    key: key.to_string(),
                    ruling: ruling_word(ruling).to_string(),
                    decided_at,
                    operation: operation.map(str::to_string),
                },
            ))
        }
        Err(refused) => {
            if let TrustRefused::Store(why) = &refused {
                tracing::error!(key = %key, error = %why, "a trust ruling could not be kept");
            }
            unapplied(refused_reason(
                refused.reason(),
                &trust_refusal_message(key, &refused),
                &no_details(),
            ))
        }
    }
}

/// What a replayed trust answer resolved to, for the typed replay row (r3 §5.2).
fn trust_replay_audit(
    verb: busbar_core_admin::KernelVerb,
    actor: &str,
    operation: Option<&str>,
    receipt: Option<&EffectReceipt>,
    answer: &AdminAnswer,
    audited: &AtomicBool,
) {
    let (action, resource) = if verb == busbar_core_admin::KernelVerb::TrustApprove {
        ("trust_approve", "/api/v1/admin/trust/approve")
    } else {
        ("trust_revoke", "/api/v1/admin/trust/revoke")
    };
    // Only answers that ran an effect are retained, so a replay is an apply (2xx), a still-unknown
    // or unreadable outcome (503), or a proven non-apply (409); never the effect header (§5.2).
    let outcome = match answer.status {
        200..=299 => busbar_kernel::audit_ring::OUTCOME_APPLIED,
        503 => busbar_kernel::audit_ring::OUTCOME_DEGRADED,
        _ => busbar_kernel::audit_ring::OUTCOME_REJECTED,
    };
    let key = match receipt {
        Some(EffectReceipt::TrustDecision { key, .. }) => Some(key.clone()),
        _ => json::parse_value(&answer.body).ok().and_then(|body| {
            body.get("key")
                .and_then(json::Value::as_str)
                .map(str::to_string)
        }),
    };
    let decided_at = match receipt {
        Some(EffectReceipt::TrustDecision { decided_at, .. }) => Some(*decided_at),
        _ => None,
    };
    let data = json::json!({
        "key": key,
        "ruling": action,
        "decided_by": {"kind": "principal", "id": actor},
        "decided_at": decided_at,
        "replayed": true,
    });
    busbar_kernel::audit_ring::AUDIT.record_row(busbar_kernel::audit::auditlog::AuditRowInput {
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: actor.to_string(),
        request_id: busbar_kernel::admin::gate::request_id_in_scope(),
        idempotency_key: operation.map(str::to_string),
        kind: Some("core".to_string()),
        instance: Some("trust".to_string()),
        data: json::to_string(&data)
            .ok()
            .and_then(|text| busbar_kernel::audit_ring::AuditData::from_json(&text).ok())
            .unwrap_or_default(),
        ..Default::default()
    });
    audited.store(true, Ordering::SeqCst);
}

#[must_use]
pub(crate) fn live_planes(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneLookup {
    Arc::new(move |key: &str| {
        let snapshot = app.load();
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key && snapshot.plane_configured(decl))
    })
}

#[must_use]
pub(crate) fn live_admin_door(app: Arc<busbar_kernel::state::AppHandle>) -> super::AdminDoorFn {
    Arc::new(
        move |request: &super::AdminRequest| -> super::AdminDoorFuture {
            let projection = request.http_projection();
            let headers = if projection.is_some() {
                None
            } else {
                request.http_headers().ok()
            };
            if projection.is_none() && headers.is_none() {
                return Box::pin(std::future::ready(
                    busbar_kernel::auth::AdminDoor::Denied.into(),
                ));
            }
            let (handle, snapshot, id, cx) = if let Some(binding) = &request.binding {
                if !Arc::ptr_eq(binding.handle(), &app)
                    || binding.check_live().is_err()
                    || binding.invocation().request_id().get() != request.unit
                    || !binding
                        .snapshot()
                        .is_ok_and(|original| Arc::ptr_eq(&original, request.snapshot()))
                {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Denied.into(),
                    ));
                }
                let id = binding.invocation();
                let mut cx = busbar_kernel::auth::admin_call_context(id);
                if let Some(deadline) = binding.deadline() {
                    cx.deadline = cx.deadline.min(deadline);
                }
                (binding.handle().clone(), binding.app().clone(), id, cx)
            } else {
                let selected = app.load();
                if selected.native_admin.is_some() {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Unavailable(
                            busbar_kernel::auth::VerifierUnavailable::NoVerdict,
                        )
                        .into(),
                    ));
                }
                let Some(request_id) = std::num::NonZeroU64::new(request.unit) else {
                    return Box::pin(std::future::ready(
                        busbar_kernel::auth::AdminDoor::Denied.into(),
                    ));
                };
                let id = busbar_kernel::state::InvocationId::from_request_id(request_id);
                (
                    app.clone(),
                    selected,
                    id,
                    busbar_kernel::auth::admin_call_context(id),
                )
            };
            let invocation = busbar_kernel::auth::native_admin::Invocation {
                handle,
                selected: snapshot,
                id,
                cx,
                request: Arc::clone(request.snapshot()),
            };
            Box::pin(async move {
                let headers = projection
                    .as_ref()
                    .map(|p| p.headers())
                    .or(headers.as_ref());
                match headers {
                    Some(headers) => {
                        busbar_kernel::auth::admin_verdict_for(invocation, headers).await
                    }
                    None => busbar_kernel::auth::AdminDoor::Denied.into(),
                }
            })
        },
    )
}

#[must_use]
pub(crate) fn live_records(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> PlaneRecordSink {
    Arc::new(move |decl, record| {
        let core = Arc::clone(&core);
        Box::pin(async move {
            use busbar_kernel::host_records_async::{AsyncHistory, HistoryError, HistoryOutcome};
            // This administrative envelope seam has always upserted seq=0 records. Its
            // objects are separate from raw plugin HostRecords; opaque parent metadata
            // never declares a parent collection or authorizes a cascade.
            let kinds = decl
                .record_kinds
                .iter()
                .map(|kind| {
                    busbar_kernel::store::plane_view::plane_owned_kind(decl.key, kind)
                        .ok_or(PlaneWriteFailure::Unapplied)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let owner = format!("busbar.admin.envelopes/{}", decl.key);
            let history = AsyncHistory::authorized_upserts(core, &owner, kinds)
                .map_err(|_| PlaneWriteFailure::Unapplied)?;
            match history
                .upsert(record.view())
                .await
                .map_err(|error| match error {
                    HistoryError::Unauthorized
                    | HistoryError::Invalid
                    | HistoryError::MissingParent => PlaneWriteFailure::Unapplied,
                    _ => PlaneWriteFailure::Unknown(None),
                })? {
                HistoryOutcome::Applied => Ok(()),
                HistoryOutcome::Pending(id)
                | HistoryOutcome::Reconcile(id)
                | HistoryOutcome::Busy(id) => Err(PlaneWriteFailure::Unknown(Some(id.0))),
                HistoryOutcome::Conflict
                | HistoryOutcome::OpIdConflict
                | HistoryOutcome::NoEffect(_) => Err(PlaneWriteFailure::Unapplied),
            }
        })
    })
}

/// THE REPLAY CACHE the two Q71(2) writes share (contract D-3): per `(actor, "<verb>:<key>")`, the
/// SHA-256 of the body the first call carried and the answer it produced. Unresolved receipts
/// have separate custody: the ordinary answer TTL cannot release an effect still owed or unknown.
#[derive(Default)]
pub(crate) struct ReplayCache {
    answers: busbar_core_admin::idempotency::IdempotencyCache<ReplayValue>,
    retained: Mutex<HashMap<(String, String), HeldReplay>>,
}

impl ReplayCache {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn retain(&self, key: (String, String), held: HeldReplay) {
        let previous = self
            .retained
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, held);
        drop(previous);
    }
}

#[derive(Clone)]
struct ReplayValue {
    digest: [u8; 32],
    answer: AdminAnswer,
    receipt: Option<EffectReceipt>,
}

#[derive(Clone)]
struct HeldReplay {
    value: ReplayValue,
    settlement: Option<Arc<HeldSettlement>>,
}

struct HeldSettlement {
    store: Arc<busbar_kernel::persistence::scoped::ScopedStore>,
    claim: busbar_core_admin::idempotency::durable::Claim,
    at: u64,
    settled: busbar_core_admin::idempotency::durable::Settled,
}

impl HeldSettlement {
    async fn retry(&self) {
        if let Err(why) = busbar_core_admin::idempotency::durable::settle(
            &self.store,
            &self.claim,
            self.at,
            &self.settled,
        )
        .await
        {
            tracing::error!(reason = %why, "the store did not acknowledge the retained Idempotency-Key receipt; its original claim remains held");
        }
    }
}

/// What a replay of a retained answer came to: the answer, and the final value a resolved receipt
/// settles to (r3 §4.6), which replaces the retained one.
struct Replayed {
    answer: AdminAnswer,
    terminal: Option<ReplayValue>,
}

/// The trust-only context a replay resolves a [`EffectReceipt::TrustDecision`] in (r3 condition
/// A-C4a). Other verbs replay with [`ReplayContext::None`] and never reach the kernel.
#[derive(Clone, Copy)]
pub(crate) enum ReplayContext<'a> {
    None,
    Trust {
        kernel: Option<&'a KernelServices>,
        /// The host-only per-request flag the replay's typed audit row sets (condition A-C4b).
        audited: &'a AtomicBool,
    },
}

/// A retained answer this build cannot read back: the operation may have had an effect (r3 §4.6,
/// B-N8), so the answer says so for every root verb.
fn unreadable_receipt() -> AdminAnswer {
    refused_reason(
        "service_unavailable",
        "this operation's outcome cannot be read back by this build; do not re-submit; read the \
         key's state",
        &no_details(),
    )
}

impl HeldReplay {
    async fn replay(
        &self,
        journal: Option<&AmendmentJournal>,
        context: ReplayContext<'_>,
    ) -> Replayed {
        if let Some(settlement) = &self.settlement {
            if let Some(EffectReceipt::PlaneRecordWrite {
                pending: Some(id), ..
            }) = &self.value.receipt
            {
                // Only this live retained entry carries the original CoreStore handle.
                // A receipt loaded after restart has no settlement and cannot restore
                // an in-memory operation from its ID. Never replan the saved record.
                if let Err(error) = settlement
                    .store
                    .retry(busbar_kernel::persistence::facade::PendingId(*id))
                    .await
                {
                    tracing::warn!(
                        ?error,
                        "the exact retained record attempt could not be reconciled"
                    );
                }
            }
            settlement.retry().await;
        }
        if let (
            Some(EffectReceipt::CommitUpgrade {
                node,
                seq,
                hash,
                body,
            }),
            Some(journal),
        ) = (&self.value.receipt, journal)
        {
            let chain = {
                let book = journal.book.lock().unwrap_or_else(|p| p.into_inner());
                (book.journal.node() == *node).then(|| book.chain_at())
            };
            let records = match chain {
                Some(chain) => Some(chain.read().await),
                None => None,
            };
            if let Some(Ok(Ok(records))) = records {
                if records.iter().any(|record| {
                    record.node == *node
                        && record.node_seq == *seq
                        && record.hash == *hash
                        && record.class == busbar_kernel_wal::RecordClass::Policy
                        && record.body == *body
                }) {
                    let _acknowledged = journal.acked(*seq).await;
                }
            }
        }
        let original = Replayed {
            answer: self.value.answer.clone(),
            terminal: None,
        };
        let Some(EffectReceipt::TrustDecision {
            version,
            attempt_op_id,
            key,
            ruling: _,
            decided_at,
            operation,
        }) = &self.value.receipt
        else {
            return original;
        };
        if *version != TRUST_RECEIPT_VERSION {
            return Replayed {
                answer: unreadable_receipt(),
                terminal: None,
            };
        }
        let ReplayContext::Trust {
            kernel: Some(kernel),
            ..
        } = context
        else {
            return original;
        };
        // Ask the record what its own settlement proves; never plan the decision again.
        let answer = match kernel
            .trust_resolve_attempt(*attempt_op_id, key, *decided_at, operation.as_deref())
            .await
        {
            Resolution::Unknown => return original,
            Resolution::Applied(row) => match trust_key_answer(&row) {
                Ok(answer) => trust_effect(answer, "applied"),
                Err(_) => return original,
            },
            Resolution::NotApplied => trust_effect(
                refused_reason(
                    "outcome_not_applied",
                    "the original decision never applied and never will; read the key's state, \
                     review it again and decide under a new Idempotency-Key",
                    &json::json!({"operation": operation, "decided_at": decided_at}),
                ),
                "not_applied",
            ),
        };
        Replayed {
            terminal: Some(ReplayValue {
                digest: self.value.digest,
                answer: answer.clone(),
                receipt: None,
            }),
            answer,
        }
    }
}

/// Make a resolved receipt terminal (r3 §4.6): the durable claim settles to the final answer
/// and the retained entry is replaced, so every later same-key replay, also after a restart,
/// answers it without asking the kernel again.
async fn settle_terminal(
    cache: &ReplayCache,
    store: Option<&ReplayStore>,
    key: (String, String),
    at: u64,
    retained: &ReplayValue,
    terminal: ReplayValue,
) {
    use busbar_core_admin::idempotency::durable::{self, Settled};
    let settled = Settled::Answer(stored_answer(&terminal));
    // The live entry first, so no clone of the retained one re-keeps the receipt after this.
    cache.retain(
        key.clone(),
        HeldReplay {
            value: terminal,
            settlement: None,
        },
    );
    if let Some(store) = store.and_then(|store| store()) {
        if let Err(why) =
            durable::settle_retained(&store, &key, at, &stored_answer(retained), &settled).await
        {
            tracing::error!(reason = %why, "the store did not keep a resolved Idempotency-Key outcome; its retained receipt remains held");
        }
    }
}

/// The answer a replay returns: marked as replayed (r3 §4.6), and for a trust verb audited by
/// one typed row (r3 §5.2).
fn replayed(
    mut answer: AdminAnswer,
    scope: &ReplayScope<'_>,
    operation: &str,
    receipt: Option<&EffectReceipt>,
    context: ReplayContext<'_>,
) -> AdminAnswer {
    if let ReplayContext::Trust { audited, .. } = context {
        trust_replay_audit(
            scope.verb,
            scope.actor,
            Some(operation),
            receipt,
            &answer,
            audited,
        );
    }
    answer
        .headers
        .push((REPLAYED_HEADER.to_string(), "true".to_string()));
    answer
}

pub(crate) type ReplayStore =
    Arc<dyn Fn() -> Option<Arc<busbar_kernel::persistence::scoped::ScopedStore>> + Send + Sync>;

pub(crate) fn live_replay_store(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> Result<ReplayStore, busbar_kernel::persistence::scoped::Error> {
    let store = Arc::new(busbar_core_admin::idempotency::durable::scoped_store(core)?);
    Ok(Arc::new(move || Some(Arc::clone(&store))))
}

fn stored_answer(value: &ReplayValue) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&bytes[..len as usize]);
    }
    let answer = &value.answer;
    let mut out = Vec::with_capacity(32 + 6 + answer.body.len() + 64);
    out.extend_from_slice(&value.digest);
    out.extend_from_slice(&answer.status.to_be_bytes());
    let count = u32::try_from(answer.headers.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in answer.headers.iter().take(count as usize) {
        push(&mut out, name.as_bytes());
        push(&mut out, value.as_bytes());
    }
    push(&mut out, &answer.body);
    if let Some(receipt) = &value.receipt {
        let receipt = json::to_vec(receipt)
            .expect("an effect receipt contains only serializable strings, integers and bytes");
        push(&mut out, &receipt);
    }
    out
}

fn kept_answer(kept: &[u8]) -> Option<ReplayValue> {
    fn take<'b>(bytes: &'b [u8], cursor: &mut usize, n: usize) -> Option<&'b [u8]> {
        let end = cursor.checked_add(n)?;
        let slice = bytes.get(*cursor..end)?;
        *cursor = end;
        Some(slice)
    }
    fn pull<'b>(bytes: &'b [u8], cursor: &mut usize) -> Option<&'b [u8]> {
        let len = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?);
        take(bytes, cursor, usize::try_from(len).ok()?)
    }
    let mut cursor = 0usize;
    let digest: [u8; 32] = take(kept, &mut cursor, 32)?.try_into().ok()?;
    let status = u16::from_be_bytes(take(kept, &mut cursor, 2)?.try_into().ok()?);
    let count = u32::from_be_bytes(take(kept, &mut cursor, 4)?.try_into().ok()?);
    let mut headers = Vec::new();
    for _ in 0..count {
        let name = String::from_utf8(pull(kept, &mut cursor)?.to_vec()).ok()?;
        let value = String::from_utf8(pull(kept, &mut cursor)?.to_vec()).ok()?;
        headers.push((name, value));
    }
    let body = pull(kept, &mut cursor)?.to_vec();
    let receipt = if cursor == kept.len() {
        None
    } else {
        Some(json::parse(pull(kept, &mut cursor)?).ok()?)
    };
    if cursor != kept.len() {
        return None;
    }
    Some(ReplayValue {
        digest,
        answer: AdminAnswer {
            status,
            headers,
            body,
        },
        receipt,
    })
}

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

pub(crate) struct ReplayScope<'a> {
    pub verb: busbar_core_admin::KernelVerb,
    pub actor: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn replayable<F, Fut>(
    cache: &ReplayCache,
    store: Option<&ReplayStore>,
    scope: ReplayScope<'_>,
    unit: &super::AdminRequest,
    body: &[u8],
    journal: Option<&AmendmentJournal>,
    context: ReplayContext<'_>,
    effect: F,
) -> Result<AdminAnswer, GovernanceError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<EffectAnswer, GovernanceError>>,
{
    use busbar_core_admin::idempotency::Probe;

    // A refusal of this wrapper's own: nothing ran, so a trust verb's answer says `not_applied`.
    let own = |answer: AdminAnswer| match context {
        ReplayContext::Trust { .. } => trust_effect(answer, "not_applied"),
        ReplayContext::None => answer,
    };
    let Some(header) = idempotency_key(unit) else {
        return effect().await.map(|outcome| outcome.answer);
    };
    // One predicate for every replayable verb (r3 condition B-C4), before any claim or effect.
    if !busbar_core_admin::valid_idempotency_key(header) {
        return Ok(own(refused_reason(
            "malformed_body",
            "Idempotency-Key must be 1 to 128 of A-Z a-z 0-9 . _ : -",
            &no_details(),
        )));
    }
    let name = busbar_core_admin::verb_name(scope.verb).unwrap_or_default();
    let digest: [u8; 32] = busbar_contract::abi::sdk::digest::sha256(body);

    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};

    let other_body = || {
        Ok(own(refused_reason(
            "idempotency_mismatch",
            "this Idempotency-Key was already used with a different request body",
            &no_details(),
        )))
    };
    let in_flight = || {
        Ok(own(refused_reason(
            "idempotency_in_flight",
            "a request with this Idempotency-Key is already in flight",
            &no_details(),
        )))
    };
    let key = (scope.actor.to_string(), format!("{name}:{header}"));
    let held = cache
        .retained
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&key)
        .cloned();
    if let Some(held) = held {
        if held.value.digest != digest {
            return other_body();
        }
        let Replayed { answer, terminal } = held.replay(journal, context).await;
        if let Some(terminal) = terminal {
            settle_terminal(cache, store, key, unit.at(), &held.value, terminal).await;
        }
        return Ok(replayed(
            answer,
            &scope,
            header,
            held.value.receipt.as_ref(),
            context,
        ));
    }
    match cache.answers.probe(key.clone(), unit.at()) {
        Probe::Replay(value) if value.digest == digest => {
            Ok(replayed(value.answer, &scope, header, None, context))
        }
        Probe::Replay(_) => other_body(),
        Probe::InFlight => in_flight(),
        Probe::NoKey => effect().await.map(|outcome| outcome.answer),
        Probe::Reserved(mut reservation) => {
            let store_now = store.and_then(|store| store());
            let claim = match &store_now {
                Some(store_now) => {
                    match durable::claim_held(store_now, reservation.key(), unit.at()).await {
                        Ok(claim) => Some(claim),
                        Err(Refused::Answer(kept) | Refused::Retained(kept)) => {
                            return match kept_answer(&kept) {
                                Some(value) if value.digest == digest => {
                                    if value.receipt.is_some() {
                                        let held = HeldReplay {
                                            value,
                                            settlement: None,
                                        };
                                        cache.retain(key.clone(), held.clone());
                                        reservation.in_flight();
                                        let Replayed { answer, terminal } =
                                            held.replay(journal, context).await;
                                        if let Some(terminal) = terminal {
                                            settle_terminal(
                                                cache,
                                                store,
                                                key,
                                                unit.at(),
                                                &held.value,
                                                terminal,
                                            )
                                            .await;
                                        }
                                        Ok(replayed(
                                            answer,
                                            &scope,
                                            header,
                                            held.value.receipt.as_ref(),
                                            context,
                                        ))
                                    } else {
                                        let answer = value.answer.clone();
                                        reservation.commit(value, unit.at());
                                        Ok(replayed(answer, &scope, header, None, context))
                                    }
                                }
                                Some(_) => other_body(),
                                None => {
                                    tracing::error!(
                                        "the store keeps an Idempotency-Key's first answer in a form this node cannot read"
                                    );
                                    Ok(own(unreadable_receipt()))
                                }
                            };
                        }
                        Err(Refused::Unavailable(why)) => {
                            tracing::error!(reason = %why, "an Idempotency-Key could not be claimed in the store");
                            return Ok(own(refused_reason(
                                "service_unavailable",
                                "the store could not record this Idempotency-Key; nothing was done",
                                &no_details(),
                            )));
                        }
                        Err(Refused::InFlight | Refused::Applied(_)) => {
                            return in_flight();
                        }
                    }
                }
                None => None,
            };

            reservation.in_flight();
            let (answer, settled) = match effect().await {
                Ok(EffectAnswer {
                    answer,
                    disposition: EffectDisposition::Applied,
                }) => {
                    let value = ReplayValue {
                        digest,
                        answer: answer.clone(),
                        receipt: None,
                    };
                    let settled = Settled::Answer(stored_answer(&value));
                    reservation.commit(value, unit.at());
                    (Ok(answer), settled)
                }
                Ok(EffectAnswer {
                    answer,
                    disposition:
                        EffectDisposition::Pending(receipt) | EffectDisposition::Unknown(receipt),
                }) => {
                    let value = ReplayValue {
                        digest,
                        answer: answer.clone(),
                        receipt: Some(receipt),
                    };
                    let settled = Settled::Retained(stored_answer(&value));
                    let settlement =
                        store_now
                            .as_ref()
                            .zip(claim.as_ref())
                            .map(|(store_now, claim)| {
                                Arc::new(HeldSettlement {
                                    store: Arc::clone(store_now),
                                    claim: claim.clone(),
                                    at: unit.at(),
                                    settled: settled.clone(),
                                })
                            });
                    cache.retain(key, HeldReplay { value, settlement });
                    (Ok(answer), settled)
                }
                Ok(EffectAnswer {
                    answer,
                    disposition: EffectDisposition::Unapplied,
                }) => {
                    reservation.clear();
                    (Ok(answer), Settled::Released)
                }
                Err(error) => {
                    reservation.clear();
                    (Err(error), Settled::Released)
                }
            };
            if let (Some(store_now), Some(claim)) = (&store_now, &claim) {
                if let Err(why) = durable::settle(store_now, claim, unit.at(), &settled).await {
                    tracing::error!(reason = %why, "the store did not keep an Idempotency-Key's outcome; its original claim remains held");
                }
            }
            answer
        }
    }
}

#[cfg(test)]
#[path = "tests/bound_tests.rs"]
pub(crate) mod bound_tests;
