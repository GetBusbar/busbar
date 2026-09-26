// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE FOUR 1.6.0 ADMIN VERBS OWNER ANSWER Q71(2) BINDS**: `verify`, `plane_facts`,
//! `plane_record_write` and `commit_upgrade` — additive, `x-busbar-since 1.6.0`, the same shape as
//! the core admin verbs of Q56. Every one is admitted by the verbs unit before it reaches this file
//! (scope, rate class, the operator ceremony for the irreducible `commit_upgrade`, dual control), so
//! each effect here speaks only to its own body and its own effect.
//!
//! * `GET /api/v1/admin/verify` — [`verify_effect`]: the ledger's own verifier
//!   ([`busbar_kernel_ledger::verify`]) over what the node holds — every sealed checkpoint re-hashes
//!   to its body, no node's sequence went backwards between two checkpoints, the book as it stands
//!   against the last checkpoint — and the reconciliation identity. A failed verification is still a
//!   `200`: the verb answers the question it was asked, and `ok` says the answer.
//! * `GET /api/v1/admin/plane-facts?plane=<key>` — [`plane_facts_effect`]: what a plane this node
//!   serves declares about itself (its contract `PlaneDeclaration`), read off the registry. A plane
//!   this node does not serve is `404` — the same Law-7 answer its admin paths give.
//! * `POST /api/v1/admin/plane-record-write` — [`plane_record_write_effect`]: one upsert of a plane
//!   record, through the plane-facing store seam the planes themselves persist through.
//! * `POST /api/v1/admin/commit-upgrade` — [`commit_upgrade_effect`]: seal, on the node's journal as
//!   a `Policy` record, that the fleet commits to the release THIS binary is. The body names the
//!   release; one this binary is not is refused, so a commit can never name a version nobody runs.

use std::sync::Arc;

use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use busbar_core_admin::GovernanceError;

use super::{AdminAnswer, AmendmentJournal, LedgerView};

/// Which plane THIS node serves under a key, and what it declares: `None` for a key no plane is
/// registered under, and for a registered plane this node has not configured (Law 7). A predicate
/// over the live configuration rather than a list, so a config apply is what the next call sees.
pub type PlaneLookup = Arc<dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync>;

/// The lookup of a node no root bound a registry to: it serves no plane.
#[must_use]
pub fn no_planes() -> PlaneLookup {
    Arc::new(|_| None)
}

/// Where `plane_record_write` lands one record: the plane-facing store seam
/// (`busbar_kernel::plane::store::PlaneStore::upsert_plane_record`). `Err` carries the store's own
/// words, for the node's log only.
pub type PlaneRecordSink = Arc<dyn Fn(&PlaneRecord) -> Result<(), String> + Send + Sync>;

/// The domain tag a `commit_upgrade` journal record's body opens with, so a `Policy`-class record
/// is recognisable as a committed release without guessing.
pub const COMMIT_UPGRADE_RECORD_TAG: &str = "busbar/commit-upgrade/v1";

/// The release this binary is — the only release a `commit_upgrade` on this node may name.
pub const RUNNING_RELEASE: &str = env!("CARGO_PKG_VERSION");

/// One refusal in the admin envelope, with a message that says what to fix.
fn refused(status: u16, code: &str, message: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(code, message).into_bytes(),
    }
}

/// A `200` carrying `value` as JSON.
fn answer(value: &serde_json::Value) -> Result<AdminAnswer, GovernanceError> {
    serde_json::to_vec(value)
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store)
}

/// One query parameter's value, or `None` when the target carries none under `name`.
fn query_param<'t>(target: &'t str, name: &str) -> Option<&'t str> {
    let (_, query) = target.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

/// `GET /api/v1/admin/verify` — everything that has to be true of this node's ledger, checked.
///
/// A node whose book holds a refused counts row is refused whole (`Store`), exactly as the ledger
/// views beside it are: an identity measured over a book with a hole in it is not a measurement.
pub(crate) fn verify_effect(ledger: &dyn LedgerView) -> Result<AdminAnswer, GovernanceError> {
    use busbar_kernel_ledger::verify::{sequences_are_monotonic, verify, AllWindowsOpen, Finding};

    if ledger.has_refused_rows() {
        return Err(GovernanceError::Store);
    }
    let (checkpoints, book) = ledger.verify_snapshot();
    let mut findings: Vec<Finding> = Vec::new();
    for checkpoint in &checkpoints {
        if !checkpoint.body_hash_verifies() {
            findings.push(Finding::CheckpointEdited {
                checkpoint_seq: checkpoint.checkpoint_seq,
            });
        }
    }
    for pair in checkpoints.windows(2) {
        findings.extend(sequences_are_monotonic(&pair[0], &pair[1]));
    }
    let since = checkpoints.last();
    let book_verified = match (since, &book) {
        (Some(since), Some(now)) => {
            // The checkpoint's own digest was checked above with every other one.
            findings.extend(
                verify(since, now, &AllWindowsOpen, None)
                    .into_iter()
                    .filter(|f| !matches!(f, Finding::CheckpointEdited { .. })),
            );
            true
        }
        _ => false,
    };
    let (ledger_rows, legacy_rows) = ledger
        .identity_snapshot()
        .map_err(|_| GovernanceError::Store)?;
    let discrepancies = crate::root::ledger_identity::reconcile(&ledger_rows, &legacy_rows)
        .map_err(|_| GovernanceError::Store)?;
    let identity_holds = discrepancies.is_empty();
    answer(&serde_json::json!({
        "checkpoints": checkpoints.len(),
        "since": since.map(|c| serde_json::json!({
            "checkpoint_seq": c.checkpoint_seq,
            "node": c.node,
            "wall": c.wall,
        })),
        "book_verified": book_verified,
        "findings": findings.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "identity_holds": identity_holds,
        "discrepancies": discrepancies.len(),
        "ok": findings.is_empty() && identity_holds,
    }))
}

/// `GET /api/v1/admin/plane-facts?plane=<key>` — what a plane this node serves declares about
/// itself. Read-only: the declaration is a constant of the plane.
pub(crate) fn plane_facts_effect(
    target: &str,
    planes: &dyn Fn(&str) -> Option<PlaneDeclaration>,
) -> Result<AdminAnswer, GovernanceError> {
    let Some(key) = query_param(target, "plane").filter(|k| !k.is_empty()) else {
        return Ok(refused(400, "invalid_request", "plane is required"));
    };
    let Some(decl) = planes(key) else {
        return Ok(refused(
            404,
            "not_found",
            &format!("plane `{key}` not found"),
        ));
    };
    answer(&serde_json::json!({
        "plane": decl.key,
        "fallback": decl.fallback,
        "config_section": decl.config_section,
        "owned_config_sections": decl.owned_config_sections,
        "scope_kinds": decl.scope_kinds,
        "subject_noun": decl.subject_noun,
        "admin_noun": decl.admin_noun,
        "audit_kind": decl.audit_kind,
        "billable_classes": decl
            .billable_classes
            .iter()
            .map(|c| serde_json::json!({"class": c.class, "family": c.family}))
            .collect::<Vec<_>>(),
        "fee_units": decl.fee_units,
        "metric_families": decl
            .metric_families
            .iter()
            .map(|m| serde_json::json!({"name": m.name, "kind": m.kind, "label_keys": m.label_keys}))
            .collect::<Vec<_>>(),
        "served_op_classes": decl
            .served_op_classes
            .iter()
            .map(|s| serde_json::json!({"op": s.op.as_str(), "name": s.name}))
            .collect::<Vec<_>>(),
    }))
}

/// `POST /api/v1/admin/plane-record-write` — upsert one record of a plane this node serves.
///
/// The body is `{ "plane": "<key>", "kind": "…", "id": "…", "parent": "…"|null, "terminal": bool,
/// "body": <json> }`. `body` is the record's opaque row, stored as its JSON bytes and never decoded
/// by the store; `terminal` (default `false`) is the retention disposition. `written_at` is the
/// arrival second, pinned by the unit.
pub(crate) fn plane_record_write_effect(
    body: &[u8],
    at: u64,
    planes: &dyn Fn(&str) -> Option<PlaneDeclaration>,
    sink: Option<&PlaneRecordSink>,
) -> Result<AdminAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
    };
    let Some(plane) = text("plane") else {
        return Ok(refused(400, "invalid_request", "plane is required"));
    };
    let Some(kind) = text("kind") else {
        return Ok(refused(400, "invalid_request", "kind is required"));
    };
    let Some(id) = text("id") else {
        return Ok(refused(400, "invalid_request", "id is required"));
    };
    let row = match obj.get("body") {
        None | Some(serde_json::Value::Null) => {
            return Ok(refused(400, "invalid_request", "body is required"));
        }
        Some(row) => row,
    };
    let parent = match obj.get("parent") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => Some(p.clone()),
        Some(_) => {
            return Ok(refused(
                400,
                "invalid_request",
                "parent must be a non-empty string or null",
            ));
        }
    };
    let terminal = match obj.get("terminal") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => {
            return Ok(refused(
                400,
                "invalid_request",
                "terminal must be a boolean",
            ));
        }
    };
    if planes(plane).is_none() {
        return Ok(refused(
            404,
            "not_found",
            &format!("plane `{plane}` not found"),
        ));
    }
    let sink = sink.ok_or(GovernanceError::Store)?;
    let record = PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent,
        seq: 0,
        ts: at,
        disposition: if terminal {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: serde_json::to_vec(row).map_err(|_| GovernanceError::Validation)?,
    };
    sink(&record).map_err(|_| GovernanceError::Store)?;
    answer(&serde_json::json!({
        "plane": plane,
        "kind": record.kind,
        "id": record.id,
        "parent": record.parent,
        "terminal": terminal,
        "written_at": at,
    }))
}

/// `POST /api/v1/admin/commit-upgrade` — the fleet commits to the release this binary is.
///
/// The body is `{ "version": "<release>" }`. A release this binary is not is refused `409
/// conflict` and seals nothing. The committed release is sealed on the node's journal as a
/// `Policy` record ([`COMMIT_UPGRADE_RECORD_TAG`], the release, the second, the principal) before
/// the answer names its position and chain hash. A node with no journal bound refuses (`Store`):
/// a commit nothing recorded did not happen.
pub(crate) fn commit_upgrade_effect(
    body: &[u8],
    at: u64,
    principal: &str,
    journal: Option<&AmendmentJournal>,
) -> Result<AdminAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(version) = obj
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(refused(400, "invalid_request", "version is required"));
    };
    if version != RUNNING_RELEASE {
        return Ok(refused(
            409,
            "conflict",
            &format!("this node runs `{RUNNING_RELEASE}`; it cannot commit `{version}`"),
        ));
    }
    let journal = journal.ok_or(GovernanceError::Store)?;
    let mut record = busbar_kernel_wal::BodyWriter::new();
    record.text(COMMIT_UPGRADE_RECORD_TAG);
    record.text(version);
    record.num(at);
    record.text(principal);
    let (node_seq, hash) = journal.seal_policy(record.finish(), at)?;
    answer(&serde_json::json!({
        "committed": version,
        "committed_at": at,
        "seq": node_seq,
        "hash": hex::encode(hash),
    }))
}

/// THE PRODUCTION PLANE LOOKUP: the registry's planes, filtered by Law 7 against the LIVE
/// configuration — read off the snapshot on every call, so a config apply that adds or removes a
/// plane section is what the next call sees.
#[must_use]
pub fn live_planes(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneLookup {
    Arc::new(move |key: &str| {
        let snapshot = app.load();
        busbar_kernel::plane::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key && snapshot.plane_configured(decl))
    })
}

/// THE PRODUCTION RECORD SINK: the live configuration's governance store, narrowed to the
/// plane-facing seam every plane persists through. A node with no store configured keeps nothing,
/// and says so (`Err`), rather than acknowledging a write that went nowhere.
#[must_use]
pub fn live_records(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneRecordSink {
    Arc::new(move |record: &PlaneRecord| {
        let snapshot = app.load();
        let gov = snapshot
            .governance
            .as_ref()
            .ok_or_else(|| "no record store is configured".to_string())?;
        busbar_kernel::plane::store::PlaneStoreView::narrow(gov.store())
            .upsert_plane_record(record)
            .map_err(|e| e.0)
    })
}
