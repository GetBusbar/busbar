// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE FOUR 1.6.0 ADMIN VERBS OWNER ANSWER Q71(2) BINDS**: `verify`, `plane_facts`,
//! `plane_record_write` and `commit_upgrade` — additive, `x-busbar-since 1.6.0`, the same shape as
//! the core admin verbs of Q56. Every one is admitted by the verbs unit before it reaches this file
//! (scope, then rate class: a plain scoped verb, #77(9) OWNER-LOCKED), so each effect here speaks
//! only to its own body and its own effect.
//!
//! * `GET /api/v1/admin/verify` — [`verify_effect`]: everything that has to be true of what the node
//!   holds — every count of the one ledger priceable at the card, the journal read back clean at
//!   boot, the amendment and audit chains as held, and every chain the store keeps. A failed
//!   verification is still a `200`: the verb answers the question it was asked, and `ok` says the
//!   answer.
//! * `GET /api/v1/admin/plane-facts?plane=<key>` — [`plane_facts_effect`]: what a plane this node
//!   serves declares about itself (its contract `PlaneDeclaration`), read off the registry. A plane
//!   this node does not serve is `404` — the same Law-7 answer its admin paths give.
//! * `POST /api/v1/admin/plane-record-write` — [`plane_record_write_effect`]: one upsert of a plane
//!   record into the named plane's own rows (keyed by the plane), through the plane-facing store
//!   seam; never onto a row the kernel keeps.
//! * `POST /api/v1/admin/commit-upgrade` — [`commit_upgrade_effect`]: seal, on the node's journal as
//!   a `Policy` record, that the fleet commits to the release THIS binary is. The body names the
//!   release; one this binary is not is refused, so a commit can never name a version nobody runs.

use std::sync::Arc;

use busbar_contract::plane::PlaneDeclaration;
use busbar_contract::records::{PlaneDisposition, PlaneRecord};
use busbar_core_admin::GovernanceError;
use busbar_kernel::host_services::{KernelServices, TrustRefused};
use busbar_kernel::trust::book::{KeyRow, Ruling};

use super::{AdminAnswer, AmendmentJournal, AuditView, LedgerView};

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
/// (`busbar_kernel::store::plane_view::PlaneStore::upsert_plane_record`). `Err` carries the store's own
/// words, for the node's log only.
pub type PlaneRecordSink = Arc<dyn Fn(&PlaneRecord) -> Result<(), String> + Send + Sync>;

/// The kernel's host services, whose trust book the three trust verbs read and decide over
/// (ARCHITECT 2026-10-06): `None` until the root composed them, and on a node that composed none —
/// which then has no trust keys, lists none and answers every key `404`.
pub type TrustDesk = Arc<dyn Fn() -> Option<Arc<KernelServices>> + Send + Sync>;

/// The desk of a node no root bound the kernel's services to: no trust keys.
#[must_use]
pub fn no_trust() -> TrustDesk {
    Arc::new(|| None)
}

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

/// A durable verb the store has not acknowledged: `503` with the reason (ARCHITECT 2026-10-07 H3
/// ruling (d)). A refusal the previous release never answered: it kept no journal.
pub(crate) fn journal_unavailable(why: &str) -> AdminAnswer {
    refused(503, "service_unavailable", why)
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
/// THE ONE LEDGER is the store's usage counts, priced by the card in core: there is no second book
/// to measure against a checkpoint, so `checkpoints` is 0, `since` is null and `book_verified` is
/// false, as on a node that never sealed one. The identity holds when every count is priceable; a
/// row the card refuses (#42) is a finding naming it, and every other check still runs. The journal
/// (what the boot could not read back, the amendment chain, the audit chain, every chain the store
/// keeps) is verified as before, through `audit`.
pub(crate) fn verify_effect(
    ledger: &dyn LedgerView,
    audit: Option<&dyn AuditView>,
) -> Result<AdminAnswer, GovernanceError> {
    let priced = ledger.priced().map_err(|why| {
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
    // WHAT THE BOOT COULD NOT READ BACK of the journal: a quarantined segment, a record that does
    // not decode, an amendment that does not link. The boot logs it and serves on, and this is
    // where an operator asking reads it.
    if let Some(audit) = audit {
        findings.extend(
            audit
                .restart_findings()
                .into_iter()
                .map(|finding| format!("restart: {finding}")),
        );
    }
    // THE AMENDMENT CHAIN, verified as it is held now: an edit made to the node's held content
    // accesses after boot is a finding.
    if let Err(broken) = crate::root::durability::verify_held() {
        findings.push(format!("amendment chain: {broken}"));
    }
    if let Some(audit) = audit {
        // THE FIXED AUDIT CHAIN, walked as it is held now: a retained record edited, relinked or
        // re-signed after it was sealed is a finding.
        findings.extend(
            audit
                .retained_audit_findings()
                .into_iter()
                .map(|finding| format!("audit chain: {finding}")),
        );
        // EVERY CHAIN THE STORE KEEPS, this node's and its peers', walked and verified against the
        // deployment keyset.
        findings.extend(
            audit
                .stored_chain_findings()
                .into_iter()
                .map(|finding| format!("stored chain: {finding}")),
        );
    }
    answer(&serde_json::json!({
        "checkpoints": 0,
        "since": null,
        "book_verified": false,
        "findings": findings,
        "identity_holds": identity_holds,
        "discrepancies": 0,
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
        "record_kinds": decl.record_kinds,
    }))
}

/// `POST /api/v1/admin/plane-record-write` — upsert one record of a plane this node serves.
///
/// The body is `{ "plane": "<key>", "kind": "…", "id": "…", "parent": "…"|null, "terminal": bool,
/// "body": <json> }`. `body` is the record's opaque row, stored as its JSON bytes and never decoded
/// by the store; `terminal` (default `false`) is the retention disposition. `written_at` is the
/// arrival second, pinned by the unit.
///
/// The record lands in the NAMED PLANE'S OWN ROWS, under the store kind
/// [`busbar_kernel::store::plane_view::plane_owned_kind`] keys by the plane; the answer names the
/// kind as written. A kind the kernel keeps its own rows under
/// ([`busbar_kernel::store::plane_view::KERNEL_RECORD_KINDS`]) is refused `403` even where the plane
/// declares it, writing nothing (`BUSBAR-7107`).
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
    let Some(decl) = planes(plane) else {
        return Ok(refused(
            404,
            "not_found",
            &format!("plane `{plane}` not found"),
        ));
    };
    // The plane's own declaration is the verdict (ARCHITECT RULING (b)): a record lands only under
    // a kind the named plane declares it keeps, never under another plane's kind or one nobody reads.
    if !busbar_contract::plane::declares_record_kind(&decl, kind) {
        return Ok(refused(
            403,
            "forbidden",
            &format!("plane `{plane}` may not write record kind `{kind}`"),
        ));
    }
    // THE KERNEL'S OWN ROWS ARE NEVER A PLANE'S, declared or not: plane-mcp declares `demotion`,
    // and the rows under it are the kernel's durable demotion record, which a write in the plane's
    // name must not alter (a demoted upstream would re-open). Refused by name, writing nothing; the
    // unit seals the refusal on the audit ring as `rejected`.
    if busbar_kernel::store::plane_view::KERNEL_RECORD_KINDS.contains(&kind) {
        busbar_kernel::diagnostics::diag_warn!(
            busbar_kernel::diagnostics::PLANE_RECORD_WRITE_KERNEL_KIND,
            plane = %plane,
            kind = %kind,
            "an admin plane record write named a record kind the kernel keeps its own records \
             under: refused, nothing written"
        );
        return Ok(refused(
            403,
            "forbidden",
            &format!(
                "record kind `{kind}` is kept by the kernel: plane `{plane}` may not write it"
            ),
        ));
    }
    // THE PLANE'S OWN ROWS, keyed by the plane: two planes declaring one kind never land on (or
    // read) each other's rows, and no plane's row is a kernel kind's.
    let Some(owned) = busbar_kernel::store::plane_view::plane_owned_kind(plane, kind) else {
        return Ok(refused(
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
        body: serde_json::to_vec(row).map_err(|_| GovernanceError::Validation)?,
    };
    sink(&record).map_err(|_| GovernanceError::Store)?;
    answer(&serde_json::json!({
        "plane": plane,
        "kind": kind,
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
/// a commit nothing recorded did not happen. Where the store keeps the journal, the commit answers
/// only once the store acknowledged its record, and `503` with the reason otherwise.
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
    if let Err(why) = journal.admit() {
        return Ok(journal_unavailable(&why));
    }
    let mut record = busbar_kernel_wal::BodyWriter::new();
    record.text(COMMIT_UPGRADE_RECORD_TAG);
    record.text(version);
    record.num(at);
    record.text(principal);
    let (node_seq, hash) = journal.seal_policy(record.finish(), at)?;
    if let Err(why) = journal.acked(node_seq) {
        return Ok(journal_unavailable(&format!(
            "the commit is sealed at journal position {node_seq} and not yet kept by the store: \
             {why}; do not re-submit"
        )));
    }
    answer(&serde_json::json!({
        "committed": version,
        "committed_at": at,
        "seq": node_seq,
        "hash": hex::encode(hash),
    }))
}

/// One trust key's row as the trust verbs write it.
fn trust_row(row: &KeyRow) -> serde_json::Value {
    serde_json::json!({
        "key": row.key(),
        "instance": row.instance,
        "counterparty": row.counterparty,
        "item": row.item,
        "state": row.state.word(),
        "approved": row.approved,
        "seen": row.seen,
    })
}

/// `GET /api/v1/admin/trust` — every trust key of the kernel's trust book and its state. A read.
pub(crate) fn trust_list_effect(desk: &TrustDesk) -> Result<AdminAnswer, GovernanceError> {
    let rows = desk().map(|k| k.trust_rows()).unwrap_or_default();
    answer(&serde_json::json!({
        "keys": rows.iter().map(trust_row).collect::<Vec<_>>(),
    }))
}

/// `POST /api/v1/admin/trust/approve` and `/revoke` — the operator's decision about one trust key,
/// `{ "key": "<instance>/<counterparty>[/<item>]" }`, made on the kernel's trust book and kept
/// durably. Idempotent: the same key twice answers the same row. An unknown key is `404`; an
/// approval with nothing ever sighted to approve at is `409`; a decision the store could not keep is
/// `Store` (`503`).
pub(crate) fn trust_decide_effect(
    body: &[u8],
    ruling: Ruling,
    desk: &TrustDesk,
) -> Result<AdminAnswer, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let Some(key) = obj
        .get("key")
        .and_then(serde_json::Value::as_str)
        .filter(|k| !k.trim().is_empty())
    else {
        return Ok(refused(400, "invalid_request", "key is required"));
    };
    let not_found = || {
        Ok(refused(
            404,
            "not_found",
            &format!("trust key `{key}` not found"),
        ))
    };
    let Some(kernel) = desk() else {
        return not_found();
    };
    match kernel.trust_rule(key, ruling) {
        Ok(row) => answer(&trust_row(&row)),
        Err(TrustRefused::NoSuchKey) => not_found(),
        Err(TrustRefused::NothingSighted) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` was never sighted"),
        )),
        // The core-admin verbs state no expected fingerprint, so a stale one is never theirs.
        Err(TrustRefused::Stale) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` moved since it was seen"),
        )),
        Err(TrustRefused::Rootless) => Ok(refused(
            409,
            "conflict",
            &format!("trust key `{key}` has no authenticity root"),
        )),
        Err(TrustRefused::Store(why)) => {
            tracing::error!(key = %key, error = %why, "a trust ruling could not be kept");
            Err(GovernanceError::Store)
        }
    }
}

/// THE PRODUCTION PLANE LOOKUP: the registry's planes, filtered by Law 7 against the LIVE
/// configuration — read off the snapshot on every call, so a config apply that adds or removes a
/// plane section is what the next call sees.
#[must_use]
pub fn live_planes(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneLookup {
    Arc::new(move |key: &str| {
        let snapshot = app.load();
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .map(|decl| decl.declaration)
            .find(|decl| decl.key == key && snapshot.plane_configured(decl))
    })
}

/// THE PRODUCTION ADMIN DOOR: the request judged on the LIVE snapshot's admin chain, through the
/// kernel's own verdict — the chain the kernel middleware reads and a
/// `PUT /api/v1/admin/admin-auth` swaps, read per call, so the swap is the next unit's door. The
/// operator credential reads the request's head through its door, on the spot.
#[must_use]
pub fn live_admin_door(app: Arc<busbar_kernel::state::AppHandle>) -> super::AdminDoorFn {
    Arc::new(move |request: &super::AdminRequest| {
        let headers: axum::http::HeaderMap = (request.headers.iter())
            .filter_map(|(name, value)| Some((name.parse().ok()?, value.parse().ok()?)))
            .collect();
        let snapshot = app.snapshot();
        busbar_kernel::auth::admin_door(&snapshot, &request.method, &request.path, &headers)
    })
}

/// THE PRODUCTION RECORD SINK: the live configuration's governance store, written through its v3
/// `upsert_plane_record`. A node with no store configured keeps nothing, and says so (`Err`),
/// rather than acknowledging a write that went nowhere. The sink is synchronous and the admin unit
/// that calls it answers on the blocking pool, so the store call is awaited here, on that thread:
/// the sink's one wait.
#[must_use]
pub fn live_records(app: Arc<busbar_kernel::state::AppHandle>) -> PlaneRecordSink {
    Arc::new(move |record: &PlaneRecord| {
        let snapshot = app.load();
        let calls = snapshot
            .governance
            .as_ref()
            .and_then(|gov| gov.store_calls())
            .ok_or_else(|| "no record store is configured".to_string())?;
        crate::root::durability::off_runtime(|| {
            crate::root::durability::wait_for(calls.upsert_plane_record(record.view()))
        })
        .map_err(|e| e.to_string())
    })
}

/// THE REPLAY CACHE the two Q71(2) writes share (contract D-3): per `(actor, "<verb>:<key>")`, the
/// SHA-256 of the body the first call carried and the answer it produced.
pub type ReplayCache = busbar_core_admin::idempotency::IdempotencyCache<([u8; 32], AdminAnswer)>;

/// The configured store a key is claimed in, read when the claim is taken.
pub type ReplayStore =
    Arc<dyn Fn() -> Option<Arc<dyn busbar_contract::records::RecordStore>> + Send + Sync>;

/// THE PRODUCTION REPLAY STORE: the live configuration's governance store.
#[must_use]
pub fn live_replay_store(app: Arc<busbar_kernel::state::AppHandle>) -> ReplayStore {
    Arc::new(move || app.load().governance.as_ref().map(|gov| gov.store()))
}

/// A first answer as the store keeps it: the body's digest, then the whole answer — status, every
/// header in emission order, body — length-prefixed, so a header value or a body may hold any byte
/// and come back identical. The store boundary is the only place an answer is bytes.
fn stored_answer(digest: &[u8; 32], answer: &AdminAnswer) -> Vec<u8> {
    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&bytes[..len as usize]);
    }
    let mut out = Vec::with_capacity(32 + 6 + answer.body.len() + 64);
    out.extend_from_slice(digest);
    out.extend_from_slice(&answer.status.to_be_bytes());
    let count = u32::try_from(answer.headers.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in answer.headers.iter().take(count as usize) {
        push(&mut out, name.as_bytes());
        push(&mut out, value.as_bytes());
    }
    push(&mut out, &answer.body);
    out
}

/// What [`stored_answer`] wrote, read back: the first body's digest and the first answer. `None`
/// on anything that is not exactly that framing. The header count is a claim the bytes make about
/// themselves, so nothing is reserved on it: each header is read off the bytes actually held.
fn kept_answer(kept: &[u8]) -> Option<([u8; 32], AdminAnswer)> {
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
    if cursor != kept.len() {
        return None;
    }
    Some((
        digest,
        AdminAnswer {
            status,
            headers,
            body,
        },
    ))
}

/// The request header carrying the client-chosen idempotency token (names arrive lowercased).
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Run a write under contract D-3's `Idempotency-Key` replay — the same cache, TTL, in-flight
/// sentinel and per-principal key scoping the key mint and rotate use.
///
/// No header: the effect runs, nothing is reserved. First sighting: the effect runs, and a `2xx`
/// answer is committed under the key (a refusal clears the reservation, so a corrected retry runs).
/// A replay with the SAME body answers the committed bytes verbatim and runs nothing; the same key
/// with a DIFFERENT body is `409 conflict`, and a key whose first call is still running is the
/// existing `409 conflict` "a request with this Idempotency-Key is already in flight".
pub(crate) fn replayable(
    cache: &ReplayCache,
    store: Option<&ReplayStore>,
    verb: busbar_core_admin::KernelVerb,
    actor: &str,
    unit: &super::AdminRequest,
    body: &[u8],
    effect: impl FnOnce() -> Result<AdminAnswer, GovernanceError>,
) -> Result<AdminAnswer, GovernanceError> {
    use busbar_core_admin::idempotency::Probe;

    let Some(header) = unit
        .headers
        .iter()
        .find(|(name, _)| name == IDEMPOTENCY_KEY_HEADER)
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
    else {
        return effect();
    };
    let name = busbar_core_admin::verb_name(verb).unwrap_or_default();
    let digest: [u8; 32] = busbar_contract::abi::sdk::digest::sha256(body);
    // Scoped to the resolved PRINCIPAL, as the key mint's is: two principals sharing a key value
    // never replay each other's answer.
    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};

    let other_body = || {
        Ok(refused(
            409,
            "conflict",
            "this Idempotency-Key was already used with a different request body",
        ))
    };
    let in_flight = || {
        Ok(refused(
            409,
            "conflict",
            "a request with this Idempotency-Key is already in flight",
        ))
    };
    match cache.probe((actor.to_string(), format!("{name}:{header}")), unit.at) {
        Probe::Replay((first, answer)) if first == digest => Ok(answer),
        Probe::Replay(_) => other_body(),
        Probe::InFlight => in_flight(),
        Probe::NoKey => effect(),
        Probe::Reserved(reservation) => {
            // Claimed in the store before the effect runs, so a retry after a restart or on another
            // node replays the first answer or is refused: it never runs the effect again.
            let store = store.and_then(|store| store());
            let claim = match &store {
                Some(store) => match durable::claim(&**store, reservation.key(), unit.at) {
                    Ok(claim) => Some(claim),
                    Err(Refused::Answer(kept)) => {
                        // The first answer, whole and byte for byte — status, headers and body: a
                        // re-render would mint a second one-time secret over one identity.
                        return match kept_answer(&kept) {
                            Some((first, answer)) if first == digest => Ok(answer),
                            Some(_) => other_body(),
                            None => {
                                tracing::error!("the store keeps an Idempotency-Key's first answer in a form this node cannot read");
                                Ok(journal_unavailable(
                                    "the first answer to this Idempotency-Key cannot be read back; nothing was done",
                                ))
                            }
                        };
                    }
                    Err(Refused::Unavailable(why)) => {
                        tracing::error!(reason = %why, "an Idempotency-Key could not be claimed in the store");
                        return Ok(journal_unavailable(
                            "the store could not record this Idempotency-Key; nothing was done",
                        ));
                    }
                    Err(Refused::InFlight | Refused::Applied(_)) => {
                        return in_flight();
                    }
                },
                None => None,
            };
            let (answer, settled) = match effect() {
                Ok(answer) if (200..300).contains(&answer.status) => {
                    let settled = Settled::Answer(stored_answer(&digest, &answer));
                    reservation.commit((digest, answer.clone()), unit.at);
                    (Ok(answer), settled)
                }
                other => {
                    reservation.clear();
                    (other, Settled::Released)
                }
            };
            if let (Some(store), Some(claim)) = (&store, &claim) {
                if let Err(why) = durable::settle(&**store, claim, unit.at, &settled) {
                    tracing::error!(reason = %why, "the store did not keep an Idempotency-Key's outcome; a retry is refused as in flight until the claim lapses");
                }
            }
            answer
        }
    }
}

#[cfg(test)]
#[path = "tests/bound_tests.rs"]
mod bound_tests;
