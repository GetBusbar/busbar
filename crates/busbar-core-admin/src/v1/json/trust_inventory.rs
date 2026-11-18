// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST READ SURFACE (TRUST-ADMIN-PRODUCER-DESIGN r3 §3): the `core/trust` instance's
//! `state`, its `custody` health check and its four views, and the `GET /trust` body. One
//! projection of the serving kernel's trust book feeds both `GET /trust` and the
//! `subjects`/`items` views, so the two can never disagree. Everything is read through
//! [`TrustReadout`], which cannot decide; pin material (`DeclaredPin.key`) never reaches here.

use busbar_contract::json::{self, Value};
use busbar_kernel::trust::readout::{Custody, Kept, KeptDecision, PinFacts, SubjectFacts};
use busbar_kernel::trust::TrustReadout;
use serde::Serialize;

/// The frozen trust key state vocabulary (r3 §3.2). `trust_state_enum_is_frozen` pins it to
/// `KeyState::word` and to every schema that carries it.
pub const KEY_STATES: [&str; 5] = ["new", "approved", "same", "drifted", "quarantined"];

/// The four `core/trust` views (r5 §15.1), in descriptor order.
pub const VIEWS: [&str; 4] = ["subjects", "items", "decisions", "documents"];

/// One trust key, as `GET /trust` lists it and as the `subjects`/`items` views begin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TrustKeyRow {
    /// `<instance>/<counterparty>[/<item>]`: what `POST /trust/approve` and `/revoke` name.
    pub key: String,
    pub instance: String,
    pub counterparty: String,
    /// `null` on a counterparty row.
    pub item: Option<String>,
    #[cfg_attr(
        feature = "openapi-schema",
        schemars(extend("enum" = ["new", "approved", "same", "drifted", "quarantined"]))
    )]
    pub state: String,
    /// What it is approved at.
    pub approved: Option<String>,
    /// What it was last sighted at: the digest an operator reviews before deciding.
    pub seen: Option<String>,
}

/// `GET /trust`: every trust key, counterparty rows before their items. Unpaged (r3 §0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TrustListView {
    pub keys: Vec<TrustKeyRow>,
}

/// The `core/trust` `state` (r3 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TrustState {
    /// The trust registry generation, as a decimal string.
    pub generation: String,
    pub standing: TrustStanding,
    pub reverify: TrustReverify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TrustStanding {
    pub attached: bool,
    /// The trust registry generation standing re-checks compare against (equal to `generation`).
    pub snapshot_generation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct TrustReverify {
    /// The shortest re-verify TTL across counterparties; 0 when there are none.
    pub ttl_ms: u64,
    /// The longest recovery backoff across counterparties; 0 when there are none.
    pub recovery_backoff_ms: u64,
}

/// One `subjects` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct SubjectRow {
    #[serde(flatten)]
    pub key: TrustKeyRow,
    pub pin_mechanism: Option<String>,
    pub pin_root: Option<bool>,
    pub pin_peer_key: Option<bool>,
    pub pin_fingerprint: Option<String>,
    pub pending: bool,
    pub quarantined: bool,
    pub revoked: bool,
    pub confirmed: bool,
    pub demoted_items: u64,
    pub last_checked_ms: Option<u64>,
    pub last_drift_ms: Option<u64>,
    pub drift_observations: u64,
    pub ttl_ms: u64,
    pub recovery_backoff_ms: u64,
}

/// One `items` row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct ItemRow {
    #[serde(flatten)]
    pub key: TrustKeyRow,
    pub demoted: bool,
}

/// One `decisions` row: a kept ruling, a kernel demotion, or a kept quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct DecisionRow {
    pub key: String,
    /// `ruling`, `demotion` or `quarantine`.
    pub row_kind: String,
    pub instance: Option<String>,
    pub counterparty: String,
    pub item: Option<String>,
    /// `approved`, `revoked`, `demoted` or `quarantined`.
    pub decision: String,
    pub approved: Option<String>,
    pub pin_mechanism: Option<String>,
    pub pin_root: Option<bool>,
    pub pin_peer_key: Option<bool>,
    pub pin_fingerprint: Option<String>,
    /// `principal`, `instance` or `kernel`; `null` for a row kept before the field existed.
    pub decided_by_kind: Option<String>,
    pub decided_by: Option<String>,
    pub via_instance: Option<String>,
    pub decided_ms: Option<u64>,
    /// The deciding request's `Idempotency-Key`.
    pub operation: Option<String>,
    pub reason: Option<String>,
}

/// Why a trust read could not be answered: the view or body is unavailable (r3 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

const NOT_INSTALLED: &str = "native trust custody is not installed";

/// One trust key as `GET /trust` and the `subjects`/`items` views carry it (the one projection).
#[must_use]
pub fn key_row(row: &busbar_kernel::trust::book::KeyRow) -> TrustKeyRow {
    TrustKeyRow {
        key: row.key(),
        instance: row.instance.clone(),
        counterparty: row.counterparty.clone(),
        item: row.item.clone(),
        state: row.state.word().to_string(),
        approved: row.approved.clone(),
        seen: row.seen.clone(),
    }
}

/// THE ONE PROJECTION (r3 §3.1): every trust key, as `GET /trust` and the views carry it.
#[must_use]
fn key_rows(readout: &TrustReadout) -> Vec<TrustKeyRow> {
    readout.rows().iter().map(key_row).collect()
}

/// The `GET /trust` body, for the root's `GetTrust` arm (its one serving point, r3 §3.1).
/// `Err` when no native trust custody is installed: never an empty success.
pub fn trust_list_body(readout: Option<&TrustReadout>) -> Result<Vec<u8>, Unavailable> {
    let readout = readout.ok_or_else(|| Unavailable(NOT_INSTALLED.into()))?;
    json::to_vec(&TrustListView {
        keys: key_rows(readout),
    })
    .map_err(|why| Unavailable(format!("the trust list could not be encoded: {why}")))
}

/// The `core/trust` `state` (r3 §3.4); `null` when no custody is installed.
#[must_use]
pub fn state(readout: Option<&TrustReadout>) -> Value {
    let Some(readout) = readout else {
        return Value::new_null();
    };
    let subjects = readout.subjects();
    let generation = busbar_kernel::trust::validate::live_generation().to_string();
    let state = TrustState {
        standing: TrustStanding {
            attached: readout.standing_attached(),
            snapshot_generation: generation.clone(),
        },
        generation,
        reverify: TrustReverify {
            ttl_ms: subjects.iter().map(|s| s.policy.ttl_ms).min().unwrap_or(0),
            recovery_backoff_ms: subjects
                .iter()
                .map(|s| s.policy.recovery_backoff_ms)
                .max()
                .unwrap_or(0),
        },
    };
    json::to_value(&state).unwrap_or_else(|_| Value::new_null())
}

/// The `core/trust` `custody` health check: `(status, detail)` (r3 §6).
#[must_use]
pub fn custody(readout: Option<&TrustReadout>) -> (&'static str, &'static str) {
    match readout.map(TrustReadout::custody) {
        None => ("failed", NOT_INSTALLED),
        Some(Custody::Unbound) => ("failed", "trust decisions cannot be kept"),
        Some(Custody::Bound) => ("ok", "trust decisions are kept durably"),
    }
}

fn field(name: &str, label: &str, kind: &str, unit: Option<&str>, role: &str) -> Value {
    json::json!({
        "name": name,
        "label": label,
        "type": kind,
        "unit": unit,
        "format": null,
        "role": role,
    })
}

fn key_fields() -> Vec<Value> {
    vec![
        field("key", "Key", "string", None, "id"),
        field("instance", "Instance", "string", None, "dimension"),
        field("counterparty", "Counterparty", "string", None, "dimension"),
        field("item", "Item", "string", None, "dimension"),
        field("state", "State", "string", None, "dimension"),
        field("approved", "Approved at", "string", None, "dimension"),
        field("seen", "Last sighted at", "string", None, "dimension"),
    ]
}

fn pin_fields() -> Vec<Value> {
    vec![
        field(
            "pin_mechanism",
            "Pin mechanism",
            "string",
            None,
            "dimension",
        ),
        field("pin_root", "Pin is a root", "bool", None, "status"),
        field(
            "pin_peer_key",
            "Pin is the peer key",
            "bool",
            None,
            "status",
        ),
        field(
            "pin_fingerprint",
            "Pin fingerprint",
            "string",
            None,
            "dimension",
        ),
    ]
}

fn table(view: &str, title: &str, fields: Vec<Value>) -> Value {
    json::json!({
        "view": view,
        "title": title,
        "shape": "table",
        "fields": fields,
        "default_sort": "key",
        "filters": ["instance", "counterparty", "state"],
        "time": null,
        "step_options": [],
    })
}

/// The four `core/trust` view descriptors (r3 §3.4), whose `fields` name exactly the members of
/// [`SubjectRow`], [`ItemRow`], [`DecisionRow`] and the documents row.
#[must_use]
pub fn descriptors() -> Vec<Value> {
    let mut subjects = key_fields();
    subjects.extend(pin_fields());
    subjects.extend([
        field("pending", "Pending", "bool", None, "status"),
        field("quarantined", "Quarantined", "bool", None, "status"),
        field("revoked", "Revoked", "bool", None, "status"),
        field("confirmed", "Confirmed", "bool", None, "status"),
        field(
            "demoted_items",
            "Demoted items",
            "int",
            Some("count"),
            "measure",
        ),
        field("last_checked_ms", "Last checked", "time", None, "time"),
        field("last_drift_ms", "Last drift", "time", None, "time"),
        field(
            "drift_observations",
            "Drift observations",
            "int",
            Some("count"),
            "measure",
        ),
        field("ttl_ms", "Re-verify TTL", "int", Some("ms"), "measure"),
        field(
            "recovery_backoff_ms",
            "Recovery backoff",
            "int",
            Some("ms"),
            "measure",
        ),
    ]);
    let mut items = key_fields();
    items.push(field("demoted", "Demoted", "bool", None, "status"));
    let mut decisions = vec![
        field("key", "Key", "string", None, "id"),
        field("row_kind", "Kind", "string", None, "dimension"),
        field("instance", "Instance", "string", None, "dimension"),
        field("counterparty", "Counterparty", "string", None, "dimension"),
        field("item", "Item", "string", None, "dimension"),
        field("decision", "Decision", "string", None, "dimension"),
        field("approved", "Approved at", "string", None, "dimension"),
    ];
    decisions.extend(pin_fields());
    decisions.extend([
        field(
            "decided_by_kind",
            "Decided by kind",
            "string",
            None,
            "dimension",
        ),
        field("decided_by", "Decided by", "string", None, "dimension"),
        field("via_instance", "Via instance", "string", None, "dimension"),
        field("decided_ms", "Decided at", "time", None, "time"),
        field("operation", "Operation", "string", None, "dimension"),
        field("reason", "Reason", "string", None, "dimension"),
    ]);
    let documents = vec![
        field("key", "Key", "string", None, "id"),
        field("instance", "Instance", "string", None, "dimension"),
        field("counterparty", "Counterparty", "string", None, "dimension"),
        field("item", "Item", "string", None, "dimension"),
        field("digest", "Digest", "string", None, "dimension"),
        field("bytes", "Size", "int", Some("bytes"), "measure"),
        field("document", "Document", "string", None, "dimension"),
    ];
    vec![
        table("subjects", "Counterparties", subjects),
        table("items", "Items at counterparties", items),
        table("decisions", "Trust decisions", decisions),
        table("documents", "Item documents", documents),
    ]
}

fn pin_members(
    pin: Option<&PinFacts>,
) -> (Option<String>, Option<bool>, Option<bool>, Option<String>) {
    pin.map_or((None, None, None, None), |p| {
        (
            Some(p.mechanism.clone()),
            Some(p.root),
            Some(p.peer_key),
            p.fingerprint.clone(),
        )
    })
}

fn subject_row(s: &SubjectFacts) -> SubjectRow {
    let (pin_mechanism, pin_root, pin_peer_key, pin_fingerprint) = pin_members(s.pin.as_ref());
    SubjectRow {
        key: key_row(&s.row),
        pin_mechanism,
        pin_root,
        pin_peer_key,
        pin_fingerprint,
        pending: s.pending,
        quarantined: s.quarantined,
        revoked: s.revoked,
        confirmed: s.confirmed,
        demoted_items: u64::try_from(s.demoted.len()).unwrap_or(u64::MAX),
        last_checked_ms: s.ledger.last_checked_ms,
        last_drift_ms: s.ledger.last_drift_ms,
        drift_observations: s.ledger.drift_observations,
        ttl_ms: s.policy.ttl_ms,
        recovery_backoff_ms: s.policy.recovery_backoff_ms,
    }
}

fn decision_row(d: &KeptDecision) -> DecisionRow {
    use busbar_kernel::trust::book::DecidedBy;
    let (pin_mechanism, pin_root, pin_peer_key, pin_fingerprint) = pin_members(d.pin.as_ref());
    let (decided_by_kind, decided_by, via_instance) = match &d.decided_by {
        None => (None, None, None),
        Some(DecidedBy::Principal { id }) => (Some("principal"), Some(id.clone()), None),
        Some(DecidedBy::Instance {
            instance,
            principal,
        }) => (
            Some("instance"),
            Some(principal.clone()),
            Some(instance.clone()),
        ),
        Some(DecidedBy::Kernel) => (Some("kernel"), None, None),
    };
    let key = match &d.item {
        Some(item) => format!("{}/{}/{item}", d.instance, d.counterparty),
        None => format!("{}/{}", d.instance, d.counterparty),
    };
    DecisionRow {
        key,
        row_kind: if d.demoted { "demotion" } else { "ruling" }.to_string(),
        instance: Some(d.instance.clone()),
        counterparty: d.counterparty.clone(),
        item: d.item.clone(),
        decision: match (d.demoted, d.approved.is_some()) {
            (true, _) => "demoted",
            (false, true) => "approved",
            (false, false) => "revoked",
        }
        .to_string(),
        approved: d.approved.clone(),
        pin_mechanism,
        pin_root,
        pin_peer_key,
        pin_fingerprint,
        decided_by_kind: decided_by_kind.map(str::to_string),
        decided_by,
        via_instance,
        decided_ms: d.decided_at.map(|at| at.saturating_mul(1000)),
        operation: d.operation.clone(),
        reason: None,
    }
}

/// A kept quarantine row. `upstream` is `instance␟counterparty`, or a bare counterparty of the
/// configured default demotion instance (host_services `demotion_key`).
fn quarantine_row(q: &busbar_kernel::trust::DemotionRow) -> DecisionRow {
    let (instance, counterparty) = match q
        .upstream
        .split_once(busbar_kernel::host_services::DEMOTION_SEP)
    {
        Some((instance, counterparty)) => (Some(instance.to_string()), counterparty.to_string()),
        None => (None, q.upstream.clone()),
    };
    let key = match &instance {
        Some(instance) => format!("{instance}/{counterparty}"),
        None => counterparty.clone(),
    };
    DecisionRow {
        key,
        row_kind: "quarantine".to_string(),
        instance,
        counterparty,
        item: None,
        decision: "quarantined".to_string(),
        approved: None,
        pin_mechanism: None,
        pin_root: None,
        pin_peer_key: None,
        pin_fingerprint: None,
        decided_by_kind: Some("kernel".to_string()),
        decided_by: None,
        via_instance: None,
        decided_ms: Some(q.recorded_at.saturating_mul(1000)),
        operation: None,
        reason: Some(q.reason.clone()),
    }
}

fn values<T: Serialize>(rows: &[T]) -> Result<Vec<Value>, Unavailable> {
    rows.iter()
        .map(|row| {
            json::to_value(row)
                .map_err(|why| Unavailable(format!("a row could not be encoded: {why}")))
        })
        .collect()
}

/// The source rows of one `core/trust` view (r3 §3.4–§3.5). `None` for a view this instance does
/// not have; `Some(Err)` when the view is unavailable (no custody, unbound record, or `documents`
/// before MIN-3 M3-4).
pub async fn rows(
    readout: Option<&TrustReadout>,
    view: &str,
) -> Option<Result<Vec<Value>, Unavailable>> {
    if !VIEWS.contains(&view) {
        return None;
    }
    let Some(readout) = readout else {
        return Some(Err(Unavailable(NOT_INSTALLED.into())));
    };
    Some(match view {
        "subjects" => values(
            &readout
                .subjects()
                .iter()
                .map(subject_row)
                .collect::<Vec<_>>(),
        ),
        "items" => {
            let demoted: std::collections::BTreeSet<(String, String, String)> = readout
                .subjects()
                .into_iter()
                .flat_map(|s| {
                    let (instance, counterparty) = (s.row.instance.clone(), s.row.counterparty);
                    s.demoted
                        .into_iter()
                        .map(move |item| (instance.clone(), counterparty.clone(), item))
                })
                .collect();
            values(
                &readout
                    .rows()
                    .iter()
                    .filter_map(|row| {
                        let item = row.item.clone()?;
                        Some(ItemRow {
                            demoted: demoted.contains(&(
                                row.instance.clone(),
                                row.counterparty.clone(),
                                item,
                            )),
                            key: key_row(row),
                        })
                    })
                    .collect::<Vec<_>>(),
            )
        }
        "decisions" => match readout.kept_decisions().await {
            Ok(Kept {
                decisions,
                quarantines,
            }) => values(
                &decisions
                    .iter()
                    .map(decision_row)
                    .chain(quarantines.iter().map(quarantine_row))
                    .collect::<Vec<_>>(),
            ),
            Err(why) => Err(Unavailable(why.0)),
        },
        _ => Err(Unavailable(
            "item documents arrive with MIN-3 M3-4 (SIGHT TR_ITEM_DOC)".into(),
        )),
    })
}

#[cfg(test)]
#[path = "tests/trust_inventory_tests.rs"]
mod tests;
