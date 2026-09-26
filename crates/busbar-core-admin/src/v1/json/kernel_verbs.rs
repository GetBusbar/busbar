// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.6.0 KERNEL VERBS, IN THE ONE DOCUMENT.
//!
//! The closed verb table (`admin_codec::verbs`) declares 17 operations 1.6.0 adds to the
//! administrative surface: the 9 money-governance verbs ([`NEW_VERBS`]), the five ledger views
//! ([`LEDGER_VERBS`]) and the three audit-chain reads ([`AUDIT_VERBS`]). The router in this crate
//! mounts none of them. The node's administrative mount walks every row the table declares whose
//! effect is bound through the kernel loop, and it is the composition root's route step that answers them — the ledger and
//! audit reads render from the node's own book and chain, `adjust` and `amend_rate_history` land on
//! the node's amendment journal, and the three disaster-recovery verbs land on the store.
//!
//! They used to be described nowhere, or in a side-car document kept beside the served one so the
//! served bytes need not move. This module is what put them in the one generated document instead:
//! [`operations`] iterates the three verb lists and the table's own `(method, path)` rows, so the
//! document cannot describe a verb the table does not declare and cannot miss one it does. Each
//! verb's contract below is what the root's code does — its request shape, its success body and
//! the statuses its refusals map to (`units_admin::answer_for`) — never what a design once intended.
//!
//! A NEW VERB WITH NO EFFECT BOUND IN THIS BUILD (`crate::verb::effect_bound`) is not served — the
//! node's mount hands it to the surface's own fallback, which answers the unmounted `404` — so this
//! document does not describe it either: [`operations`] asks the same one question the mount asks.
//! Since owner answer Q71(2) bound `verify`, `plane_facts`, `plane_record_write` and
//! `commit_upgrade`, every one of the nine is bound.

#[cfg(feature = "openapi-schema")]
use crate::admin_codec::verbs::ResolvedVerb;
#[cfg(feature = "openapi-schema")]
use crate::verb::{verb_name, KernelVerb, AUDIT_VERBS, LEDGER_VERBS, NEW_VERBS};
#[cfg(feature = "openapi-schema")]
use schemars::JsonSchema;
#[cfg(feature = "openapi-schema")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi-schema")]
use serde_json::{json, Value};
#[cfg(feature = "openapi-schema")]
use std::collections::BTreeMap;

/// The release that added every operation this module documents, stamped as `x-busbar-since`.
#[cfg(feature = "openapi-schema")]
pub(crate) const SINCE: &str = "1.6.0";

// ── the typed contracts (schema-only: never serialized at runtime) ──────────────────────────────
//
// Each mirrors, field for field, the JSON the composition root writes for the verb
// (`crates/busbar/src/root/units_admin`). The root renders those bodies by hand, byte-deterministic,
// so these are schema-only views in the same sense as `contract::schema`: the drift test keeps the
// document locked to them, and the root-leg tests pin the bodies they describe.

/// A money figure: a decimal integer carried as TEXT. The ledger keeps money in 128-bit integers and
/// JSON's number is a double, exact only to 2^53; a nano-unit total passes that on a busy day, and a
/// figure that silently lost its last digits would still look like money.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct Amount(#[schemars(regex(pattern = r"^-?[0-9]+$"))] String);

/// A 32-byte digest as 64 lower-case hex characters.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct Hash(#[schemars(regex(pattern = r"^[0-9a-f]{64}$"))] String);

/// `GET /ledger/totals`: what the ledger's lines come to, per bucket, day, lane and provider.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerTotals {
    /// The rows, in bucket, day, lane and provider order.
    rows: Vec<LedgerTotalsRow>,
}

/// One row of `GET /ledger/totals`. The row width is the reconciliation's, so a discrepancy found
/// on one endpoint is looked up on the other by the same four-part name.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerTotalsRow {
    /// Whose budget the usage was attributed to.
    bucket: String,
    /// The UTC-day bucket, as the unix second it opens at.
    day: u64,
    /// The serving lane's configured model name (empty where the node keeps no finer width).
    lane: String,
    /// The serving lane's provider (empty where the node keeps no finer width).
    provider: String,
    /// The summed priced amount of the row's lines in nano-units, each line priced against the
    /// rate card in force at its own arrival instant.
    priced_nanos: Amount,
    /// The same figure in micro-units: ONE truncating divide over the summed nano-units, never a
    /// sum of per-line divides.
    priced_micros: Amount,
    /// One per billable client request on this row.
    fee_count: u64,
}

/// `GET /ledger/checkpoints`: the sealed checkpoint figures, oldest first.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerCheckpoints {
    checkpoints: Vec<LedgerCheckpoint>,
}

/// One sealed checkpoint. `body_hash` is what an auditor re-derives independently;
/// `body_hash_verifies` is this node's own answer to the same question. A signature's presence is
/// reported and its bytes are not.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerCheckpoint {
    checkpoint_seq: u64,
    node: u64,
    /// When it was sealed, in whole seconds.
    wall: u64,
    backup_watermark: u64,
    store_seq_high_water: u64,
    body_hash: Hash,
    /// This node's own answer to whether the sealed body re-hashes to `body_hash`.
    body_hash_verifies: bool,
    /// Whether a signature is present. The signature's bytes are never served.
    signed: bool,
    heads: Vec<LedgerChainHead>,
    totals: Vec<LedgerTotalsCell>,
}

/// One node's journal head, as a checkpoint sealed it.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerChainHead {
    node: u64,
    node_seq: u64,
    hash: Hash,
}

/// One sealed balance, as the checkpoint holds it. Every money figure is an [`Amount`].
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerTotalsCell {
    bucket: String,
    dimension: String,
    scope: String,
    /// The window's opening instant, in whole seconds.
    window: u64,
    budget: Amount,
    drawn: Amount,
    released: Amount,
    settled: Amount,
    open_holds: Amount,
    open_slice_remainders: Amount,
    adjustments: Amount,
    unreconciled: Amount,
    overdraft_carried_in: Amount,
    overdraft_carried_out: Amount,
    cross_window_transfers: Amount,
    disputed: Amount,
    oldest_open_hold_age_secs: u64,
    open_dispute_count: u64,
    oldest_dispute_age_secs: u64,
}

/// `GET /ledger/reconciliation`: whether the ledger's postings reconcile with the previous
/// release's rows, and every row on which they do not.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerReconciliation {
    /// True when every row reconciles. `discrepancies` is then empty.
    holds: bool,
    discrepancies: Vec<LedgerDiscrepancy>,
}

/// One row on which the identity does not hold. Spend and fee count are checked separately
/// because they fail separately.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerDiscrepancy {
    bucket: String,
    day: u64,
    lane: String,
    provider: String,
    residual: LedgerResidual,
    /// What the ledger's postings charged fees for on this row.
    ledger_fee_count: u64,
    /// What the previous release's row says was billable.
    legacy_billable_requests: u64,
}

/// The spend residual of one row.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerResidual {
    /// Where the value the ledger drew is now.
    accounted: Amount,
    /// What the previous release's row records as taken.
    drawn: Amount,
    /// `accounted` minus `drawn`. Zero is the good answer; the sign says which side is missing the
    /// difference.
    amount: Amount,
}

/// `GET /ledger/migration`: whether this deployment has migrated, and the marker if it has.
/// `migrated` is a field of its own rather than inferred from a null marker.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerMigration {
    migrated: bool,
    marker: Option<LedgerMigrationMarker>,
}

/// The marker the first boot after the upgrade sealed.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct LedgerMigrationMarker {
    /// The checkpoint the migration sealed.
    checkpoint_seq: u64,
    /// Which node sealed it.
    node: u64,
    /// When, in whole seconds.
    sealed_at: u64,
    body_hash: Hash,
    /// How many balances the opening carries.
    balances: u64,
    /// How many of the previous release's cells were read to arrive at them.
    cells_read: u64,
    /// Which card version the opening entries were priced under.
    rate_card_version: u64,
}

/// One signed head of the audit record chain.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainSignedHead {
    /// The chain position this head seals.
    seq: u64,
    /// The chain digest at that position.
    hash: String,
    /// The head's signature, or null for an unsigned chain.
    signature: Option<String>,
    /// Which key signed it, or null for an unsigned chain.
    key_id: Option<String>,
    /// When the head was sealed, in whole seconds.
    wall: u64,
}

/// `GET /audit/head`: where the audit record chain is now, and the recipe a verifier applies.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainHeadView {
    /// The name of the published digest recipe.
    recipe: String,
    /// The signature domain-separation string.
    signature_domain: String,
    /// The signature algorithm.
    algorithm: String,
    /// The position the NEXT record will take.
    next_seq: u64,
    /// The tip, or null when the chain has sealed nothing (a true answer, not an error).
    head: Option<AuditChainSignedHead>,
}

/// `GET /audit/range`: records by position, `from` through `to` inclusive, each carrying every
/// field its digest was taken over, plus the head this node published at or before `to`.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainRangeView {
    recipe: String,
    signature_domain: String,
    algorithm: String,
    from: u64,
    to: u64,
    /// The head published at or before `to`, or null when none was.
    anchor: Option<AuditChainSignedHead>,
    records: Vec<AuditChainRecordView>,
}

/// One sealed record: the digest recipe's fields, in the recipe's order (text as strings, numbers as
/// numbers, each repeated group as an array under its own name), then the record's digest and
/// signature.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainRecordView {
    #[serde(flatten)]
    fields: BTreeMap<String, AuditRecipeValue>,
    hash: String,
    signature: Option<String>,
    key_id: Option<String>,
}

/// One digest-recipe value: a scalar, or a repeated group published as an array under its own name.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
pub(crate) enum AuditRecipeValue {
    Scalar(AuditRecipeScalar),
    Group(Vec<AuditRecipeElement>),
}

/// One recipe scalar: text is a string, a number is an unsigned 64-bit integer.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
pub(crate) enum AuditRecipeScalar {
    Text(String),
    Number(u64),
}

/// One element of a repeated group: a single value, or an object of the group's members.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
pub(crate) enum AuditRecipeElement {
    Scalar(AuditRecipeScalar),
    Members(BTreeMap<String, AuditRecipeScalar>),
}

/// `GET /audit/keys`: the public keys the chain is signed with.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainKeysView {
    recipe: String,
    signature_domain: String,
    algorithm: String,
    /// Every public key this node signs records under; empty when it signs none.
    keys: Vec<AuditChainKeyView>,
}

/// One published verifying key. Public halves only.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AuditChainKeyView {
    key_id: String,
    algorithm: String,
    /// The verifying key, as hex.
    public_key: String,
}

/// `POST /adjust`: a correction to a recorded unit's COUNTS, never to a money figure. The
/// principal, lane, card epoch and what the counts WERE are read from the book, by the digest of
/// the journal record `amends` names — never from this body.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AdjustReq {
    /// The chain digest of the journal record being corrected (64 hex characters).
    amends: String,
    /// The corrected count per billable class, each an exact non-negative decimal integer as TEXT.
    /// At least one class.
    now: BTreeMap<String, String>,
    /// Why. Required and non-blank.
    reason: String,
    /// The pool the corrected unit was dispatched through. Required, and it must name a pool this
    /// node has configured: a pool-scoped group budget for that pool takes the correction as well
    /// as the group-wide budgets do.
    pool: String,
}

/// `POST /adjust`'s answer: the sealed amendment's position and digest and the counts the unit now
/// stands at.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AdjustView {
    /// The amendment's position on the node amendment journal.
    seq: u64,
    /// The amendment's digest.
    hash: String,
    /// The digest of the record it corrects.
    amends: String,
    /// The lane the counts were recorded on (read from the book).
    lane: String,
    /// The instant, in milliseconds, whose rate card the counts price at (read from the book;
    /// a correction never moves it).
    card_epoch_ms: u64,
    /// The pool the correction names.
    pool: String,
    /// The corrected counts per class, as decimal TEXT.
    now: BTreeMap<String, String>,
}

/// `POST /ledger/amend-rate-history`: a signed, back-dated correction to the dated rate-card
/// history. It out-ranks the entry it corrects and rewrites nothing.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AmendRateHistoryReq {
    /// The start of the corrected window, in the history's instant scale (milliseconds).
    effective_from: u64,
    /// The end of the corrected window; when present it must lie strictly after
    /// `effective_from`. Absent or null: open-ended.
    #[serde(default)]
    effective_until: Option<u64>,
    /// `sha256` of the fleet's sealed operator key, as hex: which key signed this correction.
    operator_fingerprint: String,
    /// The detached ed25519 signature (128 hex characters) over the canonical correction payload,
    /// verified strictly against the sealed operator key.
    signature: String,
    /// Why. Required and non-empty; the record keeps its SHA-256, not the text.
    reason: String,
    /// The corrected flat per-request fee. Never negative.
    #[serde(default)]
    per_request_fee: Option<u64>,
    /// The corrected rates. A correction must move at least one figure: a rate here or the fee.
    #[serde(default)]
    rates: Vec<AmendRateRow>,
}

/// One corrected rate.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AmendRateRow {
    /// The lane the rate is written against.
    lane: String,
    /// The billable class.
    class: String,
    /// The rate, in micro-units per unit. Finite and non-negative.
    micro_per_unit: f64,
}

/// `POST /ledger/amend-rate-history`'s answer: the history entry an invoice will cite. It names no
/// figure — the corrected rates go into the card, never into the answer.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct AmendRateHistoryView {
    /// The history sequence number the correction was appended at.
    history_seq: u64,
    effective_from: u64,
    effective_until: Option<u64>,
    /// When the correction was appended, in milliseconds.
    amended_at: u64,
    operator_fingerprint: String,
    /// The SHA-256 of the reason, as hex.
    reason_sha256: String,
}

/// `GET /verify`: everything that has to be true of this node's ledger, checked. A failed
/// verification is still a `200`; `ok` is the answer.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct VerifyView {
    /// How many sealed checkpoints the node holds.
    checkpoints: u64,
    /// The checkpoint the book was verified against (the last sealed one); null when none is sealed.
    since: Option<VerifySince>,
    /// Whether the book as it stands was measured against `since` (false with no checkpoint, or a
    /// node that binds no book).
    book_verified: bool,
    /// Each thing verification found, in words: a checkpoint edited after it was sealed, a node
    /// sequence that went backwards, a balance out of identity, a sealed balance no longer in the
    /// book, a closed window that moved.
    findings: Vec<String>,
    /// Whether the ledger's postings reconcile with the previous release's rows.
    identity_holds: bool,
    /// How many rows do not reconcile (`GET /ledger/reconciliation` names them).
    discrepancies: u64,
    /// True when there is no finding and the identity holds.
    ok: bool,
}

/// The checkpoint `verify` measured against.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct VerifySince {
    checkpoint_seq: u64,
    node: u64,
    /// When it was sealed, in whole seconds.
    wall: u64,
}

/// `GET /plane-facts`: what a plane this node serves declares about itself.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneFactsView {
    /// The plane's registry key.
    plane: String,
    /// Whether it is the fallback catch-all plane.
    fallback: bool,
    /// The config section whose presence declares the plane.
    config_section: String,
    owned_config_sections: Vec<String>,
    scope_kinds: Vec<String>,
    subject_noun: String,
    admin_noun: String,
    audit_kind: String,
    billable_classes: Vec<PlaneFactsClass>,
    fee_units: Vec<String>,
    metric_families: Vec<PlaneFactsMetric>,
    served_op_classes: Vec<PlaneFactsServed>,
    /// The plane-record kinds the plane keeps; `POST /plane-record-write` writes only these.
    record_kinds: Vec<String>,
}

/// One billable class a plane ledgers.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneFactsClass {
    class: String,
    family: String,
}

/// One metric family a plane emits.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneFactsMetric {
    name: String,
    kind: String,
    label_keys: Vec<String>,
}

/// One operation class a plane serves one level down.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneFactsServed {
    op: String,
    name: String,
}

/// `POST /plane-record-write`: one plane record, upserted by `(kind, id)`.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneRecordWriteReq {
    /// The key of a plane this node serves.
    plane: String,
    /// The record kind.
    kind: String,
    /// The record's identity within its kind.
    id: String,
    /// The parent the record hangs off, for a child kind.
    #[serde(default)]
    parent: Option<String>,
    /// Whether retention may drop the record once it is old (default false).
    #[serde(default)]
    terminal: Option<bool>,
    /// The record's row, stored as its JSON bytes and never decoded by the store.
    body: serde_json::Value,
}

/// `POST /plane-record-write`'s answer: what was written, and when.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct PlaneRecordWriteView {
    plane: String,
    kind: String,
    id: String,
    parent: Option<String>,
    terminal: bool,
    /// The arrival second the record was written at.
    written_at: u64,
}

/// `POST /commit-upgrade`: the release the fleet commits to.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct CommitUpgradeReq {
    /// The release this node runs. Any other is refused.
    version: String,
}

/// `POST /commit-upgrade`'s answer: the committed release and the journal record that seals it.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct CommitUpgradeView {
    committed: String,
    /// The arrival second.
    committed_at: u64,
    /// The record's position on the node journal.
    seq: u64,
    /// The record's chain hash.
    hash: String,
}

/// `POST /store-restore`: the backup to restore. There is no default and no empty one.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
#[allow(dead_code)]
pub(crate) struct StoreRestoreReq {
    /// The backup the operator names. A request that names none is refused before the ceremony.
    backup_ref: String,
}

// ── one verb's contract ──────────────────────────────────────────────────────────────────────────

/// What a kernel verb answers when it succeeds.
#[cfg(feature = "openapi-schema")]
enum Success {
    /// `200` with a typed JSON body.
    Json(Value, &'static str),
    /// `200` carrying the one generated OpenAPI document.
    Document,
    /// `204`: the verb's whole result is its effect.
    NoContent(&'static str),
}

/// One kernel verb's documented contract.
#[cfg(feature = "openapi-schema")]
struct VerbDoc {
    summary: &'static str,
    description: String,
    success: Success,
    request: Option<Value>,
    query: Vec<Value>,
    errors: Vec<(&'static str, String)>,
}

/// The refusal a posture-gated verb earns, in the one status the root renders it at
/// (`units_admin::answer_for` / `scope_answer`): every gate the new verbs run answers `403`.
#[cfg(feature = "openapi-schema")]
fn gated_403() -> (&'static str, String) {
    (
        "403",
        "`forbidden`: the credential does not hold `full` (the message names the scope), the \
         fleet's operator key is not set, dual control holds the mutation for an approval, the verb's \
         per-principal rate class is exhausted, or an idempotent retry is still in flight"
            .to_string(),
    )
}

/// The `503` every kernel verb can answer: the node could not take the unit, or could not record
/// what the operation would do.
#[cfg(feature = "openapi-schema")]
fn unavailable_503(what: &str) -> (&'static str, String) {
    (
        "503",
        format!(
            "`unavailable`: {what}. The body is the admin error envelope with code \
             `unavailable`"
        ),
    )
}

/// The `400` the mount itself answers for a body it could not read to the operator's cap.
#[cfg(feature = "openapi-schema")]
const BODY_UNREADABLE: &str = "a request body that could not be read to the operator's size cap";

/// The contract for one kernel verb, or `None` for a verb this module does not document — which,
/// for a verb the build binds an effect to, the served-surface coverage test turns into a red
/// build, so an arm cannot be forgotten.
#[cfg(feature = "openapi-schema")]
fn doc_for(
    verb: KernelVerb,
    gen: &mut schemars::SchemaGenerator,
    req_gen: &mut schemars::SchemaGenerator,
) -> Option<VerbDoc> {
    let schema_of = |s: schemars::Schema| serde_json::to_value(s).unwrap_or_else(|_| json!({}));
    let ledger_read =
        |summary: &'static str, description: &str, schema: Value, ok: &'static str| VerbDoc {
            summary,
            description: format!(
                "{description} A read: it mutates nothing, is never posture-gated, and needs no \
                 more authority than `GET /usage`."
            ),
            success: Success::Json(schema, ok),
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503(
                "the node could not take the unit, or the book holds a refused counts row the \
                 read cannot price (the read is refused whole rather than served without it)",
            )],
        };
    let audit_read = |summary: &'static str, schema: Value, ok: &'static str| VerbDoc {
        summary,
        description: "A pull, never a push: the node answers and opens no connection. A read: it \
                      mutates nothing and is never posture-gated."
            .to_string(),
        success: Success::Json(schema, ok),
        request: None,
        query: Vec::new(),
        errors: vec![
            (
                "404",
                "`not_found`: this node binds no audit chain to read".to_string(),
            ),
            unavailable_503("the node could not take the unit, or the chain did not answer"),
        ],
    };
    Some(match verb {
        // ── the three disaster-recovery verbs: their effect lands on the store ──
        KernelVerb::ChainBreak => VerbDoc {
            summary: "Deliberately break the journal chain (disaster recovery; irreducible)",
            description: "Admitted through the same gates as every other new verb, then handed to \
                          the store. The request body is not read."
                .to_string(),
            success: Success::NoContent("Applied: the chain is broken. No body"),
            request: None,
            query: Vec::new(),
            errors: vec![
                gated_403(),
                (
                    "404",
                    "`not_found`: the store names no such resource".to_string(),
                ),
                unavailable_503("the node could not take the unit, or the store failed"),
            ],
        },
        KernelVerb::StoreRestore => VerbDoc {
            summary: "Restore the store from a named backup (disaster recovery; irreducible)",
            description: "The body names the backup; there is no default. A body that names none \
                          is refused before the ceremony runs. Otherwise admitted through the same \
                          gates as every other new verb, then handed to the store."
                .to_string(),
            success: Success::NoContent("Applied: the store is restored. No body"),
            request: Some(schema_of(req_gen.subschema_for::<StoreRestoreReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: the body names no `backup_ref` string, or \
                         {BODY_UNREADABLE}"
                    ),
                ),
                gated_403(),
                (
                    "404",
                    "`not_found`: the store holds no backup under `backup_ref`".to_string(),
                ),
                unavailable_503("the node could not take the unit, or the store failed"),
            ],
        },
        KernelVerb::ResealEpochFloor => VerbDoc {
            summary: "Reseal the epoch floor after a chain break or restore (irreducible)",
            description: "Admitted through the same gates as every other new verb, then handed to \
                          the store. The request body is not read."
                .to_string(),
            success: Success::NoContent("Applied: the floor is resealed. No body"),
            request: None,
            query: Vec::new(),
            errors: vec![
                gated_403(),
                (
                    "404",
                    "`not_found`: the store names no such resource".to_string(),
                ),
                unavailable_503("the node could not take the unit, or the store failed"),
            ],
        },

        // ── the four verbs owner answer Q71(2) binds ──
        KernelVerb::Verify => VerbDoc {
            summary: "Verify this node's ledger: checkpoints, sequences, the book and the identity",
            description: "Every sealed checkpoint must re-hash to its own body, no node's sequence \
                          may go backwards between two checkpoints, the book as it stands is \
                          measured against the last checkpoint, and the ledger's postings must \
                          reconcile with the previous release's rows. A failed verification is \
                          still a 200: `ok` is the answer and `findings` says why. A read: it \
                          mutates nothing and needs `read-only`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<VerifyView>()),
                "What verification found",
            ),
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503(
                "the node could not take the unit, or the book holds a refused counts row the \
                 identity cannot be measured over",
            )],
        },
        KernelVerb::PlaneFacts => VerbDoc {
            summary: "What a plane this node serves declares about itself",
            description: "The plane's registry key, config sections, grant kinds, nouns, billable \
                          classes, fee units, metric families and served operation classes. A \
                          read: it mutates nothing and needs `read-only`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<PlaneFactsView>()),
                "The plane's declared facts",
            ),
            request: None,
            query: vec![json!({
                "name": "plane", "in": "query", "required": true,
                "schema": {"type": "string"},
                "description": "The registry key of a plane this node serves.",
            })],
            errors: vec![
                (
                    "400",
                    "`invalid_request`: `plane is required`".to_string(),
                ),
                (
                    "404",
                    "`not_found`: ``plane `<key>` not found`` — no plane is registered under the \
                     key, or this node does not configure it"
                        .to_string(),
                ),
                unavailable_503("the node could not take the unit"),
            ],
        },
        KernelVerb::PlaneRecordWrite => VerbDoc {
            summary: "Upsert one record of a plane this node serves",
            description: "Upserted by `(kind, id)` through the plane-facing store the planes \
                          persist through, and only for a `kind` the named plane declares in its \
                          `record_kinds` (`GET /plane-facts` lists them). `body` is stored as its \
                          JSON bytes and never decoded by the store; `terminal` is the retention \
                          disposition."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<PlaneRecordWriteView>()),
                "What was written, and when",
            ),
            request: Some(schema_of(req_gen.subschema_for::<PlaneRecordWriteReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: malformed body, `plane is required`, `kind is \
                         required`, `id is required`, `body is required`, a `parent` that is not \
                         a non-empty string or null, a `terminal` that is not a boolean, or \
                         {BODY_UNREADABLE}"
                    ),
                ),
                {
                    let (status, gated) = gated_403();
                    (
                        status,
                        format!(
                            "{gated}, or ``plane `<key>` may not write record kind `<kind>` `` — the \
                             named plane does not declare the kind in its `record_kinds`"
                        ),
                    )
                },
                (
                    "404",
                    "`not_found`: ``plane `<key>` not found``".to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, binds no record store, or the store \
                     failed",
                ),
            ],
        },
        KernelVerb::CommitUpgrade => VerbDoc {
            summary: "Commit the fleet to the release this node runs (irreducible)",
            description: "The body names the release; one this node does not run is refused and \
                          seals nothing. The committed release is sealed on the node journal \
                          before the answer names its position and chain hash."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<CommitUpgradeView>()),
                "The committed release and the record that seals it",
            ),
            request: Some(schema_of(req_gen.subschema_for::<CommitUpgradeReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: malformed body, `version is required`, or \
                         {BODY_UNREADABLE}"
                    ),
                ),
                gated_403(),
                (
                    "409",
                    "`conflict`: ``this node runs `<release>`; it cannot commit `<version>` ``"
                        .to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, or no journal will record the commit",
                ),
            ],
        },
        // ── the two money verbs whose effect is the node's amendment journal ──
        KernelVerb::Adjust => VerbDoc {
            summary: "Correct a recorded unit's COUNTS, never a money figure (irreducible above \
                      `adjust_threshold`)",
            description: "Takes counts, never a money figure: what a recorded unit costs stays a \
                          read-time view of its counts at its own card epoch. The principal, lane, \
                          card epoch and what the counts WERE are read from the book by the digest \
                          `amends` names, never from the body. The body names the pool the unit \
                          was dispatched through, so a pool-scoped group budget for that pool \
                          takes the correction too. The correction is sealed on the node \
                          amendment journal."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<AdjustView>()),
                "The sealed amendment and the counts the unit now stands at",
            ),
            request: Some(schema_of(req_gen.subschema_for::<AdjustReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: malformed body, a blank `amends` or `reason`, an \
                         empty `now`, a count that is not an exact decimal, a count below zero, \
                         a missing or blank `pool` or one naming no configured pool (the message \
                         says which), a scope below `full`, or {BODY_UNREADABLE}"
                    ),
                ),
                gated_403(),
                (
                    "404",
                    "`not_found`: the book holds no counts-bearing entry under `amends`"
                        .to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, or could not seal the amendment",
                ),
            ],
        },
        KernelVerb::AmendRateHistory => VerbDoc {
            summary: "Append a signed, back-dated correction to the dated rate-card history \
                      (irreducible)",
            description: "The correction out-ranks the entry it corrects and rewrites nothing; \
                          recompute reprices the corrected window against the new entry. It must \
                          be signed by the fleet's sealed operator key (`operator_fingerprint` \
                          names it; `signature` verifies strictly over the canonical payload). A \
                          body carrying `currency` is refused. The durable record is written ahead \
                          of the append."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<AmendRateHistoryView>()),
                "The history entry the correction was appended as",
            ),
            request: Some(schema_of(req_gen.subschema_for::<AmendRateHistoryReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: malformed body, an empty or inverted window, no \
                         signer, signature or reason, a `currency` key, a negative fee or rate, \
                         a correction that moves no figure, an unknown operator fingerprint, a \
                         signature that does not verify, or {BODY_UNREADABLE}"
                    ),
                ),
                gated_403(),
                (
                    "404",
                    "`not_found`: the history has no opening entry to correct".to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, or no amendment journal will record it",
                ),
            ],
        },

        // ── the five ledger views ──
        KernelVerb::GetLedgerTotals => ledger_read(
            "What the ledger's lines come to, per bucket, day, lane and provider",
            "Each line is priced against the rate card in force at its own arrival instant, and \
             the row's micro-unit figure is one divide over its summed nano-units.",
            schema_of(gen.subschema_for::<LedgerTotals>()),
            "The rows, in bucket, day, lane and provider order",
        ),
        KernelVerb::GetLedgerCheckpoints => ledger_read(
            "The sealed checkpoint figures",
            "`body_hash` is what an auditor re-derives; `body_hash_verifies` is this node's own \
             answer. A signature's presence is reported, its bytes are not.",
            schema_of(gen.subschema_for::<LedgerCheckpoints>()),
            "The sealed checkpoints, oldest first",
        ),
        KernelVerb::GetLedgerReconciliation => ledger_read(
            "The residual of the ledger's postings against the previous release's rows",
            "An empty `discrepancies` list with `holds: true` is the good answer; a residual names \
             its row and the amount it is out by.",
            schema_of(gen.subschema_for::<LedgerReconciliation>()),
            "Whether the identity holds, and every row on which it does not",
        ),
        KernelVerb::GetLedgerMigration => ledger_read(
            "The marker the first boot after the upgrade sealed",
            "`migrated` is a field of its own rather than inferred from a null marker.",
            schema_of(gen.subschema_for::<LedgerMigration>()),
            "Whether this deployment has migrated, and the marker if it has",
        ),
        KernelVerb::GetLedgerOpenapiJson => VerbDoc {
            summary: "The full administrative OpenAPI 3.1 document, served at the ledger's own path",
            description: "The committed, generated document, unfiltered: every operation this \
                          BUILD can serve, including each plane's. `GET /openapi.json` serves the \
                          same document filtered to the planes this node configured."
                .to_string(),
            success: Success::Document,
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503("the node could not take the unit")],
        },

        // ── the three audit-chain reads ──
        KernelVerb::GetAuditHead => audit_read(
            "The audit record chain's tip: position, digest, signature, key identifier and clock",
            schema_of(gen.subschema_for::<AuditChainHeadView>()),
            "The recipe, the next position and the tip (null when nothing is sealed)",
        ),
        KernelVerb::GetAuditRange => {
            let mut doc = audit_read(
                "Audit records by position, each with every field its digest was taken over",
                schema_of(gen.subschema_for::<AuditChainRangeView>()),
                "The window's records and the head published at or before `to`",
            );
            doc.query = ["from", "to"]
                .into_iter()
                .map(|name| {
                    json!({
                        "name": name, "in": "query", "required": true,
                        "schema": {"type": "integer", "minimum": 0},
                        "description": format!(
                            "The window's {} position, inclusive. Both are required; `from` \
                             must not exceed `to`. A window running off either end of what the \
                             node holds is simply shorter.",
                            if name == "from" { "first" } else { "last" }
                        ),
                    })
                })
                .collect();
            doc.errors.insert(
                0,
                (
                    "400",
                    "`invalid_request`: `from` or `to` missing or not a non-negative integer, or \
                     `from` after `to`"
                        .to_string(),
                ),
            );
            doc.errors[1] = (
                "404",
                "`not_found`: this node binds no audit chain, or retains no sealed records to \
                 answer a window from (an absent record set is never rendered as an empty window)"
                    .to_string(),
            );
            doc
        }
        KernelVerb::GetAuditKeys => audit_read(
            "The public keys the audit chain is signed with",
            schema_of(gen.subschema_for::<AuditChainKeysView>()),
            "The published verifying keys (empty when the node signs nothing)",
        ),
        _ => return None,
    })
}

/// Every kernel verb's OpenAPI operation, as `(absolute path, method, operation)`.
///
/// Driven by the three verb lists and joined to the closed table's own row for each, so the path
/// and method documented are the ones the mount resolves. The success and error responses, the
/// scope annotation and the security schemes are stamped here; the caller's shared passes add the
/// error-envelope content and the stable `operationId`.
#[cfg(feature = "openapi-schema")]
pub(crate) fn operations(
    gen: &mut schemars::SchemaGenerator,
    req_gen: &mut schemars::SchemaGenerator,
) -> Vec<(String, String, Value)> {
    use super::RESPONSES_KEY;
    let table: Vec<ResolvedVerb> = crate::admin_codec::verbs::table();
    let mut out = Vec::new();
    for &verb in NEW_VERBS.iter().chain(LEDGER_VERBS).chain(AUDIT_VERBS) {
        let Some(name) = verb_name(verb) else {
            continue;
        };
        let Some(row) = table.iter().find(|row| row.verb == name) else {
            continue;
        };
        // The mount's own question: a verb with no bound effect is not served, so not described.
        if !crate::verb::effect_bound(verb) {
            continue;
        }
        let Some(doc) = doc_for(verb, gen, req_gen) else {
            continue;
        };
        let method = row.method.to_ascii_lowercase();
        let path = row.template.to_string();
        let mut by_status = serde_json::Map::new();
        match doc.success {
            Success::Json(schema, description) => {
                by_status.insert(
                    "200".into(),
                    json!({"description": description,
                           "content": {"application/json": {"schema": schema}}}),
                );
            }
            Success::Document => {
                by_status.insert(
                    "200".into(),
                    json!({"description": "The one administrative OpenAPI document",
                           "content": {"application/json": {"schema": {
                               "type": "object",
                               "description": "An OpenAPI 3.1 document (this document's shape)"}}}}),
                );
            }
            Success::NoContent(description) => {
                by_status.insert("204".into(), json!({ "description": description }));
            }
        }
        by_status.insert(
            "401".into(),
            json!({"description": "Missing/invalid admin credential (error code `unauthorized`)"}),
        );
        // Every error status speaks the one `Error` envelope (its `code` enum carries `unavailable`);
        // the caller's shared pass attaches it.
        for (status, description) in doc.errors {
            by_status.insert(status.into(), json!({ "description": description }));
        }
        let http_method = match method.as_str() {
            "get" => axum::http::Method::GET,
            "post" => axum::http::Method::POST,
            "put" => axum::http::Method::PUT,
            "patch" => axum::http::Method::PATCH,
            "delete" => axum::http::Method::DELETE,
            _ => continue,
        };
        let scope = busbar_kernel::admin::v1::contract::required_scope(&http_method, &path);
        let mut op = json!({
            "summary": doc.summary,
            "description": doc.description,
            "security": [{"adminToken": []}, {"bearerAuth": []}],
            "x-busbar-required-scope": scope.as_str(),
            "x-busbar-since": SINCE,
            RESPONSES_KEY: by_status,
        });
        if !doc.query.is_empty() {
            op["parameters"] = Value::Array(doc.query);
        }
        if let Some(schema) = doc.request {
            op["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": schema}}
            });
        }
        out.push((path, method, op));
    }
    out
}
