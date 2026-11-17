// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

#[cfg(feature = "openapi-schema")]
pub(crate) const SINCE: &str = "1.6.0";

/// A money figure: a decimal integer carried as TEXT. The ledger keeps money in 128-bit integers and
/// JSON's number is a double, exact only to 2^53; a nano-unit total passes that on a busy day, and a
/// figure that silently lost its last digits would still look like money.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct Amount(#[schemars(regex(pattern = r"^-?[0-9]+$"))] String);

/// A 32-byte digest as 64 lower-case hex characters.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct Hash(#[schemars(regex(pattern = r"^[0-9a-f]{64}$"))] String);

/// `GET /ledger/totals`: what the ledger's lines come to, per bucket, day, lane and provider.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct LedgerTotals {
    /// The rows, in bucket, day, lane and provider order. A row a `refused` entry names is absent.
    rows: Vec<LedgerTotalsRow>,
    /// Every balance whose counts a present rate card refused to price: its row has no figure, so
    /// it is withheld from `rows` rather than served as the priced remainder. Empty is the good
    /// answer.
    refused: Vec<LedgerRefusedBalance>,
}

/// A balance with no figure: a unit's counts on it that the rate card in force refused to price
/// (a present card silent about the lane or a class). The row the balance folds into — the same
/// `bucket` and `day` — is withheld from the view that names this.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct LedgerRefusedBalance {
    /// The balance's bucket.
    bucket: String,
    /// The balance's dimension.
    dimension: String,
    /// The balance's scope.
    scope: String,
    /// The balance's window, as the unix second it opens at: the `day` of the withheld row.
    day: u64,
    /// The lane that served the unit whose counts refused.
    lane: String,
    /// Why the pricing refused, in its own words.
    refusal: String,
}

/// One row of `GET /ledger/totals`. The row width is the reconciliation's, so a discrepancy found
/// on one endpoint is looked up on the other by the same four-part name.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) struct LedgerCheckpoints {
    checkpoints: Vec<LedgerCheckpoint>,
}

/// One sealed checkpoint. `body_hash` is what an auditor re-derives independently;
/// `body_hash_verifies` is this node's own answer to the same question. A signature's presence is
/// reported and its bytes are not.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) struct LedgerChainHead {
    node: u64,
    node_seq: u64,
    hash: Hash,
}

/// One sealed balance, as the checkpoint holds it. Every money figure is an [`Amount`].
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) struct LedgerReconciliation {
    /// True when every row reconciles. `discrepancies` and `refused` are then empty.
    holds: bool,
    discrepancies: Vec<LedgerDiscrepancy>,
    /// Every balance whose counts a present rate card refused to price: its row is withheld from
    /// both sides of the identity, which was not measured over it. Empty is the good answer.
    refused: Vec<LedgerRefusedBalance>,
}

/// One row on which the identity does not hold. Spend and fee count are checked separately
/// because they fail separately.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) struct LedgerMigration {
    migrated: bool,
    marker: Option<LedgerMigrationMarker>,
}

/// The marker the first boot after the upgrade sealed.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
/// field its fingerprint was taken over, under the link recipe (`busbar.audit.link.v1`), with the
/// evidence that authenticates them (SEALING-FIX r20 §3.5 "Reads").
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditChainRangeView {
    recipe: String,
    signature_domain: String,
    algorithm: String,
    from: u64,
    to: u64,
    /// The covering stamp of the page's last line (the first stamp whose `to` is at or after
    /// it), or null when none exists yet.
    anchor: Option<AuditStampView>,
    records: Vec<AuditChainRecordView>,
    /// Every page stamp over the page's lines plus the covering stamp of its last line, and every
    /// break notice over the walked lines (`kind` `break`).
    stamps: Vec<AuditEvidenceView>,
    /// The lines after the page's last line up to its covering stamp: authentication evidence,
    /// not part of the range.
    cover: Vec<AuditChainRecordView>,
    /// The `notary_key` line each returned stamp's `key_cert` names.
    certs: Vec<AuditChainRecordView>,
    /// The node's `sealed:<node>` row, or null when there is none.
    seal_row: Option<AuditSealRowView>,
    /// Fixed upper audit position captured on the first page; exact decimal string.
    snapshot_to: String,
    /// `bounded_live_range`: upper bound is fixed, retention is live, no snapshot is retained.
    semantics: String,
    returned_from: Option<String>,
    returned_to: Option<String>,
    /// Round-trip with the original from/to. May be present even when records is empty.
    next_cursor: Option<String>,
    /// There is more bounded scanning to do.
    truncated: bool,
    /// True only on the last page when this traversal found every requested position.
    complete: bool,
    /// A prior or current page had missing/oversized journal data or an audit gap.
    incomplete: bool,
    gaps: Vec<AuditRangeGapView>,
    retention: AuditRetentionView,
    scanned_positions: String,
    scan_limit: String,
}

/// One page stamp (`audit.stamp.v1`): every signed field, and the WAL position it was read at.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
struct AuditStampView {
    /// The WAL `node_seq` the stamp was read at; absent for a stamp read from a seal row.
    #[serde(skip_serializing_if = "Option::is_none")]
    node_seq: Option<u64>,
    node: u64,
    from: u64,
    to: u64,
    /// Line `to`'s fingerprint, 64 lowercase hex digits.
    fingerprint: String,
    /// `live`, `final` or `after_restart`.
    kind: String,
    sealer: u64,
    host: String,
    every: u64,
    stamped_ms: u64,
    down_from_ms: u64,
    down_to_ms: u64,
    crypto: String,
    sig_alg: String,
    key_id: String,
    /// The WAL `node_seq` of the certifying `notary_key` line; 0 for the Bootstrap key.
    key_cert: u64,
    /// 128 lowercase hex digits.
    signature: String,
}

/// One break notice (`audit.break.v1`, `kind` `break`): it vouches for no line.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
struct AuditBreakView {
    /// The WAL `node_seq` the notice was read at; absent for a notice read from a seal row.
    #[serde(skip_serializing_if = "Option::is_none")]
    node_seq: Option<u64>,
    /// `break`.
    kind: String,
    node: u64,
    sealer: u64,
    last_good: u64,
    unsealed_from: u64,
    unsealed_to: u64,
    journal_from: u64,
    journal_to: u64,
    reason: String,
    detected_ms: u64,
    host: String,
    crypto: String,
    sig_alg: String,
    key_id: String,
    /// 128 lowercase hex digits.
    signature: String,
}

/// A page stamp or a break notice.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
enum AuditEvidenceView {
    _Stamp(AuditStampView),
    _Break(AuditBreakView),
}

/// A node's seal row: who sealed it and how (`clean`, `stamp`, `break`, or `undecodable`).
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
struct AuditSealRowView {
    /// The successor node that wrote it; absent when the row does not decode.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealer: Option<u64>,
    outcome: String,
    /// `clean` only: the node's tail line.
    #[serde(skip_serializing_if = "Option::is_none")]
    through: Option<u64>,
    /// `stamp` only: the signed `after_restart` page.
    #[serde(skip_serializing_if = "Option::is_none")]
    stamp: Option<AuditStampView>,
    /// `break` only: the signed break notice.
    #[serde(skip_serializing_if = "Option::is_none", rename = "break")]
    break_notice: Option<AuditBreakView>,
}

#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
struct AuditRangeGapView {
    from: String,
    to: String,
}

#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
struct AuditRetentionView {
    ring_from: Option<String>,
    ring_to: Option<String>,
    /// Unknown: the Store does not expose an audit retention floor.
    durable_from: Option<String>,
    durable_from_known: bool,
}

/// One sealed record: the digest recipe's fields, in the recipe's order (every value a string: a
/// text as its text, a number as its decimal text; each repeated group as an array under its own
/// name), then the record's digest and signature.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) enum AuditRecipeValue {
    _Scalar(AuditRecipeScalar),
    _Group(Vec<AuditRecipeElement>),
}

/// One recipe scalar, always a JSON string: a text field is its text, and a number field (an
/// unsigned 64-bit integer) is its canonical decimal text, because a JSON number above 2^53 is not
/// exact through a reader that maps numbers to doubles. Which framing a field takes is the
/// published recipe page's kind column, not the JSON type.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditRecipeScalar(String);

/// One element of a repeated group: a single value, or an object of the group's members.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(untagged)]
pub(crate) enum AuditRecipeElement {
    _Scalar(AuditRecipeScalar),
    _Members(BTreeMap<String, AuditRecipeScalar>),
}

/// `GET /operations/{key}`: one idempotent operation record.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct OperationView {
    idempotency_key: String,
    principal: String,
    operation_id: String,
    /// One of `applied`, `rejected` or `in_flight`.
    state: OperationState,
    status: Option<u16>,
    request_sha256: String,
    received_at: u64,
    completed_at: Option<u64>,
    config_generation: Option<u64>,
    audit_seq: Option<u64>,
    /// The stored response body; `null` while in flight.
    response: Value,
}

/// Where an idempotent operation stands.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationState {
    _Applied,
    _Rejected,
    _InFlight,
}

/// `GET /audit/keys`: the public keys the chain is signed with.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditChainKeysView {
    recipe: String,
    signature_domain: String,
    algorithm: String,
    /// This page of public keys, in key-id order; empty when the node signs none.
    items: Vec<AuditChainKeyView>,
    /// The shared cursor for the next page, or null after the final key.
    next_cursor: Option<String>,
}

/// One published verifying key. Public halves only.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditChainKeyView {
    key_id: String,
    algorithm: String,
    /// The verifying key, as hex.
    public_key: String,
}

/// `POST /adjust`: a SIGNED correction to a key's COUNTS on the one ledger, never to a money
/// figure. It names the key, the lane the counts were earned on, the rate-card history entry they
/// were priced with, and the pool the unit was dispatched through.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct AdjustReq {
    /// The key whose counts are corrected.
    #[serde(rename = "key")]
    _key: String,
    /// The lane (model) the counts were earned on.
    #[serde(rename = "lane")]
    _lane: String,
    /// The rate-card history entry key the counts were priced with, as 40 hexadecimal digits.
    #[schemars(regex(pattern = r"^[0-9a-fA-F]{40}$"))]
    #[serde(rename = "entry")]
    _entry: String,
    /// The corrected unit's card epoch: its arrival instant, unix milliseconds. The correction
    /// lands in the budget windows, the card entry and the metering day holding it, never in those
    /// current when it is made, and `entry` must be the entry in force at it.
    #[serde(rename = "card_epoch_ms")]
    _card_epoch_ms: u64,
    /// The signed delta per billable class: whole counts, never a money figure. At least one class.
    #[serde(rename = "delta")]
    _delta: BTreeMap<String, i64>,
    /// Why. Required and non-blank.
    #[serde(rename = "reason")]
    _reason: String,
    /// The pool the corrected unit was dispatched through. Required, and it must name a pool this
    /// node has configured: a pool-scoped group budget for that pool takes the correction as well
    /// as the group-wide budgets do.
    #[serde(rename = "pool")]
    _pool: String,
}

/// `POST /adjust`'s answer: the correction as applied.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AdjustView {
    /// Always true: a refused correction is a `400`, and nothing of it is applied.
    applied: bool,
    /// The key corrected.
    key: String,
    /// The lane corrected.
    lane: String,
    /// The rate-card history entry key, as 40 lowercase hexadecimal digits.
    #[schemars(regex(pattern = r"^[0-9a-f]{40}$"))]
    entry: String,
    /// The corrected unit's card epoch, unix milliseconds: where the correction landed.
    card_epoch_ms: u64,
    /// The pool the correction names.
    pool: String,
    /// The signed delta applied, per class.
    delta: BTreeMap<String, i64>,
}

/// `POST /ledger/amend-rate-history`: a back-dated correction to the dated rate-card
/// history. It out-ranks the entry it corrects and rewrites nothing.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct AmendRateHistoryReq {
    /// The start of the corrected window, in the history's instant scale (milliseconds).
    #[serde(rename = "effective_from")]
    _effective_from: u64,
    /// The end of the corrected window; when present it must lie strictly after
    /// `effective_from`. Absent or null: open-ended.
    #[serde(default, rename = "effective_until")]
    _effective_until: Option<u64>,
    /// Why. Required and non-empty; the record keeps its SHA-256, not the text.
    #[serde(rename = "reason")]
    _reason: String,
    /// The corrected flat per-request fee. Never negative.
    #[serde(default, rename = "per_request_fee")]
    _per_request_fee: Option<u64>,
    /// The corrected rates. A correction must move at least one figure: a rate here or the fee.
    #[serde(default, rename = "rates")]
    _rates: Vec<AmendRateRow>,
}

/// One corrected rate.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct AmendRateRow {
    /// The lane the rate is written against.
    #[serde(rename = "lane")]
    _lane: String,
    /// The billable class.
    #[serde(rename = "class")]
    _class: String,
    /// The rate, in micro-units per unit. Finite and non-negative.
    #[serde(rename = "micro_per_unit")]
    _micro_per_unit: f64,
}

/// `POST /ledger/amend-rate-history`'s answer: the history entry an invoice will cite. It names no
/// figure — the corrected rates go into the card, never into the answer.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct AmendRateHistoryView {
    /// The history sequence number the correction was appended at.
    history_seq: u64,
    effective_from: u64,
    effective_until: Option<u64>,
    /// When the correction was appended, in milliseconds.
    amended_at: u64,
    /// The SHA-256 of the reason, as hex.
    reason_sha256: String,
}

/// `GET /verify`: everything that has to be true of this node's ledger, checked. A failed
/// verification is still a `200`; `ok` is the answer.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
    /// book, a closed window that moved, a balance whose counts the rate card refused to price.
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
pub(crate) struct VerifySince {
    checkpoint_seq: u64,
    node: u64,
    /// When it was sealed, in whole seconds.
    wall: u64,
}

/// `POST /plane-record-write`: one plane record, upserted by `(kind, id)`.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct PlaneRecordWriteReq {
    /// The key of a plane this node serves.
    #[serde(rename = "plane")]
    _plane: String,
    /// The record kind.
    #[serde(rename = "kind")]
    _kind: String,
    /// The record's identity within its kind.
    #[serde(rename = "id")]
    _id: String,
    /// The parent the record hangs off, for a child kind.
    #[serde(default, rename = "parent")]
    _parent: Option<String>,
    /// Whether retention may drop the record once it is old (default false).
    #[serde(default, rename = "terminal")]
    _terminal: Option<bool>,
    /// The record's row, stored as its JSON bytes and never decoded by the store.
    #[serde(rename = "body")]
    _body: serde_json::Value,
}

/// `POST /plane-record-write`'s answer: what was written, and when.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct PlaneRecordWriteView {
    plane: String,
    kind: String,
    id: String,
    parent: Option<String>,
    terminal: bool,
    /// The arrival second the record was written at.
    written_at: u64,
}

/// One trust key of the kernel's trust book and its state.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct TrustKeyView {
    /// The key, `<instance>/<counterparty>[/<item>]`: what `POST /trust/approve` and `/revoke` name.
    key: String,
    /// The plane instance label.
    instance: String,
    /// The counterparty, as the instance's configuration names it.
    counterparty: String,
    /// The item at the counterparty, for an item key.
    item: Option<String>,
    /// `new` (sighted and never approved, or revoked: refused), `approved` (approved, not sighted
    /// since), `same` (sighted as approved), `drifted` (sighted other than approved: refused until
    /// re-approved) or `quarantined` (the counterparty's catalogue moved: refused until re-approved).
    #[schemars(extend("enum" = ["new", "approved", "same", "drifted", "quarantined"]))]
    state: String,
    /// What it is approved at: the catalogue hash, or the item's digest.
    approved: Option<String>,
    /// What it was last sighted at.
    seen: Option<String>,
}

/// `GET /trust`: every trust key and its state.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
pub(crate) struct TrustListView {
    /// Ordered by instance, counterparty and item, each counterparty before its items.
    keys: Vec<TrustKeyView>,
}

/// `POST /trust/approve` and `/trust/revoke`: the trust key decided.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct TrustKeyReq {
    /// `<instance>/<counterparty>[/<item>]`, as `GET /trust` lists it.
    #[serde(rename = "key")]
    _key: String,
    /// Required: the digest the operator reviewed from `GET /trust` (TRUST-ADMIN-PRODUCER-DESIGN
    /// r3 §4.1). Approve: exactly the key's current `seen`; `null` only while it was never
    /// sighted. Revoke: the current `seen` or the current `approved`; `null` matches a null one of
    /// them. Omitted: 428 `reviewed_digest_required`. Anything else: 409 `reviewed_digest_stale`,
    /// and nothing changes.
    #[schemars(required, regex(pattern = r"\S"))]
    #[serde(rename = "expected_digest")]
    _expected_digest: Option<String>,
}

/// `POST /commit-upgrade`: the release the fleet commits to.
#[cfg(feature = "openapi-schema")]
#[derive(Deserialize, JsonSchema)]
pub(crate) struct CommitUpgradeReq {
    /// The release this node runs. Any other is refused.
    #[serde(rename = "version")]
    _version: String,
}

/// `POST /commit-upgrade`'s answer: the committed release and the journal record that seals it.
#[cfg(feature = "openapi-schema")]
#[derive(Serialize, JsonSchema)]
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
pub(crate) struct StoreRestoreReq {
    /// The backup the operator names. A request that names none is refused before the ceremony.
    #[serde(rename = "backup_ref")]
    _backup_ref: String,
}

#[cfg(feature = "openapi-schema")]
enum Success {
    Json(Value, &'static str),

    Document,

    NoContent(&'static str),
}

#[cfg(feature = "openapi-schema")]
struct VerbDoc {
    summary: &'static str,
    description: String,
    success: Success,
    request: Option<Value>,
    query: Vec<Value>,
    errors: Vec<(&'static str, String)>,
}

#[cfg(feature = "openapi-schema")]
fn gated_403() -> (&'static str, String) {
    (
        "403",
        "`forbidden`: the credential does not hold `full` (the message names the scope), the verb's \
         per-principal rate class is exhausted, or an idempotent retry is still in flight"
            .to_string(),
    )
}

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

#[cfg(feature = "openapi-schema")]
const BODY_UNREADABLE: &str = "a request body that could not be read to the operator's size cap";

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
                "the node could not take the unit, or a figure the read serves is past the range \
                 it is served in (refused, never pinned)",
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
        KernelVerb::GetWhoami => VerbDoc {
            summary: "Who the admin chain says the caller is, and what the caller may do",
            description: "The caller's principal, the credential behind it (`operator`, `key`, \
                `identity_provider` or `open`), its scope, and every verb of the closed table it \
                may call, computed with the gate's own predicate. Any identified admin credential \
                may read its own identity, whatever verbs it holds. A read: it mutates nothing. \
                `rate.read.limit` is `0`: reads are not metered."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::whoami::WhoamiView>()),
                "The caller's identity and authority",
            ),
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503("the node could not take the read")],
        },

        KernelVerb::ChainBreak => VerbDoc {
            summary: "Deliberately break the journal chain (disaster recovery)",
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
            summary: "Refused: the configured store has no restore operation (disaster recovery)",
            description: "Refused, always: the configured store has no restore operation, \
                          so this node restores nothing, records nothing and changes \
                          nothing. Restores happen off-node, with the store's own tooling. \
                          A body that names no `backup_ref` is refused 400 before anything \
                          else; an admitted call is refused 503 `unavailable`, and the node \
                          logs one error line naming the verb."
                .to_string(),
            success: Success::NoContent(
                "Never answered: this build has no restore operation (an admitted call is refused \
                 503)",
            ),
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
                    "`not_found`: never answered: there is no restore operation to look \
                     `backup_ref` up in"
                        .to_string(),
                ),
                unavailable_503(
                    "the configured store has no restore operation, so nothing was restored \
                     (restores happen off-node), or the node could not take the unit",
                ),
            ],
        },

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
                "the node could not take the unit, or a figure the identity is measured over is \
                 past the range it is served in",
            )],
        },
        KernelVerb::GetKinds => VerbDoc {
            summary: "What exists: every kind, by category",
            description: "One row per kind: the seven engine kinds (one per registered plane) and \
                `core`, core's own subsystems. `category` is the engine kind; `kind` is the id \
                a client routes on. `instance_count` counts the running instances; `views` and \
                `record_attributes` are on the row when every instance declares the same \
                descriptors (`descriptors_uniform`). The ETag moves whenever a kind or an instance \
                is added, removed or reconfigured. Pages with `cursor` and `limit`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::kinds::doc::KindsPage>()),
                "A page of kinds",
            ),
            request: None,
            query: super::kinds::doc::query(&["category", "cursor", "limit"]),
            errors: vec![unavailable_503("the node could not take the read")],
        },
        KernelVerb::GetKindInstances => VerbDoc {
            summary: "What is running: a kind's instances",
            description: "One row per instance: `id`, `name`, `plugin` (null for a core \
                instance; the image's own name, version and publisher otherwise), `state`, \
                `labels` and `etag`. Instance ids are unique across the deployment. Pages with \
                `cursor` and `limit`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::kinds::doc::InstancesPage>()),
                "A page of instances",
            ),
            request: None,
            query: super::kinds::doc::query(&["cursor", "limit"]),
            errors: vec![unavailable_503("the node could not take the read")],
        },
        KernelVerb::GetKindInstance => VerbDoc {
            summary: "Describe one instance",
            description: "Exactly the list-row members and `config` (under the secret rule: a \
                secret position is `{set, secret_ref}`), `config_schema` (the image's schema, \
                with `x-sensitive` beside `x-busbar-secret`), `state` and `state_schema` (the \
                instance's own answer; core writes nothing into them), `runtime` (what core \
                holds about a plugin instance; null for a core instance), `health`, `links`, \
                `views` and `actions`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::kinds::doc::Describe>()),
                "The instance",
            ),
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503("the node could not take the read")],
        },
        KernelVerb::GetKindInstanceView => VerbDoc {
            summary: "One view of an instance: generic rows",
            description: "`{fields, rows, next_cursor, as_of}`: each row a positional array in \
                `fields` order, each cell in its type's one wire encoding. \
                `filter=<field>:<value>` (repeatable) is an exact match on a dimension or id \
                field. Times are in milliseconds, steps in seconds."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::kinds::doc::ViewPage>()),
                "A page of rows",
            ),
            request: None,
            query: super::kinds::doc::query(&[
                "from_ms", "to_ms", "step_s", "filter", "cursor", "limit",
            ]),
            errors: vec![unavailable_503("the view could not be read")],
        },
        KernelVerb::RecoveryList => VerbDoc {
            summary: "Inspect retained raw ledger operations requiring recovery",
            description: "An observation-only POST requiring full scope and the ordinary CRUD budget. The opaque cursor belongs to this list; default limit 200, maximum 1000. Rows contain immutable operation identities and recovery versions, never raw bodies or mutable dollar balances. Listing does not grant resolution authority; can_resolve describes only this node's current authority."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<crate::recovery::ListView>()),
                "A bounded page of retained operations and an opaque continuation cursor",
            ),
            request: Some(schema_of(req_gen.subschema_for::<crate::recovery::ListRequest>())),
            query: Vec::new(),
            errors: vec![
                ("400", "`invalid_request`: malformed body, unknown fields, invalid limit or a malformed or foreign cursor".into()),
                gated_403(),
                unavailable_503("the recovery Store or owned task is unavailable"),
            ],
        },
        KernelVerb::RecoveryResolve => VerbDoc {
            summary: "Record an explicit landed or not-landed verdict for an exact retained operation",
            description: "Requires full scope, the original operation id and immutable body fingerprint, the inspected recovery version and nonempty evidence (at most 1024 bytes). The instance-bound recovery facade checks current authority and confirms a durable, attributed verdict before reposting or releasing dependent negative work. An expired receipt never proves not-landed. The same verdict, version, actor and reason replays its durable outcome; a conflicting retry is refused. The Store operation survives cancellation of the HTTP waiter. No raw payload, credential or mutable dollar balance is returned."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<crate::recovery::ItemView>()),
                "The retained operation after the durable verdict was confirmed",
            ),
            request: Some(schema_of(req_gen.subschema_for::<crate::recovery::ResolveRequest>())),
            query: Vec::new(),
            errors: vec![
                ("400", "`invalid_request`: malformed body, unknown fields, noncanonical operation id or fingerprint, missing verdict or invalid evidence".into()),
                gated_403(),
                ("409", "`conflict`: stale recovery version, mismatched operation fingerprint, conflicting verdict or absent resolution authority".into()),
                unavailable_503("the durable verdict could not be confirmed, or the owned task is unavailable; retry the same request"),
            ],
        },
        KernelVerb::GetTrust => VerbDoc {
            summary: "Every trust key of the kernel's trust book and its state",
            description: "The counterparties every plane instance this node serves declares, and \
                          the items sighted or approved at each: its key, state, what it is \
                          approved at and what it was last sighted at. Unpaged: the set is \
                          bounded by the configured registrations, and a reviewer reads all of it \
                          (TRUST-ADMIN-PRODUCER-DESIGN r3 §0). The same projection as the \
                          `core/trust` `subjects` and `items` views. A read: it mutates nothing \
                          and needs `read-only`."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<TrustListView>()),
                "Every trust key and its state",
            ),
            request: None,
            query: Vec::new(),
            errors: vec![unavailable_503(
                "`service_unavailable`: native trust custody is not installed on this node \
                 (never an empty list), or the node could not take the unit",
            )],
        },
        KernelVerb::TrustApprove | KernelVerb::TrustRevoke => {
            let approve = verb == KernelVerb::TrustApprove;
            VerbDoc {
                summary: if approve {
                    "Approve one trust key at the digest the operator reviewed"
                } else {
                    "Revoke one trust key"
                },
                description: format!(
                    "{} Both members of the body are required: `expected_digest` is the digest \
                     reviewed from `GET /trust` (omitted: 428 `reviewed_digest_required`; not \
                     current: 409 `reviewed_digest_stale`, nothing changes). {} The decision is \
                     kept durably before the answer and outlives a restart; every attempt is \
                     audited as `trust_approve` or `trust_revoke`, naming the key. \
                     `Idempotency-Key` (1..128 of `A-Z a-z 0-9 . _ : -`; it is echoed as the \
                     kept decision's `operation`) makes the request replayable: the same key and \
                     bytes answer the original outcome with `idempotent-replayed: true` and \
                     never decide again; other bytes are 409 `idempotency_mismatch`, a request \
                     still running 409 `idempotency_in_flight`. A durable write whose outcome is \
                     unknown answers 503 `service_unavailable` with `details` naming the \
                     attempt: replay the same key and bytes to resolve it, to 200 when it is \
                     in force or to 409 `outcome_not_applied` when the store proves it never \
                     applied; until then it stays the same 503 (read the key's state and decide \
                     again under a new key). `x-busbar-trust-effect` classifies every answer: \
                     `applied`, `not_applied` or `unknown`.",
                    if approve {
                        "A counterparty is approved at the catalogue hash it last reported, which \
                         clears its quarantine; an item at the digest it was last sighted at."
                    } else {
                        "Refused until approved again: a counterparty revoked refuses everything \
                         at it, an item revoked refuses it over its configured approval."
                    },
                    if approve {
                        "Approve is strict: `expected_digest` must equal the current `seen`, and \
                         `null` is valid only while the key was never sighted."
                    } else {
                        "Revoke accepts the current `seen` or the current `approved` digest; \
                         `null` matches a null one of them."
                    },
                ),
                success: Success::Json(
                    schema_of(gen.subschema_for::<TrustKeyView>()),
                    "The key, decided",
                ),
                request: Some(schema_of(req_gen.subschema_for::<TrustKeyReq>())),
                query: Vec::new(),
                errors: vec![
                    (
                        "400",
                        format!(
                            "`invalid_request`: `malformed_body` — a body that is not the closed \
                             object `{{key, expected_digest}}`, an empty key, or an invalid \
                             `Idempotency-Key`; or {BODY_UNREADABLE}"
                        ),
                    ),
                    gated_403(),
                    (
                        "404",
                        "`not_found`: `unknown_resource` — no plane instance this node serves \
                         has the key"
                            .to_string(),
                    ),
                    (
                        "409",
                        "`conflict`: `reviewed_digest_stale` (the review is not current), \
                         `decision_in_progress` (another decision on the key holds it), \
                         `action_in_flight` (an earlier decision on the key is still settling), \
                         `state_conflict` (the key names more than one row, was never sighted, \
                         has no authenticity root, or its last sighting failed verification), \
                         `outcome_not_applied` (a replay proved the original attempt never \
                         applied; `details` `{operation, decided_at}`), `idempotency_mismatch` \
                         or `idempotency_in_flight`"
                            .to_string(),
                    ),
                    (
                        "428",
                        "`invalid_request`: `reviewed_digest_required` — `expected_digest` was \
                         omitted"
                            .to_string(),
                    ),
                    unavailable_503(
                        "`service_unavailable`: native trust custody is not installed or cannot \
                         keep decisions, the store did not apply the decision, or its outcome is \
                         unknown (`details` `{key, ruling, decided_at, decided_by, operation}`; \
                         do not re-submit with this key)",
                    ),
                ],
            }
        }
        KernelVerb::PlaneRecordWrite => VerbDoc {
            summary: "Upsert one record of a plane this node serves",
            description: "Upserted by `(kind, id)` through the plane-facing store the planes \
                          persist through, and only for a `kind` the named plane declares in its \
                          `record_kinds` (the plane instance's `runtime.plane.facts` lists them). `body` is stored as its \
                          JSON bytes and never decoded by the store; `terminal` is the retention \
                          disposition. Honors an `Idempotency-Key` header (per-principal, ~10min \
                          replay): a retry with the same key and body answers the first answer."
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
                (
                    "409",
                    "`conflict`: `this Idempotency-Key was already used with a different request \
                     body`, or `a request with this Idempotency-Key is already in flight`"
                        .to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, binds no record store, or the store \
                     failed",
                ),
            ],
        },
        KernelVerb::CommitUpgrade => VerbDoc {
            summary: "Commit the fleet to the release this node runs",
            description: "The body names the release; one this node does not run is refused and \
                          seals nothing. The committed release is sealed on the node journal \
                          before the answer names its position and chain hash. Honors an \
                          `Idempotency-Key` header (per-principal, ~10min replay): a retry with the \
                          same key and body answers the first commit and seals nothing again."
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
                    "`conflict`: ``this node runs `<release>`; it cannot commit `<version>` ``, \
                     `this Idempotency-Key was already used with a different request body`, or \
                     `a request with this Idempotency-Key is already in flight`"
                        .to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, or no journal will record the commit",
                ),
            ],
        },

        KernelVerb::Adjust => VerbDoc {
            summary: "Correct a key's COUNTS by a signed delta, never a money figure",
            description: "Money is the one ledger's counts x the rate card, so a correction moves \
                          counts: a signed delta per class on the key's counts for one lane and \
                          one history entry, applied at once, all or nothing, to the key's own \
                          budget bucket and each group bucket the named pool takes part in, and \
                          kept beside the day's metering rows so `GET /admin/usage` serves the \
                          counts as adjusted. A delta that would take any count below zero, or \
                          names counts the day's metering does not hold, is refused and nothing \
                          is applied."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<AdjustView>()),
                "The correction as applied",
            ),
            request: Some(schema_of(req_gen.subschema_for::<AdjustReq>())),
            query: Vec::new(),
            errors: vec![
                (
                    "400",
                    format!(
                        "`invalid_request`: malformed body, a blank `key`, `lane` or `reason`, \
                         an empty `delta` or a delta that is not a whole number, an `entry` the \
                         history does not hold, a missing `card_epoch_ms` or one no history \
                         entry covers or at which `entry` is not in force, a delta that would \
                         take a count below zero or that the epoch's metering day or budget \
                         window does not hold, a missing or blank `pool` or one \
                         naming no configured pool (the message says which), a scope below \
                         `full`, or {BODY_UNREADABLE}"
                    ),
                ),
                gated_403(),
                (
                    "404",
                    "`not_found`: no key by that id".to_string(),
                ),
                unavailable_503(
                    "the node could not take the unit, or the store could not take the \
                     correction",
                ),
            ],
        },
        KernelVerb::AmendRateHistory => VerbDoc {
            summary: "Append a back-dated correction to the dated rate-card history",
            description: "The correction out-ranks the entry it corrects and rewrites nothing; \
                          recompute reprices the corrected window against the new entry. A body \
                          carrying `currency` is refused. The durable record is written ahead of \
                          the append."
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
                         reason, a `currency` key, a negative fee or rate, a correction that \
                         moves no figure, or {BODY_UNREADABLE}"
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


        KernelVerb::GetLedgerTotals => ledger_read(
            "What the one ledger's counts come to, per key",
            "Each key's usage counts priced by the one function against the rate card each era \
             was earned under — the figure `GET /keys/{id}/usage` derives. A key whose counts \
             the rate card refused to price is withheld and named under `refused`; every other \
             key with anything counted is served.",
            schema_of(gen.subschema_for::<LedgerTotals>()),
            "The rows, in bucket, day, lane and provider order",
        ),
        KernelVerb::GetLedgerCheckpoints => ledger_read(
            "The sealed checkpoint figures",
            "Money is the one ledger's counts x the rate card, recomputed on every read, so no \
             balance checkpoint is sealed and the list is empty. The shape is kept for clients \
             that read it.",
            schema_of(gen.subschema_for::<LedgerCheckpoints>()),
            "The sealed checkpoints, oldest first",
        ),
        KernelVerb::GetLedgerReconciliation => ledger_read(
            "Whether the one ledger prices whole",
            "There is one ledger, so there is no second set of figures to be out by: \
             `discrepancies` is always empty, and `holds` is true unless a key's counts the rate \
             card refused to price are named under `refused`.",
            schema_of(gen.subschema_for::<LedgerReconciliation>()),
            "Whether the identity holds, and every row on which it does not",
        ),
        KernelVerb::GetLedgerMigration => ledger_read(
            "The marker the first boot after the upgrade sealed",
            "The previous release's rows ARE the one ledger's counts, read as they are, so no \
             migration is sealed: `migrated` is false and `marker` null.",
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


        KernelVerb::GetAuditHead => audit_read(
            "The audit record chain's tip: position, digest, signature, key identifier and clock",
            schema_of(gen.subschema_for::<AuditChainHeadView>()),
            "The recipe, the next position and the tip (null when nothing is sealed)",
        ),
        KernelVerb::GetAuditRange => {
            let mut doc = audit_read(
                "Audit records by position, each with every field its digest was taken over",
                schema_of(gen.subschema_for::<AuditChainRangeView>()),
                "The window's records, their stamps, cover and certificates, and the node's seal row",
            );
            doc.query = ["from", "to"]
                .into_iter()
                .map(|name| {
                    json!({
                        "name": name, "in": "query", "required": true,
                        "schema": {"type": "integer", "minimum": 0},
                        "description": format!(
                            "The window's {} position, inclusive. Both are required; `from` \
                             must not exceed `to`. Retention gaps are explicit; continue with \
                             next_cursor until null, including through empty pages.",
                            if name == "from" { "first" } else { "last" }
                        ),
                    })
                })
                .collect();
            doc.query.push(json!({
                "name": "cursor", "in": "query", "required": false,
                "schema": {"type": "string", "maxLength": 256},
                "description": "Opaque next_cursor from this audit range, bound to node/incarnation and the original from/to. The first page pins an upper bound; retention remains live. At most 64 journal positions (256 parts each) are scanned per page; at most 1024 cached records. No retries against concurrent appends."
            }));
            doc.errors.insert(
                0,
                (
                    "400",
                    "`invalid_request`: malformed or mismatched cursor; `from` or `to` missing or not a non-negative integer, or \
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
        KernelVerb::GetAuditKeys => {
            let mut doc = audit_read(
                "The public keys the audit chain is signed with",
                schema_of(gen.subschema_for::<AuditChainKeysView>()),
                "The published verifying keys (empty when the node signs nothing)",
            );
            doc.query = super::kinds::doc::query(&["cursor", "limit"]);
            doc.errors.insert(0, (
                "400",
                "`invalid_request`: malformed or mismatched pagination cursor".to_string(),
            ));
            doc
        },
        KernelVerb::GetOperationsKey => VerbDoc {
            summary: "One idempotent operation, by its Idempotency-Key",
            description: "The caller's own operation under `Idempotency-Key`: `state` is one of \
                `applied`, `rejected` or `in_flight`, with the status, the request digest, the \
                times, the config generation it ran under, and the stored response. A 404 means \
                the key is unknown or past retention. `?principal=` reads another principal's \
                operation and needs the `full` scope."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<OperationView>()),
                "The operation record",
            ),
            request: None,
            query: vec![
                json!({"name": "key", "in": "path", "required": true,
                       "schema": {"type": "string", "minLength": 1, "maxLength": 128}}),
                json!({"name": "principal", "in": "query", "required": false,
                       "schema": {"type": "string"}}),
            ],
            errors: vec![
                (
                    "404",
                    "`not_found`: the key is unknown or past retention".to_string(),
                ),
                unavailable_503("the Store could not read the operation"),
            ],
        },
        KernelVerb::GetConfigTree => VerbDoc {
            summary: "The whole configuration, declared or effective, under the secret rule",
            description: "`view=effective` (the default) is the resolved generation: every section \
                the kernel reads back (plugin and plane sections included) and `process`, the \
                command-line and environment inputs. `view=declared` is the configuration as \
                written, by `layer`: `base` (the operator's file as it stands), `overlay` (the \
                Store overlay's per-section documents, tombstones, document-patch paths and \
                version) or `merged` (both side by side, the default). `section=<dotted key>` \
                narrows the sections served. Every secret position (a secret-named field, a \
                plugin setting the plugin did not declare public, a private key) is \
                `{set, secret_ref}`: never a value, never a hash of one; public key material is \
                a `sha256` fingerprint. `digest` is over the projected sections. The ETag is the \
                config ETag."
                .to_string(),
            success: Success::Json(
                schema_of(gen.subschema_for::<super::config_tree::ConfigTreeView>()),
                "The configuration tree",
            ),
            request: None,
            query: super::config_tree::QUERY_DOC
                .iter()
                .filter_map(|param| busbar_contract::json::parse_foreign(param.as_bytes()).ok())
                .collect(),
            errors: vec![unavailable_503("the node could not take the read")],
        },
        KernelVerb::PutHooksNameAttachmentsTarget
        | KernelVerb::DeleteHooksNameAttachmentsTarget => {
            let attach = verb == KernelVerb::PutHooksNameAttachmentsTarget;
            VerbDoc {
                summary: if attach {
                    "Attach a hook at one attach point"
                } else {
                    "Detach a hook from one attach point"
                },
                description: "`target` is `pools` (every pool), `pools.<pool>`, a plane section, or \
                    `<section>.<instance>`, exactly as `HookView.attachments[].target` lists it. \
                    Attaching places the hook at `position` (`last` or a zero-based place) in that \
                    list; an attach that changes nothing, and a repeat, answer the same hook \
                    without a new generation. A hook defined in the base config file is refused \
                    (`base_defined`). Audited as `hook.attach` and `hook.detach`; config budget."
                    .to_string(),
                success: Success::Json(
                    schema_of(gen.subschema_for::<crate::v1::contract::HookView>()),
                    "The hook, with its attachments after the change",
                ),
                request: attach.then(|| {
                    schema_of(req_gen.subschema_for::<crate::v1::contract::HookAttachRequest>())
                }),
                query: vec![
                    json!({"name": "name", "in": "path", "required": true,
                           "schema": {"type": "string"}}),
                    json!({"name": "target", "in": "path", "required": true,
                           "schema": {"type": "string"}}),
                ],
                errors: vec![
                    (
                        "400",
                        format!("`invalid_request`: malformed body or target, a position past the end, or {BODY_UNREADABLE}"),
                    ),
                    gated_403(),
                    (
                        "404",
                        "`not_found`: no such hook or pool, or (detach) the hook is not attached there"
                            .to_string(),
                    ),
                    (
                        "409",
                        "`conflict`: `base_defined`, an attach point the configuration does not \
                         have, or a higher-priority override of the list"
                            .to_string(),
                    ),
                    unavailable_503("the Store could not commit the change"),
                ],
            }
        }
        KernelVerb::GetRecords => records_doc(schema_of(
            gen.subschema_for::<crate::v1::records::RecordsPage>(),
        )),
        _ => return None,
    })
}

/// `GET /records` (ADMIN-API-1.6 §3.3): the per-unit records feed of this node.
#[cfg(feature = "openapi-schema")]
fn records_doc(schema: Value) -> VerbDoc {
    use crate::v1::records::{
        RECORDS_LIMIT_DEFAULT, RECORDS_LIMIT_MAX, RECORDS_SCAN_BOUND, RECORDS_WAIT_MAX_SECS,
    };
    let text = |name: &str, description: &str| {
        json!({"name": name, "in": "query", "required": false,
               "schema": {"type": "string"}, "description": description})
    };
    let integer = |name: &str, maximum: u64, description: &str| {
        json!({"name": name, "in": "query", "required": false,
               "schema": {"type": "integer", "minimum": 0, "maximum": maximum},
               "description": description})
    };
    let mut query = vec![
        text(
            "cursor",
            "Opaque `next_cursor` of an earlier page of this node. A cursor of another node is \
             400 `cursor_mismatch` with `details.cursor_node_id`.",
        ),
        integer(
            "limit",
            RECORDS_LIMIT_MAX as u64,
            &format!("At most this many records (default {RECORDS_LIMIT_DEFAULT})."),
        ),
        integer(
            "wait",
            RECORDS_WAIT_MAX_SECS,
            "Seconds to wait for a record when the page would be empty and caught up.",
        ),
        integer(
            "from_ms",
            u64::MAX,
            "A SEEK, not a filter: the first page starts at the first record whose \
             `arrived_at_ms` is at least this (a binary search over the chain). Ignored with a \
             cursor. A backward clock step can misplace records near the boundary.",
        ),
        integer(
            "to_ms",
            u64::MAX,
            "Only records whose `arrived_at_ms` is before this.",
        ),
    ];
    for name in [
        "kind", "instance", "key", "group", "model", "provider", "target", "outcome", "reason",
        "unit",
    ] {
        query.push(text(
            name,
            "An exact filter on the record field of this name.",
        ));
    }
    VerbDoc {
        summary: "Per-unit records: the sealed audit chain, one record per unit, as a feed",
        description: format!(
            "A read-time projection of this node's sealed per-unit audit records, oldest first. \
             `next_cursor` is always a string; `complete: true` means caught up. With no cursor \
             the feed starts at the oldest retained record. A request scans at most \
             {RECORDS_SCAN_BOUND} sealed records, so a filtered page may be short or empty with a \
             cursor that continues. Records are per node: the `core/process` view `nodes` lists every node. Spend \
             is priced at read by the rule `GET /usage` uses. A read: it mutates nothing and is \
             never posture-gated."
        ),
        success: Success::Json(schema, "One page of records"),
        request: None,
        query,
        errors: vec![
            (
                "400",
                "`invalid_request`: a malformed or unknown query parameter or cursor; \
                 `cursor_mismatch`: a cursor of another node"
                    .to_string(),
            ),
            (
                "404",
                "`not_found`: this node binds no audit chain to read".to_string(),
            ),
            (
                "410",
                "`cursor_expired`: the cursor's position is no longer retained; \
                 `details.oldest_available` resumes"
                    .to_string(),
            ),
            unavailable_503("the node could not take the unit, or the chain did not answer"),
        ],
    }
}

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

        for (status, description) in doc.errors {
            by_status.insert(status.into(), json!({ "description": description }));
        }

        let rel = path
            .strip_prefix(crate::v1::contract::ADMIN_PREFIX)
            .unwrap_or(&path);
        if let Some(tag) = crate::v1::contract::taxonomy::MethodTag::from_op_key(&method) {
            for (status, description) in crate::v1::contract::taxonomy::declared_responses(tag, rel)
            {
                by_status.insert(status, json!({ "description": description }));
            }
        }
        let http_method = match method.as_str() {
            "get" => axum::http::Method::GET,
            "post" => axum::http::Method::POST,
            "put" => axum::http::Method::PUT,
            "patch" => axum::http::Method::PATCH,
            "delete" => axum::http::Method::DELETE,
            _ => continue,
        };
        let scope = crate::v1::contract::required_scope(&http_method, &path);
        let mut op = json!({
            "summary": doc.summary,
            "description": doc.description,
            "security": [{"adminToken": []}, {"bearerAuth": []}],
            "x-busbar-required-scope": scope.as_str(),
            "x-busbar-since": SINCE,
            RESPONSES_KEY: by_status,
        });
        if let Some(verb) = crate::admin_codec::verbs::name_at(http_method.as_str(), &path) {
            op["x-busbar-verb"] = json!(verb);
        }
        if !doc.query.is_empty() {
            op["parameters"] = Value::Array(doc.query);
        }
        if let Some(schema) = doc.request {
            op["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": schema}}
            });
        }
        if matches!(verb, KernelVerb::TrustApprove | KernelVerb::TrustRevoke) {
            // TRUST-ADMIN-PRODUCER-DESIGN r3 §4.5: every answer carries the host's classification.
            // Refusals before the decision (authentication, scope, budget) do not carry it.
            if let Some(responses) = op[RESPONSES_KEY].as_object_mut() {
                for (_, response) in responses
                    .iter_mut()
                    .filter(|(status, _)| !matches!(status.as_str(), "401" | "403" | "429"))
                {
                    response["headers"]["x-busbar-trust-effect"] = json!({
                        "description": "Host-created classification of this answer's effect: \
                                        `applied`, `not_applied` (nothing changed) or `unknown` \
                                        (the decision may still land; replay the same \
                                        Idempotency-Key). Never derived from a request header.",
                        "schema": {"enum": ["applied", "not_applied", "unknown"]}
                    });
                }
            }
        }
        out.push((path, method, op));
    }
    out
}

#[cfg(all(test, feature = "openapi-schema"))]
#[test]
fn trust_request_schema_requires_a_reviewed_digest_or_null() {
    // TRUST-ADMIN-PRODUCER-DESIGN r3 §4.1: both members are required; `null` is a review.
    let schema = serde_json::to_value(schemars::schema_for!(TrustKeyReq)).unwrap();
    assert_eq!(
        schema["required"],
        serde_json::json!(["key", "expected_digest"])
    );
    assert_eq!(
        schema["properties"]["expected_digest"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(schema["properties"]["expected_digest"]["pattern"], r"\S");
}

#[cfg(all(test, feature = "openapi-schema"))]
#[test]
fn trust_key_state_is_the_frozen_enum() {
    let schema = serde_json::to_value(schemars::schema_for!(TrustKeyView)).unwrap();
    assert_eq!(
        schema["properties"]["state"]["enum"],
        serde_json::json!(crate::trust_inventory::KEY_STATES)
    );
}
