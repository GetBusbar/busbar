// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::state` cold code (see `crate::cold::governance`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, RwLock};

use busbar_contract::count::{Count, COUNT_SCALE};
use busbar_contract::kept::Text;
use busbar_contract::records::ScopeRef;

use crate::governance::{BudgetCell, LimitBlocked, MeterKey, UsageDelta};

/// `mod`: an owned-message error's text, rendered once on the failure path (`rendered_error`).
#[cold]
pub(crate) fn mod_error_text(error: &dyn std::fmt::Display) -> String {
    error.to_string()
}

/// `mod`: the per-bucket overflow sentinel a metering cell coalesces into once its shard is at cap.
#[cold]
pub(crate) fn mod_overflow_sentinel(key: &MeterKey) -> MeterKey {
    (
        crate::governance::METERING_OVERFLOW_KEY_ID.to_owned(),
        key.1,
        crate::governance::METERING_OVERFLOW_LABEL.to_owned(),
        crate::governance::METERING_OVERFLOW_LABEL.to_owned(),
        key.4,
        String::new(),
        key.6.clone(),
    )
}

/// `mod`: a metering cell's owned identity, copied from the probe once, when the cell is created.
#[cold]
pub(crate) fn mod_meter_key_first(key: &MeterKey) -> MeterKey {
    key.clone()
}

/// `mod`: the overflow warning throttle's clock reading, taken only once the accumulator is at cap.
#[cold]
pub(crate) fn mod_overflow_instant() -> std::time::Instant {
    std::time::Instant::now()
}

/// `state`: an admission refused because the key names a group this node does not have.
#[cold]
pub(crate) fn state_missing_group(group: &str) -> LimitBlocked {
    LimitBlocked::MissingGroup(group.to_owned())
}

/// `state`: an admission refused by one limit bucket, naming its group, metric and window.
#[cold]
pub(crate) fn state_limit_blocked(
    group: &str,
    metric: &'static str,
    window: Option<&'static str>,
    pool: Option<&ScopeRef>,
    downgrade_to: Option<&ScopeRef>,
    retry_after: Option<u64>,
) -> LimitBlocked {
    LimitBlocked::Limit {
        group: group.to_owned(),
        metric,
        window,
        pool: pool.map(|s| s.value.clone()),
        downgrade_to: downgrade_to.map(|s| s.value.clone()),
        retry_after,
    }
}

/// `state`: the one-fee-request unit map, built once per process.
#[cold]
pub(crate) fn state_per_request_one() -> BTreeMap<String, Count> {
    let mut one = BTreeMap::new();
    one.insert(
        busbar_kernel_ledger::cost::PER_REQUEST.to_owned(),
        Count::ONE,
    );
    one
}

/// `state`: a bucket's cell, keyed once, the first time the bucket is charged: the one allocation
/// of the bucket's name, which the map keeps as its key for the cell's life. It answers the key
/// with the cell, so the charge that made it names it by sharing the key.
#[cold]
pub(crate) fn state_fresh_cell<'m>(
    map: &'m mut foldhash::HashMap<Text, BudgetCell>,
    bucket: &str,
    window: u64,
) -> (Text, &'m mut BudgetCell) {
    let name = Text::from(Arc::<str>::from(bucket));
    let cell = map
        .entry(name.clone())
        .or_insert_with(|| BudgetCell::fresh(window));
    (name, cell)
}

/// `state`: a bucket learns an owning group once, the first time it is charged through it.
#[cold]
pub(crate) fn state_owner_first(owners: &mut BTreeSet<String>, group: &str) {
    owners.insert(group.to_owned());
}

/// `state`: a group's concurrency gauge, keyed once, the first time the group is admitted.
#[cold]
pub(crate) fn state_concurrent_gauge_first(
    gauges: &RwLock<foldhash::HashMap<String, Arc<AtomicI64>>>,
    group: &str,
) -> Arc<AtomicI64> {
    gauges
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .entry(group.to_owned())
        .or_default()
        .clone()
}

/// `state`: a bucket's first authoritative observation total, keyed once per bucket.
#[cold]
pub(crate) fn state_observation_first(
    view: &mut foldhash::HashMap<
        String,
        foldhash::HashMap<u64, crate::persistence::observations::BudgetTotal>,
    >,
    bucket: &str,
    window: u64,
    total: crate::persistence::observations::BudgetTotal,
) {
    view.entry(bucket.to_owned())
        .or_default()
        .insert(window, total);
}

/// `state`: the one fee a failed request takes back from a window its cell already rolled past.
#[cold]
pub(crate) fn state_refund_delta(lane: Option<(&str, &str)>) -> UsageDelta {
    match lane {
        None => UsageDelta {
            billable_requests: -1,
            ..UsageDelta::default()
        },
        Some((lane, unit)) => {
            let mut usage_units = BTreeMap::new();
            usage_units.insert(unit.to_owned(), -1_000_000);
            UsageDelta {
                models: vec![busbar_contract::records::ModelTokensDelta {
                    scale: COUNT_SCALE,
                    model: lane.to_owned(),
                    usage_units,
                }],
                ..UsageDelta::default()
            }
        }
    }
}

/// `signing`: the signed token text, `prefix` + base64url(payload) + `.` + base64url(signature),
/// built once per key mint, token exchange or ticket mint.
#[cold]
pub(crate) fn signing_token(
    key: &busbar_contract::crypto::ed25519::SigningKey,
    prefix: &str,
    claims: &impl serde::Serialize,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let payload = busbar_contract::json::to_vec(claims).expect("TokenClaims serializes");
    let sig = key.sign(&payload);
    let encoded = |bytes: usize| bytes.div_ceil(3) * 4;
    let mut token = String::with_capacity(prefix.len() + encoded(payload.len()) + 1 + encoded(64));
    token.push_str(prefix);
    URL_SAFE_NO_PAD.encode_string(&payload, &mut token);
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(sig, &mut token);
    token
}

/// `tickets`: a ticket's expiry index key (big-endian expiry, then the id), built once per ticket
/// mint, spend, cleanup or legacy import.
#[cold]
pub(crate) fn tickets_expiry_key(id: &str, expiry: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + id.len());
    key.extend_from_slice(&expiry.to_be_bytes());
    key.extend_from_slice(id.as_bytes());
    key
}

/// `tickets`: a ticket's stored record (version byte, expiry, body), built once per ticket mint or
/// legacy import.
#[cold]
pub(crate) fn tickets_encoded_record(
    expires_at: u64,
    record: &[u8],
) -> busbar_contract::Secret<Vec<u8>> {
    let mut bytes = Vec::with_capacity(9 + record.len());
    bytes.push(1);
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes.extend_from_slice(record);
    busbar_contract::Secret::new(bytes)
}

/// `tickets`: the consumer body a ticket's spend hands back, copied once per redemption.
#[cold]
pub(crate) fn tickets_record_body(body: &[u8]) -> busbar_contract::Secret<Vec<u8>> {
    busbar_contract::Secret::new(body.to_vec())
}

/// `tickets`: the three addresses a ticket is observed through, owned by its one store read.
#[cold]
pub(crate) fn tickets_read_addresses(
    addresses: &[busbar_contract::persistence::Address; 3],
) -> Vec<busbar_contract::persistence::Address> {
    addresses.to_vec()
}

/// `tickets`: the retained cleanup operation's map key for one expired ticket.
#[cold]
pub(crate) fn tickets_cleanup_id(id: &str) -> String {
    format!("expiry:{id}")
}

/// `tickets`: a cleanup operation, retained once, the first time its expired ticket is purged.
#[cold]
pub(crate) fn tickets_keep_first<T>(
    pending: &mut BTreeMap<String, Arc<T>>,
    id: &str,
    operation: Arc<T>,
) -> Arc<T> {
    pending.insert(id.to_owned(), operation.clone());
    operation
}

/// `tickets`: the audit resource of a ticket refused because its signing key rotated.
#[cold]
pub(crate) fn tickets_rotated_resource(sub: &str) -> String {
    format!("key:{sub}")
}
