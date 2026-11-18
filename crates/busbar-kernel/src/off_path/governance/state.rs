// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::state` off-path code (see `crate::off_path::governance`).

use std::collections::{BTreeMap, VecDeque};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::count::Count;
use busbar_contract::kept::Text;
use busbar_contract::records::{ModelTokensDelta, ScopeRef};
use busbar_kernel_ledger::cost::RawRateEra;

use crate::governance::{
    BudgetCell, MeterCounts, ModelCell, RecordStoreError, RecordStoreResult, UsageDelta, VirtualKey,
};

/// `mod`: a binding marker, minted once per key mint, rotation or revocation (control plane).
pub(crate) fn mod_binding_marker(prefix: &str, id: &str, generation: &str) -> String {
    format!("{prefix}{id}:{generation}")
}

/// `mod`: a synthesized principal key's marker (`synthesize_principal_key`, the embedder entry
/// point; the served path synthesizes bound keys).
pub(crate) fn mod_principal_marker(prefix: &str, id: &str) -> String {
    format!("{prefix}{id}")
}

/// `mod`: a ledger row's stored name, rendered once per durable row write, read or correction.
pub(crate) fn mod_era_text(name: &dyn std::fmt::Display) -> String {
    name.to_string()
}

/// `mod`: a usage delta re-keyed under its card era, built for a budget flush or a failed
/// request's refund into a rolled window.
pub(crate) fn mod_dated_delta(delta: &UsageDelta, era: RawRateEra) -> UsageDelta {
    if era == RawRateEra::legacy(0) {
        return UsageDelta::default();
    }
    let mut models: Vec<_> = delta
        .models
        .iter()
        .map(|model| ModelTokensDelta {
            model: crate::governance::era_model(era, &model.model),
            scale: model.scale,
            usage_units: model.usage_units.clone(),
        })
        .collect();
    if delta.billable_requests != 0 {
        let mut usage_units = BTreeMap::new();
        usage_units.insert(
            crate::governance::era_text(crate::governance::ERA_FEE_UNIT),
            i128::from(delta.billable_requests),
        );
        models.push(ModelTokensDelta {
            model: crate::governance::era_tag(era),
            scale: 0,
            usage_units,
        });
    }
    UsageDelta {
        models,
        ..UsageDelta::default()
    }
}

/// `mod`: per-class reporting views of one lane's counts, for the metrics scrape and usage views.
pub(crate) fn mod_token_series(
    lane: &str,
    counts: &BTreeMap<String, Count>,
) -> Vec<(String, Count)> {
    use crate::plane_driver::registry::TOKEN_FAMILY;
    let owner = crate::governance::class_owner(lane);
    let mut series: Vec<(String, Count)> = owner
        .into_iter()
        .flat_map(|d| {
            (d.billable_classes.iter())
                .filter(|c| c.family == TOKEN_FAMILY && !d.fee_units.contains(&c.class))
                .map(|c| c.class)
        })
        .map(|class| {
            (
                class.to_string(),
                crate::governance::class_total(lane, counts, class).expect("validated class total"),
            )
        })
        .collect();
    for (class, n) in counts {
        if crate::governance::is_token_class(class)
            && !series.iter().any(|(named, _)| named == class)
        {
            series.push((class.clone(), *n));
        }
    }
    series
}

/// `mod`: a legacy whole-unit count map converted to exact counts (the whole-unit test and
/// embedder entry points; the served path carries exact counts).
pub(crate) fn mod_whole_counts(units: &BTreeMap<String, u64>) -> BTreeMap<String, Count> {
    units
        .iter()
        .map(|(k, v)| (k.clone(), crate::governance::whole_count(*v)))
        .collect()
}

/// `mod`: a key's grant list, built once per key mint or binding load (control plane).
pub(crate) fn mod_grant_scopes(
    pools: Option<Vec<String>>,
    plane: Option<Vec<ScopeRef>>,
) -> Option<Vec<ScopeRef>> {
    if pools.is_none() && plane.is_none() {
        return None;
    }
    let mut list: Vec<ScopeRef> = pools.into_iter().flatten().map(ScopeRef::pool).collect();
    list.extend(plane.into_iter().flatten());
    Some(list)
}

/// `mod`: a self-serve key's pool grant, built once per mint (control plane).
pub(crate) fn mod_pool_scopes(list: Vec<String>) -> Vec<ScopeRef> {
    list.into_iter().map(ScopeRef::pool).collect()
}

/// `mod`: `n` symbols drawn uniformly-by-byte from `alphabet`, once per credential mint.
fn mod_draw(alphabet: &str, n: usize) -> Result<String, busbar_contract::crypto::RngError> {
    let symbols = alphabet.as_bytes();
    if symbols.is_empty() {
        return Ok(String::new());
    }
    let mut buf = vec![0u8; n];
    busbar_contract::crypto::fill(&mut buf)?;
    Ok(buf
        .iter()
        .map(|&b| char::from(symbols[usize::from(b) % symbols.len()]))
        .collect())
}

/// `mod`: a minted credential's public id and secret, built once per credential mint.
pub(crate) fn mod_issue_credential(
    shape: &busbar_contract::auth_calls::IssuedShape,
) -> Result<(String, String), busbar_contract::crypto::RngError> {
    let tail = shape.id_len.saturating_sub(shape.id_prefix.len());
    let tail = mod_draw(&shape.id_alphabet, tail)?;
    let id = format!("{}{tail}", shape.id_prefix);
    Ok((id, mod_draw(&shape.secret_alphabet, shape.secret_len)?))
}

/// `mod`: a cell's dead model rows (no count, no baseline) dropped, in the periodic shard sweep.
pub(crate) fn mod_prune_dead_models(cell: &mut BudgetCell) {
    if cell.correction.is_some() {
        return;
    }
    cell.models.retain(|m| {
        crate::governance::has_units(&m.cur)
            || crate::governance::has_units(&m.flushed)
            || crate::governance::has_units(&m.flushed_era)
    });
}

/// `state`: a new virtual key id, rendered once per key mint.
pub(crate) fn state_vk_id(prefix: &str, raw: &[u8]) -> String {
    format!("{prefix}{}", hex::encode(raw))
}

/// `state`: the agent-card issuer's key id, resolved once when the planes start.
pub(crate) fn state_card_kid(prefix: &str, kid: &str) -> String {
    format!("{prefix}{kid}")
}

/// `state`: an operator's group delete reclaims the clean cells only that group owned.
pub(crate) fn state_reclaim_group_cells<G>(shards: impl Iterator<Item = G>, group: &str) -> usize
where
    G: DerefMut<Target = foldhash::HashMap<Text, BudgetCell>>,
{
    let mut dropped = 0usize;
    for mut shard in shards {
        let before = shard.len();
        shard.retain(|_, cell| {
            if cell.dirty
                || cell.flushing != 0
                || cell.correction.is_some()
                || !cell.group_owners.contains(group)
            {
                return true;
            }
            cell.group_owners.remove(group);
            !cell.group_owners.is_empty()
        });
        dropped += before - shard.len();
    }
    dropped
}

/// `state`: boot hydration's bucket list: every key's own bucket, then every group bucket.
pub(crate) fn state_hydration_buckets(
    keys: &[VirtualKey],
    cost: &crate::cost::CostModel,
) -> Vec<(String, &'static str, Option<String>)> {
    let mut buckets = Vec::new();
    for key in keys {
        buckets.push((key.id.clone(), crate::governance::WINDOW_TOTAL, None));
    }
    for group in cost.groups() {
        for bucket in &group.buckets {
            buckets.push((
                bucket.bucket_id.clone(),
                bucket.window,
                Some(group.name.clone()),
            ));
        }
    }
    buckets
}

/// `state`: the periodic budget shard sweep (once per `rate_sweep_interval` admissions on the
/// shard): drops aged clean cells, then prunes dead model rows from the cells it keeps.
pub(crate) fn state_sweep_budget_shard(
    map: &mut foldhash::HashMap<Text, BudgetCell>,
    cost: &crate::cost::CostModel,
    now: u64,
) {
    let max_window = 31 * crate::governance::SECS_PER_DAY;
    map.retain(|id, c| {
        if c.window_start != 0 {
            return c.correction.is_some()
                || c.fee_obligations != 0
                || c.dirty
                || c.flushing != 0
                || c.window_start.saturating_add(max_window) > now;
        }

        c.correction.is_some()
            || c.fee_obligations != 0
            || cost.bucket_enforces_a_cap(id)
            || c.dirty
            || c.flushing != 0
            || c.last_touch.saturating_add(max_window) > now
    });

    for c in map.values_mut() {
        mod_prune_dead_models(c);
    }
}

/// `state`: shutdown custody inspection: whether any pending metering cell still holds a count.
pub(crate) fn state_metering_nonzero<K>(
    shards: &[Mutex<foldhash::HashMap<K, MeterCounts>>],
) -> bool {
    shards.iter().any(|shard| {
        shard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|counts| !counts.is_zero())
    })
}

/// `state`: shutdown custody inspection: whether any retained entry is unsettled, judged on a
/// copy taken under the lock so the judgement runs without it.
pub(crate) fn state_any_unsettled<V: Clone>(
    retained: &Mutex<foldhash::HashMap<String, V>>,
    unsettled: impl Fn(&V) -> bool,
) -> bool {
    let copies: Vec<V> = retained
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .values()
        .cloned()
        .collect();
    copies.iter().any(unsettled)
}

/// `state`: the budget flush tick's backstop clock reading, once per tick.
pub(crate) fn state_flush_instant() -> std::time::Instant {
    std::time::Instant::now()
}

/// `state`: the budget flush's second walk over the selected shards. `visit` captures one dirty
/// cell's flights into the list and answers whether the cell is left dirty; a shard holding a
/// cell left dirty is handed to `reflag` while its lock is held.
pub(crate) fn state_flush_walk<G, T>(
    shards: impl Iterator<Item = (usize, G)>,
    mut visit: impl FnMut(&Text, &mut BudgetCell, &mut Vec<T>) -> bool,
    mut reflag: impl FnMut(usize),
) -> Vec<T>
where
    G: DerefMut<Target = foldhash::HashMap<Text, BudgetCell>>,
{
    let mut flights = Vec::new();
    for (index, mut map) in shards {
        let mut left_dirty = false;
        for (id, cell) in map.iter_mut() {
            left_dirty |= visit(id, cell, &mut flights);
        }
        if left_dirty {
            reflag(index);
        }
    }
    flights
}

/// `state`: a bucket's cell rebuilt from its durable rows (hydration, recovery, corrections and
/// operator usage views), never on the served path.
pub(crate) fn state_durable_cell(
    bucket_id: &str,
    row: busbar_contract::records::UsageLedger,
    eras: busbar_contract::records::UsageLedger,
    window: u64,
) -> RecordStoreResult<BudgetCell> {
    use crate::governance::{parse_era_tag, rendered_error, ERA_FEE_UNIT, ERA_MODEL_SEP};
    let mut cell = BudgetCell::fresh(window);
    cell.requests = row.requests;
    cell.billable_requests = row.billable_requests;
    cell.flushed_requests = row.requests;
    cell.flushed_billable_requests = row.billable_requests;
    cell.models = state_durable_segments(bucket_id, row.models)?;
    let (mut fees, mut undated_fees) = (Vec::new(), row.billable_requests);
    for e in eras.models {
        for raw in e.usage_units.values() {
            let count = Count::from_stored(*raw, e.scale)
                .map_err(|e| rendered_error(RecordStoreError, e))?;
            if count.is_negative() {
                return Err(RecordStoreError("negative durable era usage total".into()));
            }
        }
        let (era, model) = match e.model.split_once(ERA_MODEL_SEP) {
            Some((era, model)) => (era, Some(model)),
            None => (e.model.as_str(), None),
        };
        let Some(era) = parse_era_tag(era)? else {
            continue;
        };
        if era == RawRateEra::legacy(0) {
            continue;
        }
        let Some(model) = model else {
            let count = Count::from_stored(
                e.usage_units.get(ERA_FEE_UNIT).copied().unwrap_or(0),
                e.scale,
            )
            .map_err(|e| rendered_error(RecordStoreError, e))?;
            if count.micros() % 1_000_000 != 0 {
                return Err(RecordStoreError("fractional fee count".into()));
            }
            let n = u64::try_from(count.micros() / 1_000_000)
                .map_err(|e| rendered_error(RecordStoreError, e))?
                .min(undated_fees);
            undated_fees -= n;
            fees.push((era, n));
            continue;
        };
        let rest =
            (cell.models.iter_mut()).find(|m| m.era == RawRateEra::legacy(0) && *m.model == *model);
        let Some(rest) = rest else {
            continue;
        };
        let mut cur = BTreeMap::new();
        for (unit, n) in e.usage_units {
            let left = rest.cur.get(&unit).copied().unwrap_or_default();
            let n =
                Count::from_stored(n, e.scale).map_err(|e| rendered_error(RecordStoreError, e))?;
            let n = n.min(left);
            if n.is_zero() {
                continue;
            }
            if left == n {
                rest.cur.remove(&unit);
            } else {
                rest.cur.insert(
                    unit.clone(),
                    left.checked_sub(n)
                        .map_err(|e| rendered_error(RecordStoreError, e))?,
                );
            }
            cur.insert(unit, n);
        }
        let model = rest.model.clone();
        cell.models.extend(ModelCell::new(
            model,
            era,
            cur,
            BTreeMap::new(),
            BTreeMap::new(),
        ));
    }
    for m in &mut cell.models {
        m.flushed = m.cur.clone();
        m.flushed_era = m.cur.clone();
    }
    cell.fee_eras = busbar_kernel_ledger::usage::FeeEras::of(fees);
    cell.flushed_fee_eras = cell.fee_eras.clone();
    Ok(cell)
}

/// `state`: a durable row's model segments, each validated and rebuilt (see
/// [`state_durable_cell`]).
fn state_durable_segments(
    bucket_id: &str,
    rows: Vec<busbar_contract::records::ModelTokens>,
) -> RecordStoreResult<Vec<ModelCell>> {
    use crate::governance::rendered_error;
    let mut dropped = 0usize;
    let cells = rows
        .into_iter()
        .map(|m| -> RecordStoreResult<Option<ModelCell>> {
            let cur = m
                .usage_units
                .into_iter()
                .map(|(unit, n)| {
                    let count = Count::from_stored(n, m.scale)
                        .map_err(|e| rendered_error(RecordStoreError, e))?;
                    if count.is_negative() {
                        return Err(RecordStoreError("negative durable usage total".into()));
                    }
                    Ok((unit, count))
                })
                .collect::<RecordStoreResult<_>>()?;
            Ok(ModelCell::new(
                m.model.into(),
                RawRateEra::legacy(0),
                cur,
                BTreeMap::new(),
                BTreeMap::new(),
            ))
        })
        .filter_map(|row| match row {
            Ok(None) => {
                dropped += 1;
                None
            }
            Ok(Some(row)) => Some(Ok(row)),
            Err(e) => Some(Err(e)),
        })
        .collect::<RecordStoreResult<Vec<_>>>()?;
    if dropped != 0 {
        // A Store written by a pre-fix 1.6.0 rc heals here: the row carries no count and no
        // flushed baseline, so it owes no money and creates no correction debt (UPG-H2).
        tracing::warn!(
            bucket = bucket_id,
            dropped,
            "usage ledger load: dropped {dropped} unnamed-lane rows with no counts"
        );
    }
    Ok(cells)
}

/// `sharded`: the budget flush tick swaps every shard's flag to clean and answers the flagged
/// shards as a mask (bit `i` = shard `i`).
pub(crate) fn sharded_take_flags<'a>(flags: impl Iterator<Item = &'a AtomicBool>) -> u64 {
    flags.enumerate().fold(0u64, |mask, (index, flag)| {
        if flag.swap(false, Ordering::AcqRel) {
            mask | (1u64 << index)
        } else {
            mask
        }
    })
}

/// `metering_flush`: the keys of the operations the flight still retains, once per flush tick.
pub(crate) fn metering_flush_key_set<'a, K>(
    keys: impl Iterator<Item = &'a K>,
) -> foldhash::HashSet<K>
where
    K: Clone + Eq + std::hash::Hash + 'a,
{
    keys.cloned().collect()
}

/// `metering_flush`: the flush tick moves every pending cell whose key the flight does not retain
/// into the flight, shard by shard.
pub(crate) fn metering_flush_take_unretained<K, V, T>(
    shards: &[Mutex<foldhash::HashMap<K, V>>],
    retained: &foldhash::HashSet<K>,
    flight: &mut VecDeque<T>,
    mut make: impl FnMut((K, V)) -> Option<T>,
) where
    K: Eq + std::hash::Hash,
{
    for shard in shards {
        let mut map = shard.lock().unwrap_or_else(|p| p.into_inner());
        let kept: Vec<(K, V)> = retained
            .iter()
            .filter_map(|key| map.remove_entry(key))
            .collect();
        flight.extend(map.drain().filter_map(&mut make));
        map.extend(kept);
    }
}

/// `metering_flush`: a first attempt's first-send wall time in milliseconds.
pub(crate) fn metering_flush_attempt_clock() -> u64 {
    crate::store::now_ms()
}

/// `metering_flush`: the fresh pending cells a failed shutdown flush leaves behind.
pub(crate) fn metering_flush_fresh_cells<K, V>(shards: &[Mutex<foldhash::HashMap<K, V>>]) -> usize {
    shards
        .iter()
        .map(|shard| shard.lock().unwrap_or_else(|p| p.into_inner()).len())
        .sum()
}

/// `revocation`: the refresh clock's origin, read once when the identity cache is built.
pub(crate) fn revocation_clock_origin() -> std::time::Instant {
    std::time::Instant::now()
}

/// `revocation`: a revocation recorded once, when a key or subject is revoked (control plane).
pub(crate) fn revocation_insert(set: &mut foldhash::HashSet<String>, sub: &str) {
    set.insert(sub.to_owned());
}

/// `money_view`: the period a usage view's memo entry is priced for.
pub(crate) fn money_view_period(period: &str) -> String {
    period.to_owned()
}

/// `money_view`: the model facts a usage view's memo entry is priced from.
pub(crate) fn money_view_models(
    cell: &BudgetCell,
) -> Vec<(Arc<str>, RawRateEra, BTreeMap<String, Count>)> {
    (cell.models.iter())
        .map(|m| (m.model.clone(), m.era, m.cur.clone()))
        .collect()
}

/// `money_view`: a bucket's first memo entry, keyed once.
pub(crate) fn money_view_keep_first<V>(
    memo: &mut foldhash::HashMap<String, V>,
    bucket_id: &str,
    entry: V,
) {
    memo.insert(bucket_id.to_owned(), entry);
}

/// `tickets`: maintenance's snapshot of the retained ticket operations, taken under the lock.
pub(crate) fn tickets_pending_snapshot<T>(
    pending: &BTreeMap<String, Arc<T>>,
) -> Vec<(String, Arc<T>)> {
    pending
        .iter()
        .map(|(id, op)| (id.clone(), op.clone()))
        .collect()
}

/// `tickets`: shutdown custody inspection: whether any retained ticket operation is unsettled.
pub(crate) fn tickets_any_unsettled<T>(
    pending: &BTreeMap<String, Arc<T>>,
    unsettled: impl Fn(&T) -> bool,
) -> bool {
    pending.values().any(|operation| unsettled(operation))
}

/// `tickets`: host custody maintenance's batched liveness observation of many tickets (see
/// `governance::ticket_records_live`).
pub(crate) async fn tickets_records_live(
    core: Arc<crate::persistence::facade::CoreStore>,
    items: &[(String, u64)],
) -> RecordStoreResult<Vec<RecordStoreResult<bool>>> {
    use crate::governance::tickets::{judge_ticket, ticket_addresses, tickets_per_read};
    use busbar_contract::persistence::{Read, ReadResult};
    let mut verdicts = Vec::with_capacity(items.len());
    for chunk in items.chunks(tickets_per_read(&core)) {
        let mut addresses = Vec::with_capacity(chunk.len() * 3);
        let mut judged = Vec::with_capacity(chunk.len());
        for (id, expires_at) in chunk {
            match ticket_addresses(id, *expires_at) {
                Ok(three) => {
                    addresses.extend(three);
                    judged.push(Ok(*expires_at));
                }
                Err(error) => judged.push(Err(error)),
            }
        }
        if addresses.is_empty() {
            verdicts.extend(judged.into_iter().map(|judged| judged.map(|_| false)));
            continue;
        }
        let observed = core
            .backend()
            .read(Arc::new(Read {
                dataset: core.info().dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(|_| RecordStoreError("native ticket observation unavailable".into()))?;
        let ReadResult::Values {
            observed_at,
            values,
        } = observed
        else {
            return Err(RecordStoreError(
                "invalid native ticket batch observation".into(),
            ));
        };
        let readable = judged.iter().filter(|judged| judged.is_ok()).count();
        if observed_at.authority != core.info().clock_authority || values.len() != readable * 3 {
            return Err(RecordStoreError(
                "invalid native ticket batch observation".into(),
            ));
        }
        let mut values = values.into_iter();
        for judged in judged {
            let expires_at = match judged {
                Ok(expires_at) => expires_at,
                Err(error) => {
                    verdicts.push(Err(error));
                    continue;
                }
            };
            let (Some(active), Some(spent), Some(index)) =
                (values.next(), values.next(), values.next())
            else {
                return Err(RecordStoreError(
                    "invalid native ticket batch observation".into(),
                ));
            };
            if observed_at.unix_seconds > expires_at {
                verdicts.push(Ok(false));
                continue;
            }
            verdicts.push(
                judge_ticket(expires_at, active, spent.as_ref(), index.as_ref())
                    .map(|record| record.is_some()),
            );
        }
    }
    Ok(verdicts)
}
