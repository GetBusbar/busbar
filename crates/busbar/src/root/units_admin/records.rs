// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /records` (ADMIN-API-1.6 §3.3): the node's per-unit records, a read-time projection of
//! its sealed audit chain. A feed: `next_cursor` is always a string, `complete` means caught up,
//! and `wait` long-polls on the one pulse a confirmed run fires. Nothing here is on the request
//! path; a sealed unit costs this read nothing until it is read.

use std::borrow::Cow;
use std::collections::BTreeMap;

use busbar_contract::caps::{Abort, Outcome};
use busbar_contract::plane::PlaneDeclaration;
use busbar_core_admin::v1::records as wire;
use busbar_core_admin::v1::records::{
    unit_reason_class, RecordsPage, RecordsSource, UnitAttempt, UnitReason, UnitRecord, UnitTiming,
    UnitUsage, RECORDS_LIMIT_DEFAULT, RECORDS_LIMIT_MAX, RECORDS_SCAN_BOUND, RECORDS_WAIT_MAX_SECS,
    TIMED_OUT, UNIT_RECORD_SCHEMA,
};
use busbar_kernel_audit::record::billing as signed;
use busbar_kernel_audit::{AuditRecord, FinishClass, Recipe, Subject};

use super::{AdminAnswer, AuditView};
use crate::root::durability::{records_pulse, AUDIT_RING};

#[cfg(test)]
#[path = "records_selected_tests.rs"]
mod selected_tests;

/// The planes this node knows, by key: where a record's `kind` and `category` come from.
pub(crate) type Planes<'p> = &'p (dyn Fn(&str) -> Option<PlaneDeclaration> + Send + Sync);

/// The cursor's version prefix: `rc1.<node as 16 hex>.<next position>`.
const CURSOR_PREFIX: &str = "rc1.";

/// A position in one node's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub(crate) node: u64,
    pub(crate) next: u64,
}

impl Cursor {
    pub(crate) fn encode(self) -> String {
        format!("{CURSOR_PREFIX}{:016x}.{}", self.node, self.next)
    }

    pub(crate) fn decode(token: &str) -> Option<Self> {
        let (node, next) = token.strip_prefix(CURSOR_PREFIX)?.split_once('.')?;
        if node.len() != 16 || next.is_empty() || !next.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Cursor {
            node: u64::from_str_radix(node, 16).ok()?,
            next: next.parse().ok().filter(|n| *n >= 1)?,
        })
    }
}

/// `node_` + 16 hex: how `/info` and `/records` name a node.
pub(crate) fn node_id(node: u64) -> String {
    format!("node_{node:016x}")
}

/// The exact filters (`from_ms` is a seek, not one of them).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Filters {
    pub(crate) kind: Option<String>,
    pub(crate) instance: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) unit: Option<String>,
    /// Only records that arrived before this.
    pub(crate) to_ms: Option<u64>,
}

fn same(want: &Option<String>, have: Option<&str>) -> bool {
    want.as_deref().is_none_or(|want| have == Some(want))
}

impl Filters {
    pub(crate) fn admits(&self, r: &UnitRecord) -> bool {
        same(&self.kind, r.kind)
            && same(&self.instance, r.instance.as_deref())
            && same(&self.key, r.key.as_deref())
            && same(&self.group, r.group.as_deref())
            && same(&self.model, r.model.as_deref())
            && same(&self.provider, r.provider.as_deref())
            && same(&self.target, r.target.as_deref())
            && same(&self.outcome, Some(r.outcome))
            && same(&self.reason, r.reason.as_ref().map(|reason| reason.code))
            && same(&self.unit, r.unit.as_deref())
            && self.to_ms.is_none_or(|to| r.arrived_at_ms < to)
    }
}

/// One `/records` request's query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: usize,
    pub(crate) wait: u64,
    pub(crate) from_ms: Option<u64>,
    pub(crate) filters: Filters,
}

/// Percent-decode one query value; `None` when it is not UTF-8 or a `%` is not two hex digits.
fn decoded(value: &str) -> Option<Cow<'_, str>> {
    if !value.contains('%') {
        return Some(Cow::Borrowed(value));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

/// Read `/records`' query from the request target. An unknown or repeated name, or a value
/// that does not parse, is refused rather than ignored: a mistyped filter must not widen a read.
pub(crate) fn parse_query(target: &str) -> Result<Query, &'static str> {
    let mut query = Query {
        cursor: None,
        limit: RECORDS_LIMIT_DEFAULT,
        wait: 0,
        from_ms: None,
        filters: Filters::default(),
    };
    let Some((_, raw)) = target.split_once('?') else {
        return Ok(query);
    };
    let raw = raw.split('#').next().unwrap_or(raw);
    let mut seen = std::collections::BTreeSet::new();
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !seen.insert(name) {
            return Err("a query parameter is repeated");
        }
        let value = decoded(value).ok_or("a query value is not percent-encoded UTF-8")?;
        let number = |max: u64| {
            value
                .parse::<u64>()
                .ok()
                .filter(|n| *n <= max)
                .ok_or("a numeric query parameter is not an integer in its range")
        };
        let text = || Some(value.clone().into_owned());
        let f = &mut query.filters;
        match name {
            "cursor" => query.cursor = text(),
            "limit" => {
                query.limit = usize::try_from(number(RECORDS_LIMIT_MAX as u64)?)
                    .unwrap_or(RECORDS_LIMIT_MAX)
                    .max(1);
            }
            "wait" => query.wait = number(RECORDS_WAIT_MAX_SECS)?,
            "from_ms" => query.from_ms = Some(number(u64::MAX)?),
            "to_ms" => f.to_ms = Some(number(u64::MAX)?),
            "kind" => f.kind = text(),
            "instance" => f.instance = text(),
            "key" => f.key = text(),
            "group" => f.group = text(),
            "model" => f.model = text(),
            "provider" => f.provider = text(),
            "target" => f.target = text(),
            "outcome" => f.outcome = text(),
            "reason" => f.reason = text(),
            "unit" => f.unit = text(),
            _ => return Err("an unknown query parameter"),
        }
    }
    Ok(query)
}

/// The arrival of a record in milliseconds: sealed (`v7`), or the sealed second times 1000.
pub(crate) fn arrived_at_ms(record: &AuditRecord) -> u64 {
    if record.recipe.carries_unit_facts() {
        record.unit.wall_ms
    } else {
        record.wall.saturating_mul(1_000)
    }
}

fn outcome_tag(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Completed => "completed",
        Outcome::Refused(..) => "refused",
        Outcome::Failed(..) => "failed",
        Outcome::Aborted(_) => "aborted",
        Outcome::TimedOut(_) => "timed_out",
    }
}

fn finish_tag(finish: FinishClass) -> &'static str {
    match finish {
        FinishClass::Complete => "complete",
        FinishClass::TurnComplete => "turn_complete",
        FinishClass::Partial => "partial",
        FinishClass::Error => "error",
    }
}

fn reason_of(record: &AuditRecord) -> Option<UnitReason> {
    let stage = record.outcome.step.map(|step| step.as_str());
    let (code, class) = match record.outcome.unit_end {
        Outcome::Completed => return None,
        Outcome::Refused(_, reason)
        | Outcome::Failed(_, reason)
        | Outcome::Aborted(Abort::Kernel { reason }) => {
            (reason.as_str(), unit_reason_class(reason))
        }
        Outcome::Aborted(Abort::Superseded { .. }) => {
            let reason = busbar_contract::caps::ReasonCode::Superseded;
            (reason.as_str(), unit_reason_class(reason))
        }
        Outcome::TimedOut(_) => (TIMED_OUT, "upstream"),
    };
    Some(UnitReason { stage, code, class })
}

fn nonzero(n: u64) -> Option<u64> {
    (n != 0).then_some(n)
}

/// What pricing a record needs, kept beside its projection until the page is priced.
#[derive(Debug, Clone)]
pub(crate) enum Priceable {
    Legacy(LegacyPriceable),
    Selected(Box<signed::BillingFacts>),
}

pub(crate) struct LegacyPriceable {
    key: [u8; 20],
    lane: String,
    fee_count: u32,
    classes: BTreeMap<String, busbar_contract::Count>,
}

/// THE PROJECTION: one sealed record as `/records` serves it, unpriced. Every field comes from
/// sealed bytes; only `kind` and `category` are looked up, and they are null for an instance this
/// node no longer has.
pub(crate) fn project(record: &AuditRecord, planes: Planes<'_>) -> (UnitRecord, Option<Priceable>) {
    let v7 = record.recipe.carries_unit_facts();
    let delivered = record.unit.billing.as_ref().and_then(|billing| {
        let ordinal = billing.facts().final_target?;
        billing.facts().partitions.iter().find(|p| {
            matches!(p.scope,
            signed::PartitionScope::Attempt { preparation, .. } if preparation == ordinal)
        })
    });
    let target = if record.recipe == Recipe::V9 {
        delivered.map(|p| p.lane.as_str())
    } else {
        record.what.destination.as_deref()
    };
    let (instance, model) = match target {
        Some(lane) => match busbar_kernel_ledger::cost::split_plane_lane(lane) {
            ("", _) => (
                Some(busbar_contract::section::RESERVED_POOLS_KEY),
                Some(lane),
            ),
            (plane, subject) => (Some(plane), (!subject.is_empty()).then_some(subject)),
        },
        None => (None, None),
    };
    let declared = instance.and_then(planes);
    let [group, pool, provider] = if v7 {
        record.unit.attributed()
    } else {
        [None, None, None]
    };
    let mut classes = BTreeMap::new();
    for line in &record.usage.lines {
        classes.insert(line.class.as_str().to_string(), line.quantity);
    }
    let rate_card_version = match &record.recipe {
        Recipe::V2 {
            legacy_rate_card_version,
            ..
        }
        | Recipe::V4 {
            legacy_rate_card_version,
        } => Some(legacy_rate_card_version.to_string()),
        _ => record.usage.rate_card_version.map(hex::encode),
    };
    let priceable = match (&record.recipe, record.usage.rate_card_version, target) {
        (Recipe::V5 | Recipe::V6 | Recipe::V7 | Recipe::V8, Some(key), Some(lane)) => {
            Some(Priceable::Legacy(LegacyPriceable {
                key,
                lane: lane.to_string(),
                fee_count: record.usage.fee_count,
                classes: classes.clone(),
            }))
        }
        (Recipe::V9, _, _) => record
            .unit
            .billing
            .as_ref()
            .map(|b| Priceable::Selected(Box::new(b.facts().clone()))),
        _ => None,
    };
    let unit = UnitRecord {
        schema: if record.recipe == Recipe::V9 {
            wire::UNIT_RECORD_SCHEMA_V2
        } else {
            UNIT_RECORD_SCHEMA
        },
        seq: record.seq.to_string(),
        unit: record.unit_id().map(|id| id.to_string()),
        unit_key: record.what.unit_key.get().to_string(),
        arrived_at_ms: arrived_at_ms(record),
        arrived_at_precision: if v7 { "ms" } else { "s" },
        op_class: record.what.op_class.as_str().to_string(),
        category: declared.map(|_| "plane"),
        kind: declared.map(|decl| decl.key),
        instance: instance.map(str::to_string),
        target: target.map(str::to_string),
        model: model.map(str::to_string),
        provider: if record.recipe == Recipe::V9 {
            delivered.and_then(|p| p.provider.clone())
        } else {
            provider.map(str::to_string)
        },
        pool: record
            .unit
            .billing
            .as_ref()
            .map(|b| b.facts().request_pool.clone())
            .or_else(|| pool.map(str::to_string)),
        group: group.map(str::to_string),
        key: match &record.subject {
            Subject::PrincipalId(key) => Some(key.clone()),
            _ => None,
        },
        // §3.5: what `records.user` and `records.labels` sealed, from the record's own bytes; a
        // record sealed before either was on, or with both off, keeps neither.
        user: record.unit.records.user.clone(),
        labels: record
            .unit
            .records
            .labels
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect(),
        attributes: BTreeMap::new(),
        outcome: outcome_tag(record.outcome.unit_end),
        finish: finish_tag(record.outcome.finish),
        reason: reason_of(record),
        status: (v7 && record.unit.status != 0).then_some(record.unit.status),
        timing: v7.then(|| UnitTiming {
            ttft_us: nonzero(record.unit.ttft_us),
            total_us: nonzero(record.unit.total_us),
            queue_us: None,
        }),
        attempts: record
            .unit
            .attempts_used()
            .zip(1u32..)
            .map(|(attempt, n)| UnitAttempt {
                n,
                target: attempt.target.clone(),
                outcome: attempt.outcome.as_str(),
                reason: (!attempt.reason.is_empty()).then(|| attempt.reason.clone()),
                us: nonzero(attempt.us),
            })
            .collect(),
        attempts_total: record.unit.attempts_total,
        usage: UnitUsage {
            classes: classes
                .iter()
                .map(|(class, count)| (class.clone(), count.to_decimal_string()))
                .collect(),
            fee_count: record.usage.fee_count,
        },
        billing: record
            .unit
            .billing
            .as_ref()
            .map(|b| billing_projection(b.facts())),
        spend_micros: None,
        rate_card_version,
        priced_by: None,
        priced: false,
        content_ref: None,
        hash: record.hash.clone(),
    };
    (unit, priceable)
}

/// Micro-units as exact decimal text with at most three fractional places, from nano-units:
/// the form `/usage`'s observation rows carry.
pub(crate) fn micros_text(nanos: u128) -> String {
    let whole = nanos / 1_000;
    match nanos % 1_000 {
        0 => whole.to_string(),
        part => format!("{whole}.{part:03}")
            .trim_end_matches('0')
            .to_string(),
    }
}

/// PRICE ONE RECORD BY THE RULE `/usage` PRICES ITS METERING ROW BY (ADMIN-API-1.6 §3.2): the
/// sealed entry, voided or not, with any later amendment that prices the instant `/usage` uses
/// for the day the unit accrued into, through the one shared `price_era`. Truncated to whole
/// nano-units once per record.
pub(crate) fn price(
    record: &mut UnitRecord,
    input: Priceable,
    view: &busbar_kernel_ledger::cost::HistoryView<'_>,
) {
    let input = match input {
        Priceable::Legacy(input) => input,
        Priceable::Selected(input) => {
            price_selected(record, &input, view);
            return;
        }
    };
    use busbar_kernel_ledger::cost::{nanos_of_exact, price_era, EntryKey, MeteredRow};
    let key = EntryKey(input.key);
    let Some(entry) = view.entry_keyed(&key) else {
        return;
    };
    let day_start = record.arrived_at_ms / 1_000 / 86_400 * 86_400;
    let wall_at =
        busbar_core_admin::v1::service::row_priced_at_ms(day_start, entry.effective_from());
    let Some((priced_by, card)) = price_era(view, Some(key.id()), entry.effective_from(), wall_at)
    else {
        return;
    };
    let row = MeteredRow::exact(
        &input.lane,
        BTreeMap::new(),
        u64::from(input.fee_count),
        input.classes,
    );
    let Some(nanos) = row
        .exact_at_card_seq(priced_by, card)
        .ok()
        .and_then(|exact| nanos_of_exact(exact).ok())
    else {
        return;
    };
    record.spend_micros = Some(micros_text(nanos));
    record.priced_by = Some(priced_by.hex());
    record.priced = true;
}

fn billing_era(era: signed::BillingEra) -> wire::BillingEra {
    wire::BillingEra {
        effective_from: era.effective_from,
        entry_id: era.entry_id.map(hex::encode),
    }
}

fn billing_projection(facts: &signed::BillingFacts) -> wire::UnitBilling {
    let (logical_request, logical_preparation) = match facts.logical_request {
        signed::LogicalRequest::None => ("none", None),
        signed::LogicalRequest::HostOrigin => ("host_origin", None),
        signed::LogicalRequest::DeliveredPreparation(n) => ("delivered_preparation", Some(n)),
    };
    let (disposition, reason) = match &facts.disposition {
        signed::BillingDisposition::End => ("end", None),
        signed::BillingDisposition::Failed => ("failed", None),
        signed::BillingDisposition::Cancel(reason) => ("cancel", Some(reason.clone())),
        signed::BillingDisposition::RecoveredRunning => ("recovered_running", None),
    };
    let quantity = |q: signed::SelectedQuantity| wire::BillingQuantity {
        count: q.count.to_decimal_string(),
        source: q.source.as_str(),
    };
    let partitions: Vec<_> = facts
        .partitions
        .iter()
        .map(|p| {
            let (scope, preparation, dispatch) = match p.scope {
                signed::PartitionScope::Session => ("session", None, None),
                signed::PartitionScope::Attempt {
                    preparation,
                    dispatch,
                } => ("attempt", Some(preparation), dispatch),
            };
            wire::BillingPartition {
                scope,
                preparation,
                dispatch,
                kind: p.kind.as_str(),
                instance: p.instance.clone(),
                lane: p.lane.clone(),
                provider: p.provider.clone(),
                selected_pool: p.selected_pool.clone(),
                resource: p.resource.clone(),
                transport: p.transport.map(signed::Transport::as_str),
                finality: p.finality.as_str(),
                priced_by: None,
                classes: p
                    .classes
                    .iter()
                    .map(|(name, c)| {
                        (
                            name.clone(),
                            wire::BillingClass {
                                reported: c.reported.map(|n| n.to_decimal_string()),
                                floor: c.floor.map(|n| n.to_decimal_string()),
                                estimated: c.estimated.map(|n| n.to_decimal_string()),
                                selected: c.selected.map(quantity),
                                billed: c.billed.map(quantity),
                                rate_high_water: c.rate_high_water.to_decimal_string(),
                            },
                        )
                    })
                    .collect(),
            }
        })
        .collect();
    wire::UnitBilling {
        version: 1,
        revision: facts.revision.to_string(),
        request_pool: facts.request_pool.clone(),
        routing_generation: facts.routing_generation.to_string(),
        era: billing_era(facts.era),
        session_instance: facts.session_origin.instance.clone(),
        session_lane: facts.session_origin.lane.clone(),
        session_provider: facts.session_origin.provider.clone(),
        logical_request,
        logical_preparation,
        fee: wire::BillingFee {
            state: facts.fee.state.as_str(),
            lane: facts.fee.lane.clone(),
            era: billing_era(facts.fee.era),
            priced_by: None,
        },
        disposition,
        reason,
        far_end_answered: facts.far_end_answered,
        caller_bytes_committed: facts.caller_bytes_committed,
        final_target: facts.final_target,
        dispatched: partitions.iter().filter(|p| p.dispatch.is_some()).count() as u32,
        partitions,
    }
}

fn selected_card<'v>(
    view: &'v busbar_kernel_ledger::cost::HistoryView<'_>,
    era: signed::BillingEra,
    arrived: u64,
) -> Option<(
    busbar_kernel_ledger::cost::EntryKey,
    &'v busbar_kernel_ledger::cost::RateCard,
)> {
    let id = busbar_kernel_ledger::cost::EntryId(era.entry_id?);
    let day_start = arrived / 1_000 / 86_400 * 86_400;
    let wall = busbar_core_admin::v1::service::row_priced_at_ms(day_start, era.effective_from);
    // Some(id) makes price_era require that exact identity AND effective date.
    busbar_kernel_ledger::cost::price_era(view, Some(id), era.effective_from, wall)
}

fn price_selected(
    record: &mut UnitRecord,
    facts: &signed::BillingFacts,
    view: &busbar_kernel_ledger::cost::HistoryView<'_>,
) {
    use busbar_kernel_ledger::cost::{nanos_of_exact, Tally, STANDARD_TIER_BP};
    let Some(billing) = record.billing.as_mut() else {
        return;
    };
    let zero = busbar_contract::Count::from_micros(0);
    let mut total = 0i128;
    let mut keys = std::collections::BTreeSet::new();
    let mut complete = facts.fee.state != signed::FeeState::Unknown;
    for (p, output) in facts.partitions.iter().zip(&mut billing.partitions) {
        let counts: Vec<_> = p
            .classes
            .iter()
            .filter_map(|(name, c)| c.billed.map(|q| (name.as_str(), q.count)))
            .collect();
        if counts.is_empty() {
            continue;
        }
        let Some((key, card)) = selected_card(view, facts.era, record.arrived_at_ms) else {
            complete = false;
            continue;
        };
        let mut tally = Tally::at_card_seq(key, card);
        let exact = tally
            .row(&p.lane, 0, STANDARD_TIER_BP, counts.into_iter(), zero)
            .and_then(|()| tally.exact());
        let Some(sum) = exact.ok().and_then(|n| total.checked_add(n)) else {
            complete = false;
            continue;
        };
        total = sum;
        output.priced_by = Some(key.hex());
        keys.insert(key.hex());
    }
    if facts.fee.state == signed::FeeState::Charged {
        if let Some((key, card)) = selected_card(view, facts.fee.era, record.arrived_at_ms) {
            let mut tally = Tally::at_card_seq(key, card);
            let one = busbar_contract::Count::from(1u64);
            let fee = match &facts.fee.lane {
                Some(lane) => tally.lane_fee(lane, 0, STANDARD_TIER_BP, one),
                None => tally.fee(0, STANDARD_TIER_BP, one),
            }
            .and_then(|()| tally.exact());
            if let Some(sum) = fee.ok().and_then(|n| total.checked_add(n)) {
                total = sum;
                billing.fee.priced_by = Some(key.hex());
                keys.insert(key.hex());
            } else {
                complete = false;
            }
        } else {
            complete = false;
        }
    }
    if complete {
        if let Ok(nanos) = nanos_of_exact(total) {
            record.spend_micros = Some(micros_text(nanos));
            record.priced = true;
            record.priced_by = if keys.len() == 1 {
                keys.into_iter().next()
            } else {
                None
            };
        }
    }
}

/// The node this view's chain seals as, and the next position it will seal.
fn bounds(view: &dyn AuditView) -> (u64, u64) {
    let mut out = (0, 1);
    view.read(&mut |chain, _| out = (chain.node(), chain.next_seq()));
    out
}

/// One window's read, or why there was none.
enum Read {
    /// The store did not answer.
    Unavailable,
    /// Read through `to`; `first` is the first record found at or after the window's start.
    Done { first: Option<u64> },
}

/// What a scan found.
pub(crate) struct Scanned {
    pub(crate) items: Vec<(UnitRecord, Option<Priceable>)>,
    /// The position after the last record scanned.
    pub(crate) next: u64,
    /// The first record found at or after the start, if any.
    pub(crate) first: Option<u64>,
}

/// SCAN FORWARD FROM `at`: at most [`RECORDS_SCAN_BOUND`] sealed records, stopping at `limit`
/// matches or at the head. `Err(())` when the store did not answer.
pub(crate) async fn scan(
    view: &dyn AuditView,
    planes: Planes<'_>,
    query: &Query,
    at: u64,
    head: u64,
) -> Result<Scanned, ()> {
    let mut out = Scanned {
        items: Vec::new(),
        next: at,
        first: None,
    };
    let mut scanned = 0u64;
    let mut at = at;
    while scanned < RECORDS_SCAN_BOUND && out.items.len() < query.limit && at < head {
        let room = (RECORDS_SCAN_BOUND - scanned).min(AUDIT_RING as u64);
        let to = at.saturating_add(room - 1).min(head - 1);
        let mut read = Read::Unavailable;
        let (items, next) = (&mut out.items, &mut out.next);
        let limit = query.limit;
        let filters = &query.filters;
        view.read_window(at, to, &mut |_chain, records| {
            let Some(records) = records else {
                return;
            };
            let mut first = None;
            for record in records.iter().filter(|r| r.seq >= at && r.seq <= to) {
                if items.len() >= limit {
                    break;
                }
                first.get_or_insert(record.seq);
                scanned += 1;
                *next = record.seq.saturating_add(1);
                let (unit, priceable) = project(record, planes);
                if filters.admits(&unit) {
                    items.push((unit, priceable));
                }
            }
            read = Read::Done { first };
        })
        .await;
        match read {
            Read::Unavailable => return Err(()),
            Read::Done { first } => {
                if out.first.is_none() {
                    out.first = first;
                }
            }
        }
        if out.items.len() >= query.limit {
            break;
        }
        // Whatever this window did not hold is not retained: the scan moves past it.
        at = to.saturating_add(1);
        out.next = out.next.max(at);
    }
    Ok(out)
}

/// THE SEEK (C1): the first position `p` with `arrived_at_ms(p) >= from_ms`, by binary search
/// over positions with point reads, outside the scan bound. A backward clock step still yields
/// such a boundary; the feed serves everything from it on.
pub(crate) async fn seek(view: &dyn AuditView, from_ms: u64, head: u64) -> u64 {
    let (mut lo, mut hi) = (1u64, head);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mut arrived = None;
        view.read_window(mid, mid, &mut |_chain, records| {
            arrived = records
                .and_then(|records| records.iter().find(|r| r.seq == mid))
                .map(arrived_at_ms);
        })
        .await;
        match arrived {
            Some(ms) if ms < from_ms => lo = mid + 1,
            Some(_) => hi = mid,
            // A position not retained is before every retained one: search above it.
            None => lo = mid + 1,
        }
    }
    lo
}

fn json_answer(status: u16, body: Vec<u8>) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body,
    }
}

fn refused(
    status: u16,
    code: &str,
    reason: Option<&str>,
    message: &str,
    detail: Option<(&str, &str)>,
) -> AdminAnswer {
    let body = busbar_kernel::admin::gate::admin_envelope_body_with(code, reason, message, detail);
    json_answer(status, body.into_bytes())
}

/// `GET /records`: one page, priced, as the envelope's JSON.
pub(crate) async fn records_answer(
    view: &dyn AuditView,
    planes: Planes<'_>,
    target: &str,
) -> AdminAnswer {
    let query = match parse_query(target) {
        Ok(query) => query,
        Err(why) => return refused(400, "invalid_request", None, why, None),
    };
    let (node, head) = bounds(view);
    let cursor = match query.cursor.as_deref().map(Cursor::decode) {
        None => None,
        Some(None) => {
            return refused(
                400,
                "invalid_request",
                None,
                "the cursor is malformed",
                None,
            )
        }
        Some(Some(cursor)) if cursor.node != node => {
            return refused(
                400,
                "invalid_request",
                Some("cursor_mismatch"),
                "the cursor was issued by another node; read that node's records from it",
                Some(("cursor_node_id", node_id(cursor.node).as_str())),
            );
        }
        Some(Some(cursor)) => Some(cursor),
    };
    let start = match (cursor, query.from_ms) {
        (Some(cursor), _) => cursor.next,
        (None, Some(from_ms)) => seek(view, from_ms, head).await,
        (None, None) => 1,
    };
    // Armed before the scan, so a run confirmed between the scan and the wait still wakes it.
    let mut pulse = std::pin::pin!(records_pulse().notified());
    let _ = pulse.as_mut().enable();
    let mut scanned = match scan(view, planes, &query, start, head).await {
        Ok(scanned) => scanned,
        Err(()) => return refused(503, "unavailable", None, "the chain did not answer", None),
    };
    if let (Some(cursor), Some(first)) = (cursor, scanned.first) {
        if first > cursor.next {
            let oldest = Cursor { node, next: first }.encode();
            return refused(
                410,
                "invalid_request",
                Some("cursor_expired"),
                "the cursor's position is no longer retained",
                Some(("oldest_available", oldest.as_str())),
            );
        }
    }
    let mut head = head;
    if query.wait > 0 && scanned.items.is_empty() && scanned.next >= head {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(query.wait), pulse).await;
        head = bounds(view).1;
        let at = scanned.next;
        scanned = match scan(view, planes, &query, at, head).await {
            Ok(scanned) => scanned,
            Err(()) => return refused(503, "unavailable", None, "the chain did not answer", None),
        };
    }
    let history = busbar_kernel::rate_apply::dated_history();
    let rates = history
        .as_deref()
        .map(busbar_kernel_ledger::cost::History::current);
    let items = scanned
        .items
        .into_iter()
        .map(|(mut unit, priceable)| {
            if let (Some(input), Some(view)) = (priceable, rates.as_ref()) {
                price(&mut unit, input, view);
            }
            unit
        })
        .collect();
    let page = RecordsPage {
        source: RecordsSource {
            deployment_id: busbar_kernel::persistence::boot_identity::live()
                .map(|live| live.deployment_id().to_string()),
            node_id: node_id(node),
            process_boot_nonce: busbar_kernel::snapshot::process_generation()
                .map(|(nonce, _)| nonce.to_string()),
        },
        items,
        next_cursor: Cursor {
            node,
            next: scanned.next.max(start),
        }
        .encode(),
        complete: scanned.next >= head,
    };
    match busbar_contract::json::to_vec(&page) {
        Ok(body) => json_answer(200, body),
        Err(_) => refused(
            503,
            "unavailable",
            None,
            "the page could not be written",
            None,
        ),
    }
}
