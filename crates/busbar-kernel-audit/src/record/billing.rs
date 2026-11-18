// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete, bounded selected-attempt evidence. Policy projection belongs to the money owner.
use crate::recipe::FieldSink;
use busbar_contract::Count;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum bytes in the canonical billing extension.
const BILLING_BYTES: usize = 4 * 1024 * 1024;
/// Maximum bytes in a complete selected audit journal body.
pub const BILLING_RECORD_BYTES: usize = 16 * 1024 * 1024;
const ID_BYTES: usize = 4096;
const ATTEMPTS: usize = 256;
const CLASSES: usize = 64;

macro_rules! tags {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $tag:literal),+ $(,)? }) => {
        $(#[$meta])* #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($(#[$vmeta])* $variant),+ }
        impl $name {
            /// Canonical wire spelling.
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $tag),+ } }
            fn read(text: &str) -> Option<Self> { match text { $($tag => Some(Self::$variant)),+, _ => None } }
        }
    };
}
tags! { /// Source of an observed cumulative quantity.
    UsageSource { /// Explicit reported count.
        Reported => "reported", /// Observed lower bound.
        Floor => "floor", /// Unbilled estimate.
        Estimated => "estimated" }
}
tags! { /// Original logical fee outcome, independent of request counters.
    FeeState { /// A child sharing another unit's fee account.
        NotOwner => "not_owner", /// Original fee remained charged.
        Charged => "charged", /// Original fee was refunded.
        Refunded => "refunded", /// Recovery lacks a resolved durable fee outcome.
        Unknown => "unknown" }
}
tags! { /// Captured target kind.
    TargetKind { /// Original host session.
        Session => "session", /// Selected model target.
        Model => "model", /// Selected registration target.
        Registration => "registration" }
}
tags! { /// Whether a preparation committed a dispatch.
    Transport { /// Prepared but never committed.
        Prepared => "prepared", /// Actual committed dispatch.
        Committed => "committed", /// Preparation explicitly ended without a send.
        NoSend => "no_send" }
}
tags! { /// Terminal source coverage; transport success does not establish completeness.
    Finality { /// Producer established complete required source coverage.
        Complete => "complete", /// Producer established partial coverage.
        Partial => "partial", /// Coverage is unknown, including recovered live attempts.
        Unknown => "unknown" }
}
/// Original exact monetary era; absence is never resolved from current configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingEra {
    /// Original entry's effective date in milliseconds.
    pub effective_from: u64,
    /// Original compact entry identity.
    pub entry_id: Option<[u8; 12]>,
}
/// One explicit source and its exact cumulative quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedQuantity {
    /// Known quantity, including known zero.
    pub count: Count,
    /// Source selected by the producer.
    pub source: UsageSource,
}
/// Raw source slots and the independently projected bill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingClass {
    /// Latest reported value; None is unknown.
    pub reported: Option<Count>,
    /// Latest lower bound.
    pub floor: Option<Count>,
    /// Latest unbilled estimate.
    pub estimated: Option<Count>,
    /// Running source selection, retained even when billing is suppressed.
    pub selected: Option<SelectedQuantity>,
    /// Eligible bill under the captured disposition.
    pub billed: Option<SelectedQuantity>,
    /// Independent physical rate high-water evidence.
    pub rate_high_water: Count,
}
/// Session scope or stable preparation and dispatch ordinals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionScope {
    /// Original session-only classes.
    Session,
    /// One preparation, with a dispatch only when committed.
    Attempt {
        /// Nonzero, strictly increasing preparation ordinal.
        preparation: u32,
        /// Consecutive committed dispatch ordinal, or absent.
        dispatch: Option<u32>,
    },
}
/// One full retained usage partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingPartition {
    /// Session or attempt identity.
    pub scope: PartitionScope,
    /// Original selected target kind.
    pub kind: TargetKind,
    /// Configured plane instance.
    pub instance: String,
    /// Fully qualified logical pricing lane.
    pub lane: String,
    /// Actual configured provider, never the plane as a substitute.
    pub provider: Option<String>,
    /// Selected target pool; absent for a session.
    pub selected_pool: Option<String>,
    /// Canonical resource identity; never a secret.
    pub resource: Option<String>,
    /// Transport disposition; absent only for a session.
    pub transport: Option<Transport>,
    /// Explicit coverage finality.
    pub finality: Finality,
    /// Every declared class in this scope, including zero/unknown.
    pub classes: BTreeMap<String, BillingClass>,
}
/// Original host identity, retained even with no session quantities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOrigin {
    /// Original instance.
    pub instance: String,
    /// Original qualified empty-subject lane.
    pub lane: String,
    /// Actual original provider, absent for a native host origin.
    pub provider: Option<String>,
}
/// Logical request identity, independent of fee ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalRequest {
    /// No logical request event.
    None,
    /// Explicit original host origin.
    HostOrigin,
    /// Actual delivered preparation ordinal.
    DeliveredPreparation(u32),
}
/// Original fee basis and frozen result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalFee {
    /// Existing account's resolved or explicitly unknown result.
    pub state: FeeState,
    /// Original fee lane; None means the flat fee base.
    pub lane: Option<String>,
    /// Original fee era, independent of usage and arrival-card identities.
    pub era: BillingEra,
}
/// Terminal monetary disposition, copied from the validated complete snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingDisposition {
    /// Ordinary terminal end.
    End,
    /// Failed unit.
    Failed,
    /// Cancelled unit, with the captured reason.
    Cancel(String),
    /// Recovery of the last durably selected running revision.
    RecoveredRunning,
}
/// Construction input from one immutable accepted complete producer revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingFacts {
    /// Accepted snapshot revision.
    pub revision: u64,
    /// Original admitted request pool.
    pub request_pool: String,
    /// Existing routing generation, qualified by the record's original node/incarnation.
    pub routing_generation: u64,
    /// Exact original usage era.
    pub era: BillingEra,
    /// Original session identity, independent of quantities.
    pub session_origin: SessionOrigin,
    /// Frozen logical request decision.
    pub logical_request: LogicalRequest,
    /// Original logical fee evidence.
    pub fee: LogicalFee,
    /// Frozen terminal projection disposition.
    pub disposition: BillingDisposition,
    /// Independent host fact: an upstream answered.
    pub far_end_answered: bool,
    /// Independent host fact: caller bytes committed.
    pub caller_bytes_committed: bool,
    /// Delivered preparation ordinal, never a vector index.
    pub final_target: Option<u32>,
    /// Session first if present, then all preparations in ordinal order.
    pub partitions: Vec<BillingPartition>,
}
/// Validated immutable V9 payload. Raw construction cannot bypass its bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionedBillingV1(Box<BillingFacts>);
/// A malformed or unrepresentable selected billing history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingError;
impl std::fmt::Display for BillingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid or oversized selected billing evidence")
    }
}
impl std::error::Error for BillingError {}

fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= ID_BYTES
}
fn optional(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(identity)
}
fn lane(instance: &str, value: &str) -> bool {
    identity(instance)
        && identity(value)
        && value
            .split_once('\u{1f}')
            .is_some_and(|(i, s)| i == instance && !s.contains('\u{1f}'))
}
fn valid_class(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':'))
}
impl BillingClass {
    fn valid(&self) -> bool {
        let nonnegative = [
            self.reported,
            self.floor,
            self.estimated,
            Some(self.rate_high_water),
        ]
        .into_iter()
        .flatten()
        .all(|n| !n.is_negative());
        let source_matches = |q: SelectedQuantity| {
            let raw = match q.source {
                UsageSource::Reported => self.reported,
                UsageSource::Floor => self.floor,
                UsageSource::Estimated => self.estimated,
            };
            raw == Some(q.count) && !q.count.is_negative()
        };
        nonnegative
            && self.selected.is_none_or(source_matches)
            && self
                .billed
                .is_none_or(|q| q.source != UsageSource::Estimated && source_matches(q))
    }
}
impl PartitionedBillingV1 {
    /// Validate the bounded complete input before it can enter a linked record.
    pub fn new(facts: BillingFacts) -> Result<Self, BillingError> {
        if !identity(&facts.request_pool)
            || !lane(&facts.session_origin.instance, &facts.session_origin.lane)
            || !facts.session_origin.lane.ends_with('\u{1f}')
            || facts.session_origin.provider.is_some()
            || !optional(&facts.fee.lane)
            || facts.partitions.len() > ATTEMPTS + 1
            || matches!(&facts.disposition, BillingDisposition::Cancel(reason) if !identity(reason))
        {
            return Err(BillingError);
        }
        let mut previous = 0;
        let mut dispatched = 0;
        let mut attempts = 0;
        let mut found_target = false;
        let mut session_classes = BTreeSet::new();
        let mut attempt_classes = BTreeSet::new();
        for (index, p) in facts.partitions.iter().enumerate() {
            if !lane(&p.instance, &p.lane)
                || !optional(&p.provider)
                || !optional(&p.selected_pool)
                || !optional(&p.resource)
                || p.classes.len() > CLASSES
                || p.classes
                    .iter()
                    .any(|(name, value)| !valid_class(name) || !value.valid())
            {
                return Err(BillingError);
            }
            match p.scope {
                PartitionScope::Session => {
                    if index != 0
                        || p.kind != TargetKind::Session
                        || p.transport.is_some()
                        || p.selected_pool.is_some()
                        || p.resource.is_some()
                        || p.instance != facts.session_origin.instance
                        || p.lane != facts.session_origin.lane
                        || p.provider != facts.session_origin.provider
                    {
                        return Err(BillingError);
                    }
                    session_classes.extend(p.classes.keys());
                }
                PartitionScope::Attempt {
                    preparation,
                    dispatch,
                } => {
                    attempts += 1;
                    if preparation <= previous
                        || p.kind == TargetKind::Session
                        || p.selected_pool.is_none()
                        || p.transport.is_none()
                    {
                        return Err(BillingError);
                    }
                    previous = preparation;
                    if p.transport == Some(Transport::Committed) {
                        dispatched += 1;
                        if dispatch != Some(dispatched) {
                            return Err(BillingError);
                        }
                        found_target |= facts.final_target == Some(preparation);
                    } else if dispatch.is_some() || p.classes.values().any(|c| c.billed.is_some()) {
                        return Err(BillingError);
                    }
                    attempt_classes.extend(p.classes.keys());
                }
            }
        }
        if attempts > ATTEMPTS
            || !session_classes.is_disjoint(&attempt_classes)
            || session_classes.len() + attempt_classes.len() > CLASSES
            || (facts.final_target.is_some() && !found_target)
            || match facts.logical_request {
                LogicalRequest::None => false,
                LogicalRequest::HostOrigin => facts.final_target.is_some(),
                LogicalRequest::DeliveredPreparation(n) => facts.final_target != Some(n),
            }
        {
            return Err(BillingError);
        }
        let result = Self(Box::new(facts));
        let mut size = Size(0);
        result.visit(&mut size);
        if size.0 > BILLING_BYTES {
            return Err(BillingError);
        }
        Ok(result)
    }
    /// Borrow the exact frozen facts; changing them requires a new checked payload.
    pub fn facts(&self) -> &BillingFacts {
        &self.0
    }
    /// The one logical fee count represented by the separate fee outcome.
    pub fn fee_count(&self) -> u32 {
        u32::from(self.0.fee.state == FeeState::Charged)
    }

    pub(crate) fn visit(&self, f: &mut impl FieldSink) {
        let b = &self.0;
        f.num("billing_version", 1);
        f.num("billing_revision", b.revision);
        f.text("billing_request_pool", &b.request_pool);
        f.num("billing_routing_generation", b.routing_generation);
        era(
            f,
            b.era,
            "billing_era_at",
            "billing_era_entry_present",
            "billing_era_entry",
        );
        f.text("billing_session_instance", &b.session_origin.instance);
        f.text("billing_session_lane", &b.session_origin.lane);
        opt_text(
            f,
            "billing_session_provider_present",
            "billing_session_provider",
            b.session_origin.provider.as_deref(),
        );
        f.num(
            "billing_metered",
            u64::from(b.logical_request != LogicalRequest::None),
        );
        let (request, preparation) = match b.logical_request {
            LogicalRequest::None => ("none", 0),
            LogicalRequest::HostOrigin => ("host_origin", 0),
            LogicalRequest::DeliveredPreparation(n) => ("delivered_preparation", u64::from(n)),
        };
        f.text("billing_logical_request", request);
        f.num("billing_logical_preparation", preparation);
        f.text("billing_fee_state", b.fee.state.as_str());
        opt_text(
            f,
            "billing_fee_lane_present",
            "billing_fee_lane",
            b.fee.lane.as_deref(),
        );
        era(
            f,
            b.fee.era,
            "billing_fee_era_at",
            "billing_fee_era_entry_present",
            "billing_fee_era_entry",
        );
        let (disposition, reason) = match &b.disposition {
            BillingDisposition::End => ("end", ""),
            BillingDisposition::Failed => ("failed", ""),
            BillingDisposition::Cancel(reason) => ("cancel", reason.as_str()),
            BillingDisposition::RecoveredRunning => ("recovered_running", ""),
        };
        f.text("billing_disposition", disposition);
        f.text("billing_reason", reason);
        f.num("billing_far_end_answered", u64::from(b.far_end_answered));
        f.num(
            "billing_caller_bytes_committed",
            u64::from(b.caller_bytes_committed),
        );
        f.num(
            "billing_final_target_present",
            u64::from(b.final_target.is_some()),
        );
        f.num(
            "billing_final_target",
            u64::from(b.final_target.unwrap_or(0)),
        );
        f.num("billing_partitions_count", b.partitions.len() as u64);
        let mut classes = 0u64;
        for p in &b.partitions {
            let (scope, preparation, dispatch) = match p.scope {
                PartitionScope::Session => ("session", 0, None),
                PartitionScope::Attempt {
                    preparation,
                    dispatch,
                } => ("attempt", preparation, dispatch),
            };
            f.text("billing_partitions[].scope", scope);
            f.num("billing_partitions[].preparation", u64::from(preparation));
            f.num(
                "billing_partitions[].dispatch_present",
                u64::from(dispatch.is_some()),
            );
            f.num(
                "billing_partitions[].dispatch",
                u64::from(dispatch.unwrap_or(0)),
            );
            f.text("billing_partitions[].kind", p.kind.as_str());
            f.text("billing_partitions[].instance", &p.instance);
            f.text("billing_partitions[].lane", &p.lane);
            opt_text(
                f,
                "billing_partitions[].provider_present",
                "billing_partitions[].provider",
                p.provider.as_deref(),
            );
            opt_text(
                f,
                "billing_partitions[].selected_pool_present",
                "billing_partitions[].selected_pool",
                p.selected_pool.as_deref(),
            );
            opt_text(
                f,
                "billing_partitions[].resource_present",
                "billing_partitions[].resource",
                p.resource.as_deref(),
            );
            f.text(
                "billing_partitions[].transport",
                p.transport.map_or("", Transport::as_str),
            );
            f.text("billing_partitions[].finality", p.finality.as_str());
            f.num("billing_partitions[].classes_count", p.classes.len() as u64);
            classes += p.classes.len() as u64;
        }
        f.num("billing_classes_count", classes);
        for (index, p) in b.partitions.iter().enumerate() {
            for (class, c) in &p.classes {
                f.num("billing_classes[].partition", index as u64);
                f.text("billing_classes[].class", class);
                count(
                    f,
                    "billing_classes[].reported_present",
                    "billing_classes[].reported_count",
                    c.reported,
                );
                count(
                    f,
                    "billing_classes[].floor_present",
                    "billing_classes[].floor_count",
                    c.floor,
                );
                count(
                    f,
                    "billing_classes[].estimated_present",
                    "billing_classes[].estimated_count",
                    c.estimated,
                );
                selected(
                    f,
                    "billing_classes[].selected_present",
                    "billing_classes[].selected_count",
                    "billing_classes[].selected_source",
                    c.selected,
                );
                selected(
                    f,
                    "billing_classes[].billed_present",
                    "billing_classes[].billed_count",
                    "billing_classes[].billed_source",
                    c.billed,
                );
                f.text_fmt(
                    "billing_classes[].rate_high_water",
                    format_args!("{}", c.rate_high_water),
                );
            }
        }
    }
}
fn opt_text(
    f: &mut impl FieldSink,
    present: &'static str,
    name: &'static str,
    value: Option<&str>,
) {
    f.num(present, u64::from(value.is_some()));
    f.text(name, value.unwrap_or(""));
}
fn count(f: &mut impl FieldSink, present: &'static str, name: &'static str, value: Option<Count>) {
    f.num(present, u64::from(value.is_some()));
    match value {
        Some(n) => f.text_fmt(name, format_args!("{n}")),
        None => f.text(name, ""),
    }
}
fn selected(
    f: &mut impl FieldSink,
    present: &'static str,
    name: &'static str,
    source: &'static str,
    value: Option<SelectedQuantity>,
) {
    count(f, present, name, value.map(|q| q.count));
    f.text(source, value.map_or("", |q| q.source.as_str()));
}
fn era(
    f: &mut impl FieldSink,
    era: BillingEra,
    at: &'static str,
    present: &'static str,
    id: &'static str,
) {
    f.num(at, era.effective_from);
    f.num(present, u64::from(era.entry_id.is_some()));
    match era.entry_id {
        Some(bytes) => f.text_fmt(id, format_args!("{}", super::HexBytes(&bytes))),
        None => f.text(id, ""),
    }
}
struct Size(usize);
impl std::fmt::Write for Size {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0 = self.0.saturating_add(s.len());
        Ok(())
    }
}
impl FieldSink for Size {
    fn text(&mut self, _: &'static str, value: &str) {
        self.0 = self.0.saturating_add(4).saturating_add(value.len());
    }
    fn text_fmt(&mut self, _: &'static str, value: std::fmt::Arguments<'_>) {
        self.0 = self.0.saturating_add(4);
        let _ = std::fmt::Write::write_fmt(self, value);
    }
    fn num(&mut self, _: &'static str, _: u64) {
        self.0 = self.0.saturating_add(8);
    }
}

impl FieldSink for crate::journal::Writer {
    fn text(&mut self, _: &'static str, value: &str) {
        self.text(value);
    }
    fn text_fmt(&mut self, _: &'static str, value: std::fmt::Arguments<'_>) {
        self.text_fmt(value);
    }
    fn num(&mut self, _: &'static str, value: u64) {
        self.num(value);
    }
}

use crate::off_path::journal::Reader;
fn text(r: &mut Reader<'_>) -> Option<String> {
    r.bounded_text(ID_BYTES)
}
fn flag(r: &mut Reader<'_>) -> Option<bool> {
    match r.num()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}
fn read_opt_text(r: &mut Reader<'_>) -> Option<Option<String>> {
    let present = flag(r)?;
    let value = text(r)?;
    if present {
        (!value.is_empty()).then_some(Some(value))
    } else {
        value.is_empty().then_some(None)
    }
}
fn ordinal(r: &mut Reader<'_>) -> Option<Option<u32>> {
    let present = flag(r)?;
    let value = u32::try_from(r.num()?).ok()?;
    if present {
        (value != 0).then_some(Some(value))
    } else {
        (value == 0).then_some(None)
    }
}
fn decimal(raw: &str) -> Option<Count> {
    let n = Count::parse(raw).ok()?;
    (!n.is_negative() && n.to_decimal_string() == raw).then_some(n)
}
fn read_count(r: &mut Reader<'_>) -> Option<Option<Count>> {
    let present = flag(r)?;
    let raw = r.bounded_text(64)?;
    if present {
        Some(Some(decimal(&raw)?))
    } else {
        raw.is_empty().then_some(None)
    }
}
fn read_selected(r: &mut Reader<'_>) -> Option<Option<SelectedQuantity>> {
    let count = read_count(r)?;
    let source = r.bounded_text(16)?;
    match count {
        Some(count) => Some(Some(SelectedQuantity {
            count,
            source: UsageSource::read(&source)?,
        })),
        None => source.is_empty().then_some(None),
    }
}
fn read_era(r: &mut Reader<'_>) -> Option<BillingEra> {
    let effective_from = r.num()?;
    let present = flag(r)?;
    let raw = r.bounded_text(24)?;
    let entry_id = if present {
        if raw.len() != 24
            || raw
                .bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0; 12];
        hex::decode_to_slice(raw, &mut bytes).ok()?;
        Some(bytes)
    } else {
        if !raw.is_empty() {
            return None;
        }
        None
    };
    Some(BillingEra {
        effective_from,
        entry_id,
    })
}
impl PartitionedBillingV1 {
    pub(crate) fn read(r: &mut Reader<'_>) -> Option<Self> {
        if r.num()? != 1 {
            return None;
        }
        let revision = r.num()?;
        let request_pool = text(r)?;
        let routing_generation = r.num()?;
        let era = read_era(r)?;
        let session_origin = SessionOrigin {
            instance: text(r)?,
            lane: text(r)?,
            provider: read_opt_text(r)?,
        };
        let metered = flag(r)?;
        let request = text(r)?;
        let preparation = u32::try_from(r.num()?).ok()?;
        let logical_request = match (request.as_str(), preparation) {
            ("none", 0) if !metered => LogicalRequest::None,
            ("host_origin", 0) if metered => LogicalRequest::HostOrigin,
            ("delivered_preparation", n) if metered && n != 0 => {
                LogicalRequest::DeliveredPreparation(n)
            }
            _ => return None,
        };
        let fee = LogicalFee {
            state: FeeState::read(&text(r)?)?,
            lane: read_opt_text(r)?,
            era: read_era(r)?,
        };
        let disposition = text(r)?;
        let reason = text(r)?;
        let disposition = match (disposition.as_str(), reason.is_empty()) {
            ("end", true) => BillingDisposition::End,
            ("failed", true) => BillingDisposition::Failed,
            ("cancel", false) => BillingDisposition::Cancel(reason),
            ("recovered_running", true) => BillingDisposition::RecoveredRunning,
            _ => return None,
        };
        let far_end_answered = flag(r)?;
        let caller_bytes_committed = flag(r)?;
        let final_target = ordinal(r)?;
        let number = usize::try_from(r.num()?).ok()?;
        if number > ATTEMPTS + 1 {
            return None;
        }
        let mut partitions = Vec::new();
        let mut sizes = Vec::new();
        partitions.try_reserve_exact(number).ok()?;
        sizes.try_reserve_exact(number).ok()?;
        for _ in 0..number {
            let scope = text(r)?;
            let preparation = u32::try_from(r.num()?).ok()?;
            let dispatch = ordinal(r)?;
            let scope = match (scope.as_str(), preparation, dispatch) {
                ("session", 0, None) => PartitionScope::Session,
                ("attempt", preparation, dispatch) if preparation != 0 => PartitionScope::Attempt {
                    preparation,
                    dispatch,
                },
                _ => return None,
            };
            let kind = TargetKind::read(&text(r)?)?;
            let instance = text(r)?;
            let lane = text(r)?;
            let provider = read_opt_text(r)?;
            let selected_pool = read_opt_text(r)?;
            let resource = read_opt_text(r)?;
            let transport = text(r)?;
            let transport = if transport.is_empty() {
                None
            } else {
                Some(Transport::read(&transport)?)
            };
            let finality = Finality::read(&text(r)?)?;
            let classes = usize::try_from(r.num()?).ok()?;
            if classes > CLASSES {
                return None;
            }
            sizes.push(classes);
            partitions.push(BillingPartition {
                scope,
                kind,
                instance,
                lane,
                provider,
                selected_pool,
                resource,
                transport,
                finality,
                classes: BTreeMap::new(),
            });
        }
        let total = usize::try_from(r.num()?).ok()?;
        if total != sizes.iter().sum::<usize>() {
            return None;
        }
        for (index, (partition, size)) in partitions.iter_mut().zip(sizes).enumerate() {
            for _ in 0..size {
                if r.num()? != index as u64 {
                    return None;
                }
                let name = r.bounded_text(64)?;
                if partition
                    .classes
                    .last_key_value()
                    .is_some_and(|(previous, _)| previous >= &name)
                {
                    return None;
                }
                let class = BillingClass {
                    reported: read_count(r)?,
                    floor: read_count(r)?,
                    estimated: read_count(r)?,
                    selected: read_selected(r)?,
                    billed: read_selected(r)?,
                    rate_high_water: decimal(&r.bounded_text(64)?)?,
                };
                partition.classes.insert(name, class);
            }
        }
        Self::new(BillingFacts {
            revision,
            request_pool,
            routing_generation,
            era,
            session_origin,
            logical_request,
            fee,
            disposition,
            far_end_answered,
            caller_bytes_committed,
            final_target,
            partitions,
        })
        .ok()
    }
}

/// Validate recipe/payload agreement before persistence or verification.
pub(crate) fn record_valid(record: &super::AuditRecord) -> bool {
    match (&record.recipe, &record.unit.billing) {
        (crate::recipe::Recipe::V9, Some(billing)) => {
            record.usage.lines.is_empty()
                && record.usage.fee_count == billing.fee_count()
                && record.signature.is_none()
                && record.key_id.is_none()
                && crate::link::Fingerprint::from_hex(&record.prev_hash).is_some()
                && record.hash.len() == 64
                && crate::link::Fingerprint::from_hex(&record.hash).is_some()
                && record.unit.records.labels.len() <= super::LABEL_SLOTS
                && record
                    .unit
                    .records
                    .user
                    .as_ref()
                    .is_none_or(|s| s.len() <= ID_BYTES)
                && record
                    .unit
                    .records
                    .labels
                    .iter()
                    .all(|(name, value)| name.len() <= ID_BYTES && value.len() <= ID_BYTES)
        }
        (crate::recipe::Recipe::V9, None) | (_, Some(_)) => false,
        (_, None) => true,
    }
}
