// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the fold is given: the values a unit's locators retained while it ran, the counts the
//! kernel derived alongside them, and the tolerances the two are compared under.

use std::collections::{BTreeMap, BTreeSet};

use busbar_caps::step::MeterClassId;

use crate::lane::LaneLegs;
use crate::source::QuantitySource;

/// The tolerance a reported quantity may differ from its kernel companion by before the posting is
/// disputed: one per cent, on the basis-point scale. A rate card may tighten it per class.
pub const DEFAULT_VARIANCE_TOLERANCE_BP: u32 = 100;

/// The one-sided sanity bound for a located class. A located figure below the kernel floor divided
/// by this ratio, or above the floor multiplied by it, raises a dispute — in both directions, so a
/// locator pointed at the wrong field is caught whichever way it is wrong. Neither case changes the
/// amount: the located figure is always the charge and the floor is always evidence.
pub const DEFAULT_LOCATOR_FLOOR_RATIO: u64 = 4;

/// One value a locator retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedValue {
    /// Which declared class the quantity belongs to.
    pub class: MeterClassId,
    /// How much of it, in the class's own quantity.
    pub quantity: u64,
    /// Where the figure came from.
    pub source: QuantitySource,
}

/// Everything the unit's locators retained: the values themselves, and the three lane names the
/// cross-check compares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetainedLocatorValues {
    values: Vec<LocatedValue>,
    lane_legs: LaneLegs,
}

impl RetainedLocatorValues {
    /// Retain a set of located values with no lane evidence — the shape a unit that never routed
    /// upstream ends with.
    pub fn new(values: Vec<LocatedValue>) -> Self {
        RetainedLocatorValues {
            values,
            lane_legs: LaneLegs::default(),
        }
    }

    /// Retain values alongside the lane names the three legs saw.
    pub fn with_lane_legs(values: Vec<LocatedValue>, lane_legs: LaneLegs) -> Self {
        RetainedLocatorValues { values, lane_legs }
    }

    /// The retained values, in the order the locators produced them.
    pub fn values(&self) -> &[LocatedValue] {
        &self.values
    }

    /// The three lane names the cross-check compares.
    pub fn lane_legs(&self) -> &LaneLegs {
        &self.lane_legs
    }

    /// Whether any locator produced a value at all. An absent locator sends the settlement down a
    /// different row of the table.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// One quantity the kernel derived for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelLine {
    /// Which declared class the quantity belongs to.
    pub class: MeterClassId,
    /// How much of it.
    pub quantity: u64,
    /// Which kernel-derived source produced it.
    pub source: QuantitySource,
}

/// The counts the kernel derived while the unit ran: the floor under every located class, and the
/// companions the variance rule compares reported figures against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelCounts {
    lines: Vec<KernelLine>,
    proxies: BTreeMap<String, u64>,
}

impl KernelCounts {
    /// The counts the kernel derived, one per class.
    pub fn new(lines: Vec<KernelLine>) -> Self {
        KernelCounts {
            lines,
            proxies: BTreeMap::new(),
        }
    }

    /// The same, plus a per-class proxy for cardinalities that have no companion of their own — a
    /// bytes or frames figure the one-sided bound can be taken against.
    pub fn with_proxies(lines: Vec<KernelLine>, proxies: BTreeMap<String, u64>) -> Self {
        KernelCounts { lines, proxies }
    }

    /// Every kernel-derived line — the floor a unit settles at when no locator arrived.
    pub fn lines(&self) -> &[KernelLine] {
        &self.lines
    }

    /// The kernel's own figure for one class, where it has one.
    pub fn companion(&self, class: &str) -> Option<u64> {
        self.lines
            .iter()
            .find(|l| l.class.as_str() == class)
            .map(|l| l.quantity)
    }

    /// The proxy figure for a class with no companion of its own.
    pub fn proxy(&self, class: &str) -> Option<u64> {
        self.proxies.get(class).copied()
    }
}

/// The tolerances and tables the fold works under.
// contract: the metering rows of the resolved policy, and the lane alias map
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterPolicy {
    /// How far a reported quantity may differ from its kernel companion before the posting is
    /// disputed, on the basis-point scale.
    pub variance_tolerance_bp: u32,
    /// Per-class tightenings of the tolerance above. A card may tighten, never loosen.
    pub class_tolerance_bp: BTreeMap<String, u32>,
    /// The one-sided sanity bound for a located class, either side of the kernel floor.
    pub locator_floor_ratio: u64,
    /// Which lanes each locatable name expands to. A pool name expands to its member lanes; a lane
    /// name expands to itself.
    pub lane_expansions: BTreeMap<String, BTreeSet<String>>,
    /// A comparable price per lane, used only to pick the cheaper entry when the three legs
    /// disagree. A lane with no entry sorts as the cheapest, which is the conservative reading.
    pub lane_prices: BTreeMap<String, u128>,
}

impl Default for MeterPolicy {
    fn default() -> Self {
        MeterPolicy {
            variance_tolerance_bp: DEFAULT_VARIANCE_TOLERANCE_BP,
            class_tolerance_bp: BTreeMap::new(),
            locator_floor_ratio: DEFAULT_LOCATOR_FLOOR_RATIO,
            lane_expansions: BTreeMap::new(),
            lane_prices: BTreeMap::new(),
        }
    }
}

impl MeterPolicy {
    /// The tolerance in force for one class: the per-class tightening where there is one, otherwise
    /// the general figure. A per-class entry that is LOOSER than the general figure is ignored — a
    /// card may tighten a tolerance and never widen it.
    pub fn tolerance_bp(&self, class: &str) -> u32 {
        match self.class_tolerance_bp.get(class) {
            Some(&bp) if bp < self.variance_tolerance_bp => bp,
            _ => self.variance_tolerance_bp,
        }
    }

    /// The lanes a located name stands for. A name with no declared expansion stands for itself,
    /// so a plain lane name needs no configuration.
    pub fn expansion_of<'a>(&'a self, name: &'a str) -> BTreeSet<&'a str> {
        match self.lane_expansions.get(name) {
            Some(set) => set.iter().map(String::as_str).collect(),
            None => BTreeSet::from([name]),
        }
    }

    /// The comparable price of a lane, for picking the cheaper entry. An unpriced lane is the
    /// cheapest thing there is.
    pub fn price_of(&self, lane: &str) -> u128 {
        self.lane_prices.get(lane).copied().unwrap_or(0)
    }
}
