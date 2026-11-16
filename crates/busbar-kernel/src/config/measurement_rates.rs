// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned common measurement rates, set only by a signed rate-history amendment (no
//! configuration key prices plugin measurements). Plugin declarations contain units, never prices.

use std::collections::BTreeMap;

use busbar_kernel_ledger::cost::{measurement_lane, UnitRate};

use super::RateEntryCfg;

/// Plugin kind -> actual host-bound configured namespace -> declared class -> exact rate.
pub type PluginRateCards = BTreeMap<String, BTreeMap<String, BTreeMap<String, UnitRate>>>;

/// Validate the common card grammar without guessing which module owns a configured namespace.
pub fn validate(cards: &PluginRateCards) -> Result<(), String> {
    for (kind, instances) in cards {
        if !busbar_contract::plugin::Kind::ALL
            .iter()
            .any(|k| k.to_string() == *kind)
        {
            return Err(format!("plugin_rate_cards: unknown plugin kind '{kind}'"));
        }
        for (namespace, classes) in instances {
            valid_name(namespace, "configured namespace")?;
            if classes.len() > busbar_contract::abi::measurement::MAX_MEASUREMENT_CLASSES {
                return Err(format!(
                    "plugin_rate_cards.{kind}.{namespace}: too many classes"
                ));
            }
            for class in classes.keys() {
                valid_name(class, "class")?;
            }
        }
    }
    Ok(())
}

fn valid_name(name: &str, what: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(format!(
            "plugin_rate_cards: {what} must be nonempty and contain no control characters"
        ));
    }
    Ok(())
}

/// Lower common rates into the existing builder's open-class cells. Legacy presence is retained.
pub fn compose(
    legacy: Option<&BTreeMap<String, RateEntryCfg>>,
    cards: &PluginRateCards,
) -> Option<BTreeMap<String, RateEntryCfg>> {
    if cards.values().all(BTreeMap::is_empty) {
        return legacy.cloned();
    }
    let mut out = legacy.cloned().unwrap_or_default();
    if legacy.is_some_and(BTreeMap::is_empty) {
        out.insert(
            busbar_kernel_ledger::cost::PLANE_LANE_SEP.to_string(),
            RateEntryCfg::default(),
        );
    }
    for (kind, instances) in cards {
        for (namespace, classes) in instances {
            out.insert(
                measurement_lane(kind, namespace),
                RateEntryCfg {
                    units: classes.clone(),
                    ..RateEntryCfg::default()
                },
            );
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "tests/measurement_rates_tests.rs"]
mod tests;
