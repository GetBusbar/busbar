// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned common measurement rates. Plugin declarations contain units, never prices.

use std::collections::{BTreeMap, BTreeSet};

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

/// Validate class ownership against the immutable declaration of the actual host binding.
/// Missing rates are advisory strings; configured classes absent from that declaration are fatal.
/// Call for every bound instance, including instances with no configured card.
pub fn validate_plugin_rate_coverage<'a>(
    cards: &PluginRateCards,
    kind: &str,
    namespace: &str,
    declared: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<String>, String> {
    validate(cards)?;
    let declared: BTreeSet<_> = declared.into_iter().collect();
    let card = cards
        .get(kind)
        .and_then(|instances| instances.get(namespace));
    if let Some(card) = card {
        let unknown: Vec<_> = card
            .keys()
            .filter(|class| !declared.contains(class.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(format!(
                "plugin_rate_cards.{kind}.{namespace}: class(es) {} are not declared by this configured instance",
                unknown.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", "),
            ));
        }
    }
    Ok(declared.into_iter().filter(|class| !card.is_some_and(|card| card.contains_key(*class)))
        .map(|class| format!("plugin_rate_cards.{kind}.{namespace}: no rate for declared class '{class}'; counts remain available and unpriced (configure 0 explicitly to make them free)"))
        .collect())
}

/// Reject cards naming namespaces that were never bound by the host. Call after bindings resolve.
pub fn validate_plugin_rate_instances<'a>(
    cards: &PluginRateCards,
    instances: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), String> {
    validate(cards)?;
    let bound: BTreeSet<_> = instances.into_iter().collect();
    for (kind, instances) in cards {
        for namespace in instances.keys() {
            if !bound.contains(&(kind.as_str(), namespace.as_str())) {
                return Err(format!(
                    "plugin_rate_cards.{kind}.{namespace}: no such configured plugin binding"
                ));
            }
        }
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
