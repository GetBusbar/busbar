// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A version-one marker (`Bool(true)`) followed by class/price/weight triples, all under
//! [`Signal::CandidateRouteCost`]. Class is `Str`, price is `U64` nano-units per unit or
//! `Bool(false)` when unknown, and weight is `F64` expected units. No entries means a legacy
//! producer; a marker with no terms means an authoritative empty recipe. Duplicate classes
//! remain separate terms, in the plane's order. No JSON or new C layout crosses the boundary.

use super::{Signal, SignalBag, SignalValue};

#[cfg(test)]
#[path = "route_cost_tests.rs"]
mod tests;

/// One term of a plane's declared routing-cost recipe, priced for one candidate lane.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Term<'a> {
    /// The plane's opaque billable class name.
    pub class: &'a str,
    /// Nano-units per unit; absent means the card does not price this class and lane.
    pub nanos_per_unit: Option<u64>,
    /// The plane's default expected units, finite and nonnegative.
    pub expected_units: f64,
}

/// Append an authoritative recipe, including its marker even when it has no terms.
pub fn append<'a>(bag: &mut SignalBag, terms: impl IntoIterator<Item = Term<'a>>) {
    let signal = Signal::CandidateRouteCost;
    bag.push(signal, SignalValue::Bool(true));
    for term in terms {
        bag.push(signal, SignalValue::Str(term.class.to_owned().into()));
        bag.push(
            signal,
            term.nanos_per_unit
                .map_or(SignalValue::Bool(false), SignalValue::U64),
        );
        bag.push(signal, SignalValue::F64(term.expected_units));
    }
}

/// Decode the recipe without conflating a legacy producer with an empty or malformed recipe.
/// Unknown prices are retained as `None`; pricing and operator overrides belong to the hook.
pub fn decode(bag: &SignalBag) -> Result<Option<Vec<Term<'_>>>, &'static str> {
    let mut terms = Vec::new();
    let present = visit(bag, |term| terms.push(term))?;
    Ok(present.then_some(terms))
}

/// Visit a recipe without allocation. `false` means a legacy producer; `true` includes an empty
/// recipe. A late error may follow earlier visits, so callers must discard their result on error.
pub fn visit<'a>(
    bag: &'a SignalBag,
    mut visitor: impl FnMut(Term<'a>),
) -> Result<bool, &'static str> {
    let mut values = bag
        .iter()
        .filter_map(|(signal, value)| (*signal == Signal::CandidateRouteCost).then_some(value));
    match values.next() {
        None => return Ok(false),
        Some(SignalValue::Bool(true)) => {}
        _ => return Err("invalid routing-cost marker"),
    }
    while let Some(value) = values.next() {
        let SignalValue::Str(class) = value else {
            return Err("invalid routing-cost class");
        };
        if class.is_empty() {
            return Err("empty routing-cost class");
        }
        let nanos_per_unit = match values.next() {
            Some(SignalValue::U64(price)) => Some(*price),
            Some(SignalValue::Bool(false)) => None,
            _ => return Err("invalid routing-cost price"),
        };
        let expected_units = match values.next() {
            Some(SignalValue::F64(weight)) if weight.is_finite() && *weight >= 0.0 => *weight,
            _ => return Err("invalid routing-cost expected units"),
        };
        visitor(Term {
            class,
            nanos_per_unit,
            expected_units,
        });
    }
    Ok(true)
}
