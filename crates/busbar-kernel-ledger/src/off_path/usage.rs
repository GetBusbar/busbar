// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A dated cell read back: its fee eras rebuilt from a durable row, and its segments folded per
//! lane for an operator usage view or a scrape; never per request.

use std::collections::BTreeMap;

use crate::cost::RawRateEra;
use crate::usage::FeeEras;

impl<E: Copy + Eq + Into<RawRateEra> + From<u64>> FeeEras<E> {
    /// A split read back from its dated eras and counts; era zero, the remainder, is dropped.
    #[must_use]
    pub fn of(dated: impl IntoIterator<Item = (E, u64)>) -> Self {
        let eras: Vec<(E, u64)> = dated
            .into_iter()
            .filter(|(e, n)| (*e).into() != RawRateEra::legacy(0) && *n != 0)
            .collect();
        let total = eras.iter().fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        Self(eras, total)
    }

    /// [`FeeEras::of`] over counts that may each be refused: the split, or the first refusal met
    /// in the order given. The split is built once, straight from the counts.
    pub fn try_of<X>(dated: impl IntoIterator<Item = Result<(E, u64), X>>) -> Result<Self, X> {
        let mut eras = Vec::new();
        let mut total = 0u64;
        for row in dated {
            let (era, n) = row?;
            if era.into() != RawRateEra::legacy(0) && n != 0 {
                eras.push((era, n));
                total = total.saturating_add(n);
            }
        }
        Ok(Self(eras, total))
    }
}

/// A dated cell's segments folded back to ONE count map per lane, in first-seen order, with `add`
pub fn by_lane<'r, V: Copy>(
    segments: impl IntoIterator<Item = (&'r str, BTreeMap<String, V>), IntoIter: Clone>,
    add: impl Fn(V, V) -> V,
) -> Vec<(String, BTreeMap<String, V>)> {
    let mut out: Vec<(String, BTreeMap<String, V>)> = Vec::new();
    for (lane, counts) in segments {
        match out.iter_mut().find(|(name, _)| name == lane) {
            None => out.push((lane.to_string(), counts)),
            Some((_, into)) => {
                for (class, v) in counts {
                    let merged = into.get(&class).map_or(v, |have| add(*have, v));
                    into.insert(class, merged);
                }
            }
        }
    }
    out
}
