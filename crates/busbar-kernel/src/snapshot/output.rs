// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checked preflight of the closed snapshot projection's requested allocations (#420).
//! Charges are conservative allocation traffic, retained until the captured result retires.
//! Standard-library node/growth layouts require supported-target qualification.

use super::{Building, Series, SeriesSlot, SnapshotName};
use crate::limits::output::{CaptureScope, OutputError};
use metrics::Key;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct Bound(usize);

impl Bound {
    pub(crate) fn add(&mut self, bytes: usize) -> Result<(), OutputError> {
        self.0 = self.0.checked_add(bytes).ok_or(OutputError::Capacity)?;
        Ok(())
    }

    pub(crate) fn repeated(&mut self, count: usize, bytes: usize) -> Result<(), OutputError> {
        self.add(count.checked_mul(bytes).ok_or(OutputError::Capacity)?)
    }

    pub(crate) fn vector<T>(&mut self, count: usize) -> Result<(), OutputError> {
        // Four times the minimum/geometric capacity covers the legacy Vec's allocation
        // traffic, including replacement overlap. Nested payloads are charged separately.
        self.repeated(
            count.max(4),
            std::mem::size_of::<T>()
                .checked_mul(4)
                .ok_or(OutputError::Capacity)?,
        )
    }

    pub(crate) fn tree<K, V>(&mut self, insertions: usize) -> Result<(), OutputError> {
        let slot = std::mem::size_of::<K>()
            .checked_add(std::mem::size_of::<V>())
            .and_then(|n| n.checked_add(std::mem::size_of::<usize>()))
            .ok_or(OutputError::Capacity)?;
        let node = slot
            .checked_mul(16)
            .and_then(|n| n.checked_add(64))
            .and_then(|n| n.checked_mul(4))
            .ok_or(OutputError::Capacity)?;
        self.repeated(insertions, node)
    }

    pub(crate) fn reserve(self, scope: &mut CaptureScope) -> Result<(), OutputError> {
        scope.reserve_requested(self.0)
    }
}

pub(super) fn copy_key(scope: &mut CaptureScope, key: &Key) -> Result<Key, OutputError> {
    // Do not retain an opaque registry Key whose shared backing may have arbitrarily larger
    // spare capacity. Construct an independently charged exact-size key before guard release.
    let name = scope.copy_str(key.name())?;
    let mut labels = scope.vector(key.labels().len())?;
    for label in key.labels() {
        labels.push(metrics::Label::new(
            scope.copy_str(label.key())?,
            scope.copy_str(label.value())?,
        ));
    }
    Ok(Key::from_parts(name, labels))
}

pub(super) fn series(scope: &mut CaptureScope, key: &Key, lines: usize) -> Result<(), OutputError> {
    series_labels(
        scope,
        key.name(),
        key.labels().map(|l| (l.key(), l.value())),
        lines,
    )
}

pub(super) fn series_labels<'a>(
    scope: &mut CaptureScope,
    name: &str,
    labels: impl Iterator<Item = (&'a str, &'a str)>,
    lines: usize,
) -> Result<(), OutputError> {
    let mut bound = Bound::default();
    bound.tree::<(u8, SnapshotName), BTreeMap<SeriesSlot, Series>>(1)?;
    bound.tree::<SeriesSlot, Series>(1)?;
    // Name, map key, temporary Key, suffix concatenation and each emitted sample name.
    bound.repeated(
        lines.checked_add(6).ok_or(OutputError::Capacity)?,
        name.len(),
    )?;
    let copies = lines
        .checked_mul(4)
        .and_then(|n| n.checked_add(8))
        .ok_or(OutputError::Capacity)?;
    let mut count = 0usize;
    for (key, value) in labels {
        count = count.checked_add(1).ok_or(OutputError::Capacity)?;
        bound.repeated(copies, key.len())?;
        bound.repeated(copies, value.len())?;
        bound.repeated(copies, std::mem::size_of::<(String, String)>())?;
    }
    // Minimum Vec allocations, the optional summary coordinate, retained Key control, and
    // numeric String formatting traffic (f64 decimal output is at most 327 bytes).
    bound.repeated(lines.checked_add(1).ok_or(OutputError::Capacity)?, 4096)?;
    bound.vector::<(String, String)>(count)?;
    bound.vector::<busbar_contract::export_calls::Sample>(lines)?;
    bound.vector::<(&str, Option<String>, String)>(lines)?;
    bound.reserve(scope)
}

pub(super) fn finish(
    out: Building,
    help: &std::collections::HashMap<String, String>,
    scope: &mut Option<CaptureScope>,
) -> Result<Vec<busbar_contract::export_calls::Family>, OutputError> {
    let mut families = match scope {
        Some(scope) => scope.vector(out.len())?,
        None => Vec::with_capacity(out.len()),
    };
    for ((kind, mut name), series) in out {
        let count = series.values().try_fold(0usize, |sum, value| {
            sum.checked_add(value.samples.len())
                .ok_or(OutputError::Capacity)
        })?;
        let mut samples = match scope {
            Some(scope) => scope.vector(count)?,
            None => Vec::with_capacity(count),
        };
        for value in series.into_values() {
            samples.extend(value.samples);
        }
        let help = match (scope.as_mut(), help.get(&name.0)) {
            (Some(scope), Some(text)) => Some(scope.copy_str(text)?),
            (_, text) => text.cloned(),
        };
        families.push(busbar_contract::export_calls::Family {
            name: std::mem::take(&mut name.0),
            help,
            unit: None,
            kind,
            samples,
        });
    }
    Ok(families)
}
