// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Kind-neutral factual usage. Plugins name units and cumulative quantities; only the host
//! supplies attribution, operation identity, durable storage and prices. No capabilities cross
//! this interface. A missing class is unobserved, never an implied zero.

use crate::abi::mechanism::call::AbiStr;
use crate::abi::mechanism::check::{fault, listed, named, Fault, Rule};

/// Maximum immutable declarations and cumulative counts per invocation.
pub const MAX_MEASUREMENT_CLASSES: usize = 64;

/// Immutable disjoint raw class and unit family, carried in the signed Statement.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BillableClass {
    /// The class.
    pub class: AbiStr,
    /// Its unit family.
    pub family: AbiStr,
}

impl BillableClass {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    pub const ZERO: Self = Self {
        class: AbiStr::ZERO,
        family: AbiStr::ZERO,
    };
}

/// Legacy plane-only estimate; rejected by common measurement batches.
pub const UNITS_ESTIMATED: u32 = 0;
/// A factual whole-unit report; pricing and attribution belong to the host.
pub const UNITS_REPORTED: u32 = 1;
/// [`UnitCount::source`]: the legacy plane's floor for a delivered reply whose far-end usage could not be
pub const UNITS_FLOOR: u32 = 2;
/// An estimated count whose amount is an exact scale-six mantissa; never billed.
pub const UNITS_ESTIMATED_MICROS: u32 = 3;
/// A reported count whose amount is an exact scale-six mantissa.
pub const UNITS_REPORTED_MICROS: u32 = 4;
/// A usage floor whose amount is an exact scale-six mantissa.
pub const UNITS_FLOOR_MICROS: u32 = 5;

/// Legacy plane source eligibility. This supplies neither a price nor attribution authority.
pub const fn units_bill(source: u32) -> bool {
    matches!(
        source,
        UNITS_REPORTED | UNITS_FLOOR | UNITS_REPORTED_MICROS | UNITS_FLOOR_MICROS
    )
}

/// One exact cumulative raw count.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnitCount {
    /// Index into the owning declaration list (common Statement or legacy plane tail).
    pub class: u32,
    /// Whole-unit source 0/1/2, or the corresponding explicit micro-unit source 3/4/5.
    pub source: u32,
    /// The cumulative count, interpreted using `source`; legacy whole values are unchanged.
    pub amount: u64,
}

impl UnitCount {
    /// Read the measurement without changing the legacy whole-unit source codes.
    pub fn count(self) -> Result<crate::Count, crate::count::CountError> {
        let scale = match self.source {
            UNITS_ESTIMATED | UNITS_REPORTED | UNITS_FLOOR => 0,
            UNITS_ESTIMATED_MICROS | UNITS_REPORTED_MICROS | UNITS_FLOOR_MICROS => 6,
            _ => return Err(crate::count::CountError::UnknownScale),
        };
        crate::Count::from_stored(i128::from(self.amount), scale)
    }

    /// Encode a nonnegative measurement within the declared signed store range.
    /// Whole counts retain their original source and amount; fractional counts explicitly name scale six.
    pub fn from_count(
        class: u32,
        source: u32,
        count: crate::Count,
    ) -> Result<Self, crate::count::CountError> {
        use crate::count::CountError;
        if count.is_negative() {
            return Err(CountError::Negative);
        }
        if !count.fits_a_64_bit_column() {
            return Err(CountError::OutOfRange);
        }
        let base = match source {
            UNITS_ESTIMATED | UNITS_ESTIMATED_MICROS => UNITS_ESTIMATED,
            UNITS_REPORTED | UNITS_REPORTED_MICROS => UNITS_REPORTED,
            UNITS_FLOOR | UNITS_FLOOR_MICROS => UNITS_FLOOR,
            _ => return Err(CountError::UnknownScale),
        };
        let micros = u64::try_from(count.micros()).map_err(|_| CountError::OutOfRange)?;
        Ok(if micros % 1_000_000 == 0 {
            Self {
                class,
                source: base,
                amount: micros / 1_000_000,
            }
        } else {
            Self {
                class,
                source: base + 3,
                amount: micros,
            }
        })
    }

    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    pub const ZERO: Self = Self {
        class: 0,
        source: 0,
        amount: 0,
    };
}

/// A bounded cumulative report. `revision` echoes the host's input cursor; it grants no authority.
/// Arrays follow the common Envelope lifetime: retained until the next operation on that ticket,
/// or copied by the host before another call on the same thread for unticketed operations.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MeasurementBatch {
    /// Host-supplied revision. Zero means no report.
    pub revision: u64,
    /// Distinct class indexes and exact factual counts; no estimates or usage floors.
    pub counts: *const UnitCount,
    /// At most 64; omitted indexes remain unknown.
    pub counts_len: usize,
}

impl MeasurementBatch {
    /// No reporting requested or supplied.
    pub const ZERO: Self = Self {
        revision: 0,
        counts: core::ptr::null(),
        counts_len: 0,
    };
}

/// Check signed class declarations before accepting any reports.
///
/// # Safety
/// Every non-NULL string pointer names its stated number of live bytes.
pub unsafe fn check_declarations(classes: &[BillableClass]) -> Result<(), Fault> {
    if classes.len() > MAX_MEASUREMENT_CLASSES {
        return Err(fault(Rule::OverMax, "statement.measurement_classes"));
    }
    let mut names = std::collections::HashSet::new();
    for class in classes {
        for (value, field) in [
            (class.class, "measurement_class.class"),
            (class.family, "measurement_class.family"),
        ] {
            named(value, field)?;
            if value.len > 256 {
                return Err(fault(Rule::OverMax, field));
            }
            // SAFETY: the caller guarantees live string storage; named checked NULL/length.
            let bytes = unsafe { core::slice::from_raw_parts(value.ptr, value.len) };
            if !valid_name(bytes) {
                return Err(fault(Rule::UnknownCode, field));
            }
        }
        // SAFETY: checked above and live under the caller's contract.
        let name = unsafe { core::slice::from_raw_parts(class.class.ptr, class.class.len) };
        if !names.insert(name) {
            return Err(fault(Rule::Contradiction, "measurement_class.class"));
        }
    }
    Ok(())
}

pub(crate) fn valid_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= 256
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
}

/// Check count bounds, exact storage range, sources and distinct declared indexes.
pub fn check_counts(counts: &[UnitCount], declared_classes: usize) -> Result<(), Fault> {
    if declared_classes > MAX_MEASUREMENT_CLASSES || counts.len() > MAX_MEASUREMENT_CLASSES {
        return Err(fault(Rule::OverMax, "measurements.counts"));
    }
    let mut seen = 0u64;
    for count in counts {
        if count.class as usize >= declared_classes {
            return Err(fault(Rule::IndexOutOfRange, "measurements.class"));
        }
        let mask = 1u64 << count.class;
        if seen & mask != 0 {
            return Err(fault(Rule::Contradiction, "measurements.class"));
        }
        seen |= mask;
        if !matches!(count.source, UNITS_REPORTED | UNITS_REPORTED_MICROS) {
            return Err(fault(Rule::UnknownCode, "measurements.source"));
        }
        if !count
            .count()
            .is_ok_and(|value| value.fits_a_64_bit_column())
        {
            return Err(fault(Rule::OverMax, "measurements.amount"));
        }
    }
    Ok(())
}

/// Validate a report against the host cursor and signed declaration count before copying it.
/// An all-zero report is absence, even for an active cursor. An active empty report echoes the
/// cursor but observes no classes. Pending and short retries must echo the same cursor.
///
/// # Safety
/// A non-NULL counts pointer names `counts_len` live UnitCounts, if its count is within bounds.
pub unsafe fn check_batch(
    batch: &MeasurementBatch,
    declared_classes: usize,
    expected_revision: u64,
) -> Result<(), Fault> {
    if batch.counts_len > MAX_MEASUREMENT_CLASSES || declared_classes > MAX_MEASUREMENT_CLASSES {
        return Err(fault(Rule::OverMax, "measurements.counts"));
    }
    if batch.revision == 0 && batch.counts_len == 0 && batch.counts.is_null() {
        return Ok(());
    }
    if expected_revision == 0 || batch.revision != expected_revision || declared_classes == 0 {
        return Err(fault(Rule::Foreign, "measurements.revision"));
    }
    listed(batch.counts, batch.counts_len, "measurements.counts")?;
    if batch.counts_len != 0
        && !(batch.counts as usize).is_multiple_of(core::mem::align_of::<UnitCount>())
    {
        return Err(fault(Rule::Misaligned, "measurements.counts"));
    }
    let counts = if batch.counts_len == 0 {
        &[]
    } else {
        // SAFETY: bounded and aligned above; caller supplies live storage.
        unsafe { core::slice::from_raw_parts(batch.counts, batch.counts_len) }
    };
    check_counts(counts, declared_classes)
}
