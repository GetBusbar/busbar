// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 watchdog: the §10.6 ceiling row an image's describe fixes (the clamp table, frozen in round 11) and
//! the registry's scan thread (IF §10.6, §11.2). The thread runs `watch::scan` over the registry's `SlotTable`;
//! it holds no Instance and no Image reference. The 1.5 crossing watchdog stays in `dispatch::watchdog`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_plugin_abi::host_side::watch::{
    ENTRY_CANCEL, ENTRY_CLOSE, ENTRY_DESCRIBE, ENTRY_OPEN, ENTRY_RESUME,
};
use busbar_plugin_abi::records::CEIL_OPEN;

use crate::instance::SlotTable;

const MS: u64 = 1_000;
const S: u64 = 1_000_000;

/// S0 owns the scan thread; dropping that owner stops and joins it.
pub(crate) struct Watchdog {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    pub(crate) fn start(table: Arc<SlotTable>) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("busbar-plugin-watchdog".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    busbar_plugin_abi::host_side::watch::scan(
                        |slot, entry| table.watch_view(slot, entry),
                        |slot, epoch, entry, busy_ms| table.hung(slot, epoch, entry, busy_ms),
                    );
                    std::thread::park_timeout(Duration::from_millis(100));
                }
            })
            .map_err(|error| format!("plugin watchdog thread: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Runtime teardown takes the already-constructed thread exactly once.
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

/// One declared value that fell outside its range and was clamped (logged once at `add`).
pub(crate) struct Clamp {
    pub entry: u8,
    pub declared: u64,
    pub clamped: u64,
}

/// The slot row for one image and the clamps `add` logs.
pub(crate) struct Row {
    pub row: [u32; 64],
    pub clamped: Vec<Clamp>,
}

/// A ceiling's default and clamp range in microseconds.
struct Range {
    default: u64,
    min: u64,
    max: u64,
}

/// The fixed describe row: every index 5 s (round 14).
pub(crate) fn describe_row() -> [u32; 64] {
    [(5 * S) as u32; 64]
}

/// §10.6 "the clamp ranges, frozen". `declared` is every D_CEILING `(method, micros)` of the image, `blocking` is
/// the store `F_BLOCKING_FILE` fact (the store-lane column). A declared value outside its range is clamped, never
/// refused; a method naming no entry (not exactly one bit of 0..=55, and not `CEIL_OPEN`) is `Err(have)`, the
/// caller's `DescribeInvalid`. Entries with no declared value take the default.
pub(crate) fn ceiling_row(declared: &[(u64, u64)], blocking: bool) -> Result<Row, String> {
    let method = if blocking {
        Range {
            default: 30 * S,
            min: 50 * MS,
            max: 120 * S,
        }
    } else {
        Range {
            default: 50 * MS,
            min: MS,
            max: S,
        }
    };
    let open = if blocking {
        Range {
            default: 30 * S,
            min: 5 * S,
            max: 3_600 * S,
        }
    } else {
        Range {
            default: 5 * S,
            min: 5 * S,
            max: 60 * S,
        }
    };
    let mut row = [(5 * S) as u32; 64];
    for slot in row.iter_mut().take(56) {
        *slot = method.default as u32;
    }
    row[usize::from(ENTRY_OPEN)] = open.default as u32;
    row[usize::from(ENTRY_RESUME)] = (2 * S) as u32;
    row[usize::from(ENTRY_DESCRIBE)] = (5 * S) as u32;
    row[usize::from(ENTRY_CANCEL)] = (5 * S) as u32;
    row[usize::from(ENTRY_CLOSE)] = (if blocking { 30 * S } else { 5 * S }) as u32;
    let mut clamped = Vec::new();
    for &(m, micros) in declared {
        let (entry, range) = if m == CEIL_OPEN {
            (ENTRY_OPEN, &open)
        } else if m.count_ones() == 1 && m.trailing_zeros() < 56 {
            (m.trailing_zeros() as u8, &method)
        } else {
            return Err(format!("method {m:#x}"));
        };
        let value = micros.clamp(range.min, range.max);
        if value != micros {
            clamped.push(Clamp {
                entry,
                declared: micros,
                clamped: value,
            });
        }
        row[usize::from(entry)] = value as u32;
    }
    Ok(Row { row, clamped })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeclared_row_takes_the_defaults() {
        let row = ceiling_row(&[], false).unwrap().row;
        assert_eq!(row[0], 50_000);
        assert_eq!(row[usize::from(ENTRY_OPEN)], 5_000_000);
        assert_eq!(row[usize::from(ENTRY_RESUME)], 2_000_000);
    }

    #[test]
    fn a_declared_value_is_clamped_and_reported() {
        let r = ceiling_row(&[(1 << 3, 10 * S), (CEIL_OPEN, S)], false).unwrap();
        assert_eq!(r.row[3], S as u32);
        assert_eq!(r.row[usize::from(ENTRY_OPEN)], (5 * S) as u32);
        assert_eq!(r.clamped.len(), 2);
    }

    #[test]
    fn the_store_lane_has_its_own_column() {
        let r = ceiling_row(&[(CEIL_OPEN, 3_600 * S)], true).unwrap();
        assert_eq!(r.row[usize::from(ENTRY_OPEN)], (3_600 * S) as u32);
        assert_eq!(r.row[usize::from(ENTRY_CLOSE)], (30 * S) as u32);
        assert!(r.clamped.is_empty());
    }

    #[test]
    fn a_method_naming_no_entry_is_refused() {
        assert!(ceiling_row(&[(0b11, S)], false).is_err());
        assert!(ceiling_row(&[(1 << 56, S)], false).is_err());
    }
}
