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
use busbar_plugin_abi::types::KindCode;

use crate::instance::SlotTable;

/// The thread that holds a hung entry, as the hang report names it. The watch table records, when a
/// thread claims its word (once per thread, cold), that thread's name and id; the scan hands the claim of
/// the word it found stuck. With it an operator (and the core watch) can tell a plugin that never
/// returns from a worker that is itself parked, which the slot and entry alone cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder<'a> {
    /// The thread's name; None for a thread started without one.
    pub name: Option<&'a str>,
    /// The thread's id as the standard library numbers it.
    pub id: u64,
    /// The index of the thread's watch word.
    pub word: u32,
    /// Entries nested on that thread when it was found stuck (1: the hung entry alone).
    pub depth: u32,
}

impl Holder<'static> {
    /// A report with no claim behind it (a test driving `SlotTable::hung` directly).
    pub const UNKNOWN: Holder<'static> = Holder {
        name: None,
        id: 0,
        word: u32::MAX,
        depth: 0,
    };
}

impl<'a> Holder<'a> {
    /// From the watch table's record of the claim.
    pub fn of(held: &'a busbar_plugin_abi::host_side::watch::Held) -> Holder<'a> {
        Holder {
            name: held.thread_name.as_deref(),
            id: held.thread_id,
            word: held.word,
            depth: held.depth,
        }
    }
}

/// The name of a watchdog entry index: a kind's method by its table index (the same index the one
/// crossing place calls), or one of the five header entries.
pub fn entry_name(kind: KindCode, entry: u8) -> &'static str {
    const STORE: [&str; 5] = ["read", "scan", "commit", "clock", "info"];
    const SECRET: [&str; 1] = ["resolve"];
    const AUTH: [&str; 6] = [
        "verify",
        "verify_io",
        "login",
        "outbound",
        "refresh",
        "serve",
    ];
    const HOOK: [&str; 2] = ["on", "on_io"];
    const EXPORT: [&str; 3] = ["deliver", "render", "confirm"];
    const PLANE: [&str; 11] = [
        "request",
        "upstream",
        "piece",
        "end",
        "rewrite",
        "render",
        "admin",
        "probe",
        "demux",
        "select_resources",
        "channel",
    ];
    const TRANSPORT: [&str; 7] = [
        "begin", "ingest", "emit", "timer", "datagram", "event", "offer",
    ];
    match entry {
        ENTRY_DESCRIBE => return "describe",
        ENTRY_OPEN => return "open",
        ENTRY_RESUME => return "resume",
        ENTRY_CANCEL => return "cancel",
        ENTRY_CLOSE => return "close",
        _ => {}
    }
    let methods: &[&str] = match kind {
        KindCode::Store => &STORE,
        KindCode::Secret => &SECRET,
        KindCode::Auth => &AUTH,
        KindCode::Hook => &HOOK,
        KindCode::Export => &EXPORT,
        KindCode::Plane => &PLANE,
        KindCode::Transport => &TRANSPORT,
    };
    methods
        .get(usize::from(entry))
        .copied()
        .unwrap_or("an entry this engine has no name for")
}

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
                        |slot, epoch, entry, busy_ms, held| {
                            table.hung(slot, epoch, entry, busy_ms, &Holder::of(held))
                        },
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

#[cfg(test)]
mod holder_tests {
    use super::*;
    use crate::call::kinds;

    #[test]
    fn an_entry_is_named_by_the_index_the_crossing_place_calls() {
        assert_eq!(entry_name(KindCode::Plane, kinds::plane::PIECE), "piece");
        assert_eq!(
            entry_name(KindCode::Plane, kinds::plane::CHANNEL),
            "channel"
        );
        assert_eq!(
            entry_name(KindCode::Transport, kinds::transport::EMIT),
            "emit"
        );
        assert_eq!(entry_name(KindCode::Auth, kinds::auth::SERVE), "serve");
        assert_eq!(
            entry_name(KindCode::Export, kinds::export::CONFIRM),
            "confirm"
        );
        assert_eq!(entry_name(KindCode::Store, kinds::store::INFO), "info");
        assert_eq!(entry_name(KindCode::Hook, kinds::hook::ON_IO), "on_io");
        assert_eq!(
            entry_name(KindCode::Secret, kinds::secret::RESOLVE),
            "resolve"
        );
    }

    #[test]
    fn the_header_entries_have_their_names_for_every_kind() {
        for kind in KindCode::ALL {
            assert_eq!(entry_name(kind, ENTRY_OPEN), "open");
            assert_eq!(entry_name(kind, ENTRY_RESUME), "resume");
            assert_eq!(entry_name(kind, ENTRY_CLOSE), "close");
        }
        assert_eq!(
            entry_name(KindCode::Secret, 9),
            "an entry this engine has no name for"
        );
    }

    #[test]
    fn a_report_carries_the_thread_the_watch_table_recorded() {
        let held = busbar_plugin_abi::host_side::watch::Held {
            thread_name: Some("busbar-worker-3".into()),
            thread_id: 41,
            word: 7,
            depth: 2,
        };
        let holder = Holder::of(&held);
        assert_eq!(holder.name, Some("busbar-worker-3"));
        assert_eq!((holder.id, holder.word, holder.depth), (41, 7, 2));
    }
}
