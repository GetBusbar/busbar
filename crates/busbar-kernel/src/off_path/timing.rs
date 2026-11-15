// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `timing` profiler's report table: printed on demand (`dump`, `dump_scoped`) or once at
//! process exit, never per request. It sits outside the request-path marker because it sorts the
//! rows it prints.

#![cfg(feature = "timing")]

use crate::timing::{MethodStat, ThreadRegistry};

/// Print one scope's table, rows by total time, largest first.
pub(crate) fn print_table(scope: &str, map: &ThreadRegistry) {
    if map.is_empty() {
        eprintln!("BUSBAR_TIMING scope={scope} (no samples)");
        return;
    }
    let mut rows: Vec<(&&'static str, &MethodStat)> = map.iter().collect();
    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.total_ns));
    eprintln!(
        "BUSBAR_TIMING scope={scope}  {:<28} {:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "name", "count", "total", "mean", "p50", "p99", "min", "max"
    );
    for (name, s) in rows {
        let mean = s.total_ns.checked_div(s.count).unwrap_or(0);
        let min = if s.min_ns == u64::MAX { 0 } else { s.min_ns };
        eprintln!(
            "BUSBAR_TIMING scope={scope}  {:<28} {:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10}",
            name,
            s.count,
            Ns(s.total_ns),
            Ns(mean),
            Ns(s.percentile(0.50)),
            Ns(s.percentile(0.99)),
            Ns(min),
            Ns(s.max_ns),
        );
    }
}

/// A nanosecond count rendered as `Nns` / `N.NNus` / `N.NNms`, honouring the table's width and
/// alignment. It is written into a stack buffer, so a table row allocates no strings.
struct Ns(u64);

impl std::fmt::Display for Ns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let mut buf = StackText::default();
        let ns = self.0;
        if ns < 1_000 {
            write!(buf, "{ns}ns")?;
        } else if ns < 1_000_000 {
            write!(buf, "{:.2}us", ns as f64 / 1_000.0)?;
        } else {
            write!(buf, "{:.2}ms", ns as f64 / 1_000_000.0)?;
        }
        f.pad(buf.as_str())
    }
}

/// A fixed stack buffer for one [`Ns`] cell; `u64::MAX` ns is 18 digits plus `.NNms`.
#[derive(Default)]
struct StackText {
    bytes: [u8; 32],
    len: usize,
}

impl StackText {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl std::fmt::Write for StackText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        let dst = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
