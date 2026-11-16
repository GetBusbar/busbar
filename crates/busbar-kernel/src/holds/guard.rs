// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mass-deprovision guard's cell `W` (IF §12.29): `window_start_s u64 BE ‖ moved u32 BE ‖ released_until_s u64
//! BE` in the instance's `dir_ns`. One codec and one judgement shared by the directory's writes (W1-K6P, which
//! reads `W` in the same read and commits it in the same commit as the record) and the admin release (W2-K8P).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::min3::ProvisioningGuard;

/// The `dir_ns` key of the guard cell.
pub const W_KEY: &[u8] = b"W";
/// Encoded length of the guard cell.
pub const W_LEN: usize = 20;
/// `for_s` of a release without a body.
pub const RELEASE_DEFAULT_S: u64 = 900;
/// Smallest accepted `for_s`.
pub const RELEASE_MIN_S: u64 = 60;
/// Largest accepted `for_s`.
pub const RELEASE_MAX_S: u64 = 86_400;

/// The guard cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardCell {
    pub window_start_s: u64,
    pub moved: u32,
    pub released_until_s: u64,
}

impl GuardCell {
    /// None = not 20 bytes (a store written by something else; the directory answers Unavailable).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let b: &[u8; W_LEN] = bytes.try_into().ok()?;
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[0..8]);
        let mut m = [0u8; 4];
        m.copy_from_slice(&b[8..12]);
        let mut r = [0u8; 8];
        r.copy_from_slice(&b[12..20]);
        Some(Self {
            window_start_s: u64::from_be_bytes(w),
            moved: u32::from_be_bytes(m),
            released_until_s: u64::from_be_bytes(r),
        })
    }

    pub fn encode(&self) -> [u8; W_LEN] {
        let mut out = [0u8; W_LEN];
        out[0..8].copy_from_slice(&self.window_start_s.to_be_bytes());
        out[8..12].copy_from_slice(&self.moved.to_be_bytes());
        out[12..20].copy_from_slice(&self.released_until_s.to_be_bytes());
        out
    }

    /// The cell as of `now_s`: a window that has run out restarts with `moved` 0 (the release is kept).
    pub fn current(cell: Option<Self>, now_s: u64, window_s: u64) -> Self {
        match cell {
            Some(c) if now_s < c.window_start_s.saturating_add(window_s) => c,
            Some(c) => Self {
                window_start_s: now_s,
                moved: 0,
                released_until_s: c.released_until_s,
            },
            None => Self {
                window_start_s: now_s,
                moved: 0,
                released_until_s: 0,
            },
        }
    }

    /// true = an operator release is in force at `now_s`.
    pub fn released(&self, now_s: u64) -> bool {
        now_s < self.released_until_s
    }
}

/// What a write that moves `n` linked principals may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Proceed; the commit puts this cell (`moved + n`) under the same predicates as the record.
    Pass(GuardCell),
    /// Proceed: an operator release is in force; the cell is read (predicate) but not rewritten.
    Released,
    /// dir::GUARD: write nothing, audit `directory_guard{instance, would_move: n}`; raise
    /// `provisioning_guard_tripped{instance}` when [`TripLatch::first`] says so. `window_start_s` names the window.
    Trip { window_start_s: u64 },
}

/// The guard's judgement of a write that moves `n` linked principals at `now_s` (IF §12.29).
pub fn judge(cell: Option<GuardCell>, now_s: u64, n: u32, guard: ProvisioningGuard) -> GuardVerdict {
    let c = GuardCell::current(cell, now_s, guard.window_s);
    if c.released(now_s) {
        return GuardVerdict::Released;
    }
    if u64::from(c.moved) + u64::from(n) > u64::from(guard.max) {
        return GuardVerdict::Trip {
            window_start_s: c.window_start_s,
        };
    }
    GuardVerdict::Pass(GuardCell {
        moved: c.moved + n,
        ..c
    })
}

/// Why a release body was refused (400, the text names the field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRefused {
    /// `for_s` outside 60..=86,400.
    ForOutOfRange(u64),
}

impl core::fmt::Display for ReleaseRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ForOutOfRange(n) => write!(
                f,
                "`for_s` is {n}; it must be {RELEASE_MIN_S}..={RELEASE_MAX_S} seconds (default {RELEASE_DEFAULT_S})"
            ),
        }
    }
}

/// The cell an operator release commits: `moved` 0, `released_until_s = now_s + for_s` (default 900).
pub fn release(
    cell: Option<GuardCell>,
    now_s: u64,
    for_s: Option<u64>,
    window_s: u64,
) -> Result<GuardCell, ReleaseRefused> {
    let for_s = for_s.unwrap_or(RELEASE_DEFAULT_S);
    if !(RELEASE_MIN_S..=RELEASE_MAX_S).contains(&for_s) {
        return Err(ReleaseRefused::ForOutOfRange(for_s));
    }
    let c = GuardCell::current(cell, now_s, window_s);
    Ok(GuardCell {
        window_start_s: c.window_start_s,
        moved: 0,
        released_until_s: now_s.saturating_add(for_s),
    })
}

/// Raises `provisioning_guard_tripped` once per window per instance on this replica.
#[derive(Debug)]
pub struct TripLatch(AtomicU64);

impl Default for TripLatch {
    fn default() -> Self {
        Self::new()
    }
}

impl TripLatch {
    pub const fn new() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }

    /// true = the first trip this replica saw in window `window_start_s`: raise the alert.
    pub fn first(&self, window_start_s: u64) -> bool {
        self.0.swap(window_start_s, Ordering::AcqRel) != window_start_s
    }
}
