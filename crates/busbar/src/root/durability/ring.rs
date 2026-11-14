// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bounded audit ring. The contract: ordered by seq, at most `AUDIT_RING`
//! records, oldest evicted, chain-verifiable as a window. Its storage is
//! private; callers read the window through `as_slice`.

use busbar_kernel_audit::AuditRecord;

use super::AUDIT_RING;

/// Compaction batch: evicted records are dropped this many at a time.
pub(crate) const AUDIT_SLACK: usize = 128;

pub(crate) struct AuditRing {
    buf: Vec<AuditRecord>,
    #[cfg(test)]
    compactions: u64,
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditRing {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::with_capacity(AUDIT_RING + AUDIT_SLACK),
            #[cfg(test)]
            compactions: 0,
        }
    }

    /// Keeps the newest `AUDIT_RING` of `sealed` (the resume path).
    pub(crate) fn from_sealed(mut sealed: Vec<AuditRecord>) -> Self {
        let keep = sealed.len().saturating_sub(AUDIT_RING);
        let mut ring = Self::new();
        ring.buf.extend(sealed.drain(keep..));
        ring
    }

    pub(crate) fn push(&mut self, record: AuditRecord) {
        self.buf.push(record);
        if self.buf.len() > AUDIT_RING {
            let over = self.buf.len() - AUDIT_RING;
            self.buf.drain(..over);
            #[cfg(test)]
            {
                self.compactions += 1;
            }
        }
    }

    /// Push unless an equal record (full-struct equality) is already in the view.
    pub(crate) fn push_unique(&mut self, record: AuditRecord) -> bool {
        if self.as_slice().iter().any(|existing| existing == &record) {
            return false;
        }
        self.push(record);
        true
    }

    /// The ring as the contract defines it: the newest <= `AUDIT_RING` records, oldest first.
    pub(crate) fn as_slice(&self) -> &[AuditRecord] {
        let n = self.buf.len();
        &self.buf[n.saturating_sub(AUDIT_RING)..]
    }

    /// Test-only: in-place mutation of exactly the visible window (never dead slack).
    #[cfg(test)]
    pub(crate) fn window_mut_for_tamper_test(&mut self) -> &mut [AuditRecord] {
        let n = self.buf.len();
        &mut self.buf[n.saturating_sub(AUDIT_RING)..]
    }

    /// Test-only: drops the dead slack, then retains over the window, so the
    /// result equals `Vec::retain` on the ring.
    #[cfg(test)]
    pub(crate) fn retain_for_tamper_test(&mut self, f: impl FnMut(&AuditRecord) -> bool) {
        let dead = self.buf.len().saturating_sub(AUDIT_RING);
        self.buf.drain(..dead);
        self.buf.retain(f);
    }

    #[cfg(test)]
    pub(crate) fn compactions(&self) -> u64 {
        self.compactions
    }
}

#[cfg(test)]
#[path = "../tests/durability_ring.rs"]
mod tests;
