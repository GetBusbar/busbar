// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `datagram` (and its DTLS engine, `dtls`) off-path code (see `crate::off_path`): the clock tick's
//! sweeps. The tick visits the associations whose deadline passed and expires what aged out; no
//! datagram, emit or admission runs it.

use std::net::SocketAddr;
use std::time::Instant;

use crate::datagram::{Answered, Owed, PortAssociations};
use crate::dtls::{Association, CONSENT_TIMEOUT};

impl PortAssociations {
    /// The serving caller's incremental clock path. A busy producer retains its ordinary
    pub fn timeout_incremental(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<_> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|deadline| deadline <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter_map(|(id, f)| {
                    f.deadline()
                        .is_some_and(|deadline| deadline <= now)
                        .then_some(*id)
                })
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.incremental(id, Owed::Timer, now, send))
            .collect()
    }

    /// The clock, for every association whose deadline has passed (one out is owed it).
    pub fn timeout(&self, now: Instant, send: &dyn Fn(SocketAddr, &[u8])) -> Answered {
        let due: Vec<u64> = {
            let mut assocs = self.lock();
            for out in assocs.out.values_mut() {
                if out.deadline.is_some_and(|d| d <= now) {
                    out.deadline = None;
                    out.owed.push_back(Owed::Timer);
                }
            }
            assocs
                .framings
                .iter()
                .filter(|(_, f)| f.deadline().is_some_and(|d| d <= now))
                .map(|(id, _)| *id)
                .collect()
        };
        due.into_iter()
            .flat_map(|id| self.turn(id, Owed::Timer, now, send).1)
            .collect()
    }
}

impl Association {
    /// `dtls` timers: heard and proven paths and probes older than [`CONSENT_TIMEOUT`] age out (the
    /// bound and wanted paths are kept), the probe index with its probes.
    pub(crate) fn expire(&mut self, now: Instant) {
        let keep = [self.bound, self.wanted];
        let fresh = |t: &Instant| now.saturating_duration_since(*t) < CONSENT_TIMEOUT;
        self.heard
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.proven
            .retain(|p, t| keep.contains(&Some(*p)) || fresh(t));
        self.probes.retain(|_, (_, sent)| fresh(sent));
        self.probed.retain(|_, sents| {
            sents.retain(|sent| fresh(&*sent));
            !sents.is_empty()
        });
    }
}
