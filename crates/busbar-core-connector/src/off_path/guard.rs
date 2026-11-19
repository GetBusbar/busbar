// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The destination guard's name resolution (`crate::guard`): a resolution runs on a thread of its
//! own, started once per name the guard must resolve, never per request byte; the thread owns the
//! name it resolves and the list of addresses it answers.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::guard::Resolved;

/// The system's answer for `host`: every address it resolves to.
pub(crate) fn system_lookup(host: &str) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
    let found = (host, 0)
        .to_socket_addrs()
        .map_err(|e| crate::cold::egress::lookup_failed(&e));
    found.map(|a| a.map(|s| s.ip()).collect())
}

/// Resolve `host` by `lookup` on a thread of its own, answering through `done`, with at most `cap`
/// resolutions in flight in `in_flight`: one more is answered at once as a failure, no thread
/// started.
pub(crate) fn resolve_capped<F>(
    host: &str,
    done: Resolved,
    cap: usize,
    in_flight: &'static AtomicUsize,
    lookup: F,
) where
    F: FnOnce(&str) -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    use std::sync::Mutex;
    let Some(place) = LookupPlace::take(cap, in_flight) else {
        done(Err(crate::cold::egress::lookups_in_flight(cap)));
        return;
    };
    let cell = Arc::new(Mutex::new(Some(done)));
    let mine = Arc::clone(&cell);
    let take = |c: &Mutex<Option<Resolved>>| c.lock().unwrap_or_else(|e| e.into_inner()).take();
    let host = host.to_owned();
    let spawned = std::thread::Builder::new()
        .name("busbar-resolve".into())
        .spawn(move || {
            let _place = place;
            let answer = lookup(host.as_str());
            if let Some(done) = take(&mine) {
                done(answer);
            }
        });
    if spawned.is_err() {
        if let Some(done) = take(&cell) {
            done(Err("no resolver thread".into()));
        }
    }
}

/// One taken place among the lookups in flight; dropping it gives the place back.
pub(crate) struct LookupPlace(&'static AtomicUsize);

impl LookupPlace {
    /// Takes a place if fewer than `cap` are taken.
    pub(crate) fn take(cap: usize, in_flight: &'static AtomicUsize) -> Option<Self> {
        in_flight
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < cap).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(in_flight))
    }
}

impl Drop for LookupPlace {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
