// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code for `auth::login` and `auth::login_limits`: refusal and audit text, the first sight of
//! a name the limiter keys once and then shares, and the capacity sweeps of the per-node limiter
//! tables, which run only when a table is full.

use crate::auth::login_limits::node::{AdminTable, AuditGate, SourceTable, Sustained, MAX_TRACKED};
use crate::auth::login_limits::source::SourceBucket;

/// The hosted login's redirect URI, spelled only when a credential form is fetched on a cache miss.
#[cold]
pub(crate) fn token_redirect_uri(public_url: Option<&str>) -> String {
    format!("{}/auth/token", public_url.unwrap_or(""))
}

/// A name owned once, on its first sight: a self-serve key's provider, a method's outage breaker,
/// an audit latch or a throttled account.
#[cold]
pub(crate) fn owned_name(name: &str) -> String {
    name.to_owned()
}

/// How a per-source bucket is named in logs and audit (an address or `net/len`), spelled only when
/// a source is throttled.
#[cold]
pub(crate) fn source_label(bucket: &SourceBucket) -> String {
    match bucket {
        SourceBucket::V4(v4) => v4.to_string(),
        SourceBucket::V6(len, net) => format!("{net}/{len}"),
    }
}

/// The audit principal of a throttled source.
#[cold]
pub(crate) fn source_principal(label: &str) -> String {
    format!("source:{label}")
}

/// The audit resource of the suppressed-records summary (at most once a minute).
#[cold]
pub(crate) fn suppressed_count(count: u64) -> String {
    count.to_string()
}

/// `busbar_login_throttled_total{method,limiter}`: one throttled submission.
#[cold]
pub(crate) fn throttled_metric(method: &str, limiter: &'static str) {
    metrics::counter!(
        crate::auth::login_limits::LOGIN_THROTTLED_TOTAL,
        "method" => method.to_owned(),
        "limiter" => limiter
    )
    .increment(1);
}

impl SourceTable {
    /// The full table's sweep: drop idle buckets, then (still full) the least recently touched
    /// bucket that is not at a ceiling.
    #[cold]
    pub(crate) fn evict(&mut self, now: u64, window: u64) {
        self.buckets.retain(|_, b| {
            b.prune(now, window);
            !b.idle()
        });
        if self.buckets.len() < MAX_TRACKED {
            return;
        }
        let victim = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| (b.failures.len(), b.touched))
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.buckets.remove(&k);
        }
    }
}

impl AdminTable {
    /// The full table's sweep: drop every source with no refusal inside the window.
    #[cold]
    pub(crate) fn evict(&mut self, now: u64, window_secs: u64) {
        self.buckets.retain(|_, b| {
            b.back()
                .is_some_and(|t| now.saturating_sub(*t) < window_secs)
        });
    }
}

impl AuditGate {
    /// The full gate's sweep: keep only the latches of the current window.
    #[cold]
    pub(crate) fn evict(&mut self, window: u64) {
        for subjects in self.latches.values_mut() {
            subjects.retain(|_, w| *w == window);
        }
        self.latches.retain(|_, subjects| !subjects.is_empty());
        self.latched = self.latches.values().map(|subjects| subjects.len()).sum();
    }

    /// The first latch of `subject` under `action`.
    #[cold]
    pub(crate) fn first_latch(&mut self, action: &str, subject: &str, window: u64) {
        match self.latches.get_mut(action) {
            Some(subjects) => {
                subjects.insert(owned_name(subject), window);
            }
            None => {
                let mut subjects = foldhash::HashMap::default();
                subjects.insert(owned_name(subject), window);
                self.latches.insert(owned_name(action), subjects);
            }
        }
        self.latched += 1;
    }
}

impl Sustained {
    /// The full table's sweep: keep the accounts throttled in this window or the one before.
    #[cold]
    pub(crate) fn evict(&mut self, window: u64) {
        self.accounts
            .retain(|_, (w, _, _)| window.saturating_sub(*w) <= 1);
    }

    /// The first throttle of `fingerprint` in this table.
    #[cold]
    pub(crate) fn first_throttle(&mut self, fingerprint: &str, window: u64) {
        self.accounts
            .insert(owned_name(fingerprint), (window, 0, false));
    }
}
