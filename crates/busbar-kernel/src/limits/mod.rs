// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub(crate) mod admission;

use crate::config::{
    LimitsResolved, DEFAULT_KEY_GAUGE_LIMIT, DEFAULT_POLICY_TIMEOUT_MS,
    DEFAULT_RATE_SWEEP_INTERVAL, DEFAULT_USAGE_FLUSH_INTERVAL_MS,
};

#[cfg(test)]
use crate::config::DEFAULT_REQUEST_BODY_MAX_BYTES;

#[cfg(test)]
pub(crate) use busbar_kernel::config::limits::InstallGuard;

#[cfg(test)]
pub(crate) use busbar_kernel::config::limits::LIMITS_TEST_LOCK;

fn get() -> Option<LimitsResolved> {
    busbar_kernel::config::limits::installed()
}

pub fn tls_handshake_timeout_secs() -> u64 {
    get()
        .map(|l| l.tls_handshake_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS)
}

pub fn request_body_read_timeout_secs() -> u64 {
    get()
        .map(|l| l.request_body_read_timeout_secs)
        .unwrap_or(crate::config::DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS)
}

pub(crate) fn key_gauge_limit() -> usize {
    get()
        .map(|l| l.key_gauge_limit)
        .unwrap_or(DEFAULT_KEY_GAUGE_LIMIT)
}

pub(crate) fn rate_sweep_interval() -> u32 {
    get()
        .map(|l| l.rate_sweep_interval)
        .unwrap_or(DEFAULT_RATE_SWEEP_INTERVAL)
}

pub(crate) fn usage_flush_interval_ms() -> u64 {
    get()
        .map(|l| l.usage_flush_interval_ms)
        .unwrap_or(DEFAULT_USAGE_FLUSH_INTERVAL_MS)
}

pub(crate) fn default_policy_timeout_ms() -> u64 {
    get()
        .map(|l| l.default_policy_timeout_ms)
        .unwrap_or(DEFAULT_POLICY_TIMEOUT_MS)
}

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod tests;
