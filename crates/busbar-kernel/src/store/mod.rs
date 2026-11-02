// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

#[cfg(test)]
const COOLDOWN_TRANSIENT_SECS: u64 = 10;

#[cfg(test)]
const HARD_DOWN_COOLDOWN_SECS: u64 = crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS;

#[cfg(test)]
const MAX_HONORED_RETRY_AFTER_SECS: u64 = crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS;

fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn read_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}

fn write_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static IN_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[allow(dead_code)]
#[cfg(test)]
fn set_now_for_test(t: u64) {
    TEST_NOW.with(|c| c.set(t));
    IN_TEST.with(|c| c.set(true));
}

#[allow(dead_code)]
#[cfg(test)]
fn now_for_test() -> u64 {
    if IN_TEST.with(|c| c.get()) {
        TEST_NOW.with(|c| c.get())
    } else {
        now()
    }
}

mod in_memory;
pub use in_memory::*;

pub const MAX_POOL_MEMBERS: usize = 8;

pub mod plane_view;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/breaker_race_tests.rs"]
mod breaker_race_tests;

mod vocab;
pub use vocab::*;
