// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-only grant and restrictions a nested child route runs under. Targets and limits
//! originate in host configuration.
use std::sync::Arc;
use std::time::Instant;

/// A single immutable operation binding. Payload bytes cannot change any of these fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub revision: u64,
    pub plane: String,
    pub operation: String,
    pub target: String,
    pub target_binding: String,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_children: u32,
    pub timeout_ms: u64,
    pub max_budget_micros: u64,
}
impl Grant {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.revision == 0
            || self.plane.is_empty()
            || self.operation.is_empty()
            || self.target_binding.is_empty()
            || !self.target.starts_with('/')
            || self.target.contains(['\r', '\n', '#'])
            || self.operation.contains(char::is_whitespace)
            || self.max_input_bytes == 0
            || self.max_input_bytes > 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 1024 * 1024
            || self.max_children != 1
            || self.timeout_ms == 0
            || self.timeout_ms > 60_000
            || self.max_budget_micros == 0
        {
            return Err("invalid hook child dispatch grant");
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Cancellation {
    cancelled: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
    pub async fn cancelled(&self) {
        loop {
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            wake.await;
        }
    }
}

/// Host-only restrictions handed to the ordinary nested route.
#[derive(Debug, Clone)]
pub struct Constraints {
    pub grant: Arc<Grant>,
    pub deadline: Instant,
    pub cancellation: Arc<Cancellation>,
}
