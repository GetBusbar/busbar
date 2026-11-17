// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

const MAX_INFLIGHT_TAP_NOTIFICATIONS: usize = 1024;
static TAP_INFLIGHT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
fn tap_inflight() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    TAP_INFLIGHT.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_TAP_NOTIFICATIONS))
    })
}

/// One in-flight slot for a tap notification, or `None` when every slot is taken (the dropped
/// notification is counted).
pub(crate) fn tap_slot() -> Option<tokio::sync::OwnedSemaphorePermit> {
    let Ok(permit) = tap_inflight().clone().try_acquire_owned() else {
        metrics::counter!(TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => TAP_GATE_NAME)
            .increment(1);
        return None;
    };
    Some(permit)
}

pub fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(permit) = tap_slot() else {
        return;
    };
    crate::detached::spawn_detached(async move {
        let _permit = permit;
        fut.await;
    });
}

const TAP_GATE_NAME: &str = "tap";

const TAP_NOTIFICATIONS_DROPPED_TOTAL: &str = "busbar_tap_notifications_dropped_total";
