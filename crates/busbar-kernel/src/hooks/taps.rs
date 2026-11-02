// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub struct StageShape<'a> {
    pub request_id: u64,
    pub pool: &'a str,
    pub ingress_protocol: &'a str,
    pub message_count: usize,
    pub has_tools: bool,
    pub total_chars: usize,
    pub max_tokens: Option<u32>,
    pub stream: bool,
}

impl<'a> StageShape<'a> {
    pub fn zeroed(
        request_id: u64,
        pool: &'a str,
        ingress_protocol: &'a str,
        stream: bool,
    ) -> StageShape<'a> {
        StageShape {
            request_id,
            pool,
            ingress_protocol,
            message_count: 0,
            has_tools: false,
            total_chars: 0,
            max_tokens: None,
            stream,
        }
    }
}

pub fn fire_stage_taps_where(
    taps: &[crate::hooks::TapEntry],
    shape: &StageShape<'_>,
    stage: busbar_contract::hook_wire::HookStageProjection<'_>,
    signals: busbar_contract::signal::SignalBag,
    fires: &dyn Fn(&[String]) -> bool,
) {
    if taps.is_empty() {
        return;
    }

    let req = busbar_contract::hooks::RoutingRequest {
        request_id: shape.request_id,
        pool: shape.pool,
        ingress_protocol: shape.ingress_protocol,
        requested_model: None,
        message_count: shape.message_count,
        tool_count: 0,
        has_tools: shape.has_tools,
        total_chars: shape.total_chars,
        system_chars: 0,
        max_tokens: shape.max_tokens,
        stream: shape.stream,
        prompt: None,
        identity: None,
        signals,
        session: None,
    };
    let tap = busbar_contract::abi::host::hook::NotifyFrame::build(&req, Some(&stage), false);
    for (timeout, _send_prompt, hook, groups) in taps {
        if !fires(groups) {
            continue;
        }
        let policy = hook.clone();
        let budget = *timeout;
        let tap = tap.clone();
        spawn_bounded_tap(async move { policy.notify(tap, budget).await });
    }
}

const MAX_INFLIGHT_TAP_NOTIFICATIONS: usize = 1024;
static TAP_INFLIGHT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();
fn tap_inflight() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    TAP_INFLIGHT.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_TAP_NOTIFICATIONS))
    })
}

pub fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = tap_inflight().clone().try_acquire_owned() else {
        metrics::counter!(TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => TAP_GATE_NAME)
            .increment(1);
        return;
    };
    crate::detached::spawn_detached(async move {
        let _permit = permit;
        fut.await;
    });
}

const TAP_GATE_NAME: &str = "tap";

const TAP_NOTIFICATIONS_DROPPED_TOTAL: &str = "busbar_tap_notifications_dropped_total";
