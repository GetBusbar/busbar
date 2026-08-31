// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `default_max_tokens` precedence and `cache_control` clamping on the IR egress-prep seam,
//! RELOCATED here from `busbar-core`'s `proxy/tests/`. They drive
//! the witnessed `chat_handle::chat_prepare_for_egress` over a concrete `IrRequest`, which a neutral
//! crate's tests must not name — so they live beside the IR/codec they exercise.
//!
//! Byte-identical to the pre-relocation suite, save one mechanical fixture change: the core version
//! built a `crate::state::Lane` (a `pub(crate)` core type) purely to read its `protocol` and
//! `default_max_tokens` into the `EgressPrep`. Here those two values are passed directly — the
//! `EgressPrep` built, the seam driven, and every assertion are unchanged.

use super::*;
use crate::ir::IrRequest;

/// `default_max_tokens` resolution precedence on the translation seam (only fires when the source
/// omitted `max_tokens` AND the egress protocol REQUIRES it): per-model lane default wins → else
/// the global `limits.default_max_tokens` (the `global` arg) → else the historical 4096 (which is
/// just the value the global itself defaults to). This pins all three rungs. The egress protocol is
/// Anthropic (its writer `requires_max_tokens()` is true).
#[test]
fn per_model_then_global_then_4096() {
    let global = 8192; // a non-4096 global to prove it is consulted distinctly.
                       // The defaulting lives on the IR (`IrReq::prepare_for_egress`) — the engine passes the
                       // lane's resolved primitives. Drive it exactly as the translate seam does.
    let prep = |proto: &'static str, lane_default: Option<u32>, global: u32| {
        busbar_substrate::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "openai",
            egress_requires_max_tokens: decl_for(proto).is_some_and(|d| d.requires_max_tokens),
            lane_default_max_tokens: lane_default,
            global_default_max_tokens: global,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
        }
    };
    let apply = |ir: IrRequest, lane_default: Option<u32>, global: u32| -> Option<u32> {
        let mut req = ir;
        crate::chat_handle::chat_prepare_for_egress(
            &mut req,
            &prep("anthropic", lane_default, global),
        );
        req.max_tokens
    };

    // 1. Per-model set → per-model wins over the global.
    assert_eq!(
        apply(IrRequest::default(), Some(1234), global),
        Some(1234),
        "per-model default must win"
    );

    // 2. Per-model unset → fall back to the global.
    assert_eq!(
        apply(IrRequest::default(), None, global),
        Some(global),
        "with no per-model default, the global limit must be used"
    );

    // 3. Per-model unset AND global left at its historical default → 4096.
    assert_eq!(
        apply(IrRequest::default(), None, DEFAULT_MAX_TOKENS),
        Some(4096),
        "with neither per-model nor a custom global, the 4096 fallback must be used"
    );

    // 4. A caller-supplied value is NEVER overridden by any default.
    assert_eq!(
        apply(
            IrRequest {
                max_tokens: Some(7),
                ..IrRequest::default()
            },
            Some(1234),
            global
        ),
        Some(7),
        "an explicit caller max_tokens must be preserved over every default"
    );
}

/// Anthropic 400s with "A maximum of 4 blocks with cache_control may be provided".
/// The IR carries breakpoints unbounded, so a cross-protocol request (e.g. Bedrock ingress, whose
/// reader populates `cache_control` from `cachePoint`) can exceed it. `prepare_for_egress` must
/// clamp to the egress writer's cap, in Anthropic's own prefix order (system -> messages -> tools),
/// and warn with the dropped count.
#[test]
fn cache_control_breakpoints_clamped_to_four_on_anthropic_egress() {
    use crate::ir::{CacheControl, CacheKind, IrBlock, IrMessage, IrRole};
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let bp = || {
        Some(CacheControl {
            kind: CacheKind::Ephemeral,
        })
    };
    let text_with = |t: &str, cc: Option<CacheControl>| IrBlock::Text {
        text: t.to_string(),
        cache_control: cc,
        citations: Vec::new(),
    };

    // 6 breakpoints total: one on `system`, five spread across two user messages.
    let ir = IrRequest {
        system: vec![text_with("sys", bp())],
        messages: vec![
            IrMessage {
                role: IrRole::User,
                content: vec![
                    text_with("m1a", bp()),
                    text_with("m1b", bp()),
                    text_with("m1c", bp()),
                ],
            },
            IrMessage {
                role: IrRole::User,
                content: vec![text_with("m2a", bp()), text_with("m2b", bp())],
            },
        ],
        ..IrRequest::default()
    };

    let count_breakpoints = |req: &IrRequest| -> usize {
        req.system
            .iter()
            .filter(|b| {
                matches!(
                    b,
                    IrBlock::Text {
                        cache_control: Some(_),
                        ..
                    }
                )
            })
            .count()
            + req
                .messages
                .iter()
                .flat_map(|m| &m.content)
                .filter(|b| {
                    matches!(
                        b,
                        IrBlock::Text {
                            cache_control: Some(_),
                            ..
                        }
                    )
                })
                .count()
    };
    assert_eq!(count_breakpoints(&ir), 6, "fixture carries 6 breakpoints");

    let prep = busbar_substrate::ir::egress_prep::EgressPrep {
        thought_signature_fill: false,
        ingress_protocol: "bedrock",
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: Some(4),
    };

    // The cache_control over-cap drop was reclassified benign-recurring (per-request cross-protocol
    // seam) and now emits at `diag_debug!` (BUSBAR-7081), so capture at DEBUG to preserve the
    // cap/dropped-count content coverage rather than assert on a level the diagnostic no longer uses.
    let cap = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let mut req = ir;
    tracing::subscriber::with_default(subscriber, || {
        crate::chat_handle::chat_prepare_for_egress(&mut req, &prep)
    });
    let clamped = req;

    assert_eq!(
        count_breakpoints(&clamped),
        4,
        "exactly 4 breakpoints must survive the Anthropic egress cap"
    );
    // Anthropic's own prefix order: system first, so `sys` and the first three message
    // breakpoints (`m1a`,`m1b`,`m1c`) survive; `m2a`/`m2b` are dropped.
    assert!(
        matches!(
            &clamped.system[0],
            IrBlock::Text {
                cache_control: Some(_),
                ..
            }
        ),
        "the system breakpoint must survive (it is first in prefix order)"
    );
    assert!(
        matches!(
            &clamped.messages[1].content[0],
            IrBlock::Text {
                cache_control: None,
                ..
            }
        ),
        "m2a must be dropped (past the cap)"
    );
    assert!(
        cap.contains("cap of 4") && cap.contains("dropping 2"),
        "must warn naming the cap and the dropped count: {:?}",
        cap.messages()
    );
}
