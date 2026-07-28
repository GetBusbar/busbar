use crate::ir::variant::{EgressPrep, IrReq};
use crate::ir::IrRequest;
use crate::proto::Protocol;
use crate::state::Lane;
use std::collections::HashMap;
use std::sync::Arc;

// An Anthropic lane (its writer `requires_max_tokens()` is true) with a given per-model default.
fn anthropic_lane(default_max_tokens: Option<u32>) -> Lane {
    Lane {
        reasoning: false,
        prompt_caching: false,
        default_max_tokens,
        model: "claude".to_string(),
        provider: "anthropic".to_string(),
        signing_host: "api.anthropic.com".to_string(),
        base_url: "https://api.anthropic.com".to_string(),
        api_key: "k".to_string(),
        credential: crate::egress_auth::resolve("anthropic", None),
        protocol: Arc::new(Protocol::anthropic()),
        max: 1,
        error_map: Arc::new(HashMap::new()),
        context_max: None,
        path: None,
        path_base: None,
        health: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

/// `default_max_tokens` resolution precedence on the translation seam (only fires when the source
/// omitted `max_tokens` AND the egress protocol REQUIRES it): per-model lane default wins → else
/// the global `limits.default_max_tokens` (the `global` arg) → else the historical 4096 (which is
/// just the value the global itself defaults to). This pins all three rungs.
#[test]
fn per_model_then_global_then_4096() {
    let global = 8192; // a non-4096 global to prove it is consulted distinctly.
                       // The defaulting now lives on the IR (`IrReq::prepare_for_egress`) — the engine passes the
                       // lane's resolved primitives. Drive it exactly as the translate seam does.
    let prep = |lane: &Lane, global: u32| EgressPrep {
        ingress_protocol: "openai",
        egress_requires_max_tokens: lane.protocol.writer().requires_max_tokens(),
        lane_default_max_tokens: lane.default_max_tokens,
        global_default_max_tokens: global,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: None,
    };
    let apply = |ir: IrRequest, lane: &Lane, global: u32| -> Option<u32> {
        let mut req = IrReq::Chat(ir);
        req.prepare_for_egress(&prep(lane, global));
        match req {
            IrReq::Chat(c) => c.max_tokens,
            _ => unreachable!(),
        }
    };

    // 1. Per-model set → per-model wins over the global.
    assert_eq!(
        apply(IrRequest::default(), &anthropic_lane(Some(1234)), global),
        Some(1234),
        "per-model default must win"
    );

    // 2. Per-model unset → fall back to the global.
    assert_eq!(
        apply(IrRequest::default(), &anthropic_lane(None), global),
        Some(global),
        "with no per-model default, the global limit must be used"
    );

    // 3. Per-model unset AND global left at its historical default → 4096.
    assert_eq!(
        apply(
            IrRequest::default(),
            &anthropic_lane(None),
            crate::proto::DEFAULT_MAX_TOKENS
        ),
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
            &anthropic_lane(Some(1234)),
            global
        ),
        Some(7),
        "an explicit caller max_tokens must be preserved over every default"
    );
}

/// class-6 6b1: Anthropic 400s with "A maximum of 4 blocks with cache_control may be provided".
/// The IR carries breakpoints unbounded, so a cross-protocol request (e.g. Bedrock ingress, whose
/// reader populates `cache_control` from `cachePoint`) can exceed it. `prepare_for_egress` must
/// clamp to the egress writer's cap, in Anthropic's own prefix order (system -> messages -> tools),
/// and warn with the dropped count.
#[test]
fn cache_control_breakpoints_clamped_to_four_on_anthropic_egress() {
    use crate::ir::{CacheControl, CacheKind, IrBlock, IrMessage, IrRole};
    use crate::test_support::warn_capture::WarnCapture;
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

    let prep = EgressPrep {
        ingress_protocol: "bedrock",
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: Some(4),
    };

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let mut req = IrReq::Chat(ir);
    tracing::subscriber::with_default(subscriber, || req.prepare_for_egress(&prep));
    let IrReq::Chat(clamped) = req else {
        unreachable!()
    };

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
