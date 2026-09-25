// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping Q57 — the IR-CORE half of the typed slots: what the shared stream machinery does with
//! a slot a reader set. Buffered == stream: a slot the buffered response carries must reach the
//! synthesized stream a streaming client of a buffered upstream is given.

use crate::ir::{IrBlock, IrResponse, IrStopDetail, IrStopReason, IrStreamEvent, IrUsage};

fn refusal_answer() -> IrResponse {
    IrResponse {
        content: vec![IrBlock::Text {
            text: "I can't help with that.".to_string(),
            cache_control: None,
            citations: vec![],
            refusal: true,
        }],
        stop_reason: Some(IrStopReason::Refusal),
        stop_detail: Some(IrStopDetail::Refusal {
            category: Some("cyber".to_string()),
            explanation: None,
        }),
        usage: IrUsage {
            input_tokens: 3,
            output_tokens: 6,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// IR-02: a refusal message synthesized into a stream opens a refusal text block.
#[test]
fn ir02_refusal_text_opens_a_refusal_block_on_the_synthesized_stream() {
    let events = crate::proto_stream::response_to_ir_events(&refusal_answer());
    let start = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart { refusal, .. } => Some(*refusal),
            _ => None,
        })
        .expect("a BlockStart");
    assert!(
        start,
        "refusal flag lost on the synthesized stream: {events:?}"
    );
}

/// IR-16 / IR-02: the stop refinement rides the synthesized terminal delta.
#[test]
fn ir16_stop_detail_rides_the_synthesized_terminal_delta() {
    let mut ir = refusal_answer();
    ir.stop_reason = Some(IrStopReason::MaxTokens);
    ir.stop_detail = Some(IrStopDetail::ContextWindowExceeded);
    let events = crate::proto_stream::response_to_ir_events(&ir);
    let detail = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta {
                stop_reason: Some(_),
                stop_detail,
                ..
            } => Some(stop_detail.clone()),
            _ => None,
        })
        .expect("a terminal MessageDelta");
    assert_eq!(detail, Some(IrStopDetail::ContextWindowExceeded));
}

/// An answer that set no slot synthesizes exactly what it did before the slots existed.
#[test]
fn an_answer_without_slots_synthesizes_no_slot() {
    let mut ir = refusal_answer();
    ir.stop_detail = None;
    if let IrBlock::Text { refusal, .. } = &mut ir.content[0] {
        *refusal = false;
    }
    for e in crate::proto_stream::response_to_ir_events(&ir) {
        match e {
            IrStreamEvent::BlockStart { refusal, .. } => assert!(!refusal),
            IrStreamEvent::MessageDelta { stop_detail, .. } => assert!(stop_detail.is_none()),
            _ => {}
        }
    }
}
