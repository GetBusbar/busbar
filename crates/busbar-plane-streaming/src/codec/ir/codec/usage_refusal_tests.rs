//! ITEM 133 (the duplex twin) — A PRESENT-BUT-UNREADABLE BILLED COUNT REFUSES THE TURN (#42).
//!
//! Both duplex dialects read every billed count as `read_count_u64(..).unwrap_or_default()`, so a
//! stringified count metered a real turn at ZERO. Each test drives the real `read_down` path: an
//! unreadable count now surfaces as a session `Error` (the plane closes the turn as failed and
//! records the error), never a `Usage` event carrying zero; an ABSENT count keeps meaning zero.
use super::gemini::GeminiLiveCodec;
use super::*;

fn wire(v: &Value) -> WireEvent {
    WireEvent(Bytes::from(v.to_string().into_bytes()))
}

fn refused(ir: &[IrServerEvent]) -> bool {
    matches!(ir, [IrServerEvent::Error { code, .. }] if code == "usage_unreadable")
}

#[test]
fn openai_realtime_refuses_a_stringified_count() {
    let mut st = DecodeState::default();
    for usage in [
        json!({"input_tokens": "1500", "output_tokens": 9}),
        json!({"input_tokens": 10, "output_tokens": 9, "input_token_details": {"audio_tokens": "8"}}),
        json!({"input_tokens": 10, "output_tokens": 9, "input_token_details": {"cached_tokens": "3"}}),
    ] {
        let src = json!({"type": "response.done", "response": {"usage": usage}});
        let ir = OpenAiRealtimeCodec.read_down(wire(&src), &mut st);
        assert!(refused(&ir), "{usage} must refuse, not meter zero: {ir:?}");
    }
}

#[test]
fn openai_realtime_absent_counts_still_read_as_zero() {
    let mut st = DecodeState::default();
    let src = json!({"type": "response.done", "response": {"usage": {"output_tokens": 9}}});
    let ir = OpenAiRealtimeCodec.read_down(wire(&src), &mut st);
    let [IrServerEvent::Usage(u)] = ir.as_slice() else {
        panic!("expected Usage, got {ir:?}")
    };
    assert_eq!((u.text_in, u.text_out, u.cached), (0, 9, 0));
}

#[test]
fn gemini_live_refuses_a_stringified_count() {
    let mut st = DecodeState::default();
    for um in [
        json!({"promptTokenCount": "95", "responseTokenCount": 50}),
        json!({"promptTokenCount": 95, "responseTokenCount": 50, "cachedContentTokenCount": "5"}),
        json!({"promptTokensDetails": [{"modality": "AUDIO", "tokenCount": "80"}]}),
    ] {
        let src = json!({"usageMetadata": um});
        let ir = GeminiLiveCodec.read_down(wire(&src), &mut st);
        assert!(refused(&ir), "{um} must refuse, not meter zero: {ir:?}");
    }
}

#[test]
fn gemini_live_absent_counts_still_read_as_zero() {
    let mut st = DecodeState::default();
    let src = json!({"usageMetadata": {"responseTokenCount": 50}});
    let ir = GeminiLiveCodec.read_down(wire(&src), &mut st);
    let [IrServerEvent::Usage(u)] = ir.as_slice() else {
        panic!("expected Usage, got {ir:?}")
    };
    assert_eq!((u.text_in, u.text_out, u.cached), (0, 50, 0));
}
