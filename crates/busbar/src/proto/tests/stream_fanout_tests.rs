use super::*;
use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent, IrUsage, StreamDecodeState};
use serde_json::json;

// OpenAI flat stream → Anthropic-shaped IR events. Exact-sequence decode asserts
// (ungameable: the expected Vec is derived from the state-machine spec, not from output).
#[test]
fn test_openai_read_fanout_text() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"role":"assistant"}}]}),
        json!({"choices":[{"delta":{"content":"Hel"}}]}),
        json!({"choices":[{"delta":{"content":"lo"}}]}),
        json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }
    assert_eq!(
        events,
        vec![
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None
            },
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("Hel".to_string())
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("lo".to_string())
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::EndTurn),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None
                },
            },
            IrStreamEvent::MessageStop,
        ]
    );
}

#[test]
fn test_openai_read_fanout_tool_call() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"loc\":\"SF\"}"}}]}}]}),
        json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }
    assert_eq!(
        events,
        vec![
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None
            },
            // Tool-only stream (no text) is 0-based — text reserves index 0 ONLY
            // when text actually appears. Previously asserted the buggy 1-based index.
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "get_weather".to_string()
                }
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta(String::new())
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::InputJsonDelta("{\"loc\":\"SF\"}".to_string())
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::ToolUse),
                stop_sequence: None,
                usage: IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None
                },
            },
            IrStreamEvent::MessageStop,
        ]
    );
}

/// INV-C: a backend that streams `tool_calls[{index:1}]` with NO index 0 (observed from vLLM /
/// Azure / OpenRouter re-indexing) must not let the text block, which derives its slot from
/// `open_tools.len()`, collide with the tool's own upstream-index-derived slot. Both blocks must
/// claim DISTINCT IR indices, each opened exactly once and closed exactly once.
#[test]
fn openai_sparse_tool_index_does_not_collide_text_onto_tool_block() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        json!({"choices":[{"delta":{"content":"hi"}}]}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }

    let tool_index = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { .. },
        } => Some(*index),
        _ => None,
    });
    let text_index = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::Text,
        } => Some(*index),
        _ => None,
    });
    assert_ne!(
        tool_index, text_index,
        "tool and text must not share an IR index: tool={tool_index:?} text={text_index:?}, events={events:?}"
    );
    // Each opened index must have exactly one BlockStart and one matching BlockStop.
    let mut start_indices: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart { index, .. } => Some(*index),
            _ => None,
        })
        .collect();
    let n = start_indices.len();
    start_indices.sort_unstable();
    start_indices.dedup();
    assert_eq!(
        start_indices.len(),
        n,
        "no two BlockStart frames may share an index; got duplicate in {events:?}"
    );
}

/// INV-C: `tool_calls[{index:1}]`, then a text chunk, then `tool_calls[{index:0}]` (the OTHER
/// half of the same collision — a second tool arriving with a LOWER upstream index than the first
/// must not walk backward into an index text or the first tool already claimed). All three blocks
/// must land on three DISTINCT, densely-packed IR indices.
#[test]
fn openai_tool_index_zero_after_text_does_not_collide() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        json!({"choices":[{"delta":{"content":"hi"}}]}),
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_2","type":"function","function":{"name":"get_time","arguments":""}}]}}]}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }

    let mut start_indices: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            IrStreamEvent::BlockStart { index, .. } => Some(*index),
            _ => None,
        })
        .collect();
    start_indices.sort_unstable();
    assert_eq!(
        start_indices,
        vec![0, 1, 2],
        "three blocks (tool, text, tool) must land on three distinct dense indices; got {start_indices:?}, events={events:?}"
    );
}

/// INV-C, the GAP case: a lone `tool_calls[{index:5}]` (no other blocks) must claim IR index 0,
/// not the raw upstream index 5. `v1`'s fix (`tool_ir_index.values().max() + 1`) would have shipped
/// this exact gap — index 0 never opened, breaking an Anthropic SDK accumulator that appends on
/// `content_block_start` and indexes `snapshot.content[index]` on the following delta.
#[test]
fn openai_sparse_tool_indices_are_dense_from_zero() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let events = reader.read_response_events(
        "",
        &json!({"choices":[{"delta":{"tool_calls":[{"index":5,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        &mut st,
    );
    let tool_index = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { .. },
        } => Some(*index),
        _ => None,
    });
    assert_eq!(
        tool_index,
        Some(0),
        "a lone tool block must claim IR index 0 (dense from zero), not the raw upstream index 5; events={events:?}"
    );
}

/// REGRESSION PROOF (passes at HEAD too — HEAD's recomputed-base arithmetic happens to land on 2
/// here, a slot neither tool0 nor text ever claimed) — but is RED against v2's now-withdrawn dense
/// formula (`offset + text_index.is_some() + tool_ir_index.len()`), which computes 1 = text's own
/// slot on this exact path, because the terminal branch's `mem::take` clears the tool maps but not
/// `text_index`. This test exists to stop that formula from ever being reintroduced: a tool_calls
/// chunk arriving AFTER a finish chunk must claim a FRESH index that collides with neither the
/// pre-finish tool NOR the text block.
#[test]
fn openai_tool_after_finish_chunk_claims_a_fresh_index() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    for chunk in [
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
        json!({"choices":[{"delta":{"content":"hi"}}]}),
        json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
        // Arrives AFTER the finish chunk — an already-degraded path at HEAD (stream.rs only drops
        // trailing MessageDeltas post-stop, not BlockStart/Delta/Stop), but the index arithmetic
        // must still not collide.
        json!({"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":""}}]}}]}),
    ] {
        events.extend(reader.read_response_events("", &chunk, &mut st));
    }

    // Index claimed by the pre-finish tool (tool0) and by the text block.
    let pre_finish_tool_index = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { name, .. },
        } if name == "get_weather" => Some(*index),
        _ => None,
    });
    let text_index = events.iter().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::Text,
        } => Some(*index),
        _ => None,
    });
    // The post-finish tool's BlockStart is the LAST BlockStart in the sequence.
    let post_finish_tool_index = events.iter().rev().find_map(|e| match e {
        IrStreamEvent::BlockStart {
            index,
            block: IrBlockMeta::ToolUse { name, .. },
        } if name == "get_time" => Some(*index),
        _ => None,
    });

    assert!(
        post_finish_tool_index.is_some(),
        "the post-finish tool_calls chunk must still open a block; events={events:?}"
    );
    assert_ne!(
        post_finish_tool_index, text_index,
        "the post-finish tool must NOT collide with the text block's index; got post-finish={post_finish_tool_index:?} text={text_index:?}, events={events:?}"
    );
    assert_ne!(
        post_finish_tool_index, pre_finish_tool_index,
        "the post-finish tool must NOT collide with the pre-finish tool's index; got post-finish={post_finish_tool_index:?} pre-finish={pre_finish_tool_index:?}, events={events:?}"
    );
}

#[test]
fn test_openai_read_fanout_cached_tokens() {
    let reader = OpenAiReader;
    let mut st = StreamDecodeState::default();
    let mut events: Vec<IrStreamEvent> = Vec::new();
    events.extend(reader.read_response_events(
        "",
        &json!({"choices":[{"delta":{"content":"hi"}}]}),
        &mut st,
    ));
    events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":7}}}),
            &mut st,
        ));
    let usage = events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage.clone()),
            _ => None,
        })
        .expect("MessageDelta present");
    assert_eq!(
        usage.cache_read_input_tokens,
        Some(7),
        "cached_tokens → cache_read"
    );
    assert_eq!(
        usage.cache_creation_input_tokens, None,
        "OpenAI has no cache-creation split"
    );
    // A2 normalization: input_tokens is UNCACHED (prompt_tokens 100 - cached 7 = 93).
    assert_eq!(usage.input_tokens, 93);
    assert_eq!(usage.output_tokens, 50);
    // Billing is unchanged for OpenAI-family: billable = uncached(93) + cache_read(7) + out(50)
    // = 150 = the pre-A2 prompt_total(100) + output(50). No double-count, no regression.
    assert_eq!(usage.billable_tokens(), 150);
}

#[test]
fn test_anthropic_read_events_wraps_singular() {
    let reader = AnthropicReader;
    let mut st = StreamDecodeState::default();
    let data =
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}});
    let single = reader.read_response_event("content_block_delta", &data);
    let plural = reader.read_response_events("content_block_delta", &data, &mut st);
    assert_eq!(
        plural,
        single.into_iter().collect::<Vec<_>>(),
        "Anthropic plural wraps singular 1:1"
    );
    assert_eq!(plural.len(), 1);
    // ping → empty
    assert_eq!(
        reader.read_response_events("ping", &json!({}), &mut st),
        Vec::<IrStreamEvent>::new()
    );
}
