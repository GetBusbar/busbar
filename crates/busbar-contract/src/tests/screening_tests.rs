// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the screening projection's render cost (`ir/facts.rs`).

use super::*;

fn payload() -> serde_json::Value {
    serde_json::json!({"query": "a tool call argument object", "rows": [1, 2, 3, 4, 5]})
}

/// A `Data` item renders its payload EVERY time it is asked for its screenable text — that is the
/// cost the memo exists to pay once. Pinned so the memo test below is measuring something real
/// rather than a counter that never moves.
#[test]
fn asking_a_data_item_for_its_text_renders_the_payload_every_time() {
    let value = payload();
    let item = ContentItem::Data {
        author: "assistant",
        slot: Slot::ToolArgs(0),
        label: "args",
        value: &value,
    };
    let _ = take_data_renders();
    for _ in 0..7 {
        let _ = item.screenable_text();
    }
    assert_eq!(
        take_data_renders(),
        7,
        "each screenable_text() on a Data item serializes the payload again"
    );
}

/// THE MEMO. A screening pass reads each item's text many times — the size sum, the cleared-set
/// digest, and the prompt projection, all of that again for every attached gate. Through
/// `ScreenedContent` the payload is serialized ONCE for the whole pass, however many readers and
/// however many gates there are.
#[test]
fn a_screening_pass_renders_each_data_payload_exactly_once() {
    let value = payload();
    let items = vec![
        ContentItem::Text {
            author: "user",
            slot: Slot::Turn(0),
            text: std::borrow::Cow::Borrowed("hello"),
        },
        ContentItem::Data {
            author: "assistant",
            slot: Slot::ToolArgs(0),
            label: "args",
            value: &value,
        },
    ];

    let _ = take_data_renders();
    let screened = ScreenedContent::over(&items);
    // Five gates, each doing what one gate does: filter to the not-yet-cleared pieces, sum the size
    // signals, digest what it screened, and flatten the text for the prompt projection.
    for _ in 0..5 {
        let unscreened = screened.select(|_, _| true);
        let _ = unscreened.counts();
        let _: Vec<String> = unscreened.digests().collect();
        let _: String = unscreened
            .iter()
            .map(|(_, t)| t)
            .collect::<Vec<_>>()
            .join("\n");
    }
    assert_eq!(
        take_data_renders(),
        1,
        "the screening pass must serialize a Data payload once, not once per reader per gate"
    );
}

/// The memo is a COST fix, not a behaviour fix: what it hands out is byte-identical to asking the
/// item directly, digests included.
#[test]
fn the_memo_answers_exactly_what_the_item_answers() {
    let value = payload();
    let items = vec![
        ContentItem::Text {
            author: "system",
            slot: Slot::System,
            text: std::borrow::Cow::Borrowed("you are a proxy"),
        },
        ContentItem::Data {
            author: "assistant",
            slot: Slot::ToolArgs(0),
            label: "args",
            value: &value,
        },
        ContentItem::Opaque {
            author: "assistant",
            slot: Slot::Turn(1),
            label: "reasoning",
            marker: "[opaque]",
        },
    ];
    let screened = ScreenedContent::over(&items);

    assert_eq!(screened.len(), items.len());
    for (i, item) in items.iter().enumerate() {
        assert_eq!(
            screened.iter().nth(i).map(|(_, t)| t.to_string()),
            Some(item.screenable_text().into_owned()),
            "item {i}'s memoised text"
        );
        assert_eq!(
            screened.digest(i),
            Some(item.screening_digest()),
            "item {i}'s digest is unchanged by the memo"
        );
    }
    assert_eq!(
        screened.counts(),
        Shape::counts_over(&items),
        "the memo's size signals are the same sum"
    );
}

/// A filtered subset (the incremental scan's not-yet-cleared pieces) keeps its rendered text: the
/// filter must not send the pass back to the items to re-render what it already had.
#[test]
fn selecting_a_subset_carries_the_rendered_text_across() {
    let value = payload();
    let items = vec![
        ContentItem::Data {
            author: "assistant",
            slot: Slot::ToolArgs(0),
            label: "args",
            value: &value,
        },
        ContentItem::Text {
            author: "user",
            slot: Slot::Turn(0),
            text: std::borrow::Cow::Borrowed("hi"),
        },
    ];
    let screened = ScreenedContent::over(&items);
    let _ = take_data_renders();
    let only_data = screened.select(|item, _| matches!(item, ContentItem::Data { .. }));
    assert_eq!(only_data.len(), 1);
    assert_eq!(
        only_data.iter().next().map(|(_, t)| t.to_string()),
        Some(items[0].screenable_text().into_owned())
    );
    // One render: the `screenable_text()` in the assertion above. The select itself did none.
    assert_eq!(
        take_data_renders(),
        1,
        "filtering must carry the rendered text, not re-render it"
    );
}
