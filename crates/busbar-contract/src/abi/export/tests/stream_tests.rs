// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM TYPE FOR BOTH LANES: the export kind's tail order (the discriminant) and the frozen

use super::*;
use crate::export_stream::ExportStream;

/// The frozen stream words, in the order every export config, sink and tail has carried them.
const FROZEN: [&str; 10] = [
    "metrics",
    "logs",
    "traces",
    "costs",
    "decisions",
    "events",
    "identity",
    "prompts",
    "completions",
    "content",
];

#[test]
fn every_stream_s_discriminant_is_its_position_in_the_frozen_order() {
    assert_eq!(ExportStream::ALL.len(), FROZEN.len());
    for (i, (s, tok)) in ExportStream::ALL.iter().zip(FROZEN).enumerate() {
        assert_eq!(*s as u8 as usize, i, "{tok}: the tail position");
        assert_eq!(s.as_token(), tok, "the config token");
        assert_eq!(
            serde_json::to_value(s).expect("serializes"),
            serde_json::json!(tok),
            "the wire token"
        );
        assert_eq!(ExportStream::from_token(tok), Some(*s));
    }
}

#[test]
fn content_is_stream_nine_last_in_all_with_seven_and_eight_reserved() {
    let content = ExportStream::from_token("content").expect("`content` is in the vocabulary");
    assert_eq!(content as u8, 9, "IF r33 section 49: STREAM_CONTENT = 9");
    assert_eq!(
        ExportStream::ALL.len(),
        10,
        "IF r33 section 49: STREAM_COUNT = 10"
    );
    assert_eq!(ExportStream::ALL.last(), Some(&content), "last in ALL");
    assert_eq!(ExportStream::Prompts as u8, 7, "7 stays reserved");
    assert_eq!(ExportStream::Completions as u8, 8, "8 stays reserved");
    assert!(ExportStream::vocabulary().ends_with("| content"));
}

#[test]
fn content_stream_fields_are_the_content_line_members() {
    let content = ExportStream::from_token("content").expect("`content` is in the vocabulary");
    let tokens = |fs: &[ExportField]| fs.iter().map(|f| f.as_token()).collect::<Vec<_>>();
    assert_eq!(
        tokens(content.default_fields()),
        [
            "correlation_id",
            "ts",
            "deployment_id",
            "node_id",
            "content_ref"
        ]
    );
    assert_eq!(
        tokens(content.pinned_fields()),
        ["correlation_id", "deployment_id", "node_id"]
    );
    for tok in ["content_ref", "deployment_id", "node_id"] {
        let f = ExportField::from_token(tok).expect(tok);
        assert_eq!(f.as_token(), tok);
    }
    assert!(ExportField::ALL.len() <= 64, "the projection mask is a u64");
    for tok in ["messages", "content", "finish_reason"] {
        assert!(
            ExportField::from_token(tok).is_some(),
            "{tok} stays: prompts and completions are reserved, not folded"
        );
    }
}
