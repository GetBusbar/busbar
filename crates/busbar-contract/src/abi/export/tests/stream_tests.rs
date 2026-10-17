// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM TYPE FOR BOTH LANES: the export kind's tail order (the discriminant) and the frozen
//! token order (`ALL`, serde, `as_token`) are one order.

use super::*;

/// The frozen stream words, in the order every export config, sink and tail has carried them.
const FROZEN: [&str; 9] = [
    "metrics",
    "logs",
    "traces",
    "costs",
    "decisions",
    "events",
    "identity",
    "prompts",
    "completions",
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
