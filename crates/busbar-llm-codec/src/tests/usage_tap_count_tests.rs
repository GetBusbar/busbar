// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE-TAP COUNT PIN (#83a SD-3, architect ruling R-USAGE): every way a same-protocol usage
//! tap can fail to read a 2xx body reports ONCE to the host's usage-tap seam, under the reason that
//! says which way — whether the tap is the chat cell's own (unknown protocol / bad JSON / a body its
//! reader refuses), a leaf cell's default (the host's decode reporter), or the signing dialect's
//! direct shape-probed call (`bedrock::handler::same_protocol_usage`, which calls both). One report
//! is one increment of `busbar_billing_tap_decode_fail_total{protocol,reason}`: the host's suite pins
//! that step. The plane names no metrics crate and reaches no host: this suite reads the reports the
//! test host recorded.

use busbar_contract::codec::OperationHandler;
use busbar_contract::operation::OpVerb;
use std::collections::BTreeMap;

fn faults(pairs: &[(&str, &'static str, u64)]) -> BTreeMap<(String, &'static str), u64> {
    pairs
        .iter()
        .map(|&(p, r, n)| ((p.to_string(), r), n))
        .collect()
}

fn cell(op: OpVerb) -> &'static dyn OperationHandler {
    crate::bedrock::DECL
        .handler
        .and_then(|h| h.operation_handler(op))
        .expect("the signing dialect serves the operation")
}

/// A JSON body the signing dialect's chat reader refuses (it is not a Converse document).
const UNREADABLE: &[u8] = b"[1,2,3]";
const NOT_JSON: &[u8] = b"{not json";

#[test]
fn the_chat_cells_three_fault_paths_each_count_once_under_their_reason() {
    let chat = crate::chat_handle::ChatOperation("bedrock");
    let unknown = crate::chat_handle::ChatOperation("no-such-dialect");
    let counts = crate::test_host::tap_faults(|| {
        assert!(chat.extract_usage("bedrock", UNREADABLE).is_none());
        assert!(chat.extract_usage("bedrock", NOT_JSON).is_none());
        assert!(chat.extract_usage("bedrock", NOT_JSON).is_none());
        assert!(unknown.extract_usage("no-such-dialect", b"{}").is_none());
    });
    assert_eq!(
        counts,
        faults(&[
            ("bedrock", "decode", 1),
            ("bedrock", "bad_json", 2),
            ("no-such-dialect", "unknown_protocol", 1),
        ])
    );
}

#[test]
fn a_leaf_cells_default_tap_counts_a_refused_body_as_a_decode_failure() {
    let counts = crate::test_host::tap_faults(|| {
        assert!(cell(OpVerb::EMBEDDINGS)
            .extract_usage("bedrock", NOT_JSON)
            .is_none());
        assert!(cell(OpVerb::IMAGE)
            .extract_usage("bedrock", NOT_JSON)
            .is_none());
    });
    assert_eq!(counts, faults(&[("bedrock", "decode", 2)]));
}

/// THE DIRECT CALL R-USAGE names: the signing dialect's shape-probed same-protocol tap reaches the
/// chat cell or a leaf cell by the body's shape, and each counts exactly as the cell counts when the
/// host dispatches it.
#[test]
fn the_shape_probed_same_protocol_tap_counts_exactly_as_the_cell_it_reaches() {
    // The probe reads the parsed SHAPE; the tap it picks reads the body — so a body the picked cell
    // refuses, under each shape, is what reaches each cell's fault path.
    let image_shaped: serde_json::Value = serde_json::json!({"images": []});
    let converse_shaped: serde_json::Value = serde_json::json!({"output": {}});
    let counts = crate::test_host::tap_faults(|| {
        let usage = crate::bedrock::handler::same_protocol_usage;
        assert!(usage(NOT_JSON, None).is_none());
        assert!(usage(NOT_JSON, Some(&image_shaped)).is_none());
        assert!(usage(UNREADABLE, Some(&converse_shaped)).is_none());
    });
    assert_eq!(
        counts,
        faults(&[("bedrock", "bad_json", 1), ("bedrock", "decode", 2)])
    );
}
