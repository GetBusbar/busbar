// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EACH DIALECT'S OPERATION CELLS, read off its own declaration's handler. Ported from the kernel's
//! deleted handler registry suites (`handlers/tests/contract_tests.rs`
//! `no_handler_lookup_returns_none_for_unsupported_op`, `handlers/tests/dispatch_tests.rs`
//! `every_cell_of_the_six_protocols_reports_its_protocol_vocabulary`; ARCHITECT F25 ruling
//! 2026-10-07): the kernel no longer looks a cell up by protocol name, so the behaviours are proved
//! here, over the declarations this plane owns.

use busbar_contract::operation::OpVerb;
use busbar_plane_llm::codec::DECLS;

/// Every operation verb, written out once so a new verb is not silently skipped by the sweeps.
const ALL_OPERATIONS: [OpVerb; 13] = [
    OpVerb::CHAT,
    OpVerb::EMBEDDINGS,
    OpVerb::MODERATION,
    OpVerb::IMAGE,
    OpVerb::TRANSCRIPTION,
    OpVerb::SPEECH,
    OpVerb::RERANK,
    OpVerb::INVOKE,
    OpVerb::CATALOGUE,
    OpVerb::FETCH,
    OpVerb::TASK,
    OpVerb::SUBSCRIBE,
    OpVerb::CONTROL,
];

/// AN UNSUPPORTED OPERATION HAS NO CELL: a dialect's handler answers a cell for exactly the verbs
/// its declaration names, and `None` — the no-handler 404 — for every other.
#[test]
fn no_handler_lookup_returns_none_for_unsupported_op() {
    let mut refused = 0;
    for decl in DECLS {
        let handler = decl.handler.expect("every dialect declares a handler");
        assert_eq!(handler.protocol_name(), decl.name);
        for op in ALL_OPERATIONS {
            let declared = decl.verbs.contains(&op);
            assert_eq!(
                handler.operation_handler(op).is_some(),
                declared,
                "{}/{}: a cell exactly when the verb is declared",
                decl.name,
                op.name()
            );
            refused += usize::from(!declared);
        }
    }
    assert!(
        refused > 0,
        "some dialect refuses some verb, or nothing was proved"
    );
}

/// EVERY OPERATION OF EVERY DIALECT REPORTS EXACTLY WHAT ITS DIALECT READER REPORTS: a non-2xx
/// answer on any cell attributes the same status, provider code, structured type and retry advice
/// as the dialect's own reader, so an operator's `error_map` classifies every operation's failures
/// the same way. Swept over every cell, a spread of statuses and real error envelopes.
#[test]
fn every_cell_of_the_six_protocols_reports_its_protocol_vocabulary() {
    const BODIES: [&[u8]; 8] = [
        br#"{"error":{"message":"You exceeded your quota","type":"insufficient_quota","code":"insufficient_quota"}}"#,
        br#"{"error":{"code":429,"message":"Resource has been exhausted","status":"RESOURCE_EXHAUSTED"}}"#,
        br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        br#"{"message":"Rate exceeded","__type":"ThrottlingException"}"#,
        br#"{"message":"too many tokens: prompt is too long for this model"}"#,
        br#"{"error":{"message":"prompt is too long: 300000 tokens > 200000 maximum","type":"invalid_request_error"}}"#,
        br#"{}"#,
        b"upstream is not speaking JSON today",
    ];
    const STATUSES: [u16; 12] = [400, 401, 403, 404, 408, 413, 422, 429, 500, 502, 503, 529];
    let mut cells = 0;
    for decl in DECLS {
        let dialect = decl
            .dialect()
            .unwrap_or_else(|| panic!("{} declares a wire codec", decl.name));
        let handler = decl.handler.expect("every dialect declares a handler");
        for op in ALL_OPERATIONS {
            let Some(cell) = handler.operation_handler(op) else {
                continue;
            };
            cells += 1;
            for status in STATUSES {
                for body in BODIES {
                    let (got, want) = (
                        cell.extract_error(status, body),
                        dialect.extract_error(status, body),
                    );
                    assert_eq!(
                        (
                            got.http_status,
                            &got.provider_code,
                            &got.structured_type,
                            got.retry_after_secs
                        ),
                        (
                            want.http_status,
                            &want.provider_code,
                            &want.structured_type,
                            want.retry_after_secs
                        ),
                        "{}/{} attributed {status} differently from its dialect reader",
                        decl.name,
                        op.name()
                    );
                }
            }
        }
    }
    assert!(
        cells >= DECLS.len(),
        "every dialect swept at least one cell"
    );
}
