// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Round-trip tests for the MCP plane rows through their actual persisted shapes — the neutral\n//! call-log journal body read back via `from_journal_body`, and the demotion row. Relocated out of\n//! `record.rs` per the tests-in-their-own-file convention.

use super::*;

/// The call record is read back ONLY through the ACTUAL persisted shape — the neutral
/// `{seq, prev_hash, hash, content}` journal body the engine's call-log seam writes — so this
/// round-trips THAT body through [`McpCallRecord::from_journal_body`], the real reader path, and
/// asserts every digest-faithful field is reconstructed. There is no plane-side writer for the
/// call record (see the note on `impl McpCallRecord`); the body is built here exactly as the seam
/// frames it (a LengthPrefixed field suffix inside the neutral envelope).
#[test]
fn mcp_call_record_round_trips_through_the_actual_journal_reader() {
    fn lp_text(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    fn lp_num(out: &mut Vec<u8>, v: u64) {
        let b = v.to_be_bytes();
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&b);
    }
    let (ts, server, tool, outcome, reason, tool_digest, pin_generation) = (
        1000u64,
        "fs",
        "fs_read",
        "dispatched",
        "",
        "sha256:aaa",
        7u64,
    );
    // The pre-framed content SUFFIX the record's digest is sealed over: ts, server, tool, outcome,
    // reason, tool_digest, pin_generation — the exact order and framing the seam writes.
    let mut content = Vec::new();
    lp_num(&mut content, ts);
    lp_text(&mut content, server);
    lp_text(&mut content, tool);
    lp_text(&mut content, outcome);
    lp_text(&mut content, reason);
    lp_text(&mut content, tool_digest);
    lp_num(&mut content, pin_generation);
    // The neutral envelope the engine persists, encoded the same way (`serde_json`) the reader
    // decodes it. `content` is a `Vec<u8>` — serde renders it as a JSON byte array.
    let body = serde_json::to_vec(&serde_json::json!({
        "seq": 3u64,
        "prev_hash": "prev",
        "hash": "deadbeef",
        "content": content,
    }))
    .unwrap();

    let got = McpCallRecord::from_journal_body("key-1", &body).unwrap();
    assert_eq!(
        got,
        McpCallRecord {
            principal: "key-1".into(),
            seq: 3,
            ts,
            server: server.into(),
            tool: tool.into(),
            outcome: outcome.into(),
            reason: reason.into(),
            tool_digest: tool_digest.into(),
            pin_generation,
            // The request id is a join key, never in the digest and so never in the neutral body:
            // it comes back EMPTY through the real reader.
            request_id: String::new(),
            prev_hash: "prev".into(),
            hash: "deadbeef".into(),
        }
    );
}

#[test]
fn mcp_demotion_row_round_trips_through_the_plane_record_envelope() {
    let row = McpDemotionRow {
        server: "fs".into(),
        reason: "drift".into(),
        recorded_at: 42,
    };
    let env = row.to_plane_record().unwrap();
    assert_eq!(env.kind, KIND_DEMOTION);
    assert_eq!(env.id, "fs");
    assert_eq!(env.parent, None);
    assert_eq!(env.ts, 42);
    assert_eq!(McpDemotionRow::from_body(&env.body).unwrap(), row);
}
