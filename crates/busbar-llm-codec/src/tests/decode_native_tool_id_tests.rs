// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `decode_native_tool_id`'s lowercase-hex guard. `native_for` only ever emits a lowercase-hex tail,
//! so a client-authored id of the busbar-marker shape carrying an UPPERCASE/mixed-case hex tail must
//! NOT be mis-detected as busbar-reshaped and mangled — it passes through verbatim.

use crate::proto_codec::{decode_native_tool_id, ToolIdRemap, TOOL_ID_REMAP_MAX_MEMO};

// A genuine busbar-minted id (lowercase hex, produced by `native_for`) still decodes back to the
// ORIGINAL egress id — the fix must not reject any real busbar id.
#[test]
fn genuine_lowercase_busbar_id_still_decodes() {
    let mut remap = ToolIdRemap::default();
    let native = remap.native_for("anthropic", "call_abc123");
    // Sanity: `native_for` emits an all-lowercase-hex tail after `toolu_bb1`.
    assert!(native.starts_with("toolu_bb1"));
    assert_eq!(
        native.strip_prefix("toolu_bb1").unwrap(),
        native
            .strip_prefix("toolu_bb1")
            .unwrap()
            .to_ascii_lowercase()
    );
    assert_eq!(
        decode_native_tool_id("anthropic", &native).as_deref(),
        Some("call_abc123")
    );
}

// An UPPERCASE-hex tail can only come from a client-authored id (`native_for` never emits it).
// `hex::decode` alone would accept it and mangle the id; the lowercase-hex guard must reject it
// (decode => None) so the id passes through VERBATIM. `43616C6C` is the uppercase hex of "Call"
// (valid UTF-8), which is exactly the collision that would be mis-detected without the guard.
#[test]
fn uppercase_hex_client_id_passes_through_verbatim() {
    assert_eq!(
        decode_native_tool_id("anthropic", "toolu_bb143616C6C"),
        None
    );
    // Mixed case is likewise rejected (not busbar-shaped).
    assert_eq!(
        decode_native_tool_id("anthropic", "toolu_bb143616c6C"),
        None
    );
}

/// The memo is an OPTIMIZATION over a pure, deterministic encode, and it is fed from UNTRUSTED
/// upstream bytes: the Anthropic reader has no per-stream gate on how many distinct `tool_use`
/// blocks a response may open, so one long-lived stream can grow the map without bound. Cap the
/// retention at the dialects' `MAX_OPEN_TOOLS` scale — and, because the encode is deterministic,
/// ids past the cap must still get the IDENTICAL native id (just uncached), so the cap is invisible
/// in behaviour and visible only in memory.
#[test]
fn memo_is_capped_and_answers_identically_past_the_cap() {
    let mut remap = ToolIdRemap::default();
    for i in 0..(TOOL_ID_REMAP_MAX_MEMO + 500) {
        let _ = remap.native_for("anthropic", &format!("call_{i}"));
    }
    assert!(
        remap.memo_len() <= TOOL_ID_REMAP_MAX_MEMO,
        "memo must be capped at {TOOL_ID_REMAP_MAX_MEMO}, retained {}",
        remap.memo_len()
    );

    // Behaviour under AND past the cap is unchanged: the same egress id always yields the same
    // native id, and it still decodes back to the original.
    let past_cap = format!("call_{}", TOOL_ID_REMAP_MAX_MEMO + 400);
    let native = remap.native_for("anthropic", &past_cap);
    assert_eq!(
        native,
        ToolIdRemap::default().native_for("anthropic", &past_cap),
        "an uncached id past the cap must map to the same deterministic native id"
    );
    assert_eq!(
        remap.native_for("anthropic", &past_cap),
        native,
        "repeat lookups past the cap stay stable"
    );
    assert_eq!(
        decode_native_tool_id("anthropic", &native).as_deref(),
        Some(past_cap.as_str()),
        "an uncached native id still reverses to the original egress id"
    );
}
