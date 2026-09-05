// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `decode_native_tool_id`'s lowercase-hex guard. `native_for` only ever emits a lowercase-hex tail,
//! so a client-authored id of the busbar-marker shape carrying an UPPERCASE/mixed-case hex tail must
//! NOT be mis-detected as busbar-reshaped and mangled — it passes through verbatim.

use crate::proto_codec::{decode_native_tool_id, ToolIdRemap};

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
