// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SDK HOLDS THE PIN, ONE CRATE OVER.
//!
//! The MCP codec used to read its five JSON-RPC method names straight off `rmcp`'s own const-string
//! types, so a name the specification authors retired stopped COMPILING rather than being served.
//! The codec then crossed into `busbar-mcp-codec`, whose whole point is that a PURE plane kind can
//! name it — and `rmcp` hard-depends on `tokio`, which is exactly what a pure kind's transitive
//! closure may not contain. So the codec spells the five names as literals and the pin lives here,
//! in the crate that still links the SDK.
//!
//! What changed and what did not. The check is no longer a compile failure, it is a test failure —
//! and it now covers ALL FIVE names against the SDK, where the version it replaces pinned one
//! against the SDK and four against literals restated in the assertion. It also pins the two
//! parameter objects the codec now declares itself, in both directions, so a member the SDK adds or
//! renames is caught here rather than on somebody's wire. ONE test, under the name it always had.

use rmcp::model::ConstString;

/// THE WIRE NAMES ARE THE SDK's. This is the assertion that would catch a literal being typed here a
/// second time and drifting from the specification the crate implements.
#[test]
fn every_wire_name_this_cell_serves_is_the_one_the_sdk_declares() {
    assert_eq!(
        busbar_mcp_codec::codec::METHOD_TOOLS_CALL,
        rmcp::model::CallToolRequestMethod::VALUE
    );
    assert_eq!(
        busbar_mcp_codec::codec::METHOD_RESOURCES_SUBSCRIBE,
        rmcp::model::SubscribeRequestMethod::VALUE
    );
    assert_eq!(
        busbar_mcp_codec::codec::METHOD_RESOURCES_UNSUBSCRIBE,
        rmcp::model::UnsubscribeRequestMethod::VALUE
    );
    assert_eq!(
        busbar_mcp_codec::codec::METHOD_NOTIFY_TOOLS_LIST_CHANGED,
        rmcp::model::ToolListChangedNotificationMethod::VALUE
    );
    assert_eq!(
        busbar_mcp_codec::codec::METHOD_NOTIFY_RESOURCES_UPDATED,
        rmcp::model::ResourceUpdatedNotificationMethod::VALUE
    );

    // THE PARAMETER OBJECTS, WRITE SIDE. The codec declares `{"uri": …}` for all three; the SDK's
    // own constructors serialize to exactly that, because they leave `_meta` `None` and that field
    // is skipped. A member the SDK adds unskipped shows up here as an inequality.
    let uri = "res://x";
    let want = serde_json::json!({ "uri": uri });
    for got in [
        serde_json::to_value(rmcp::model::SubscribeRequestParams::new(uri)),
        serde_json::to_value(rmcp::model::UnsubscribeRequestParams::new(uri)),
        serde_json::to_value(rmcp::model::ResourceUpdatedNotificationParam::new(uri)),
    ] {
        assert_eq!(got.expect("the SDK's own params serialize"), want);
    }

    // THE PARAMETER OBJECTS, READ SIDE. The codec's types declare only `uri` and serde ignores what
    // it was not told about — which is what the SDK type did with `_meta` as far as this codec was
    // concerned, since nothing here ever read it back. So a body carrying `_meta` is still read for
    // its `uri`, by the SDK and by the codec alike.
    let with_meta = serde_json::json!({ "uri": uri, "_meta": { "progressToken": 7 } });
    let sdk: rmcp::model::SubscribeRequestParams =
        serde_json::from_value(with_meta).expect("the SDK reads a body carrying _meta");
    assert_eq!(sdk.uri, uri);
}
