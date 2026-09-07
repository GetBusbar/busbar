// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/plane_host/build_input.rs` — chiefly that the resolved
//! provider credential the carrier holds cannot be printed out of it.

use super::*;

fn lane(api_key: &str) -> LaneInput {
    LaneInput {
        model: "m".to_string(),
        provider: "p".to_string(),
        protocol: "openai".to_string(),
        base_url: "https://example.invalid".to_string(),
        path: None,
        path_base: None,
        upstream_model: None,
        api_key: busbar_api::Redacted::new(api_key.to_string()),
        auth_style: AuthStyleInput::Default,
        scope: None,
        token_url: None,
        subject: None,
        error_map: HashMap::new(),
        health: None,
        allow_metadata_hosts: Vec::new(),
        context_max: None,
        lane_default_max_tokens: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
        max_concurrent: 1,
        limited: false,
        budget: -1,
    }
}

/// The carrier is formatted on the build path (a trace, a panic message, an error `{:?}`), so the
/// credential it holds must not be printable — from the lane itself, or from anything the lane is
/// nested inside.
#[test]
fn the_build_carrier_cannot_print_the_provider_credential() {
    const SECRET: &str = "sk-live-must-never-be-printed";
    let one = lane(SECRET);
    let shown = format!("{one:?}");
    assert!(
        !shown.contains(SECRET),
        "the lane carrier printed the credential: {shown}"
    );
    assert!(shown.contains("[REDACTED]"), "and says so: {shown}");
    assert!(shown.contains("openai"), "the lane is still identifiable");

    let nested = format!("{:?}", vec![lane(SECRET)]);
    assert!(!nested.contains(SECRET), "nested print leaked: {nested}");
}

/// The one way to the plaintext is the audited read.
#[test]
fn the_credential_is_reachable_only_through_the_audited_read() {
    let one = lane("sk-live-1");
    assert_eq!(one.api_key.expose_secret(), "sk-live-1");
}
