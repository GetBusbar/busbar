// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/provider.rs`.

use super::*;

/// The provider endpoint carries no credential: the plane builds a keyless target and declares where
/// the host presents the secret.
#[test]
fn the_provider_endpoint_is_keyless_and_each_dialect_names_its_placement() {
    assert_eq!(
        provider_ws_url("https://generativelanguage.googleapis.com/", GEMINI_LIVE),
        "wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.\
         GenerativeService.BidiGenerateContent"
    );
    assert_eq!(
        provider_ws_url("https://api.openai.com", OPENAI_REALTIME),
        "wss://api.openai.com/v1/realtime"
    );
    assert_eq!(
        credential_placement(GEMINI_LIVE),
        CredentialPlacement::Query("key")
    );
    assert_eq!(
        credential_placement(OPENAI_REALTIME),
        CredentialPlacement::Header {
            name: "authorization",
            prefix: "Bearer ",
        }
    );
}

/// No code in the plane formats a credential into a URL.
#[test]
fn the_plane_source_formats_no_credential_into_a_url() {
    let src = include_str!("../provider.rs");
    assert!(!src.contains("?key={"), "provider.rs formats a query key");
    assert!(!src.contains("api_key"), "provider.rs takes an api_key");
}
