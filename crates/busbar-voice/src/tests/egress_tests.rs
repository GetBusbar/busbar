// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS CREDENTIAL CELL — `egress-auth × voice-client`. The voice plane plans its provider
//! credential through the ONE egress mechanism (`ProtocolDecl::egress_auth_headers`), and the value it
//! plans is the PROVIDER credential (the WebRTC `ek_` / the real provider key / the telephony carrier
//! secret), NEVER a caller governance token forwarded through.
//!
//! RED before the wiring: `DECLS.egress_auth_headers` was `None`, so the plane planned no egress
//! credential at all and the decl could not state that the dial carries busbar's own authority.

use crate::DECLS;
use busbar_api::UpstreamCreds;
use busbar_substrate::proto::SigningContext;

#[test]
fn the_provider_dial_carries_the_planned_credential_and_never_a_caller_token() {
    let builder = DECLS
        .egress_auth_headers
        .expect("the voice plane declares an egress credential builder (the ONE egress mechanism)");

    // The resolved per-lane PROVIDER credential — what the composition root leases for the dial. A
    // distinct token the caller might have presented at the front door, which must NEVER be the value
    // planned onto the provider hop.
    const PROVIDER_CREDENTIAL: &str = "ek_provider_scoped_secret_abc";
    const CALLER_TOKEN: &str = "caller-inbound-governance-bearer-xyz";

    let ctx = SigningContext {
        host: "api.openai.com",
        canonical_uri: "/v1/realtime/calls",
        body: b"",
        timestamp_epoch: 0,
        upstream_creds: UpstreamCreds::Own,
    };
    let headers = builder(PROVIDER_CREDENTIAL, &ctx);

    // Exactly one header: the provider-facing `Authorization: Bearer <provider credential>`.
    assert_eq!(
        headers.len(),
        1,
        "the plan is one provider Authorization header"
    );
    let (name, value) = &headers[0];
    assert_eq!(name.as_str(), "authorization");
    assert_eq!(
        value.to_str().unwrap(),
        format!("Bearer {PROVIDER_CREDENTIAL}"),
        "the dial carries the PLANNED provider credential"
    );

    // The provider hop carries ONLY the leased provider credential — the caller's inbound governance
    // token appears nowhere in the plan (the builder reads the resolved credential string and nothing
    // else, so a caller token could reach the wire only by being the leased credential, which the
    // egress gate is what forbids).
    assert!(
        !value.to_str().unwrap().contains(CALLER_TOKEN),
        "the caller's inbound governance token is never the value planned onto the provider dial"
    );

    // And the lane-constant declaration holds: the builder read nothing off the SigningContext (a pure
    // function of the credential string), so the boot path may prebuild it once per lane.
    assert!(
        DECLS.egress_auth_lane_constant,
        "the bearer credential is a pure function of the resolved string (lane-constant)"
    );
}
