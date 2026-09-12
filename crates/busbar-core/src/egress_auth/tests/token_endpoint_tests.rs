// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the seated token-endpoint judgement in `crates/busbar-core/src/egress_auth/mod.rs`.
//!
//! These are the posture cases the two credential mechanisms used to carry, ONE COPY EACH, back
//! when each judged for itself. There is one copy now, so the two can no longer answer differently
//! for the same spelling — which is exactly what they used to do, the deployment-global stance being
//! honoured by one of them and ignored by the other.

use crate::egress_auth::{token_endpoint_judge, MetadataSsrfPolicy, TokenEndpointVerdict};

/// Judge `url` under the default posture: no operator carve-out, nothing extra denied.
fn judge(url: &str) -> TokenEndpointVerdict {
    token_endpoint_judge(
        url,
        &MetadataSsrfPolicy {
            allow_overrides: &[],
            allow_all: false,
            blocked_hosts: &[],
        },
    )
}

/// The blocked-host verdict for `host`, for comparing against.
fn blocked(host: &str) -> TokenEndpointVerdict {
    TokenEndpointVerdict::BlockedMetadataHost {
        host: host.to_string(),
    }
}

// The endpoint receives busbar's own credential, so it gets the TLS requirement and the
// cloud-metadata denylist — for BOTH mechanisms, because there is only one of these now.
#[test]
fn requires_tls_for_a_public_host_and_blocks_metadata() {
    assert_eq!(
        judge("https://token.example.com/token"),
        TokenEndpointVerdict::Admitted
    );
    // Plaintext to a public host would put the credential on the wire in the clear.
    assert_eq!(
        judge("http://token.example.com/token"),
        TokenEndpointVerdict::InsecureScheme
    );
    // Plaintext to a loopback/private endpoint is permitted (a co-located identity provider).
    assert_eq!(
        judge("http://127.0.0.1:8080/token"),
        TokenEndpointVerdict::Admitted
    );
    // Cloud-metadata / IMDS is denied even under TLS (the direct-target case).
    assert_eq!(
        judge("https://metadata.google.internal/token"),
        blocked("metadata.google.internal")
    );
    assert_eq!(
        judge("https://169.254.169.254/token"),
        blocked("169.254.169.254")
    );
}

// The operator's DEPLOYMENT-GLOBAL posture is honoured: `allow_all_metadata` disables the guard
// wholesale, a surgical allow-override unblocks exactly one host, and an extra denylist entry is
// ENFORCED. The asymmetry this closed was jwt-bearer ignoring all three.
#[test]
fn honours_the_operators_metadata_posture() {
    let nuclear = MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: true,
        blocked_hosts: &[],
    };
    assert_eq!(
        token_endpoint_judge("https://169.254.169.254/token", &nuclear),
        TokenEndpointVerdict::Admitted
    );

    let allowed = ["169.254.169.254".to_string()];
    let carved = MetadataSsrfPolicy {
        allow_overrides: &allowed,
        allow_all: false,
        blocked_hosts: &[],
    };
    assert_eq!(
        token_endpoint_judge("https://169.254.169.254/token", &carved),
        TokenEndpointVerdict::Admitted
    );

    let extra = ["evil.example.com".to_string()];
    let denied = MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: false,
        blocked_hosts: &extra,
    };
    assert_eq!(
        token_endpoint_judge("https://evil.example.com/token", &denied),
        blocked("evil.example.com")
    );
}

// THE ORDER. The scheme is judged first, so a destination written as a bare `host:port` — the one
// spelling where the surviving copy of the control is deliberately STRICTER than the dying one (it
// judges a scheme-less authority instead of returning nothing for it) — is refused as insecure and
// never reaches the denylist arm. That is why composing on the surviving copy cannot change the
// answer for any input at this step.
#[test]
fn a_scheme_less_authority_is_refused_before_the_denylist() {
    assert_eq!(
        judge("169.254.169.254:8080"),
        TokenEndpointVerdict::InsecureScheme
    );
    assert_eq!(
        judge("token.example.com"),
        TokenEndpointVerdict::InsecureScheme
    );
    assert_eq!(judge(""), TokenEndpointVerdict::InsecureScheme);
}

// The scheme reads the same way here as it does at the socket: case-insensitively, and after the
// leading/trailing trim that the connecting stack applies. A padded IMDS spelling is still IMDS —
// the bug a copy WITHOUT that trim shipped was an operator denylist silently not firing.
#[test]
fn the_scheme_and_the_host_are_read_the_way_the_socket_reads_them() {
    assert_eq!(
        judge("HTTPS://token.example.com/token"),
        TokenEndpointVerdict::Admitted
    );
    assert_eq!(
        judge("ftp://token.example.com/token"),
        TokenEndpointVerdict::InsecureScheme
    );
    assert_eq!(
        judge("https://169.254.169.254/token "),
        blocked("169.254.169.254")
    );
    // An alternate encoding of the same IMDS address, which no range check built on
    // `IpAddr::from_str` would catch on its own.
    assert_eq!(judge("https://2852039166/token"), blocked("2852039166"));
}
