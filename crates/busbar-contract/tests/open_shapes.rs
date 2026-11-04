// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A fourth transport family costs no reader an edit.

use busbar_contract::transport::registry::facts;
use busbar_contract::transport::wire::WireStatus;
use busbar_contract::transport::UpstreamAddress;

/// A status namespace nothing in this tree registers, spelled here and nowhere else.
const QUIC: &str = "quic";

#[test]
fn a_fourth_status_namespace_needs_no_reader_edit() {
    let quic = WireStatus::new(QUIC, 42);

    assert_eq!(quic.namespace.as_ref(), QUIC);
    assert_eq!(quic.code, 42);
    assert_eq!(quic.in_namespace(QUIC), Some(42));
    for one in ["alpha-status", "beta-status"] {
        assert_eq!(quic.in_namespace(one), None);
        assert_eq!(WireStatus::new(one, 42).in_namespace(one), Some(42));
    }
    assert_ne!(
        WireStatus::new("alpha-status", 42),
        WireStatus::new("beta-status", 42)
    );
}

#[test]
fn a_fourth_destination_family_needs_no_reader_edit() {
    let quic = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: Some("upstream.internal"),
        extras: &[("stream-group", "inference")],
    };

    assert_eq!(quic.authority(), Some("upstream.internal:8443"));
    assert_eq!(quic.sni(), Some("upstream.internal"));

    assert_eq!(quic.extra("stream-group"), Some("inference"));

    assert_eq!(quic.extra(facts::METHOD), None);
}

#[test]
fn the_method_a_call_per_path_family_dials_by_is_a_key_on_a_socket() {
    let per_path = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: Some("upstream.internal"),
        extras: &[(facts::METHOD, "/vendor.Inference/Chat")],
    };
    assert_eq!(per_path.authority(), Some("upstream.internal:8443"));
    assert_eq!(
        per_path.extra(facts::METHOD),
        Some("/vendor.Inference/Chat")
    );

    let program = UpstreamAddress::Program {
        path: "/usr/local/bin/server",
        args: &["--pipe"],
        env: &[],
        extras: &[],
    };
    assert_eq!(program.authority(), None);
    assert_eq!(program.extra(facts::METHOD), None);
}

#[test]
fn a_transport_refuses_the_key_it_requires_and_ignores_the_rest() {
    let bare = UpstreamAddress::socket("upstream.internal:8443");
    assert_eq!(
        bare.missing(&[facts::METHOD]),
        Some(facts::METHOD),
        "a required key the destination never declared is the refusal, not a default"
    );

    let named = UpstreamAddress::Socket {
        authority: "upstream.internal:8443",
        sni: None,
        extras: &[(facts::METHOD, "/vendor.Inference/Chat")],
    };
    assert_eq!(named.missing(&[facts::METHOD]), None);

    assert_eq!(named.missing(&[]), None);
}
