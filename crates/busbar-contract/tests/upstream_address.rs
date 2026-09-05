// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed upstream address, read from each transport family's own side.
//!
//! One opaque host string was read three incompatible ways at once — a socket address whose IP
//! doubled as the offered certificate name, an absolute program path with no argument vector, and
//! an address a gRPC method had nowhere to sit beside. These assert that each family now asks for
//! exactly what it dials with, and gets nothing that belongs to another family.

use busbar_contract::UpstreamAddress;

#[test]
fn a_socket_target_carries_an_authority_and_an_optional_certificate_name() {
    let plain = UpstreamAddress::socket("10.0.0.1:443");
    assert_eq!(plain.authority(), Some("10.0.0.1:443"));
    assert_eq!(plain.sni(), None, "no name is declared unless one is written");

    let named = UpstreamAddress::Socket {
        authority: "10.0.0.1:443",
        sni: Some("api.example"),
    };
    assert_eq!(named.authority(), Some("10.0.0.1:443"));
    assert_eq!(
        named.sni(),
        Some("api.example"),
        "the pinned address and the name it resolved from are two facts"
    );
}

#[test]
fn a_program_target_carries_a_path_an_argv_and_an_environment() {
    let program = UpstreamAddress::Program {
        path: "/usr/local/bin/server",
        args: &["--stdio", "--quiet"],
        env: &[("TOKEN_FILE", "/run/secrets/token")],
    };
    assert_eq!(program.program(), Some("/usr/local/bin/server"));
    assert_eq!(program.args(), &["--stdio", "--quiet"]);
    assert_eq!(program.env(), &[("TOKEN_FILE", "/run/secrets/token")]);
    assert_eq!(
        program.authority(),
        None,
        "a process is not something to connect a socket to"
    );
    assert_eq!(program.sni(), None);
    assert_eq!(program.method(), None);
}

#[test]
fn a_grpc_target_carries_the_method_its_wire_names_every_call_by() {
    let grpc = UpstreamAddress::Grpc {
        authority: "upstream.internal:8443",
        sni: Some("upstream.internal"),
        method: "/vendor.Inference/Chat",
    };
    assert_eq!(grpc.authority(), Some("upstream.internal:8443"));
    assert_eq!(grpc.sni(), Some("upstream.internal"));
    assert_eq!(grpc.method(), Some("/vendor.Inference/Chat"));
    assert_eq!(grpc.args(), &[] as &[&str]);
    assert_eq!(grpc.env(), &[] as &[(&str, &str)]);
}

#[test]
fn a_socket_target_names_no_method_and_a_program_names_no_socket() {
    assert_eq!(UpstreamAddress::socket("host:1").method(), None);
    assert_eq!(UpstreamAddress::socket("host:1").program(), None);
    assert_eq!(UpstreamAddress::socket("host:1").args(), &[] as &[&str]);
    let program = UpstreamAddress::Program {
        path: "/bin/true",
        args: &[],
        env: &[],
    };
    assert_eq!(program.authority(), None);
}
