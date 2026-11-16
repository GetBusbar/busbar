// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNIX-DEST: rules (1) to (3).

use super::*;
use busbar_plugin_abi::need::egress::{DEFAULT, LOOPBACK_ALLOWED};

const OPS: u32 = OPERATOR_INFRASTRUCTURE;

#[test]
fn a_well_formed_unix_dest_names_its_path() {
    assert_eq!(
        unix_rules("unix:/run/v.sock", &TlsMode::None, OPS),
        Ok("/run/v.sock")
    );
}

/// Rule (1): the grammar.
#[test]
fn a_malformed_unix_dest_is_invalid() {
    let long = format!("unix:/{}", "a".repeat(MAX_PATH));
    let edge = format!("unix:/{}", "a".repeat(MAX_PATH - 1));
    for bad in [
        "unix:",
        "unix:/",
        "unix:rel/path",
        "unix://x",
        "unix:/a\0b",
        "UNIX:/x",
        long.as_str(),
    ] {
        assert_eq!(
            unix_rules(bad, &TlsMode::None, OPS),
            Err(NeedErr::Invalid),
            "{bad:?}"
        );
    }
    assert_eq!(unix_rules(&edge, &TlsMode::None, OPS), Ok(&edge[5..]));
}

/// Rule (2): TLS, trust, SNI and ALPN on a unix OPEN are INVALID, and checked before the class.
#[test]
fn tls_on_a_unix_dest_is_invalid_before_the_class_is() {
    let tls = TlsMode::Required {
        sni: "",
        alpn: "",
        trust: 0,
    };
    assert_eq!(unix_rules("unix:/s", &tls, DEFAULT), Err(NeedErr::Invalid));
    let inband = TlsMode::Inband {
        sni: "",
        alpn: "",
        trust: 0,
        cert: None,
    };
    assert_eq!(unix_rules("unix:/s", &inband, OPS), Err(NeedErr::Invalid));
}

/// Rule (3): only OPERATOR_INFRASTRUCTURE, whatever the caller's kind (the function has no kind).
#[test]
fn only_operator_infrastructure_may_dial_a_unix_socket() {
    for class in [DEFAULT, LOOPBACK_ALLOWED, 1, 3] {
        assert_eq!(
            unix_rules("unix:/s", &TlsMode::None, class),
            Err(NeedErr::Denied),
            "{class}"
        );
    }
}

#[test]
fn the_prefix_is_read_without_regard_to_case() {
    assert!(names_unix("unix:/s") && names_unix("UNIX:/s") && names_unix("unix:"));
    assert!(!names_unix("db:5432") && !names_unix("uni") && !names_unix("unixy:/s"));
}
