// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::host_side::caller::Accept;

fn limits(yaml: &str) -> Result<InstanceLimitsCfg, String> {
    let doc: LimitsDoc = busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    doc.resolve("store.main")
}

fn transport(yaml: &str) -> Result<InsecureTransport, String> {
    let doc: InsecureTransportDoc =
        busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    doc.resolve("auth.corp-ldap")
}

#[test]
fn limits_parse_every_key() {
    let l = limits(
        "{ timeout_ms: 10000, connect_timeout_ms: 3000, max_inflight: 64, stream_stall_ms: 5000 }",
    )
    .expect("parses");
    assert_eq!(
        l,
        InstanceLimitsCfg {
            timeout_ms: 10_000,
            connect_timeout_ms: 3_000,
            max_inflight: 64,
            stream_stall_ms: 5_000
        }
    );
    assert_eq!(limits("{}").expect("empty"), InstanceLimitsCfg::default());
}

#[test]
fn limits_bounds_refuse_naming_the_key() {
    let err = limits("{ timeout_ms: 600001 }").expect_err("over 600,000 ms");
    assert!(err.contains("store.main.limits.timeout_ms"), "{err}");
    let err = limits("{ connect_timeout_ms: 700000 }").expect_err("over 600,000 ms");
    assert!(err.contains("limits.connect_timeout_ms"), "{err}");
    let err = limits("{ max_inflight: 65536 }").expect_err("over 65,535");
    assert!(err.contains("limits.max_inflight"), "{err}");
    assert_eq!(
        limits("{ max_inflight: 65535 }")
            .expect("limit")
            .max_inflight,
        65_535
    );
    let err = limits("{ stream_stall_ms: 999 }").expect_err("under 1,000");
    assert!(err.contains("limits.stream_stall_ms"), "{err}");
}

#[test]
fn limits_has_no_plaintext_key() {
    let err = limits("{ plaintext: deny }").expect_err("the row is deleted");
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn insecure_transport_accepts_one_word_or_a_list() {
    let t = transport("{ accept: plaintext, reason: \"legacy db, CHG-12\" }").expect("parses");
    assert_eq!(t.accept, Accept(Accept::PLAINTEXT));
    assert_eq!(t.accept_words(), ["plaintext"]);
    let t = transport("{ accept: [plaintext, unverified_tls], reason: r }").expect("both");
    assert_eq!(t.accept, Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS));
    let t = transport("{ accept: [unverified_tls], reason: r }").expect("list of one");
    assert_eq!(t.accept, Accept(Accept::UNVERIFIED_TLS));
}

#[test]
fn insecure_transport_refusals_are_busbar_3163_naming_the_key() {
    for (yaml, key) in [
        ("{ accept: [], reason: r }", "accept"),
        ("{ accept: [plaintext, plaintext], reason: r }", "accept"),
        ("{ accept: plaintext }", "reason"),
        ("{ accept: plaintext, reason: \"\" }", "reason"),
        ("{ accept: plaintext, reason: \"  \" }", "reason"),
        (
            "{ accept: plaintext, reason: \"<why this instance needs it>\" }",
            "reason",
        ),
        ("{ accept: plaintext, reason: \"two\\nlines\" }", "reason"),
    ] {
        let err = transport(yaml).expect_err(yaml);
        assert!(err.starts_with("BUSBAR-3163"), "{yaml}: {err}");
        assert!(
            err.contains(&format!("auth.corp-ldap.insecure_transport.{key}")),
            "{yaml}: {err}"
        );
    }
    let long = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(257));
    assert!(transport(&long).expect_err("257").contains("256"));
    let ok = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(256));
    transport(&ok).expect("256 is the limit");
}

#[test]
fn insecure_transport_refuses_bad_words_and_unknown_keys() {
    assert!(transport("{ accept: yes, reason: r }").is_err());
    assert!(transport("{ accept: plaintext, reason: r, extra: 1 }")
        .expect_err("unknown key")
        .contains("unknown field"));
    assert!(transport("{ reason: r }").is_err(), "accept is required");
}

#[test]
fn the_warning_line_carries_the_instance_reason_and_removal_advice() {
    let t =
        transport("{ accept: unverified_tls, reason: \"AD DC cert expired\" }").expect("parses");
    let line = t.warning_line(
        "auth.corp-ldap",
        "ldap",
        &["dc1.corp:636 (tcp+tls, certificate not verified)".to_owned()],
    );
    assert!(line.starts_with("BUSBAR-3162: auth.corp-ldap (module ldap) runs with insecure_transport: accept unverified_tls for dc1.corp:636"), "{line}");
    assert!(line.contains("Reason: \"AD DC cert expired\"."), "{line}");
    assert!(
        line.ends_with(
            "Remove auth.corp-ldap.insecure_transport once the server offers verifiable TLS."
        ),
        "{line}"
    );
    let none = t.warning_line("auth.corp-ldap", "ldap", &[]);
    assert!(
        none.contains("no declared endpoint uses this yet"),
        "{none}"
    );
}
