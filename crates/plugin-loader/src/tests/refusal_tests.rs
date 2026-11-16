// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The refusal line (IF §4.3, r10 §4.1): one diagnostic for every code, the r10 middle clauses, the rebuild
//! tail and link only where a rebuild cures it, and no untrusted name printed.

use super::*;

fn engine() -> String {
    format!("{}.{}.{}", ENGINE.major, ENGINE.minor, ENGINE.patch)
}

fn target() -> String {
    let t = busbar_plugin_abi::stamp::target_now();
    let end = t.iter().position(|&b| b == 0).unwrap_or(t.len());
    String::from_utf8(t[..end].to_vec()).expect("an ASCII target")
}

#[test]
fn every_code_is_busbar_6013() {
    let codes = [
        RefusalCode::Integrity,
        RefusalCode::Signature,
        RefusalCode::StampMissing,
        RefusalCode::StampAmbiguous,
        RefusalCode::StampMalformed {
            byte: 16,
            rule: "format is not 2",
        },
        RefusalCode::KindUnknown,
        RefusalCode::KindAbi,
        RefusalCode::Mechanism,
        RefusalCode::Layout,
        RefusalCode::Semantic,
        RefusalCode::Target,
        RefusalCode::EngineRange,
        RefusalCode::Crypto,
        RefusalCode::ManifestMismatch,
        RefusalCode::DoorStampMismatch,
        RefusalCode::ImageBounds,
        RefusalCode::DescribeInvalid,
        RefusalCode::CapUnknown,
        RefusalCode::OutOfProcessUnavailable,
        RefusalCode::LocalBuild,
        RefusalCode::Superseded,
        RefusalCode::NameConflict,
    ];
    for code in codes {
        let r = Refusal::new(code, "field", "have", "want").named("busbar-x");
        assert_eq!(r.diagnostic(), "BUSBAR-6013", "{code:?}");
        let line = r.to_string();
        assert!(
            line.starts_with("BUSBAR-6013 plugin refused: 'busbar-x' "),
            "{code:?}: {line}"
        );
        assert!(!line.contains('\n'), "one line: {line}");
    }
}

#[test]
fn a_kind_abi_refusal_prints_the_r10_line_with_its_download_link() {
    let r = Refusal::new(
        RefusalCode::KindAbi,
        "kind_abi",
        "secret ABI 1",
        "secret ABI 2",
    )
    .named("busbar-secret-env");
    let link = format!(
        "{LINK_BASE}/busbar-secret-env?engine={}&target={}",
        engine(),
        target()
    );
    assert_eq!(r.link.as_deref(), Some(link.as_str()));
    assert_eq!(r.plugin.as_deref(), Some("busbar-secret-env"));
    assert_eq!(
        r.to_string(),
        format!(
            "BUSBAR-6013 plugin refused: 'busbar-secret-env' is built for secret ABI 1; this busbar {} requires \
             secret ABI 2 exactly. Rebuild it against the busbar {}.{} SDK, or download a build for this busbar: {link}",
            engine(),
            ENGINE.major,
            ENGINE.minor
        )
    );
}

#[test]
fn the_stamp_clauses_are_r10s() {
    let missing = Refusal::new(RefusalCode::StampMissing, "stamp", "", "one stamp").to_string();
    assert_eq!(
        missing,
        format!(
            "BUSBAR-6013 plugin refused: the image carries no busbar compatibility stamp — a 1.5.x plugin or a \
             library not built with the busbar SDK. Rebuild it against the busbar {}.{} SDK",
            ENGINE.major, ENGINE.minor
        )
    );
    let two = Refusal::new(RefusalCode::StampAmbiguous, "stamp", "2", "1").to_string();
    assert!(
        two.contains(
            "carries 2 stamps; exactly one is required (universal binaries are not supported)"
        ),
        "{two}"
    );
    let bad = Refusal::new(
        RefusalCode::StampMalformed {
            byte: 36,
            rule: "an unknown flag is set",
        },
        "stamp",
        "byte 36",
        "an unknown flag is set",
    )
    .to_string();
    assert!(
        bad.contains("carries a malformed stamp (byte 36: an unknown flag is set)"),
        "{bad}"
    );
}

#[test]
fn the_crypto_clause_names_a_non_rust_plugin() {
    let external = Refusal::new(RefusalCode::Crypto, "crypto", "external", "fips")
        .named("busbar-secret-c")
        .to_string();
    assert!(
        external.contains(
            "'busbar-secret-c' is a non-Rust plugin (crypto: external), which this crypto backend (fips) does not load"
        ),
        "{external}"
    );
    let other = Refusal::new(RefusalCode::Crypto, "crypto", "aws-lc", "software").to_string();
    assert!(
        other.contains("was built against crypto backend aws-lc; this busbar uses software"),
        "{other}"
    );
}

#[test]
fn a_manifest_mismatch_prints_the_manifest_value_only_when_it_passed_its_rule() {
    let shown = Refusal::new(
        RefusalCode::ManifestMismatch,
        "manifest.version",
        "999.0.0",
        "1.6.0",
    )
    .named("busbar-x")
    .to_string();
    assert!(
        shown.contains("its signed manifest states version 999.0.0; its binary states 1.6.0"),
        "{shown}"
    );
    assert!(
        !shown.contains("Rebuild"),
        "a manifest mismatch is not a rebuild: {shown}"
    );
    let hidden = Refusal::new(
        RefusalCode::ManifestMismatch,
        "manifest.version",
        "",
        "1.6.0",
    )
    .named("busbar-x")
    .to_string();
    assert!(
        hidden.contains("its signed manifest's version does not match its binary (1.6.0)"),
        "{hidden}"
    );
}

#[test]
fn a_name_that_fails_valid_name_is_never_printed_or_linked() {
    for name in ["Bad_Name", "-lead", "trail-", "", "a\nforged line"] {
        let r = Refusal::new(RefusalCode::Target, "target", "x", "y").named(name);
        assert_eq!(r.plugin, None, "{name:?}");
        assert_eq!(r.link, None, "{name:?}");
        assert!(r
            .to_string()
            .starts_with("BUSBAR-6013 plugin refused: the image "));
    }
}

#[test]
fn trust_and_integrity_refusals_carry_no_rebuild_tail() {
    for code in [
        RefusalCode::Integrity,
        RefusalCode::Signature,
        RefusalCode::NameConflict,
        RefusalCode::DescribeInvalid,
    ] {
        let line = Refusal::new(code, "f", "h", "w")
            .named("busbar-x")
            .to_string();
        assert!(!line.contains("Rebuild"), "{code:?}: {line}");
        assert!(!line.contains(LINK_BASE), "{code:?}: {line}");
    }
}
