// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn refused(target: &str, host: &str) {
    let err = check(target).expect_err(target);
    assert_eq!(
        err.to_string(),
        format!("refused: `{host}` is a cloud metadata host, which no connection may reach"),
        "{target}"
    );
}

/// RED: every spelling of a metadata host is refused, by name.
#[test]
fn every_spelling_of_a_metadata_host_is_refused() {
    for (target, host) in [
        ("169.254.169.254", "169.254.169.254"),
        ("169.254.169.254:80", "169.254.169.254"),
        ("2852039166:80", "2852039166"),
        ("0251.0376.0251.0376:80", "0251.0376.0251.0376"),
        ("0xa9fea9fe", "0xa9fea9fe"),
        ("0xA9.0xFE.0xA9.0xFE", "0xA9.0xFE.0xA9.0xFE"),
        ("169.254.43518", "169.254.43518"),
        ("169.16689662", "169.16689662"),
        ("[::ffff:169.254.169.254]:80", "::ffff:169.254.169.254"),
        ("[::ffff:a9fe:a9fe]", "::ffff:a9fe:a9fe"),
        ("::ffff:169.254.169.254", "::ffff:169.254.169.254"),
        ("[fd00:ec2::254]:80", "fd00:ec2::254"),
        ("fd00:ec2::254", "fd00:ec2::254"),
        (
            "[fd00:0ec2:0000::0254%eth0]:80",
            "fd00:0ec2:0000::0254%eth0",
        ),
        ("metadata.google.internal:80", "metadata.google.internal"),
        ("METADATA.Google.Internal.", "METADATA.Google.Internal"),
        ("169.254.170.2:80", "169.254.170.2"),
        ("2852039170", "2852039170"),
        ("[::ffff:169.254.170.2]", "::ffff:169.254.170.2"),
        ("[fd00:ec2::23]:80", "fd00:ec2::23"),
        ("fd00:ec2:0:0:0:0:0:23", "fd00:ec2:0:0:0:0:0:23"),
        ("100.100.100.200:80", "100.100.100.200"),
        ("0x64.0x64.0x64.0xc8", "0x64.0x64.0x64.0xc8"),
        ("[::ffff:100.100.100.200]", "::ffff:100.100.100.200"),
        ("192.0.0.192:80", "192.0.0.192"),
        ("0300.0.0.0300", "0300.0.0.0300"),
        ("3221225664", "3221225664"),
        ("169.254.0.1", "169.254.0.1"),
        ("169.254.255.255:443", "169.254.255.255"),
        ("169.254.169.253", "169.254.169.253"),
        ("0251.0376.1.1", "0251.0376.1.1"),
        ("[::ffff:169.254.1.1]", "::ffff:169.254.1.1"),
    ] {
        refused(target, host);
    }
}

/// GREEN: neighbours of the metadata addresses outside link-local, and ordinary hosts, pass.
#[test]
fn a_neighbour_of_a_metadata_host_passes() {
    for target in [
        "169.253.169.254",
        "169.255.0.1",
        "100.100.100.201",
        "192.0.0.193",
        "fd00:ec2::22",
        "127.0.0.1:1",
        "[::1]:443",
        "fd00:ec2::253",
        "api.example.com:443",
        "metadata.google.internal.example.com",
        "google.internal",
        "0x1ffffffff",
        "256.254.169.254",
    ] {
        assert_eq!(check(target), Ok(()), "{target}");
    }
}

/// RED: a URL-shaped target is judged on its HOST, not its scheme, and the one shared metadata list
/// covers Azure's WireServer and the `metadata.internal` names the private list here never had. A
/// target with no readable host is refused rather than waved through unjudged.
#[test]
fn a_url_target_and_every_shared_metadata_host_is_refused() {
    for target in [
        "https://169.254.169.254/",
        "https://[fd00:ec2::254]/latest",
        "https://metadata.google.internal./x",
        "168.63.129.16:80",
        "metadata.internal:80",
        "instance-data.ec2.internal",
        "",
    ] {
        assert!(check(target).is_err(), "{target:?}");
    }
    assert_eq!(check("https://api.example.com/v1"), Ok(()));
}

/// RED: IPv6 link-local, fe80::/10, is refused in every spelling, as predev's private list refused
/// it (PB-100); the addresses just outside the /10 pass.
#[test]
fn ipv6_link_local_is_refused_in_every_spelling() {
    for (target, host) in [
        ("fe80::1", "fe80::1"),
        ("[fe80::1]", "fe80::1"),
        ("[fe80::1]:443", "fe80::1"),
        ("[FE80::a9fe:a9fe]:80", "FE80::a9fe:a9fe"),
        ("[fe80::1%eth0]:80", "fe80::1%eth0"),
        ("[febf:ffff::1]", "febf:ffff::1"),
        ("https://[fe80::1]/latest", "fe80::1"),
    ] {
        refused(target, host);
    }
    for target in ["[fe7f:ffff::1]:80", "[fec0::1]:80", "[fd00::1]:80"] {
        assert_eq!(check(target), Ok(()), "{target}");
    }
}
