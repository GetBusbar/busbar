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
        ("METADATA.Google.Internal.", "METADATA.Google.Internal."),
    ] {
        refused(target, host);
    }
}

/// GREEN: neighbours of the metadata addresses, and ordinary hosts, pass.
#[test]
fn a_neighbour_of_a_metadata_host_passes() {
    for target in [
        "169.254.169.253:80",
        "169.254.170.254",
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
