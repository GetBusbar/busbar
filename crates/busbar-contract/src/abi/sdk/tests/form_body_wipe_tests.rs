// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::abi::sdk::cred::{Cred, FormBody, FormValue};
use crate::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};

pub(super) fn watch(bytes: &[u8]) {
    // SAFETY: FormBody's instrumentation passes the base initialized prefixes of its owned Strings
    // and output Vec. An active probe's unsafe contract requires these allocations to remain owned
    // on this thread until deallocation or the end of observation. Outside a probe this is a no-op.
    unsafe { watch_initialized_payload(bytes) }
}

fn finish(probe: InitializedPayloadProbe) -> Vec<crate::alloc_counter::ObservedPayload> {
    let observations = probe.finish();
    assert!(
        !observations.reentered,
        "the memory reader reentered the allocator"
    );
    for record in &observations.payloads {
        assert!(
            record.freed,
            "registered form allocation was not freed: {record:?}"
        );
        #[cfg(target_os = "linux")]
        {
            assert_eq!(record.read_error, None, "OS memory read failed: {record:?}");
            assert!(
                record.complete_read,
                "OS memory read was incomplete: {record:?}"
            );
            assert_eq!(record.bytes_read, record.len, "OS memory read was short");
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
            assert!(!record.complete_read);
            assert_eq!(record.bytes_read, 0);
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("FormBody behavior and frees checked; allocation memory proof requires Linux /proc/self/mem");
    observations.payloads
}

#[test]
fn every_secret_bearing_form_buffer_is_wiped_before_it_is_freed() {
    let secret = Cred::captured(zeroize::Zeroizing::new(b"s&=e cr+t".repeat(256)))
        .secure_for("https://issuer.example");
    let body = FormBody::new()
        .sealed("client_secret", &secret)
        .public("code", "a b&c");
    // SAFETY: the output and every instrumented temporary remain on this thread until dropped.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open the memory observer") };
    let encoded = body.encoded().expect("form encodes");
    let expected = format!(
        "client_secret={}&code=a+b%26c",
        "s%26%3De+cr%2Bt".repeat(256)
    );
    assert_eq!(&encoded.buf[..], expected.as_bytes());
    assert!(
        encoded.secure_required(),
        "the credential's requirement survives encoding"
    );
    drop(encoded);
    let records = finish(probe);
    let secret_records: Vec<_> = records
        .iter()
        .filter(|record| record.len > b"client_secret=".len())
        .collect();
    assert!(
        secret_records
            .iter()
            .any(|record| record.len == expected.len()),
        "the complete initialized form payload was registered"
    );
    for record in secret_records {
        assert!(
            record.freed,
            "secret-bearing buffer destruction was observed: {record:?}"
        );
        #[cfg(target_os = "linux")]
        assert!(
            record.wiped,
            "form secret reached deallocation unwiped: {record:?}"
        );
    }
}

#[test]
fn form_names_public_values_and_jws_inputs_are_wiped_on_drop() {
    let key = Cred::captured(zeroize::Zeroizing::new(b"not used for signing".to_vec()));
    let body = FormBody::new().public("code", "authorization code").value(
        "assertion",
        FormValue::JwsRs256 {
            key,
            signing_input: "header.claims".to_owned(),
        },
    );
    // SAFETY: the form's instrumented Strings are initialized and dropped on this thread below.
    let probe = unsafe { InitializedPayloadProbe::start().expect("open the memory observer") };
    drop(body);
    let records = finish(probe);
    for len in [
        "code".len(),
        "authorization code".len(),
        "assertion".len(),
        "header.claims".len(),
    ] {
        assert!(
            records.iter().any(|record| record.len == len),
            "form payload was registered"
        );
    }
    for record in records {
        assert!(record.freed, "form payload was freed: {record:?}");
        #[cfg(target_os = "linux")]
        assert!(record.wiped, "form payload was not wiped: {record:?}");
    }
}
