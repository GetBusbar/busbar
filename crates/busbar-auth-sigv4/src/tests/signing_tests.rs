// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `sigv4` style, ported from the identity unit's `egress_auth/tests.rs` in the kernel: the assembly
//! around the signer, the refusals, and the day keys.

use super::*;

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

fn params() -> SigV4Params {
    SigV4Params {
        service: "iam".to_string(),
        region: "us-east-1".to_string(),
        content_type: "application/json".to_string(),
    }
}

fn facts<'a>(hash: &'a str) -> SignFacts<'a> {
    SignFacts {
        host: "runtime.signer.example",
        canonical_uri: "/model/m/converse",
        payload_hash: hash,
        timestamp_epoch: 1_440_938_160,
    }
}

fn field(fields: &[(String, String)], name: &str) -> String {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("{name} is sent"))
}

/// A temporary credential's session token is SENT and SIGNED over exactly the set 1.5.5's signing
/// writer signed (`content-type`, `host`, the two `x-amz-*` fields and the token), and the whole
/// `Authorization` value is the one `sign_v4` computes from arguments written out in its own
/// parameter order — so a transposed region/service or a dropped input disagrees.
#[test]
fn session_token_is_sent_and_signed_over_the_writer_header_set() {
    let hash = sigv4::sha256_hex(br#"{"messages":[]}"#);
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")),
    );
    let sent = b.sign(&facts(&hash));
    assert_eq!(
        sent.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        [
            "authorization",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token"
        ],
        "1.5.5's field order"
    );
    assert_eq!(field(&sent, "x-amz-security-token"), "SESSIONTOKEN");
    assert_eq!(field(&sent, "x-amz-content-sha256"), hash);
    let signed_over = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), "runtime.signer.example".to_string()),
        ("x-amz-content-sha256".to_string(), hash.clone()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        (
            "x-amz-security-token".to_string(),
            "SESSIONTOKEN".to_string(),
        ),
    ];
    let (signature, signed_headers) = sigv4::sign_v4(
        SECRET,
        "us-east-1",
        "iam",
        "POST",
        "/model/m/converse",
        "",
        &signed_over,
        &hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(
        signed_headers,
        "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    );
    assert_eq!(
        field(&sent, "authorization"),
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders={signed_headers}, Signature={signature}"
        )
    );
}

/// Every credential 1.5.5 refused to sign with signs nothing: a session token the wire cannot
/// carry, an empty secret or access key id (the split refuses those), no credential at all.
#[test]
fn unsendable_or_incomplete_signing_credentials_sign_nothing() {
    let hash = sigv4::sha256_hex(b"{}");
    for raw in [
        format!("AKIDEXAMPLE:{SECRET}:TOK\r\nEN"),
        format!("AKIDEXAMPLE:{SECRET}:TOK\u{1}EN"),
        "AKIDEXAMPLE:".to_string(),
        format!(":{SECRET}"),
    ] {
        let b = SigV4Binding::new(params(), SigningCredential::split(&raw));
        assert!(
            b.sign(&facts(&hash)).is_empty(),
            "{raw:?} must sign nothing"
        );
    }
    assert!(SigV4Binding::new(params(), None)
        .sign(&facts(&hash))
        .is_empty());
}

/// An access key id that makes the `Authorization` value illegal signs nothing.
#[test]
fn an_access_key_id_the_wire_cannot_carry_signs_nothing() {
    let hash = sigv4::sha256_hex(b"{}");
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKID\u{7f}:{SECRET}")),
    );
    assert!(b.sign(&facts(&hash)).is_empty());
}

/// Re-signing the same request is idempotent: the day key held after the first signature signs the
/// second exactly as a fresh derivation would.
#[test]
fn the_held_day_key_signs_exactly_as_a_fresh_derivation() {
    let hash = sigv4::sha256_hex(b"{}");
    let cred = || SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}"));
    let warm = SigV4Binding::new(params(), cred());
    let first = warm.sign(&facts(&hash));
    let second = warm.sign(&facts(&hash));
    let cold = SigV4Binding::new(params(), cred()).sign(&facts(&hash));
    assert_eq!(first, second);
    assert_eq!(first, cold);
}

/// `tick` derives the next UTC day's key within the hour before midnight, and keeps at most two.
#[test]
fn tick_prederives_tomorrows_key_ahead_of_midnight() {
    let b = SigV4Binding::new(
        params(),
        SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}")),
    );
    let midnight = 1_440_979_200; // 2015-08-31T00:00:00Z
    b.prederive(midnight - 7_200);
    assert_eq!(b.held(), ["20150830"], "two hours out: today only");
    b.prederive(midnight - 600);
    assert_eq!(
        b.held(),
        ["20150830", "20150831"],
        "ten minutes out: tomorrow too"
    );
    b.prederive(midnight + 86_400 - 600);
    assert_eq!(
        b.held(),
        ["20150831", "20150901"],
        "two kept, the oldest dropped"
    );
}

/// A logged credential shows that a secret and a token are present, never either.
#[test]
fn a_logged_credential_redacts_its_secret_and_token() {
    let c = SigningCredential::split(&format!("AKIDEXAMPLE:{SECRET}:SESSIONTOKEN")).unwrap();
    let printed = format!("{c:?}");
    assert!(!printed.contains("SESSIONTOKEN"), "{printed}");
    assert!(!printed.contains("wJalr"), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
}

/// THE SIGNING DIFFERENTIAL OVER THE SHARED FIXTURE (ported from the kernel's deleted
/// `egress_auth/tests/prebuilt_auth_tests.rs`: `each_declared_scheme_presents_what_its_dialect_builder_wrote`
/// for the signing dialect, `a_signing_dialect_request_carries_the_scope_the_host_names`,
/// `a_session_token_is_sent_and_signed_for_the_hosts_region`,
/// `a_fips_host_signs_for_its_region_and_an_unnamed_one_for_the_default`; ARCHITECT F25 ruling
/// 2026-10-07). `testing/plane-copies/declared-credentials.json` records the signing dialect's
/// declared scheme, the region each recorded host names (a FIPS host its own region, a host naming
/// none the declared default — resolved at seal by the root from the dialect's parameters,
/// `root/tests/door_steps.rs` `a_members_binding_is_opened_with_its_dialects_parameters_under_the_providers_own`),
/// and the headers the dialect's own 1.5.5 signer wrote for every credential, host, body and
/// timestamp. Signed under the recorded scheme for the recorded region, this plugin writes exactly
/// those headers, in order — the scope names the host's region, a session token is sent and signed,
/// and a credential that cannot be signed signs nothing.
#[test]
fn every_recorded_signing_row_signs_as_the_dialects_signer_wrote() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/declared-credentials.json"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the fixture")).expect("JSON");
    let scheme = &doc["schemes"]["bedrock"];
    assert_eq!(scheme["kind"], "sigv4");
    let region_of = |host: &str| -> String {
        doc["regions"]
            .as_array()
            .expect("regions")
            .iter()
            .find(|r| r["host"] == host)
            .and_then(|r| r["region"].as_str())
            .unwrap_or_else(|| scheme["default_region"].as_str().expect("default"))
            .to_string()
    };
    let mut compared = 0;
    for row in doc["rows"].as_array().expect("rows") {
        if row["dialect"] != "bedrock" {
            continue;
        }
        let host = row["host"].as_str().expect("host");
        let params = SigV4Params {
            service: scheme["service"].as_str().expect("service").to_string(),
            region: region_of(host),
            content_type: scheme["content_type"].as_str().expect("ct").to_string(),
        };
        let key = String::from_utf8(unhex(row["key_hex"].as_str().expect("key"))).expect("utf-8");
        let body = unhex(row["body_hex"].as_str().expect("body"));
        let hash = sigv4::sha256_hex(&body);
        let binding = SigV4Binding::new(params, SigningCredential::split(&key));
        let sent: Vec<serde_json::Value> = binding
            .sign(&SignFacts {
                host,
                canonical_uri: row["canonical_uri"].as_str().expect("uri"),
                payload_hash: &hash,
                timestamp_epoch: row["timestamp_epoch"].as_u64().expect("ts"),
            })
            .into_iter()
            .map(|(k, v)| {
                let hex: String = v.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                serde_json::json!([k, hex])
            })
            .collect();
        assert_eq!(
            serde_json::Value::Array(sent),
            row["headers"],
            "key {key:?}, host {host}, mode {}, uri {}",
            row["mode"],
            row["canonical_uri"]
        );
        compared += 1;
    }
    assert_eq!(compared, 320, "every recorded signing row was signed");
}
