// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SIGV4 BOTH WAYS, proven on the real binary: the shipped `busbar` VERIFIES an inbound AWS SigV4
//! request (the linked `sigv4` auth plugin's `verify`, reading the virtual key's AWS secret through
//! the host's `records.secret`) and SIGNS the outbound one (the same plugin, bound to the bedrock
//! lane's `ACCESS:SECRET` credential).
//!
//! One node: `auth.chain: [keys]`, an admin token, one `bedrock` provider whose `base_url` is a
//! capturing upstream on loopback. A virtual key with an AWS credential is minted through the admin
//! API, exactly as an operator would, and then:
//!
//! 1. a correctly signed Converse request is ADMITTED, and the request the upstream received carries
//!    a SigV4 `authorization` under the PROVIDER's AccessKeyId for the `bedrock` service — whose
//!    signature this test recomputes from the provider secret over the received bytes (canonical
//!    URI double-encoded, as non-S3 SigV4 requires), so it is proven VALID, not merely present;
//! 2. the same request with one body byte changed (the signed payload hash no longer matches) is
//!    REFUSED with the bedrock dialect's auth refusal, and the upstream sees nothing;
//! 3. a correctly signed request under an UNKNOWN AccessKeyId is refused with the byte-identical
//!    response (no oracle between "bad signature" and "no such key");
//! 4. the key's own signed token carried as `Authorization: Bearer` on the same route is still
//!    admitted (the plugin passes a non-SigV4 credential, the `keys` bearer path admits it);
//! 5. a body over the size cap under a MALFORMED SigV4 authorization line is refused AT THE CAP
//!    (413), before any verdict, and nothing reaches the upstream: the body the kernel holds for the
//!    `HeadBody` verify is bounded by the cap (ARCHITECT ruling D1 2026-10-05, inbound buffering).
#![cfg(unix)]
// A bootable data plane with the bedrock path ingress, the admin listener, the admin-token door and
// the SigV4 auth plugin must all be linked.
#![cfg(all(
    linked_axis_body_ingress,
    feature = "root-admin",
    feature = "auth-admin-tokens",
    feature = "auth-sigv4"
))]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const ADMIN_TOKEN: &str = "sigv4-both-ways-admin";
/// The bedrock lane's own AWS credential (`ACCESS:SECRET`), handed to busbar through this env var.
const UPSTREAM_CREDS_ENV: &str = "SIGV4_E2E_UPSTREAM_CREDS";
const UPSTREAM_AKID: &str = "AKIAUPSTREAMLANE0001";
const UPSTREAM_SECRET: &str = "upstreamLaneSecret/0123456789+abcdefghijklmn";
/// The client-facing model name, and the Bedrock modelId sent on the wire. The `:` in the wire id
/// is what makes the canonical URI's double encoding observable (`%3A` on the wire, `%253A` signed).
const MODEL: &str = "test-model";
const WIRE_MODEL: &str = "anthropic.claude-test-v1:0";
const REGION: &str = "us-east-1";
const SERVICE: &str = "bedrock";
/// Every bounded wait in this test.
const BOOT_BUDGET: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn sigv4_is_verified_inbound_and_signed_outbound() {
    let dir = fixture_dir();
    let upstream = Upstream::spawn();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port, upstream.port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env(
            UPSTREAM_CREDS_ENV,
            format!("{UPSTREAM_AKID}:{UPSTREAM_SECRET}"),
        )
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let mut node = Node {
        child,
        dir,
        log_path,
    };
    node.wait_listening(data_port, admin_port);

    // ── the operator mints an AWS-capable virtual key through the admin API ─────────────────────
    let minted = node.mint_aws_key(admin_port);
    let vk_akid = minted["aws_access_key_id"]
        .as_str()
        .unwrap_or_else(|| node.fail(&format!("the mint carried no AccessKeyId: {minted}")))
        .to_string();
    let vk_secret = minted["aws_secret_access_key"]
        .as_str()
        .unwrap_or_else(|| node.fail(&format!("the mint carried no AWS secret: {minted}")))
        .to_string();
    let vk_token = minted["token"]
        .as_str()
        .unwrap_or_else(|| node.fail(&format!("the mint carried no token: {minted}")))
        .to_string();

    let host = format!("127.0.0.1:{data_port}");
    let path = format!("/model/{MODEL}/converse");
    let body = br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#.to_vec();

    // ── 1. a correctly signed request is admitted, and the upstream gets a VALID outbound SigV4 ──
    let signed = sign_client_request(&vk_akid, &vk_secret, &host, &path, &body);
    let ok = send(data_port, &host, &path, &signed, &body);
    if ok.status != 200 {
        node.fail(&format!(
            "a correctly signed bedrock request must be admitted (200), got {}:\n{}",
            ok.status, ok.text
        ));
    }
    let seen = upstream.captured();
    if seen.len() != 1 {
        node.fail(&format!(
            "the upstream must have received exactly the one admitted request, got {}",
            seen.len()
        ));
    }
    let out = &seen[0];
    assert_outbound_signed(&node, out, &vk_akid);

    // ── 2. one body byte changed: the signature no longer covers the body → refused ─────────────
    let mut tampered = body.clone();
    let at = tampered
        .windows(2)
        .position(|w| w == b"hi")
        .expect("the body carries `hi`")
        + 1;
    tampered[at] = b'j';
    assert_eq!(tampered.len(), body.len());
    let bad_sig = send(data_port, &host, &path, &signed, &tampered);
    assert_eq!(
        bad_sig.status,
        403,
        "a request whose body no longer matches its signature must get the bedrock auth refusal \
         (403): {}\nlog:\n{}",
        bad_sig.text,
        node.log()
    );
    assert!(
        bad_sig.header("x-amzn-errortype").is_some(),
        "the refusal is the bedrock dialect's native error (x-amzn-errortype): {}",
        bad_sig.text
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "a refused request must never reach the upstream"
    );

    // ── 3. an unknown AccessKeyId, correctly signed under its own secret → the SAME refusal ──────
    let unknown = sign_client_request(
        "AKIAUNKNOWNKEY000000",
        "notTheSecretOfAnyKeyBusbarHolds0123456789",
        &host,
        &path,
        &body,
    );
    let no_key = send(data_port, &host, &path, &unknown, &body);
    assert_eq!(
        no_key.status,
        403,
        "an unknown AccessKeyId must get the bedrock auth refusal (403): {}\nlog:\n{}",
        no_key.text,
        node.log()
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "a refused request must never reach the upstream"
    );
    assert_eq!(
        no_key.masked(),
        bad_sig.masked(),
        "an unknown AccessKeyId and a bad signature must be refused byte-identically (only the \
         per-response request id and date may differ), or the refusal is an oracle"
    );

    // ── 4. the key's own token as Bearer on the same route: the plugin passes, `keys` admits ──────
    let bearer = vec![
        ("authorization".to_string(), format!("Bearer {vk_token}")),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let via_bearer = send(data_port, &host, &path, &bearer, &body);
    if via_bearer.status != 200 {
        node.fail(&format!(
            "a Bearer-carried virtual key on the bedrock route must still be admitted (200), got \
             {}:\n{}",
            via_bearer.status, via_bearer.text
        ));
    }
    let seen = upstream.captured();
    if seen.len() != 2 {
        node.fail(&format!(
            "the bearer request must reach the upstream (2 total), got {}",
            seen.len()
        ));
    }
    assert_outbound_signed(&node, &seen[1], &vk_akid);

    // ── 5. over the cap, under a malformed SigV4 line: refused at the cap, before a verdict ──────
    // (ARCHITECT D1 2026-10-05, INBOUND BUFFERING.) The body a signed ingress buffers for the
    // verifier is capped at `limits.request_body_max_bytes` BEFORE the buffer: a body over it is
    // refused with the opaque auth refusal, the same bytes as a bad signature, and never buffered
    // whole, never verified, never forwarded.
    let bogus = vec![
        (
            "authorization".to_string(),
            "AWS4-HMAC-SHA256 not-a-credential-at-all".to_string(),
        ),
        ("x-amz-date".to_string(), "20260101T000000Z".to_string()),
        (
            "x-amz-content-sha256".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        ("content-type".to_string(), "application/json".to_string()),
    ];
    let over = vec![b'x'; BODY_CAP + 1];
    let at_cap = send(data_port, &host, &path, &bogus, &over);
    assert_eq!(
        (at_cap.status, at_cap.masked()),
        (403, bad_sig.masked()),
        "a body over the cap under a malformed SigV4 line is refused with the opaque auth refusal: \
         {}\nlog:\n{}",
        at_cap.text,
        node.log()
    );
    assert_eq!(
        upstream.captured().len(),
        2,
        "an over-cap request must never reach the upstream"
    );

    // ── 6. the CAP refuses it, not the verdict: a CORRECTLY signed request over the cap ──────────
    // The same key that was admitted in step 1 signs the over-cap body itself; the signature is
    // good, so only the cap can refuse it — before the verifier is asked.
    let signed_over = sign_client_request(&vk_akid, &vk_secret, &host, &path, &over);
    let refused = send(data_port, &host, &path, &signed_over, &over);
    assert_eq!(
        (refused.status, refused.masked()),
        (403, bad_sig.masked()),
        "a correctly signed body over the cap is refused at the cap with the opaque auth refusal: \
         {}\nlog:\n{}",
        refused.text,
        node.log()
    );
    assert_eq!(
        upstream.captured().len(),
        2,
        "an over-cap request must never reach the upstream"
    );

    drop(node);
}

/// The node's `limits.request_body_max_bytes`: the size gate the `HeadBody` buffer is bounded by.
const BODY_CAP: usize = 64 * 1024;

/// The request the upstream received carries busbar's OWN outbound SigV4 — the lane credential,
/// the `bedrock` service — and that signature verifies under the lane secret over what arrived.
fn assert_outbound_signed(node: &Node, out: &Captured, client_akid: &str) {
    let ctx = || format!("upstream received:\n{out:#?}\nlog:\n{}", node.log());
    let auth = out
        .header("authorization")
        .unwrap_or_else(|| node.fail(&format!("no outbound authorization; {}", ctx())));
    assert!(
        auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={UPSTREAM_AKID}/")),
        "the outbound request must be SigV4-signed under the PROVIDER's AccessKeyId; {}",
        ctx()
    );
    assert!(
        !auth.contains(client_akid),
        "the client's own AccessKeyId must never be forwarded upstream; {}",
        ctx()
    );
    let amzdate = out
        .header("x-amz-date")
        .unwrap_or_else(|| node.fail(&format!("no outbound x-amz-date; {}", ctx())));
    let content_sha = out
        .header("x-amz-content-sha256")
        .unwrap_or_else(|| node.fail(&format!("no outbound x-amz-content-sha256; {}", ctx())));
    assert_eq!(
        content_sha,
        sha256_hex(&out.body),
        "x-amz-content-sha256 must be the hash of the body the upstream actually received; {}",
        ctx()
    );
    assert_eq!(out.method, "POST", "{}", ctx());
    assert_eq!(
        out.path,
        format!("/model/{}/converse", uri_encode(WIRE_MODEL)),
        "the wire path carries the encoded Bedrock modelId; {}",
        ctx()
    );

    let parsed = parse_authorization(auth).unwrap_or_else(|| {
        node.fail(&format!(
            "the outbound authorization is malformed; {}",
            ctx()
        ))
    });
    assert_eq!(
        parsed.service,
        SERVICE,
        "the scope names bedrock; {}",
        ctx()
    );
    assert_eq!(
        parsed.datestamp,
        &amzdate[..8],
        "the scope date is the x-amz-date's day; {}",
        ctx()
    );
    for required in ["host", "x-amz-content-sha256", "x-amz-date"] {
        assert!(
            parsed.signed_headers.split(';').any(|h| h == required),
            "the outbound signature must cover `{required}`; {}",
            ctx()
        );
    }

    // RECOMPUTE the signature over what the upstream received: every header the signature names,
    // the received path double-encoded (non-S3 SigV4 encodes the already-encoded path once more),
    // no query, the received body's hash.
    let mut canonical_headers = String::new();
    for name in parsed.signed_headers.split(';') {
        let value = out.header(name).unwrap_or_else(|| {
            node.fail(&format!(
                "the signature names `{name}` but the upstream received no such header; {}",
                ctx()
            ))
        });
        canonical_headers.push_str(&format!("{name}:{}\n", canonical_value(value)));
    }
    let canonical_request = format!(
        "POST\n{}\n\n{canonical_headers}\n{}\n{}",
        uri_encode(&out.path),
        parsed.signed_headers,
        sha256_hex(&out.body)
    );
    let expected = signature(
        UPSTREAM_SECRET,
        amzdate,
        &parsed.datestamp,
        &parsed.region,
        &parsed.service,
        &canonical_request,
    );
    assert_eq!(
        parsed.signature,
        expected,
        "the outbound SigV4 signature must VERIFY under the lane secret over the received request \
         (canonical request:\n{canonical_request}\n); {}",
        ctx()
    );
}

// ── the client-side SigV4 signer and the shared SigV4 primitives ─────────────────────────────────

/// Sign a Converse POST the way an AWS SDK does: `host;x-amz-content-sha256;x-amz-date`, service
/// `bedrock`, the path double-encoded as the canonical URI. Returns every header to send.
fn sign_client_request(
    akid: &str,
    secret: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> Vec<(String, String)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (amzdate, datestamp) = format_amz_time(now);
    let payload_hash = sha256_hex(body);
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "POST\n{}\n\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n\n\
         {signed_headers}\n{payload_hash}",
        uri_encode(path)
    );
    let sig = signature(
        secret,
        &amzdate,
        &datestamp,
        REGION,
        SERVICE,
        &canonical_request,
    );
    vec![
        (
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={akid}/{datestamp}/{REGION}/{SERVICE}/aws4_request, \
                 SignedHeaders={signed_headers}, Signature={sig}"
            ),
        ),
        ("x-amz-date".to_string(), amzdate),
        ("x-amz-content-sha256".to_string(), payload_hash),
        ("content-type".to_string(), "application/json".to_string()),
    ]
}

/// The SigV4 signature (hex) of `canonical_request` under `secret`'s derived signing key.
fn signature(
    secret: &str,
    amzdate: &str,
    datestamp: &str,
    region: &str,
    service: &str,
    canonical_request: &str,
) -> String {
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()))
}

/// HMAC-SHA256 (RFC 2104) over `sha2`, the digest this crate's tests already carry.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(&opad)
        .chain_update(inner)
        .finalize()
        .to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// SigV4 URI encoding of a path: unreserved bytes and `/` pass, every other byte is `%XX`.
fn uri_encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A canonical header value: trimmed, each run of ASCII spaces collapsed to one.
fn canonical_value(v: &str) -> String {
    v.split(' ')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `(YYYYMMDDTHHMMSSZ, YYYYMMDD)` for a Unix time, in UTC (civil-from-days).
fn format_amz_time(epoch: u64) -> (String, String) {
    let days = (epoch / 86_400) as i64;
    let sod = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    );
    (stamp, date)
}

struct ParsedAuth {
    datestamp: String,
    region: String,
    service: String,
    signed_headers: String,
    signature: String,
}

fn parse_authorization(v: &str) -> Option<ParsedAuth> {
    let rest = v.strip_prefix("AWS4-HMAC-SHA256 ")?;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let (k, val) = part.trim().split_once('=')?;
        match k {
            "Credential" => credential = Some(val),
            "SignedHeaders" => signed_headers = Some(val),
            "Signature" => signature = Some(val),
            _ => return None,
        }
    }
    let scope: Vec<&str> = credential?.split('/').collect();
    if scope.len() != 5 || scope[4] != "aws4_request" {
        return None;
    }
    Some(ParsedAuth {
        datestamp: scope[1].to_string(),
        region: scope[2].to_string(),
        service: scope[3].to_string(),
        signed_headers: signed_headers?.to_string(),
        signature: signature?.to_string(),
    })
}

// ── the node ─────────────────────────────────────────────────────────────────────────────────────

struct Node {
    child: Child,
    dir: PathBuf,
    log_path: PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Node {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn fail(&self, why: &str) -> ! {
        panic!("{why}\nbusbar log:\n{}", self.log())
    }

    /// Both listeners accept, failing loud (with the log) if the process dies or the budget runs out.
    fn wait_listening(&mut self, data_port: u16, admin_port: u16) {
        let deadline = Instant::now() + BOOT_BUDGET;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                self.fail(&format!(
                    "busbar exited before listening (status {status:?})"
                ));
            }
            let up = |p: u16| {
                TcpStream::connect_timeout(
                    &format!("127.0.0.1:{p}").parse().unwrap(),
                    Duration::from_millis(300),
                )
                .is_ok()
            };
            if up(data_port) && up(admin_port) {
                return;
            }
            if Instant::now() >= deadline {
                self.fail(&format!("busbar did not listen within {BOOT_BUDGET:?}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `POST /api/v1/admin/keys {"issue_aws_credential": true}` under the admin token, retried only
    /// while the admin listener is not yet answering (bounded).
    fn mint_aws_key(&self, admin_port: u16) -> serde_json::Value {
        let host = format!("127.0.0.1:{admin_port}");
        let body = br#"{"name":"sigv4-both-ways","issue_aws_credential":true}"#;
        let headers = vec![
            ("authorization".to_string(), format!("Bearer {ADMIN_TOKEN}")),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let r = send(admin_port, &host, "/api/v1/admin/keys", &headers, body);
            if r.status == 201 || r.status == 200 {
                return serde_json::from_slice(&r.body).unwrap_or_else(|e| {
                    self.fail(&format!("the mint answered non-JSON ({e}): {}", r.text))
                });
            }
            if Instant::now() >= deadline {
                self.fail(&format!(
                    "the admin API did not mint an AWS key within {IO_TIMEOUT:?}; last answer {}:\n{}",
                    r.status, r.text
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-sigv4-both-ways-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        format!(
            "bedrock-lane:\n  protocol: bedrock\n  base_url: \"http://127.0.0.1:{upstream_port}\"\n  \
             api_key_env: {UPSTREAM_CREDS_ENV}\n"
        ),
    )
    .unwrap();
    let signing_key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(signing_key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &signing_key.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
limits:
  request_body_max_bytes: {cap}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: [keys]
  signing_key: {{ file: "{signing}" }}
  admin_auth: [admin-tokens]
providers:
  bedrock-lane:
    api_key: {{ env: {UPSTREAM_CREDS_ENV} }}
models:
  {MODEL}:
    provider: bedrock-lane
    upstream_model: "{WIRE_MODEL}"
"#,
            signing = dir.join("signing.key").display(),
            cap = BODY_CAP,
        ),
    )
    .unwrap();
}

// ── the capturing upstream ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Captured {
    method: String,
    path: String,
    /// Lowercased names, values as received.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A Bedrock Converse stand-in on loopback: records every request it receives and answers each
/// with a minimal Converse response, one request per connection.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<Captured>>>,
}

impl Upstream {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let sink = sink.clone();
                std::thread::spawn(move || serve_one(stream, &sink));
            }
        });
        Self { port, seen }
    }

    fn captured(&self) -> Vec<Captured> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve_one(mut stream: TcpStream, sink: &Mutex<Vec<Captured>>) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 {
            return;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let find = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v): &(String, String)| v.clone())
    };
    let mut body = Vec::new();
    if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            if reader.read_line(&mut size).unwrap_or(0) == 0 {
                return;
            }
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            let mut chunk = vec![0u8; n + 2];
            if reader.read_exact(&mut chunk).is_err() {
                return;
            }
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        let n: usize = find("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        body.resize(n, 0);
        if reader.read_exact(&mut body).is_err() {
            return;
        }
    }
    sink.lock().unwrap().push(Captured {
        method,
        path,
        headers,
        body,
    });
    let payload = br#"{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2},"metrics":{"latencyMs":1}}"#;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-amzn-RequestId: 00000000-0000-4000-8000-000000000000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

// ── raw HTTP client ──────────────────────────────────────────────────────────────────────────────

struct Response {
    /// `0` means no status line arrived at all.
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The whole response as text, for failure messages and the byte-identity check.
    text: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The raw response with the two values that legitimately differ per response — the AWS
    /// request id and the HTTP date — blanked; everything else is compared byte for byte.
    fn masked(&self) -> String {
        self.text
            .split("\r\n")
            .map(|l| {
                let lower = l.to_ascii_lowercase();
                if lower.starts_with("x-amzn-requestid:") || lower.starts_with("date:") {
                    l.split(':').next().unwrap_or_default().to_string() + ": <masked>"
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}

/// One POST on a fresh connection with exactly `headers` (plus Host, Content-Length, close).
fn send(port: u16, host: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Response {
    let empty = Response {
        status: 0,
        headers: Vec::new(),
        body: Vec::new(),
        text: String::new(),
    };
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return empty;
    };
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let mut head = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Response {
            text: String::from_utf8_lossy(&raw).into_owned(),
            ..empty
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let rest = &raw[split + 4..];
    Response {
        status,
        headers,
        body: if chunked {
            dechunk(rest)
        } else {
            rest.to_vec()
        },
        text: String::from_utf8_lossy(&raw).into_owned(),
    }
}

/// The payload of a chunked body (the whole body was read to EOF first).
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = String::from_utf8_lossy(&rest[..eol]);
        let n =
            usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        rest = &rest[eol + 2..];
        if n == 0 || rest.len() < n {
            break;
        }
        out.extend_from_slice(&rest[..n]);
        rest = rest.get(n + 2..).unwrap_or_default();
    }
    out
}
