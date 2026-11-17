// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ABI-only byte owner and its result/sink boundaries must share the contract's custody.
#![forbid(unsafe_code)]

use busbar_plugin_abi::need::{need, SecretHandle};
use busbar_plugin_abi::secure::{SecureVec, Tail};

#[cfg(target_os = "linux")]
use busbar_plugin_test::canary_scan::{WipeProof, CANARY_LEN, OFFSET, PAYLOAD_LEN};

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[test]
fn sdk_secure_custody_surface_and_identity() {
    fn secret(_: need::NeedFut<'static, SecureVec>) {}
    secret(need::secret(SecretHandle(1)));
    fn read_surface(conn: &need::Conn, bytes: &mut SecureVec) {
        fn read(_: need::NeedFut<'_, SecureVec>) {}
        read(need::read(conn, 128));
        drop(need::read_into(conn, 128, bytes));
    }
    let _ = read_surface;
    let contract = busbar_contract::secure::SecureString::from("credential").into_bytes();
    let bytes: SecureVec = contract;
    let contract: busbar_contract::secure::SecureVec = bytes;
    assert_eq!(contract.as_slice(), b"credential");
    let fetched = need::Fetched {
        status: 200,
        headers: vec![("set-cookie".into(), SecureVec::from(&b"session"[..]))],
        body: SecureVec::from(&b"token"[..]),
    };
    let body: SecureVec = fetched.body;
    let headers: Vec<(String, SecureVec)> = fetched.headers;
    drop(headers);
    assert_eq!(body.as_slice(), b"token");
    for done in [need::Done::Secret(body), need::Done::Read(SecureVec::new())] {
        match done {
            need::Done::Secret(bytes) => assert_eq!(bytes.as_slice(), b"token"),
            need::Done::Read(bytes) => assert!(bytes.is_empty()),
            _ => panic!("unexpected result"),
        }
    }
}

#[test]
fn failed_and_panicking_read_loans_preserve_the_live_prefix() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut bytes = SecureVec::from(&b"prefix"[..]);
        let result = bytes.read_into(32, tail, |loan| {
            loan.fill(7);
            Err(std::io::ErrorKind::Interrupted.into())
        });
        assert!(result.expect("allocation").is_err());
        assert_eq!(bytes.as_slice(), b"prefix");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = bytes.read_into(32, tail, |loan| {
                loan.fill(9);
                panic!("reader panicked");
            });
        }));
        assert!(panic.is_err());
        assert_eq!(bytes.as_slice(), b"prefix");
    }
}

#[cfg(target_os = "linux")]
fn payload(proof: &WipeProof) -> SecureVec {
    let mut bytes = SecureVec::zeroed(PAYLOAD_LEN);
    proof.write_canary(&mut bytes[OFFSET..OFFSET + CANARY_LEN]);
    bytes
}

#[cfg(target_os = "linux")]
#[test]
fn growing_sdk_scratch_wipes_released_blocks_and_drop() {
    let proof = WipeProof::new();
    let mut bytes = payload(&proof);
    bytes.extend_from_slice(&[0; 1024]);
    bytes.extend_from_slice(&[0; 2048]);
    drop(bytes);
    proof.assert_absent("SDK scratch growth and drop");
}

#[cfg(target_os = "linux")]
#[test]
fn fetched_field_moves_keep_independent_wiping_owners() {
    let proof = WipeProof::new();
    let fetched = need::Fetched {
        status: 200,
        headers: vec![("set-cookie".into(), payload(&proof))],
        body: payload(&proof),
    };
    let body = fetched.body;
    drop(fetched.headers);
    drop(body);
    proof.assert_absent("FETCH body and header owners");
}

#[cfg(target_os = "linux")]
#[test]
fn sdk_unwind_wipes_uncommitted_read_loan() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let proof = WipeProof::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut bytes = SecureVec::new();
            let _ = bytes.read_into(PAYLOAD_LEN, tail, |loan| {
                proof.write_canary(&mut loan[OFFSET..OFFSET + CANARY_LEN]);
                panic!("reader panicked");
            });
        }));
        assert!(panic.is_err());
        proof.assert_absent("SDK abandoned read loan");
    }
}

mod fixture {
    use super::*;
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::{egress, ChainBytes, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Reply, Writer};
    use busbar_plugin_abi::Secret;

    pub const URL: &str = "https://custody.test/token";
    pub const DEST: &str = "custody.test:443";
    pub struct Probe;

    impl Open for Probe {
        async fn open(_: &'static Host, _: ChainBytes) -> Result<Self, Fail> {
            Ok(Self)
        }
        fn check(_: &Host, _: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            ends.fetch(URL, egress::DEFAULT);
            ends.open(
                DEST,
                busbar_plugin_abi::need::need_flag::TLS_REQUIRED,
                egress::DEFAULT,
            );
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
            d.item(
                busbar_plugin_abi::secret::tag::D_REF_SCHEMA,
                br#"{"type":"object"}"#,
            );
            d.methods(busbar_plugin_abi::secret::M_RESOLVE);
        }
    }

    impl Secret for Probe {
        async fn resolve(
            &self,
            _: &'static Host,
            _: ChainBytes,
        ) -> Result<busbar_plugin_abi::records::Reply, Fail> {
            let secret: SecureVec = need::secret(SecretHandle(1)).await?;
            let request = need::Fetch {
                method: "POST",
                url: URL,
                headers: &[],
                body: &secret,
                max_body: 4096,
                trust: TrustHandle::NONE,
                cert: None,
                egress: egress::DEFAULT,
            };
            let fetched = need::fetch(&request).await?;
            let opened = need::open(
                DEST,
                need::Tls::Required {
                    sni: "custody.test",
                    alpn: &[],
                    trust: TrustHandle::NONE,
                },
                egress::DEFAULT,
            )
            .await?;
            let mut bytes: SecureVec = need::read(&opened.conn, 3).await?;
            assert!(!need::read_into(&opened.conn, 16, &mut bytes).await?);
            assert!(need::read_into(&opened.conn, 16, &mut bytes).await?);
            let mut batch = need::Batch::new();
            batch.secret(SecretHandle(1)).secret(SecretHandle(99));
            let mut answers = batch.run().await?;
            assert!(matches!(answers.pop(), Some(Err(need::NeedErr::Absent))));
            let Some(Ok(need::Done::Secret(batched))) = answers.pop() else {
                panic!("successful batch item was lost beside an error")
            };
            // Subsequent Needs reset driver result storage; every earlier answer remains owned.
            assert_eq!(secret.as_slice(), b"credential");
            assert_eq!(batched.as_slice(), secret.as_slice());
            assert_eq!(bytes.as_slice(), b"abcdef");
            let body: SecureVec = fetched.body;
            assert_eq!(fetched.headers[0].0, "set-cookie");
            assert_eq!(fetched.headers[0].1.as_slice(), b"session");
            drop(fetched.headers);
            assert_eq!(body.as_slice(), b"token");
            need::close(opened.conn, false).await?;
            let mut reply = Reply::new();
            reply.put(busbar_plugin_abi::secret::tag::VALUE, &body)?;
            Ok(reply)
        }
    }
    busbar_plugin_abi::plugin!(Secret, Probe, name: "fixture-sdk-custody");
}

#[test]
fn safe_host_decodes_owned_results_and_preserves_batch_partial_success() {
    use busbar_plugin_test::suites::harness::Harness;
    use busbar_plugin_test::{CallCx, ConnScript, FakeNeeds};
    use std::time::{Duration, Instant};
    let mut needs = FakeNeeds::new();
    needs.secret("/credential", b"credential");
    needs.fetch(
        "POST",
        fixture::URL,
        200,
        &[("set-cookie", b"session")],
        b"token",
    );
    needs.conn(fixture::DEST, ConnScript::new().reply(b"abcdef").eof());
    let h = Harness::admit(fixture::PLUGIN.plugin(), needs).expect("admit custody probe");
    let port = h.open_secret("custody", b"{}").expect("open custody probe");
    let cx = CallCx {
        request_id: 1,
        deadline: Instant::now() + Duration::from_secs(10),
        stack: Default::default(),
    };
    let answer = h
        .block_on(port.resolve(cx, b"{}"))
        .expect("resolve custody probe");
    assert_eq!(answer.value.as_slice(), b"token");
}
