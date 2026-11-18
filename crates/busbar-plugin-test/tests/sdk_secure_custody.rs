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
    let from_contract = busbar_contract::secure::SecureString::from("credential").into_bytes();
    let bytes: SecureVec = from_contract;
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
    let allocator = std::env::var("_RJEM_MALLOC_CONF").expect("Q24 allocator configuration");
    for setting in ["dirty_decay_ms:-1", "muzzy_decay_ms:-1"] {
        let key = setting.split(':').next().expect("setting key");
        assert_eq!(
            allocator
                .split(',')
                .rev()
                .find(|part| part.split(':').next() == Some(key)),
            Some(setting),
            "Q24 requires freed pages to stay mapped"
        );
    }
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
    use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
    use busbar_plugin_abi::Secret;

    /// The reference a resolve was asked for: the host port sends it as one CONFIG record (IF 8.2, the
    /// loader's `encode_reference`); a chain started raw (`start1` below) carries the bytes themselves.
    fn asked(bytes: &[u8]) -> &[u8] {
        Records::new(bytes)
            .next()
            .and_then(Result::ok)
            .filter(|rec| rec.tag == tag::CONFIG)
            .map_or(bytes, |rec| rec.body)
    }

    pub const URL: &str = "https://custody.test/token";
    pub const DEST: &str = "custody.test:443";
    pub(super) static SCRATCH_DROPS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    struct Scratch(SecureVec);
    impl Drop for Scratch {
        fn drop(&mut self) {
            SCRATCH_DROPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
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
            d.secret_path("/credential");
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
            reference: ChainBytes,
        ) -> Result<busbar_plugin_abi::records::Reply, Fail> {
            if reference.with(|bytes| asked(bytes) == b"park") {
                let scratch = Scratch(SecureVec::from(&b"owned-request"[..]));
                let request = need::Fetch {
                    method: "POST",
                    url: URL,
                    headers: &[],
                    body: &scratch.0,
                    max_body: 4096,
                    trust: TrustHandle::NONE,
                    cert: None,
                    egress: egress::DEFAULT,
                };
                assert_eq!(need::fetch(&request).await?.status, 204);
                let _ = need::fetch(&request).await?;
                panic!("the cancellation test must not answer its parked FETCH");
            }
            #[cfg(target_os = "linux")]
            if reference.with(|bytes| asked(bytes).len() == PAYLOAD_LEN + 1) {
                let credential = need::secret(SecretHandle(1)).await?;
                let mut scratch = reference.with(|bytes| SecureVec::from(asked(bytes)));
                scratch.extend_from_slice(&credential);
                let request = need::Fetch {
                    method: "POST",
                    url: URL,
                    headers: &[("authorization", &credential)],
                    body: &scratch,
                    max_body: 4096,
                    trust: TrustHandle::NONE,
                    cert: None,
                    egress: egress::DEFAULT,
                };
                let _ = need::fetch(&request).await?;
                panic!("the cancellation test must not answer FETCH");
            }
            #[cfg(target_os = "linux")]
            if reference.with(|bytes| asked(bytes).len() == PAYLOAD_LEN) {
                let mut scratch = reference.with(|bytes| SecureVec::from(asked(bytes)));
                scratch.extend_from_slice(&[0; 1024]);
                let request = need::Fetch {
                    method: "POST",
                    url: URL,
                    headers: &[],
                    body: &scratch,
                    max_body: 4096,
                    trust: TrustHandle::NONE,
                    cert: None,
                    egress: egress::DEFAULT,
                };
                let _ = need::fetch(&request).await?;
                panic!("the cancellation test must not answer FETCH");
            }

            if reference.with(|bytes| asked(bytes) == b"batch") {
                let mut batch = need::Batch::new();
                batch.secret(SecretHandle(1)).secret(SecretHandle(2));
                let _ = batch.run().await?;
                panic!("the malformed second result must fail decoding");
            }
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
            assert!(matches!(answers.pop(), Some(Err(need::NeedErr::Denied))));
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
fn safe_parked_fetch_checks_lifecycle_and_rejects_counterfeit_cancellation() {
    use busbar_plugin_test::fake_needs::{FakeNeeds, FetchNeed};
    use busbar_plugin_test::suites::harness::Harness;
    use busbar_plugin_test::CallCx;
    use std::future::{pending, poll_fn, Future};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::Poll;
    use std::time::{Duration, Instant};

    let cx = || CallCx {
        request_id: 1,
        deadline: Instant::now() + Duration::from_secs(10),
        stack: Default::default(),
    };
    let host = |url: &str, denied: bool, inspect: fn(FetchNeed<'_>)| {
        let mut needs = FakeNeeds::new();
        needs.fetch("POST", fixture::URL, 204, &[], b"");
        let visits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&visits);
        let drops_before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
        let parked = needs.park_fetch("POST", url, move |request| {
            assert_eq!(
                fixture::SCRATCH_DROPS.load(Ordering::SeqCst),
                drops_before,
                "scratch is still owned at FETCH"
            );
            seen.fetch_add(1, Ordering::SeqCst);
            inspect(request);
        });
        if denied {
            needs.deny("custody.test");
        }
        let h = Harness::admit(fixture::PLUGIN.plugin(), needs).expect("fixture admission");
        let port = h.open_secret("parked", b"{}").expect("fixture open");
        (h, port, parked, visits)
    };
    fn inspect(request: FetchNeed<'_>) {
        assert!(request.method == "POST" && request.url == fixture::URL);
        assert!(request.body == b"owned-request", "borrowed request differs");
    }
    let (h, port, gate, visits) = host(fixture::URL, false, inspect);
    let before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
    assert!(!gate.entered() && !gate.cancelled());
    assert_eq!(h.needs().released(), 0);
    h.cancel_at_fetch(&gate, port.resolve(cx(), b"park"));
    assert!(gate.entered() && gate.cancelled());
    assert_eq!(visits.load(Ordering::SeqCst), 1);
    assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before + 1);
    assert_eq!(h.needs().released(), 1);
    assert_eq!(
        h.seen().len(),
        2,
        "ordinary response precedes parked response"
    );
    assert!(catch_unwind(AssertUnwindSafe(|| h.cancel_at_fetch(&gate, async {}))).is_err());

    for ready in [false, true] {
        let (h, _port, gate, _) = host(fixture::URL, false, inspect);
        let result = catch_unwind(AssertUnwindSafe(|| {
            h.cancel_at_fetch(&gate, async {
                if !ready {
                    pending::<()>().await;
                }
            });
        }));
        assert!(result.is_err());
        assert!(!gate.entered() && !gate.cancelled());
        assert_eq!(h.needs().released(), 0);
    }
    for (url, denied) in [("https://other.test/token", false), (fixture::URL, true)] {
        let (h, port, gate, visits) = host(url, denied, inspect);
        let before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
        assert!(catch_unwind(AssertUnwindSafe(
            || h.cancel_at_fetch(&gate, port.resolve(cx(), b"park"))
        ))
        .is_err());
        assert!(!gate.entered());
        assert_eq!(visits.load(Ordering::SeqCst), 0);
        assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before + 1);
        assert_eq!(h.needs().released(), 1);
    }
    let (h, port, gate, _) = host(fixture::URL, false, inspect);
    let before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
    let mut owner = Box::pin(port.resolve(cx(), b"park"));
    assert!(catch_unwind(AssertUnwindSafe(|| h.cancel_at_fetch(&gate, owner.as_mut()))).is_err());
    assert!(gate.entered() && !gate.cancelled());
    assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before);
    assert_eq!(h.needs().released(), 0);
    drop(owner);
    assert!(gate.cancelled());
    assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before + 1);
    assert_eq!(h.needs().released(), 1);

    let (h, port, gate, _) = host(fixture::URL, false, inspect);
    let before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
    let counterfeit = async {
        let mut owner = Box::pin(port.resolve(cx(), b"park"));
        poll_fn(|cx| {
            assert!(owner.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(owner);
        pending::<()>().await;
    };
    assert!(catch_unwind(AssertUnwindSafe(|| h.cancel_at_fetch(&gate, counterfeit))).is_err());
    assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before + 1);
    assert_eq!(h.needs().released(), 1);

    let (h, port, gate, _) = host(fixture::URL, false, |_| panic!("inspector control"));
    let before = fixture::SCRATCH_DROPS.load(Ordering::SeqCst);
    assert!(catch_unwind(AssertUnwindSafe(
        || h.cancel_at_fetch(&gate, port.resolve(cx(), b"park"))
    ))
    .is_err());
    assert!(!gate.entered() && gate.cancelled());
    assert_eq!(fixture::SCRATCH_DROPS.load(Ordering::SeqCst), before + 1);
    assert_eq!(h.needs().released(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn safe_parked_fetch_wipes_request_and_secret_script_owners() {
    use busbar_plugin_test::suites::harness::Harness;
    use busbar_plugin_test::{CallCx, FakeNeeds};
    use std::time::{Duration, Instant};
    let proof = WipeProof::new_text();
    let mut input = payload(&proof);
    input.fill(b'a');
    proof.write_canary(&mut input[OFFSET..OFFSET + CANARY_LEN]);
    assert!(input.iter().all(u8::is_ascii_alphanumeric));
    input.extend_from_slice(b"a");
    let mut needs = FakeNeeds::new();
    needs.secret("/credential", &input);
    let parked = needs.park_fetch("POST", fixture::URL, |request| {
        assert_eq!(request.body.len(), (PAYLOAD_LEN + 1) * 2);
        assert!(request.body.iter().all(u8::is_ascii_alphanumeric));
        let (input, secret) = request.body.split_at(PAYLOAD_LEN + 1);
        assert!(input == secret, "SECRET result must match guarded input");
        let mut headers = request.headers;
        let header = headers.next().expect("one header").expect("header record");
        let (name, value) = header.pair().expect("header pair");
        assert!(
            name == "authorization" && value == secret,
            "guarded SECRET header"
        );
        assert!(headers.next().is_none());
    });
    let h = Harness::admit(fixture::PLUGIN.plugin(), needs).expect("fixture admission");
    let port = h
        .open_secret(
            "custody",
            br#"{"credential":{"module":"fixture","key":"credential"}}"#,
        )
        .expect("open");
    h.cancel_at_fetch(
        &parked,
        port.resolve(
            CallCx {
                request_id: 1,
                deadline: Instant::now() + Duration::from_secs(10),
                stack: Default::default(),
            },
            &input,
        ),
    );
    assert!(parked.entered() && parked.cancelled());
    assert_eq!(h.needs().released(), 1);
    drop(port);
    drop(h);
    drop(input);
    drop(parked);
    proof.assert_absent("safe cancelled FETCH and SECRET scripts");
}

#[cfg(target_os = "linux")]
#[test]
fn text_canary_control_detects_an_unwiped_owner() {
    let proof = WipeProof::new_text();
    let raw = payload(&proof).into_vec();
    drop(raw);
    assert!(proof.canary_copies("text canary unwiped control") > 0);
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

#[test]
fn secure_byte_wipe_counters_track_growth_and_drop() {
    let before = busbar_contract::secure::wipe_counts();
    let mut bytes = SecureVec::with_capacity(8).expect("allocation");
    bytes.extend_from_slice(b"password");
    bytes.extend_from_slice(&[1; 1024]);
    let grown = busbar_contract::secure::wipe_counts();
    assert_eq!(grown.0 - before.0, 1, "one old block was wiped on growth");
    assert_eq!(grown.1, before.1, "the byte owner is still live");
    drop(bytes);
    let dropped = busbar_contract::secure::wipe_counts();
    assert_eq!(dropped.1 - before.1, 1, "the final block was wiped on drop");
}

#[cfg(target_os = "linux")]
#[test]
fn custody_memory_probe_detects_an_unwiped_raw_transfer() {
    let proof = WipeProof::new();
    let raw = payload(&proof).into_vec();
    // Negative control only: no production consumer may transfer to this non-wiping owner.
    drop(raw);
    assert!(proof.canary_copies("unwiped raw transfer") > 0);
}

#[cfg(target_os = "linux")]
#[test]
fn failed_read_loan_wipes_the_entire_written_extent() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let proof = WipeProof::new();
        let mut bytes = SecureVec::new();
        let result = bytes.read_into(PAYLOAD_LEN, tail, |loan| {
            proof.write_canary(&mut loan[OFFSET..OFFSET + CANARY_LEN]);
            Err(std::io::ErrorKind::Interrupted.into())
        });
        assert!(result.expect("allocation").is_err());
        drop(bytes);
        proof.assert_absent("failed SDK read loan");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cancelling_pending_fetch_drops_its_owned_request_scratch() {
    use busbar_ffi::host::{ChainBufs, OpenAnswer, OutLease, Started};
    use busbar_ffi::image::Admitted;
    use busbar_ffi::{Arg, Status};
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_abi::need::{op, NeedRec};
    use busbar_plugin_abi::records::{tag, Records};

    let proof = WipeProof::new();
    let mut lease = OutLease::new(vec![0; 64 * 1024], 64 * 1024).expect("lease");
    let image = Admitted::linked(&fixture::PLUGIN).expect("fixture image");
    let instance =
        match image.open::<busbar_plugin_abi::secret::Marker>(&HOST, b"{}".to_vec(), 0, &mut lease)
        {
            OpenAnswer::Done(Status::OK, Some(instance)) => instance,
            _ => panic!("fixture did not open"),
        };
    let mut arguments = ChainBufs::new();
    // This existing host chain owner wipes every argument on drop; no FakeNeeds script keeps a copy.
    let index = arguments.push(payload(&proof).into_vec());
    let chain = match instance.start1(
        |vt| &vt.resolve,
        arguments,
        move |arguments| Arg::bytes(arguments.get(index)),
        &mut lease,
    ) {
        Started::Need(chain) => chain,
        _ => panic!("FETCH must park before it receives a result"),
    };
    lease.with_answer(|bytes| {
        let record = Records::new(bytes)
            .map(|record| record.expect("record"))
            .find(|record| record.tag == tag::NEED)
            .expect("FETCH Need");
        let (need, _) = record.pod_tail::<NeedRec>().expect("Need header");
        assert_eq!(need.op, op::FETCH);
    });
    drop(chain);
    drop(instance);
    drop(lease);
    proof.assert_absent("cancelled FETCH request scratch and host loans");
}

#[cfg(target_os = "linux")]
#[test]
fn malformed_later_batch_result_drops_completed_secret_owners() {
    use busbar_ffi::host::{ChainBufs, OpenAnswer, OutLease, Resumed, Started};
    use busbar_ffi::image::Admitted;
    use busbar_ffi::{Arg, Status};
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_abi::need::{op, NeedResRec};
    use busbar_plugin_abi::records::{tag, Reply, Writer};

    let proof = WipeProof::new();
    let mut lease = OutLease::new(vec![0; 64 * 1024], 64 * 1024).expect("lease");
    let image = Admitted::linked(&fixture::PLUGIN).expect("fixture image");
    let instance =
        match image.open::<busbar_plugin_abi::secret::Marker>(&HOST, b"{}".to_vec(), 0, &mut lease)
        {
            OpenAnswer::Done(Status::OK, Some(instance)) => instance,
            _ => panic!("fixture did not open"),
        };
    let mut arguments = ChainBufs::new();
    let index = arguments.push(b"batch".to_vec());
    let mut chain = match instance.start1(
        |vt| &vt.resolve,
        arguments,
        move |arguments| Arg::bytes(arguments.get(index)),
        &mut lease,
    ) {
        Started::Need(chain) => chain,
        _ => panic!("batch must park"),
    };
    let mut results = Reply::new();
    let value = payload(&proof);
    let first = NeedResRec {
        op: op::SECRET,
        status: 0,
        a: 0,
        b: 0,
        lens: [PAYLOAD_LEN as u32, 0],
        _r: 0,
    };
    results
        .put_pod_tail(tag::NEED_RES, &first, &value)
        .expect("first result");
    let wrong = NeedResRec {
        op: op::READ,
        lens: [0, 0],
        ..first
    };
    results
        .put_pod_tail(tag::NEED_RES, &wrong, &[])
        .expect("wrong second result");
    drop(value);
    // resume immediately places this final-sized copy in its existing wiping ChainBufs owner.
    let answer = chain.resume(results.as_bytes().to_vec(), &mut lease);
    assert!(matches!(answer, Resumed::Done(Status::FAULT, None)));
    drop(chain);
    drop(results);
    drop(instance);
    drop(lease);
    proof.assert_absent("completed batch secret dropped on later decoding fault");
}

#[cfg(target_os = "linux")]
#[path = "sdk_secure_custody/store_rows.rs"]
mod store_rows;
