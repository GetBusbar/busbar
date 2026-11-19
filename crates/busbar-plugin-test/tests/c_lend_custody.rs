// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LEND-CUSTODY (IF §0 I11, §10.1, decision 60): what a sync entry is lent holds nothing an earlier entry
//! wrote, and core reads only what the entry wrote.
//!
//! A sync entry's answer buffer is the thread's (`sync_out`, `sync_bufs`). It is lent as it is (busbar-ffi `OutLease::clean`),
//! so the custody rests on the wipe after each call: every byte an entry wrote is zeroed before the call returns,
//! and a block that grew for a large answer is zeroed and freed, never kept. Driven through the ports core calls,
//! on one thread, with two plugins, three sessions and an answer larger than the first block, this checks byte for
//! byte the block the next entry is lent, its size, and that a later empty answer brings back no earlier record.

use busbar_plugin_abi::host_side::pool::sync_bufs;
use busbar_plugin_abi::records::{tag as head_tag, Reply, Writer};
use busbar_plugin_abi::transport as tp;
use busbar_ports::auth::{AuthIn, Verify};
use busbar_ports::transport::{ConnIn, TransportOut};
use busbar_ports::CallCx;

use crate::min3_transport;
use busbar_plugin_test::suites::harness::Harness;
use busbar_plugin_test::FakeNeeds;

/// An auth plugin whose sync `verify` answers a subject.
mod subject_auth {
    use busbar_plugin_abi::auth::{self, AuthReq};
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{tag, Out, Writer};

    pub struct SubjectAuth;
    impl Open for SubjectAuth {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(SubjectAuth)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.methods(auth::M_VERIFY)
                .schema(r#"{"type":"object"}"#)
                .item_text(auth::tag::D_CRED_HEADER, "authorization");
        }
    }
    impl busbar_plugin_abi::Auth for SubjectAuth {
        fn verify(&self, _h: &Host, _req: &AuthReq<'_>, out: &mut Out<'_>) -> Result<(), Fail> {
            out.put_text(tag::ID_SUBJECT, "subject-canary@example.test")?;
            Ok(())
        }
    }
    busbar_plugin_abi::plugin!(Auth, SubjectAuth, name: "fixture-custody-auth");
}

/// The first block's size (the pool's class 0): every entry is lent at least this (IF §3.2).
const FIRST_BLOCK: usize = 4 << 10;

/// The block the thread's next sync entry is lent: empty, every byte zero, and the first block's size.
fn next_lend_is_clean(after: &str) {
    sync_bufs(1 << 20, |_args, out| {
        assert!(
            out.bytes().is_empty(),
            "after {after}: the next entry's buffer holds an answer"
        );
        assert_eq!(
            out.capacity(),
            FIRST_BLOCK,
            "after {after}: the thread kept a block grown for an earlier answer"
        );
        let stale = out.whole().iter().filter(|byte| **byte != 0).count();
        assert_eq!(
            stale, 0,
            "after {after}: {stale} bytes of an earlier answer are lent to the next entry"
        );
    });
}

/// A head naming `authority`, which the fixture echoes into its answer (a WRITE of the request line).
fn head(authority: &str) -> Reply {
    let mut head = Reply::new();
    head.put_text(head_tag::H_AUTHORITY, authority)
        .expect("a head record");
    head
}

fn conn() -> ConnIn<'static> {
    ConnIn {
        role: tp::ROLE_CLIENT,
        flags: 0,
        alpn: "",
        sni: "",
        peer: "192.0.2.1:50000",
        local: "192.0.2.2:8443",
        tls_peer_cert: &[],
        leftover: &[],
        head: &[],
        local_fingerprint: "",
        mono_ns: 1,
    }
}

#[test]
fn a_lent_buffer_holds_no_earlier_answer_and_core_reads_only_what_was_written() {
    let h = Harness::admit(min3_transport::PLUGIN.plugin(), FakeNeeds::default())
        .unwrap_or_else(|r| panic!("admit: {r:?}"));
    let port = h
        .open_transport("custody-transport", b"{}")
        .unwrap_or_else(|e| panic!("open: {e:?}"));
    let begin = || {
        port.begin(&conn(), &mut |_o: TransportOut<'_>| {})
            .unwrap_or_else(|e| panic!("begin: {e:?}"))
    };
    let mut items = 0usize;

    // One session's answer: STREAM_OPENED and a WRITE carrying the authority.
    let mut first = begin();
    let secret = "credential-canary-0123456789abcdef.example";
    port.emit(
        &mut first,
        0,
        tp::E_HEAD,
        0,
        head(secret).as_bytes(),
        &mut |_o: TransportOut<'_>| items += 1,
    )
    .expect("the head opens the stream");
    assert_eq!(items, 2, "the head's answer is STREAM_OPENED and WRITE");
    next_lend_is_clean("one session's answer");

    // Another session, an empty answer: none of the first session's records come back.
    let mut second = begin();
    items = 0;
    port.ingest(&mut second, b"bytes", &mut |_o: TransportOut<'_>| {
        items += 1
    })
    .expect("ingest");
    assert_eq!(items, 0, "an empty answer after a full one reads as empty");
    next_lend_is_clean("another session's empty answer");

    // An answer larger than the first block: the block grows for it, then is wiped and released.
    let mut third = begin();
    let large = "a".repeat(3 * FIRST_BLOCK / 2);
    items = 0;
    port.emit(
        &mut third,
        0,
        tp::E_HEAD,
        0,
        head(&large).as_bytes(),
        &mut |_o: TransportOut<'_>| items += 1,
    )
    .expect("the large head opens the stream");
    assert_eq!(items, 2, "the large answer arrived whole");
    next_lend_is_clean("an answer larger than the first block");
    items = 0;
    port.ingest(&mut third, b"bytes", &mut |_o: TransportOut<'_>| items += 1)
        .expect("ingest");
    assert_eq!(
        items, 0,
        "an empty answer after a larger one reads as empty"
    );

    // Another plugin on the same thread: its answer is gone before the transport's next entry.
    let auth = Harness::admit(subject_auth::PLUGIN.plugin(), FakeNeeds::default())
        .unwrap_or_else(|r| panic!("admit: {r:?}"));
    let verifier = auth
        .open_auth("custody-auth", b"{}")
        .unwrap_or_else(|e| panic!("open: {e:?}"));
    let req = AuthIn {
        method: "GET",
        path: "/",
        query: "",
        authority: "api.example.test",
        headers: &[],
        peer: "192.0.2.1:50000",
        tls_peer_cert: &[],
        body: &[],
        now_s: 1_800_000_000,
    };
    let cx = CallCx {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
        request_id: 1,
        stack: busbar_plugin_abi::host_side::caller::CallStack::default(),
    };
    match verifier.verify(cx, &req, None) {
        Verify::Done(Ok(_)) => {}
        Verify::Done(Err(e)) => panic!("verify: {e:?}"),
        Verify::Io(_) => panic!("a sync verify answers at once"),
    }
    next_lend_is_clean("another plugin's answer");
    items = 0;
    port.ingest(&mut second, b"bytes", &mut |_o: TransportOut<'_>| {
        items += 1
    })
    .expect("ingest");
    assert_eq!(
        items, 0,
        "the auth plugin's subject does not reach the transport's answer"
    );
}
