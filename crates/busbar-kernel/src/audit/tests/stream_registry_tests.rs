// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{append_full, handle, register, seed, Decode, StreamRecord};
use crate::audit::journal::NeutralBody;
use crate::audit::Framing;
use crate::store::plane_view::{decode, encode};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_KIND_ID: AtomicU32 = AtomicU32::new(400_000);
fn fresh_kind_id() -> u32 {
    NEXT_KIND_ID.fetch_add(1, Ordering::SeqCst)
}

fn neutral_decode(scope: &str, body: &[u8]) -> RecordStoreResult<StreamRecord> {
    let nb: NeutralBody = decode(body)?;
    Ok(StreamRecord::from_parts(
        scope.to_string(),
        nb.seq,
        nb.prev_hash,
        nb.hash,
        nb.content,
        Framing::LengthPrefixed,
        true,
    ))
}

fn failing_decode(_scope: &str, _body: &[u8]) -> RecordStoreResult<StreamRecord> {
    Err(RecordStoreError("the stream's own reason".to_string()))
}

fn register_ram(kind_id: u32, decode: Decode) {
    register(
        kind_id,
        "registry_test".to_string(),
        Framing::LengthPrefixed,
        true,
        decode,
        usize::MAX,
        None,
    );
}

fn body(seq: u64, prev_hash: &str, hash: &str, content: &[u8]) -> Vec<u8> {
    encode(&NeutralBody {
        seq,
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
        content: content.to_vec(),
    })
    .expect("neutral body encodes")
}

#[test]
fn a_native_stream_seeds_from_its_bodies_and_continues_without_a_host() {
    let kind_id = fresh_kind_id();
    register_ram(kind_id, Decode::Native(neutral_decode));
    let (s1, p1, hash1) = append_full(kind_id, "tenant", b"|one").expect("append 1");
    let (s2, p2, hash2) = append_full(kind_id, "tenant", b"|two").expect("append 2");
    assert_eq!((s1, p1.as_str()), (1, ""), "genesis");
    assert_eq!(
        (s2, p2.as_str()),
        (2, hash1.as_str()),
        "record 2 links record 1"
    );

    register_ram(kind_id, Decode::Native(neutral_decode));
    let stored = [
        body(1, "", &hash1, b"|one"),
        body(2, &hash1, &hash2, b"|two"),
    ];
    assert_eq!(
        seed(kind_id, "tenant", &stored),
        Ok(false),
        "an intact stored chain seeds without a break"
    );
    let (s3, p3, _) = append_full(kind_id, "tenant", b"|three").expect("append 3");
    assert_eq!(
        (s3, p3.as_str()),
        (3, hash2.as_str()),
        "the seeded chain continues where it stopped, never forking at seq 1"
    );
}

#[test]
fn seed_reports_a_break_and_refuses_what_it_cannot_address() {
    let kind_id = fresh_kind_id();
    register_ram(kind_id, Decode::Native(neutral_decode));
    let (_, _, hash1) = append_full(kind_id, "tenant", b"|one").expect("append 1");
    let (_, _, hash2) = append_full(kind_id, "tenant", b"|two").expect("append 2");

    register_ram(kind_id, Decode::Native(neutral_decode));
    let forged = [
        body(1, "", &hash1, b"|one"),
        body(2, &hash1, &hash2, b"|forged"),
    ];
    assert_eq!(
        seed(kind_id, "tenant", &forged),
        Ok(true),
        "the forged row is a break"
    );
    assert_eq!(
        seed(kind_id, "tenant", &[b"not a body".to_vec()]),
        Err(()),
        "an undecodable body faults the seed"
    );
    assert_eq!(
        seed(kind_id, "", &forged),
        Err(()),
        "an empty scope is refused"
    );
    assert_eq!(
        seed(fresh_kind_id(), "tenant", &forged),
        Err(()),
        "an unregistered stream is refused"
    );
    let unregistered = append_full(fresh_kind_id(), "tenant", b"|x").expect_err("unregistered");
    assert_eq!(unregistered.0, "journal stream is not registered");
    let empty = append_full(kind_id, "", b"|x").expect_err("empty scope");
    assert_eq!(empty.0, "journal scope must be a non-empty key");
}

#[test]
fn decode_native_rescopes_and_reports_a_fault_as_the_bridge_did() {
    let ok_id = fresh_kind_id();
    register(
        ok_id,
        "registry_test".to_string(),
        Framing::PipeSeparated,
        false,
        Decode::Native(neutral_decode),
        usize::MAX,
        None,
    );
    let h = handle(ok_id).expect("registered");
    let r = h
        .decode_native("parent", &body(7, "p", "h", b"|c"))
        .expect("decodes");
    assert_eq!(
        r.scope, "parent",
        "the scope is the store parent the registry knows"
    );
    assert_eq!(
        r.framing,
        Framing::PipeSeparated,
        "the framing is the stream's"
    );
    assert_eq!(
        (r.seq, r.prev_hash.as_str(), r.hash.as_str()),
        (7, "p", "h")
    );

    let bad_id = fresh_kind_id();
    register_ram(bad_id, Decode::Native(failing_decode));
    let Err(e) = handle(bad_id)
        .expect("registered")
        .decode_native("parent", b"x")
    else {
        panic!("a failing decode must not yield a record");
    };
    assert_eq!(e.0, "journal reframe failed: Fault");
}
