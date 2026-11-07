// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::time::Duration;

use super::*;
use crate::persistence::{facade::CoreStore, scoped::ScopedStore};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{
    RecordChain, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
};
use busbar_contract::kinds::RecordBytes;

fn scope_for_key(
    store: &Arc<CoreStore>,
    schema: RecordSchemaId,
    key: &[u8],
) -> (ScopedStore, Vec<u8>) {
    let label_len = u16::from_be_bytes(key[..2].try_into().unwrap()) as usize;
    let instance = std::str::from_utf8(&key[2..2 + label_len]).unwrap();
    let rows =
        ScopedStore::authorized(store.clone(), instance, [schema.as_str().to_string()]).unwrap();
    (rows, key[2 + label_len..].to_vec())
}
async fn read_row(
    store: &Arc<CoreStore>,
    schema: RecordSchemaId,
    key: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let (rows, key) = scope_for_key(store, schema, key);
    rows.get(schema.as_str(), &key)
        .await
        .map(|value| value.map(|value| value.into_exposed(&crate::seal::lend())))
        .map_err(|error| format!("{error:?}"))
}
async fn put_row(
    store: &Arc<CoreStore>,
    schema: RecordSchemaId,
    key: &[u8],
    value: &RecordBytes,
) -> Result<(), String> {
    let (rows, key) = scope_for_key(store, schema, key);
    let outcome = rows
        .put(
            schema.as_str(),
            &key,
            busbar_contract::Secret::new(value.as_slice().to_vec()),
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    assert!(matches!(
        outcome,
        crate::persistence::scoped::Outcome::Applied
    ));
    Ok(())
}
async fn scan_rows(
    store: &Arc<CoreStore>,
    schema: RecordSchemaId,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let rows = ScopedStore::authorized(store.clone(), INST, [schema.as_str().to_string()]).unwrap();
    let mut cursor = None;
    let mut result = Vec::new();
    loop {
        let page = rows
            .page(schema.as_str(), prefix, cursor.as_ref())
            .await
            .map_err(|error| format!("{error:?}"))?;
        result.extend(page.rows.into_iter().map(|(key, value)| {
            (
                record_key(INST, &key),
                value.into_exposed(&crate::seal::lend()),
            )
        }));
        cursor = page.next;
        if cursor.is_none() {
            return Ok(result);
        }
    }
}
async fn redeem_claim(
    store: &Arc<CoreStore>,
    kind: &str,
    token: &str,
    expires_at: u64,
) -> Result<bool, String> {
    let rows = ScopedStore::authorized(store.clone(), INST, [EV.as_str().to_string()]).unwrap();
    let outcome = rows
        .redeem(kind, token, expires_at)
        .await
        .map_err(|error| format!("{error:?}"))?;
    Ok(matches!(
        outcome,
        crate::persistence::scoped::ClaimOutcome::Claimed
    ))
}

struct Inline;

impl Offload for Inline {
    fn run_async(&self, job: crate::host_services::AsyncJob) {
        match std::thread::spawn(move || futures::executor::block_on(job)).join() {
            Ok(()) => {}
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    fn run(&self, job: Box<dyn FnOnce() + Send>) {
        job();
    }
}

const EV: RecordSchemaId = RecordSchemaId::new("ev");

const INST: &str = "inst";

fn me() -> Caller {
    Caller {
        instance: Arc::from(INST),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Plane,
    }
}

async fn services_over(store: &Arc<CoreStore>, framing: u32, flags: u32) -> KernelServices {
    let s = KernelServices::new().with_pool(Arc::new(Inline));
    assert!(s.attach_persistence(store.clone()));
    s.admit(
        INST,
        InstanceFacts {
            record_kinds: vec![EV],
            record_chains: vec![RecordChain {
                kind: 0,
                framing,
                flags,
                _reserved: 0,
            }],
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    s
}

async fn rig() -> (KernelServices, Arc<CoreStore>) {
    let store = crate::real_store::core().await;
    let s = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    (s, store)
}

type Answered = Arc<Mutex<Option<Result<(), &'static str>>>>;

fn append(s: &KernelServices, scope: &[u8], bytes: &[u8]) -> Result<(), &'static str> {
    let got: Answered = Arc::default();
    let into = Arc::clone(&got);
    s.record_write(
        &me(),
        EV.as_str(),
        scope,
        RecordBytes::new(bytes.to_vec()).unwrap(),
        Box::new(move |r| *into.lock().unwrap() = Some(r)),
    )?;
    assert!(
        s.drain(Duration::from_secs(5)),
        "the write reached the store"
    );
    let answered = got.lock().unwrap().take();
    answered.expect("the write was answered")
}

fn listed(s: &KernelServices, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let into = Arc::clone(&slot);
    let ran = s.records_list(
        &me(),
        RecordsList {
            kind: EV.as_str().into(),
            prefix: prefix.to_vec(),
            after: None,
            limit: 0,
        },
        Box::new(move |st| *into.lock().unwrap() = Some(st)),
    );
    let stored = match ran {
        Ran::Now(st) => st,
        Ran::Later => slot.lock().unwrap().take().expect("the list was answered"),
    };
    assert_eq!(stored.outcome, Outcome::Ready, "{}", stored.error);
    let cut = |sp: Span| stored.bytes[sp.offset as usize..(sp.offset + sp.len) as usize].to_vec();
    stored
        .spans
        .iter()
        .map(|sp| (cut(sp.key), cut(sp.value)))
        .collect()
}

fn record_of(scope: &str, seq: u64) -> Vec<u8> {
    format!("{scope}/{seq:020}").into_bytes()
}

fn stored_at(scope: &str, seq: u64) -> Vec<u8> {
    record_key(INST, &record_of(scope, seq))
}

async fn tamper(store: &Arc<CoreStore>, key: &[u8], from: &[u8], to: &[u8]) {
    let held = read_row(&store, EV, key)
        .await
        .unwrap()
        .expect("the record is in the store")
        .as_slice()
        .to_vec();
    let at = held
        .windows(from.len())
        .position(|w| w == from)
        .expect("the record holds the bytes to change");
    let mut edited = held[..at].to_vec();
    edited.extend_from_slice(to);
    edited.extend_from_slice(&held[at + from.len()..]);
    put_row(&store, EV, key, &RecordBytes::new(edited).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn each_append_to_a_chained_kind_is_its_own_record() {
    let (s, _store) = rig().await;
    append(&s, b"t1", b"|100|task.submitted").unwrap();
    append(&s, b"t1", b"|160|task.working").unwrap();
    assert_eq!(
        listed(&s, b"t1"),
        vec![
            (record_of("t1", 1), b"|100|task.submitted".to_vec()),
            (record_of("t1", 2), b"|160|task.working".to_vec()),
        ],
        "two appends, two records, in sequence"
    );
}

#[tokio::test]
async fn a_tampered_row_is_reported_when_its_chain_is_read() {
    let (s, store) = rig().await;
    append(&s, b"t1", b"|100|task.submitted|planner").unwrap();
    append(&s, b"t1", b"|160|task.working|planner").unwrap();
    append(&s, b"t2", b"|100|task.submitted|planner").unwrap();
    let clean = listed(&s, b"");
    assert!(
        clean.iter().all(|(k, _)| k.len() > 3),
        "an intact store announces no break: {clean:?}"
    );
    tamper(&store, &stored_at("t1", 1), b"|planner", b"|attacker").await;
    let read = listed(&s, b"");
    let (key, words) = &read[0];
    assert_eq!(
        key.as_slice(),
        b"t1",
        "the broken chain is named by its scope"
    );
    assert!(!words.is_empty(), "with the break's words");
    let words = String::from_utf8_lossy(words);
    assert!(words.contains("seq 1"), "{words}");
    assert!(
        words.contains("EDITED"),
        "an in-place edit is a digest mismatch: {words}"
    );
    assert_eq!(
        read[1..].iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        vec![record_of("t1", 1), record_of("t1", 2), record_of("t2", 1)],
        "every record is still answered, and the intact chain announces nothing"
    );
}

#[tokio::test]
async fn a_tampered_chain_is_resumed_on_restore_and_still_reported() {
    let (s, store) = rig().await;
    append(&s, b"t1", b"|100|a").unwrap();
    append(&s, b"t1", b"|160|b").unwrap();
    tamper(&store, &stored_at("t1", 2), b"|160|b", b"|161|b").await;
    drop(s);
    let restarted = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    append(&restarted, b"t1", b"|200|c").unwrap();
    let read = listed(&restarted, b"t1");
    assert_eq!(read[0].0, b"t1", "the break is still reported");
    assert_eq!(
        read.last().map(|(k, v)| (k.clone(), v.clone())),
        Some((record_of("t1", 3), b"|200|c".to_vec())),
        "the chain went on at seq 3"
    );
}

#[tokio::test]
async fn a_length_prefixed_chain_without_its_scope_verifies_and_reports_an_edit() {
    let store = crate::real_store::core().await;
    let s = services_over(&store, CHAIN_LENGTH_PREFIXED, 0).await;
    append(&s, b"log", b"\0\0\0\0\0\0\0\x01x").unwrap();
    append(&s, b"log", b"\0\0\0\0\0\0\0\x01y").unwrap();
    assert_eq!(listed(&s, b"log").len(), 2, "two records, no break");
    tamper(&store, &stored_at("log", 2), b"\x01y", b"\x01z").await;
    assert_eq!(listed(&s, b"log")[0].0, b"log", "the edit is reported");
}

#[tokio::test]
async fn the_host_seals_each_record_over_the_declared_prelude() {
    let (s, store) = rig().await;
    append(&s, b"a11ce/t1", b"|100|task.submitted").unwrap();
    append(&s, b"a11ce/t1", b"|160|task.working").unwrap();
    let framing = crate::host_chains::ChainFraming::of(&RecordChain {
        kind: 0,
        framing: CHAIN_PIPE_SEPARATED,
        flags: CHAIN_DIGESTS_SCOPE,
        _reserved: 0,
    })
    .unwrap();
    let read = async |seq| {
        let body = read_row(&store, EV, &stored_at("a11ce/t1", seq))
            .await
            .unwrap()
            .unwrap();
        crate::host_chains::decode("a11ce/t1", body.as_slice(), framing).unwrap()
    };
    let (e1, e2) = (read(1).await, read(2).await);
    let expect = |prev: &str, seq: u64, own: &str| {
        busbar_contract::redacted::sha256_hex(format!("{prev}|a11ce/t1|{seq}{own}").as_bytes())
    };
    use crate::audit::ChainedRecord as _;
    assert_eq!((e1.seq(), e1.prev_hash()), (1, ""));
    assert_eq!(e1.hash(), expect("", 1, "|100|task.submitted"));
    assert_eq!((e2.seq(), e2.prev_hash()), (2, e1.hash()));
    assert_eq!(e2.hash(), expect(e1.hash(), 2, "|160|task.working"));
}

#[tokio::test]
async fn an_empty_append_drops_the_chain_whole() {
    let (s, _store) = rig().await;
    append(&s, b"t1", b"|1|a").unwrap();
    append(&s, b"t1", b"|2|b").unwrap();
    append(&s, b"t10", b"|1|c").unwrap();
    append(&s, b"t1", b"").unwrap();
    assert_eq!(
        listed(&s, b""),
        vec![(record_of("t10", 1), b"|1|c".to_vec())],
        "the dropped chain reads as absent, the other stands"
    );
    append(&s, b"t1", b"|3|d").unwrap();
    assert_eq!(
        listed(&s, b"t1/"),
        vec![(record_of("t1", 1), b"|3|d".to_vec())],
        "a fresh chain at seq 1, verifying"
    );
}

#[tokio::test]
async fn a_dropped_chain_scans_empty_in_the_store() {
    let (s, store) = rig().await;
    append(&s, b"t1", b"|1|a").unwrap();
    append(&s, b"t1", b"|2|b").unwrap();
    assert_eq!(scan_rows(&store, EV, b"").await.unwrap().len(), 2);
    append(&s, b"t1", b"").unwrap();
    assert_eq!(
        scan_rows(&store, EV, b"").await.unwrap(),
        Vec::new(),
        "the dropped chain's rows are gone from the store"
    );
}

#[tokio::test]
async fn a_chain_dropped_and_begun_again_never_meets_its_old_claims() {
    use crate::host_chains::{decode, life_key, position_token, ChainFraming, CHAIN_LIFE_SCHEMA};
    let (s, store) = rig().await;
    let framing = ChainFraming::of(&RecordChain {
        kind: 0,
        framing: CHAIN_PIPE_SEPARATED,
        flags: CHAIN_DIGESTS_SCOPE,
        _reserved: 0,
    })
    .unwrap();
    let first = async |what: &str| {
        let body = read_row(&store, EV, &stored_at("t1", 1))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{what}: record 1 is in the store"));
        decode("t1", body.as_slice(), framing).unwrap()
    };
    append(&s, b"t1", b"|1|a").unwrap();
    let old = position_token(INST, EV, "t1", 0, &first("the old chain").await);
    let now = busbar_kernel::store::now();
    assert!(redeem_claim(
        &store,
        crate::host_records::CLAIM_KIND,
        &old,
        now.saturating_add(60)
    )
    .await
    .unwrap());
    append(&s, b"t1", b"").unwrap();
    assert_eq!(
        scan_rows(&store, EV, b"").await.unwrap(),
        Vec::new(),
        "the drop leaves nothing in the plane's kind"
    );
    let life = read_row(&store, CHAIN_LIFE_SCHEMA, &life_key(INST, EV, "t1"))
        .await
        .unwrap()
        .expect("the drop raised the chain's life in the store");
    assert_eq!(life.as_slice(), 1u64.to_be_bytes().as_slice());
    append(&s, b"t1", b"|2|b").expect("the chain begun again takes its first record");
    let again = first("the chain begun again").await;
    assert_eq!(
        position_token(INST, EV, "t1", 0, &again),
        old,
        "the re-begun first record stands where the old one stood"
    );
    let now = busbar_kernel::store::now();
    assert!(
        !redeem_claim(
            &store,
            crate::host_records::CLAIM_KIND,
            &old,
            now.saturating_add(60)
        )
        .await
        .unwrap(),
        "the old life's claim on that position is still held, and was never needed"
    );
    assert_eq!(
        listed(&s, b"t1/"),
        vec![(record_of("t1", 1), b"|2|b".to_vec())],
        "a fresh chain at seq 1, verifying"
    );

    append(&s, b"t1", b"").unwrap();
    append(&s, b"t1", b"|3|c").expect("the third life takes its first record");
    assert_eq!(
        listed(&s, b"t1/"),
        vec![(record_of("t1", 1), b"|3|c".to_vec())]
    );
}

#[tokio::test]
async fn a_chain_dropped_on_one_node_is_begun_again_on_another() {
    let store = crate::real_store::core().await;
    let a = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    let b = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    append(&a, b"t1", b"|1|a").unwrap();
    append(&a, b"t1", b"|2|a").unwrap();
    append(&a, b"t1", b"").unwrap();
    append(&b, b"t1", b"|1|b").expect("node b begins the dropped chain again");
    append(&a, b"t1", b"|2|a").expect("node a continues node b's chain");
    assert_eq!(
        listed(&a, b"t1/"),
        vec![
            (record_of("t1", 1), b"|1|b".to_vec()),
            (record_of("t1", 2), b"|2|a".to_vec()),
        ],
        "one chain, begun again on b and continued on a, verifying"
    );
}

#[tokio::test]
async fn a_chained_kind_refuses_what_it_cannot_hold() {
    let (s, _store) = rig().await;
    for unfit in [&b""[..], b"\xff", record_of("t1", 1).as_slice()] {
        assert_eq!(
            append(&s, unfit, b"|1|a"),
            Err(crate::host_chains::CHAIN_SCOPE_UNFIT),
            "{unfit:?}"
        );
    }
    let room = busbar_contract::bounded::MAX_RECORD_BYTES - crate::host_chains::CHAIN_OVERHEAD;
    assert_eq!(
        append(&s, b"t1", &vec![b'x'; room + 1]),
        Err(crate::host_chains::CHAIN_RECORD_TOO_LARGE)
    );
    append(&s, b"t1", &vec![b'x'; room]).expect("the largest record that fits is kept");
    let slot: Arc<Mutex<Option<Stored>>> = Arc::default();
    let into = Arc::clone(&slot);
    let ran = s.records_get(
        &me(),
        EV.as_str(),
        b"t1",
        Box::new(move |st| *into.lock().unwrap() = Some(st)),
    );
    let Ran::Now(st) = ran else {
        panic!("a chained get is refused at once")
    };
    assert_eq!(
        (st.outcome, st.error),
        (Outcome::Refused, crate::host_chains::CHAIN_READ_WHOLE)
    );
}

#[tokio::test]
async fn two_instances_never_share_a_chain_and_an_undeclared_kind_is_not_chained() {
    let (s, store) = rig().await;
    s.admit(
        "other",
        InstanceFacts {
            record_kinds: vec![EV],
            record_chains: vec![RecordChain {
                kind: 0,
                framing: CHAIN_LENGTH_PREFIXED,
                flags: 0,
                _reserved: 0,
            }],
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    append(&s, b"ref", b"a").unwrap();
    let other = Caller {
        instance: Arc::from("other"),
        ..me()
    };
    let got: Answered = Arc::default();
    let into = Arc::clone(&got);
    s.record_write(
        &other,
        EV.as_str(),
        b"ref",
        RecordBytes::new(b"b".to_vec()).unwrap(),
        Box::new(move |r| *into.lock().unwrap() = Some(r)),
    )
    .unwrap();
    assert!(s.drain(Duration::from_secs(5)));
    assert_eq!(got.lock().unwrap().take(), Some(Ok(())));
    assert!(
        read_row(&store, EV, &stored_at("ref", 1))
            .await
            .unwrap()
            .is_some(),
        "this instance's first record"
    );
    assert!(
        read_row(&store, EV, &record_key("other", &record_of("ref", 1)))
            .await
            .unwrap()
            .is_some(),
        "the other instance's chain starts at 1 under its own label"
    );
    assert!(
        read_row(&store, EV, &stored_at("ref", 2))
            .await
            .unwrap()
            .is_none(),
        "the other instance's append never advanced this chain"
    );

    let plain = services_with_plain_kind(&store).await;
    let got: Answered = Arc::default();
    let into = Arc::clone(&got);
    plain
        .record_write(
            &me(),
            "plain",
            b"ref",
            RecordBytes::new(b"x".to_vec()).unwrap(),
            Box::new(move |r| *into.lock().unwrap() = Some(r)),
        )
        .unwrap();
    assert!(plain.drain(Duration::from_secs(5)));
    assert_eq!(got.lock().unwrap().take(), Some(Ok(())));
    assert!(read_row(
        &store,
        RecordSchemaId::new("plain"),
        &record_key(INST, b"ref")
    )
    .await
    .unwrap()
    .is_some());
}

async fn services_with_plain_kind(store: &Arc<CoreStore>) -> KernelServices {
    let s = KernelServices::new().with_pool(Arc::new(Inline));
    assert!(s.attach_persistence(store.clone()));
    s.admit(
        INST,
        InstanceFacts {
            record_kinds: vec![RecordSchemaId::new("plain")],
            ..InstanceFacts::default()
        },
    )
    .await
    .unwrap();
    s
}

#[tokio::test]
async fn two_nodes_appending_to_one_chain_continue_each_other_and_never_overwrite() {
    let store = crate::real_store::core().await;
    let a = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    let b = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    append(&a, b"t1", b"|1|a").unwrap();
    append(&b, b"t1", b"|2|b").unwrap();
    append(&a, b"t1", b"|3|a").unwrap();
    assert_eq!(
        listed(&a, b"t1/"),
        vec![
            (record_of("t1", 1), b"|1|a".to_vec()),
            (record_of("t1", 2), b"|2|b".to_vec()),
            (record_of("t1", 3), b"|3|a".to_vec()),
        ],
        "every node's record is kept, in one chain that verifies"
    );
}

#[tokio::test]
async fn malformed_persisted_chain_life_refuses_append_without_reinterpreting_it_as_genesis() {
    let (services, store) = rig().await;
    let key = crate::host_chains::life_key(INST, EV, "broken-life");
    put_row(
        &store,
        crate::host_chains::CHAIN_LIFE_SCHEMA,
        &key,
        &RecordBytes::new(vec![1]).unwrap(),
    )
    .await
    .unwrap();
    assert!(append(&services, b"broken-life", b"event").is_err());
    assert!(read_row(&store, EV, &stored_at("broken-life", 1))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        read_row(&store, crate::host_chains::CHAIN_LIFE_SCHEMA, &key)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        &[1]
    );
}

#[tokio::test]
async fn exhausted_chain_life_refuses_drop_without_deleting_its_records() {
    let (services, store) = rig().await;
    append(&services, b"last-life", b"event").unwrap();
    let key = crate::host_chains::life_key(INST, EV, "last-life");
    put_row(
        &store,
        crate::host_chains::CHAIN_LIFE_SCHEMA,
        &key,
        &RecordBytes::new(u64::MAX.to_be_bytes().to_vec()).unwrap(),
    )
    .await
    .unwrap();
    assert!(append(&services, b"last-life", b"").is_err());
    assert!(read_row(&store, EV, &stored_at("last-life", 1))
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        read_row(&store, crate::host_chains::CHAIN_LIFE_SCHEMA, &key)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        &u64::MAX.to_be_bytes()
    );
}

#[tokio::test]
async fn a_cached_writer_observes_a_remote_completed_drop() {
    let store = crate::real_store::core().await;
    let a = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    let b = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    append(&a, b"t1", b"|old").unwrap();
    append(&b, b"t1", b"").unwrap();
    append(&a, b"t1", b"|new").unwrap();
    assert_eq!(
        listed(&a, b"t1/"),
        vec![(record_of("t1", 1), b"|new".to_vec())]
    );
}

#[tokio::test]
async fn an_unreadable_occupied_tail_does_not_wedge_future_evidence() {
    let (s, store) = rig().await;
    append(&s, b"t1", b"|first").unwrap();
    put_row(
        &store,
        EV,
        &stored_at("t1", 2),
        &RecordBytes::new(vec![255]).unwrap(),
    )
    .await
    .unwrap();
    drop(s);
    let restarted = services_over(&store, CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE).await;
    append(&restarted, b"t1", b"|after unreadable").unwrap();
    assert_eq!(
        read_row(&store, EV, &stored_at("t1", 2))
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        &[255]
    );
    let read = listed(&restarted, b"t1/");
    assert_eq!(read[0].0, b"t1", "the sequence gap remains reported");
    assert_eq!(
        read.last(),
        Some(&(record_of("t1", 3), b"|after unreadable".to_vec()))
    );
}

#[tokio::test]
async fn an_unreadable_genesis_does_not_reuse_its_occupied_key() {
    let (s, store) = rig().await;
    put_row(
        &store,
        EV,
        &stored_at("t1", 1),
        &RecordBytes::new(vec![255]).unwrap(),
    )
    .await
    .unwrap();
    append(&s, b"t1", b"|after unreadable").unwrap();
    let read = listed(&s, b"t1/");
    assert_eq!(read[0].0, b"t1", "missing genesis remains reported");
    assert_eq!(
        read.last(),
        Some(&(record_of("t1", 2), b"|after unreadable".to_vec()))
    );
}
