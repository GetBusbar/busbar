// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[derive(Default)]
struct RetryRows {
    records: Mutex<BTreeMap<(String, Vec<u8>), RecordBytes>>,
    claims: Mutex<BTreeMap<String, u64>>,
    claim_calls: std::sync::atomic::AtomicUsize,
    fail_put: std::sync::atomic::AtomicBool,
}

impl RecordRows for RetryRows {
    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), busbar_contract::kinds::StoreError> {
        if self
            .fail_put
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(busbar_contract::kinds::StoreError::Unavailable);
        }
        let mut records = self.records.lock().unwrap();
        let key = (schema.as_str().to_string(), key.to_vec());
        if value.as_slice().is_empty() {
            records.remove(&key);
        } else {
            records.insert(key, RecordBytes::new(value.as_slice().to_vec()).unwrap());
        }
        Ok(())
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, busbar_contract::kinds::StoreError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .get(&(schema.as_str().to_string(), key.to_vec()))
            .map(|value| RecordBytes::new(value.as_slice().to_vec()).unwrap()))
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, busbar_contract::kinds::StoreError> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|((kind, key), _)| kind == schema.as_str() && key.starts_with(prefix))
            .take(limit as usize)
            .map(|((_, key), value)| {
                (
                    key.clone(),
                    RecordBytes::new(value.as_slice().to_vec()).unwrap(),
                )
            })
            .collect())
    }

    fn claim(
        &self,
        _kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, busbar_contract::kinds::StoreError> {
        self.claim_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut claims = self.claims.lock().unwrap();
        claims.retain(|_, expires| *expires > now);
        match claims.entry(token.to_string()) {
            std::collections::btree_map::Entry::Occupied(_) => Ok(false),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(expires_at);
                Ok(true)
            }
        }
    }
}

#[test]
fn a_losing_claim_leaves_the_winners_expiry_unchanged() {
    let rows = RetryRows::default();
    assert!(rows.claim(CLAIM_KIND, "token", 100, 1).unwrap());
    assert!(!rows.claim(CLAIM_KIND, "token", 200, 2).unwrap());
    assert_eq!(rows.claims.lock().unwrap().get("token"), Some(&100));
    assert!(rows.claim(CLAIM_KIND, "token", 300, 100).unwrap());
}

#[test]
fn a_failed_put_can_retry_under_its_live_claim() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .is_err());
    book.append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .unwrap();
    assert_eq!(
        rows.claim_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(rows.record_scan(EV, b"", u32::MAX).unwrap().len(), 1);
}

#[test]
fn a_mismatched_body_sequence_cannot_reposition_before_an_occupied_key() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    let (record, _) = sealed();
    let body = RecordBytes::new(encode(&record).unwrap()).unwrap();
    rows.record_put(
        EV,
        &record_key(&instance, &chain_key(SCOPE.as_bytes(), 9)),
        &body,
    )
    .unwrap();
    book.append(&rows, &instance, EV, SCOPE, b"after mismatch", LP_SCOPED)
        .unwrap();
    let next = rows
        .record_get(EV, &record_key(&instance, &chain_key(SCOPE.as_bytes(), 10)))
        .unwrap()
        .expect("continue beyond the occupied key");
    let next = decode(SCOPE, next.as_slice(), LP_SCOPED).unwrap();
    assert_eq!(next.seq(), 10);
    assert_eq!(next.prev_hash(), record.hash());
    assert_eq!(rows.record_scan(EV, b"", u32::MAX).unwrap().len(), 2);
}

#[test]
fn a_failed_drop_preserves_the_still_live_failed_write_claim() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .is_err());
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book.drop_chain(&rows, &instance, EV, SCOPE).is_err());
    book.append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .unwrap();
    assert_eq!(
        rows.claim_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(rows.record_scan(EV, b"", u32::MAX).unwrap().len(), 1);
}

#[test]
fn a_retained_claim_expires_at_its_exact_deadline() {
    let book = ChainBook::default();
    let at = (
        Arc::from("inst"),
        EV.as_str().to_string(),
        SCOPE.to_string(),
    );
    book.hold(&at, "token".to_string(), 100);
    assert_eq!(book.holds(&at, "token", 99), Some(100));
    assert_eq!(book.holds(&at, "token", 100), None);
    assert!(book.claimed.lock().unwrap().is_empty());
}

#[test]
fn expired_retry_does_not_bypass_a_renewed_store_claim() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .is_err());

    for held in book.claimed.lock().unwrap().values_mut() {
        held.expires_at = 0;
    }
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .is_err());
    assert!(rows.record_scan(EV, b"", u32::MAX).unwrap().is_empty());
    assert_eq!(
        rows.claim_calls.load(std::sync::atomic::Ordering::SeqCst),
        1 + CLAIM_ATTEMPTS
    );
    assert!(book.claimed.lock().unwrap().is_empty());
}

#[test]
fn abandoned_and_dropped_positions_retire_only_local_retry_custody() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .is_err());
    assert_eq!(book.claimed.lock().unwrap().len(), 1);

    let (record, _) = sealed();
    rows.record_put(
        EV,
        &record_key(&instance, &chain_key(SCOPE.as_bytes(), 1)),
        &RecordBytes::new(encode(&record).unwrap()).unwrap(),
    )
    .unwrap();
    book.append(&rows, &instance, EV, SCOPE, b"event", LP_SCOPED)
        .unwrap();
    assert!(book.claimed.lock().unwrap().is_empty());
    rows.fail_put
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(book
        .append(&rows, &instance, EV, SCOPE, b"next", LP_SCOPED)
        .is_err());
    assert_eq!(book.claimed.lock().unwrap().len(), 1);
    let store_claims = rows.claims.lock().unwrap().clone();
    book.drop_chain(&rows, &instance, EV, SCOPE).unwrap();
    assert!(book.claimed.lock().unwrap().is_empty());
    assert_eq!(
        *rows.claims.lock().unwrap(),
        store_claims,
        "retirement never edits the store's claims"
    );
}

const SCOPE: &str = "a11ce/task-1";

fn own(ts: u64, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(&ts.to_be_bytes());
    for f in fields {
        field(f.as_bytes());
    }
    out
}

fn own_1() -> Vec<u8> {
    own(
        1_700_000_000,
        &["task.submitted", "ctx-1", "a11ce", "planner", "submitted"],
    )
}

fn own_2() -> Vec<u8> {
    own(
        1_700_000_060,
        &["task.working", "ctx-1", "a11ce", "planner", "working"],
    )
}

const LP_SCOPED: ChainFraming = ChainFraming {
    framing: Framing::LengthPrefixed,
    digests_scope: true,
};

const EV: RecordSchemaId = RecordSchemaId::new("ev");

fn sealed() -> (StreamRecord, StreamRecord) {
    let mut chain = Chain::<StreamRecord>::new();
    let input = |b: Vec<u8>| StreamInput::new(b, Framing::LengthPrefixed, true);
    let e1 = chain.append(SCOPE, input(own_1()));
    let e2 = chain.append(SCOPE, input(own_2()));
    (e1, e2)
}

fn stored() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (e1, e2) = sealed();
    vec![
        (chain_key(SCOPE.as_bytes(), 1), encode(&e1).unwrap()),
        (chain_key(SCOPE.as_bytes(), 2), encode(&e2).unwrap()),
    ]
}

#[test]
fn the_host_seals_the_length_prefixed_prelude_and_the_planes_bytes() {
    let (e1, e2) = sealed();
    let expect = |prev: &str, seq: u64, own: &[u8]| {
        let mut input = Vec::new();
        let seq = seq.to_be_bytes();
        for f in [prev.as_bytes(), SCOPE.as_bytes(), &seq[..]] {
            input.extend_from_slice(&(f.len() as u64).to_be_bytes());
            input.extend_from_slice(f);
        }
        input.extend_from_slice(own);
        busbar_contract::redacted::sha256_hex(&input)
    };
    assert_eq!(e1.hash(), expect("", 1, &own_1()));
    assert_eq!(e2.hash(), expect(e1.hash(), 2, &own_2()));
    verify_chain(&[e1, e2]).expect("the sealed chain verifies");
}

#[test]
fn a_read_of_a_sealed_chain_reports_no_tamper() {
    assert_eq!(
        verified("inst", EV, stored(), LP_SCOPED),
        vec![
            (chain_key(SCOPE.as_bytes(), 1), own_1()),
            (chain_key(SCOPE.as_bytes(), 2), own_2()),
        ],
        "a persisted chain reported TAMPERED means the host's framing drifted"
    );
}

#[test]
fn one_undecodable_record_does_not_drop_the_others() {
    let mut rows = stored();
    rows[1].0 = chain_key(SCOPE.as_bytes(), 3);
    rows.push((chain_key(SCOPE.as_bytes(), 2), b"{not an event".to_vec()));
    assert_eq!(
        verified("inst", EV, rows, LP_SCOPED),
        vec![
            (chain_key(SCOPE.as_bytes(), 1), own_1()),
            (chain_key(SCOPE.as_bytes(), 3), own_2()),
        ],
        "the undecodable record is skipped, the surviving chain intact"
    );
}

#[test]
fn the_verifier_detects_a_tampered_link_in_the_persisted_chain() {
    let mut rows = stored();
    let (_, e2) = sealed();
    let edited = StreamRecord::from_parts(
        SCOPE.into(),
        2,
        e2.prev_hash().into(),
        e2.hash().into(),
        own(
            1_700_000_060,
            &[
                "task.working",
                "ctx-1",
                "a11ce",
                "attacker-agent",
                "working",
            ],
        ),
        Framing::LengthPrefixed,
        true,
    );
    rows[1].1 = encode(&edited).unwrap();
    let read = verified("inst", EV, rows, LP_SCOPED);
    assert_eq!(read[0].0, SCOPE.as_bytes(), "the broken chain is named");
    let words = String::from_utf8(read[0].1.clone()).unwrap();
    assert!(
        words.contains("seq 2"),
        "the verifier names WHICH record: {words}"
    );
    assert!(words.contains("EDITED"), "an in-place edit: {words}");
    assert_eq!(read.len(), 3, "and both records are still answered");
}

#[test]
fn a_relinked_record_is_a_link_break() {
    let mut rows = stored();
    let (_, e2) = sealed();
    let relinked = StreamRecord::from_parts(
        SCOPE.into(),
        2,
        e2.hash().into(),
        e2.hash().into(),
        own_2(),
        Framing::LengthPrefixed,
        true,
    );
    rows[1].1 = encode(&relinked).unwrap();
    let read = verified("inst", EV, rows, LP_SCOPED);
    let words = String::from_utf8(read[0].1.clone()).unwrap();
    assert!(words.contains("prev_hash"), "{words}");
}

#[test]
fn a_stored_body_round_trips_and_a_foreign_one_is_none() {
    let (e1, e2) = sealed();
    let body = encode(&e2).unwrap();
    assert!(body.len() <= CHAIN_OVERHEAD + own_2().len());
    let back = decode(SCOPE, &body, LP_SCOPED).unwrap();
    assert_eq!(
        (back.seq(), back.prev_hash(), back.hash(), back.content()),
        (2, e1.hash(), e2.hash(), own_2().as_slice())
    );
    let mut foreign = body.clone();
    foreign[0] = 2;
    assert!(decode(SCOPE, &foreign, LP_SCOPED).is_none());
    assert!(decode(SCOPE, &body[..20], LP_SCOPED).is_none());
    assert!(decode(SCOPE, b"", LP_SCOPED).is_none());
}

#[test]
fn the_declaration_names_its_framing() {
    let chain = |framing, flags| RecordChain {
        kind: 0,
        framing,
        flags,
        _reserved: 0,
    };
    assert_eq!(
        ChainFraming::of(&chain(CHAIN_LENGTH_PREFIXED, CHAIN_DIGESTS_SCOPE)),
        Some(LP_SCOPED)
    );
    assert_eq!(
        ChainFraming::of(&chain(CHAIN_PIPE_SEPARATED, 0)),
        Some(ChainFraming {
            framing: Framing::PipeSeparated,
            digests_scope: false,
        })
    );
    assert_eq!(ChainFraming::of(&chain(0, 0)), None);
    assert_eq!(ChainFraming::of(&chain(CHAIN_PIPE_SEPARATED, 2)), None);
}

#[test]
fn a_scope_is_never_a_record_key() {
    assert_eq!(scope_of(b"a11ce/t1"), Some("a11ce/t1"));
    assert_eq!(scope_of(b""), None);
    assert_eq!(scope_of(b"\xff"), None);
    assert_eq!(scope_of(&chain_key(b"t1", 1)), None);
}
