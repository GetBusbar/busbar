// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §9 test 26 (a), and the handle protocol of §3.3: live pages are signed on the
//! notary signer thread, one at a time; checkpoint batches are one job on the Bootstrap thread,
//! one signature per body, the same bytes as the deployment key's checkpoint signature.

use std::sync::{Arc, Condvar, Mutex, OnceLock};

use busbar_contract::crypto::{LocalSigner, PublicKey, SignError, Signer};
use busbar_kernel_audit::{
    AuditSigningKey, AuditVerifyingKey, BootstrapSigner, Fingerprint, LiveSigner, Notary, Stamp,
    StampKind,
};

use crate::root::durability::signer::{spawn, SignFailure, Signers};

const SEED: [u8; 32] = [0x26; 32];
const DELEGATED: [u8; 32] = [0x62; 32];

#[tokio::test]
async fn bootstrap_thread_certifies_and_stages_the_exact_chain_position() {
    use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};
    use crate::root::durability::Durability;
    use busbar_kernel_audit::notary_key::notary_key_from_journal_body;
    let fixture = NativeFixture::new(41).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    Durability::seal_unit(&book, audit_inputs(1), audit_pass(), &token())
        .await
        .unwrap();
    let rig = rig(true);
    let live = LocalSigner::from_seed(&DELEGATED).unwrap();
    let bootstrap = LocalSigner::from_seed(&SEED).unwrap();
    let (node, seq, prev) = {
        let book = book.lock().unwrap();
        (
            book.record.node(),
            book.record.next_seq(),
            Fingerprint::from_hex(book.record.head()).unwrap(),
        )
    };
    let certificate = rig
        .signers
        .seal
        .submit_certificate(node, seq, prev, live.public_key().clone())
        .await
        .unwrap();
    let prepared =
        busbar_kernel_audit::AuditChain::prepare_notary_key(node, seq, prev, certificate);
    let (journal, record, run) = {
        let mut book = book.lock().unwrap();
        let (record, run) = book
            .stage_notary_key(prepared, &audit_pass(), &token())
            .unwrap();
        (book.journal.clone(), record, run)
    };
    record.verify(bootstrap.public_key()).unwrap();
    assert_eq!(run.records().len(), 1);
    let row = &run.records()[0];
    assert_eq!(
        notary_key_from_journal_body(&row.body).unwrap(),
        Some(record.clone())
    );
    journal.confirm(&run).await.unwrap();
    // Confirmation of the original stage is idempotent; retries must not append certificates.
    journal.confirm(&run).await.unwrap();
    Durability::seal_unit(&book, audit_inputs(3), audit_pass(), &token())
        .await
        .unwrap();
    let book = book.lock().unwrap();
    assert_eq!(book.record.next_seq(), seq + 2);
    assert_eq!(
        book.audit_records().last().unwrap().prev_hash,
        record.fingerprint.to_string()
    );
}

/// A delegated live signer that records the thread each sign runs on, and can hold a sign until
/// released.
struct Recording {
    inner: LocalSigner,
    threads: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl Signer for Recording {
    fn public_key(&self) -> &PublicKey {
        self.inner.public_key()
    }
    fn sign(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), SignError> {
        self.threads.lock().unwrap().push(
            std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_owned(),
        );
        let (open, ready) = &*self.gate;
        let mut open = open.lock().unwrap();
        while !*open {
            open = ready.wait(open).unwrap();
        }
        self.inner.sign(msg, out)
    }
}

struct Rig {
    signers: Signers,
    threads: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

fn rig(open: bool) -> Rig {
    let threads = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new((Mutex::new(open), Condvar::new()));
    let delegated = Recording {
        inner: LocalSigner::from_seed(&DELEGATED).unwrap(),
        threads: Arc::clone(&threads),
        gate: Arc::clone(&gate),
    };
    let (notary, bootstrap) = AuditSigningKey::from_seed(&SEED)
        .into_grants(LiveSigner::Delegated(Box::new(delegated)))
        .unwrap();
    let signers = spawn(
        Notary::new(notary),
        BootstrapSigner::new(bootstrap),
        Arc::new(OnceLock::new()),
    )
    .unwrap();
    Rig {
        signers,
        threads,
        gate,
    }
}

fn open(gate: &(Mutex<bool>, Condvar)) {
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
}

fn live_page(to: u64) -> Stamp {
    Stamp {
        node: 9,
        from: 1,
        to,
        fingerprint: Fingerprint([7; 32]),
        kind: StampKind::Live,
        sealer: 9,
        host: "signer-test-host".into(),
        every: 1,
        stamped_ms: 1_700_000_000_000,
        down_from_ms: 0,
        down_to_ms: 0,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 3,
        signature: Vec::new(),
    }
}

/// Test 26 (a): a live sign runs on `busbar-notary-signer`, never on the submitting runtime, and
/// the page verifies under the delegated key it names.
#[tokio::test]
async fn live_signs_run_on_the_notary_signer_thread() {
    let rig = rig(true);
    let signed = rig
        .signers
        .live
        .submit(live_page(5))
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *rig.threads.lock().unwrap(),
        vec!["busbar-notary-signer".to_owned()]
    );
    let public = LocalSigner::from_seed(&DELEGATED).unwrap();
    let key = AuditVerifyingKey::from_hex(&hex::encode(&public.public_key().bytes)).unwrap();
    assert_eq!(signed.key_id, key.key_id());
    assert_eq!(
        signed.key_cert, 3,
        "the caller's certificate position is kept"
    );
    signed.verify(&key).expect("the live page verifies");
    assert!(
        !rig.signers.live.busy(),
        "the thread clears busy before it replies"
    );
}

/// One live sign at a time: a second submit while the first is on the thread is refused at once,
/// and nothing is queued.
#[tokio::test]
async fn a_second_live_submit_while_busy_is_refused() {
    let rig = rig(false);
    let first = rig.signers.live.submit(live_page(1)).unwrap();
    assert!(rig.signers.live.busy());
    assert_eq!(
        rig.signers.live.submit(live_page(2)).err(),
        Some(SignFailure::Busy)
    );
    open(&rig.gate);
    first.await.unwrap().expect("the held sign completes");
    assert_eq!(
        rig.threads.lock().unwrap().len(),
        1,
        "the refused page never reached the thread"
    );
}

/// A checkpoint batch is one job on the Bootstrap thread: one signature per body, in order, the
/// same bytes the deployment key's checkpoint signature has (a later boot verifies them as today).
#[tokio::test]
async fn checkpoint_batch_is_one_job_with_one_signature_per_body() {
    let rig = rig(true);
    let bodies: [&[u8]; 3] = [b"unit-a", b"unit-b", b"unit-c"];
    let signatures = rig
        .signers
        .checkpoint
        .sign_checkpoints(&bodies)
        .await
        .unwrap();
    let key = AuditSigningKey::from_seed(&SEED);
    assert_eq!(signatures.len(), 3);
    for (body, signature) in bodies.iter().zip(&signatures) {
        assert_eq!(*signature, key.sign_checkpoint_body(body));
    }
    assert!(
        rig.threads.lock().unwrap().is_empty(),
        "checkpoints never touch the live (delegated) signer"
    );
    assert!(!rig.signers.threads.bootstrap_finished());
    assert!(!rig.signers.threads.live_finished());
}
