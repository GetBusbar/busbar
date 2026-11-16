// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::crypto::{LocalSigner, Signer};
use busbar_kernel_audit::notary_key::{
    notary_key_body, notary_key_from_journal_body, NotaryKeyRecord,
};
use busbar_kernel_audit::{AuditSigningKey, BootstrapSigner, Fingerprint, LiveSigner};

fn fixture() -> (NotaryKeyRecord, LocalSigner) {
    let key = AuditSigningKey::from_seed(&[7; 32]);
    let (_, grant) = key.into_grants(LiveSigner::SameAsBootstrap).unwrap();
    let bootstrap = BootstrapSigner::new(grant);
    let live = LocalSigner::from_seed(&[9; 32]).unwrap();
    let certificate = bootstrap
        .sign_notary_key(11, 1, Fingerprint::ZERO, live.public_key())
        .unwrap();
    let mut record = NotaryKeyRecord {
        node: 11,
        seq: 1,
        linked_ms: 123,
        prev_link: Fingerprint::ZERO,
        fingerprint: Fingerprint::ZERO,
        certificate,
    };
    record.fingerprint = record.recompute_fingerprint();
    (record, LocalSigner::from_seed(&[7; 32]).unwrap())
}

#[test]
fn bootstrap_certificate_round_trips_and_binds_node_sequence_and_predecessor() {
    let (record, bootstrap) = fixture();
    record.verify(bootstrap.public_key()).unwrap();
    let body = notary_key_body(&record).unwrap();
    assert_eq!(
        notary_key_from_journal_body(&body).unwrap(),
        Some(record.clone())
    );
    for field in 0..3 {
        let mut relocated = record.clone();
        match field {
            0 => relocated.node += 1,
            1 => relocated.seq += 1,
            _ => relocated.prev_link = Fingerprint([3; 32]),
        }
        relocated.fingerprint = relocated.recompute_fingerprint();
        assert!(relocated.verify(bootstrap.public_key()).is_err());
    }
    let other = LocalSigner::from_seed(&[10; 32]).unwrap();
    assert!(record.verify(other.public_key()).is_err());
}

#[test]
fn certificate_codec_refuses_truncation_trailing_data_and_corruption() {
    let (record, bootstrap) = fixture();
    let body = notary_key_body(&record).unwrap();
    // Once the complete recognized tag is present, every truncated body is malformed.
    let tag_end = 4 + "audit.notary_key.v2".len();
    for end in tag_end..body.len() {
        assert!(
            notary_key_from_journal_body(&body[..end]).is_err(),
            "end {end}"
        );
    }
    let mut trailing = body;
    trailing.push(0);
    assert!(notary_key_from_journal_body(&trailing).is_err());
    let mut changed = record.clone();
    changed.linked_ms += 1;
    assert!(changed.verify(bootstrap.public_key()).is_err());
    changed = record.clone();
    changed.certificate.signature[0] ^= 1;
    changed.fingerprint = changed.recompute_fingerprint();
    assert!(changed.verify(bootstrap.public_key()).is_err());
    changed = record;
    changed.certificate.key_id = "0000000000000000".into();
    changed.fingerprint = changed.recompute_fingerprint();
    assert!(notary_key_from_journal_body(&notary_key_body(&changed).unwrap()).is_err());
}

#[test]
fn signature_preimage_has_literal_v2_framing() {
    let (record, _) = fixture();
    // Independent literal framing rather than calling a production frame helper.
    let mut expected = b"busbar.audit.notary_key.v2\0".to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 11]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 32]);
    expected.extend_from_slice(&[0; 32]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 16]);
    expected.extend_from_slice(record.certificate.key_id.as_bytes());
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
    expected.extend_from_slice(b"ed25519");
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 32]);
    expected.extend_from_slice(&record.certificate.public_key);
    assert_eq!(
        record
            .certificate
            .preimage(record.node, record.seq, record.prev_link),
        expected
    );
}

#[test]
fn shared_linked_reader_and_head_preserve_certificate_positions() {
    use busbar_kernel_audit::linked_record::{
        linked_record_from_journal_body, verify_linked_chain, verify_linked_window,
        AuditLinkedRecord,
    };
    let (record, _) = fixture();
    let body = notary_key_body(&record).unwrap();
    let parsed = linked_record_from_journal_body(&body, &|_| None)
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed,
        AuditLinkedRecord::NotaryKey(Box::new(record.clone()))
    );
    assert_eq!(parsed.node(), record.node);
    assert_eq!(parsed.chain_seq(), record.seq);
    assert_eq!(parsed.fingerprint().unwrap(), record.fingerprint);
    verify_linked_chain(std::slice::from_ref(&parsed)).unwrap();
    let mut later = record.clone();
    later.seq = 2;
    later.prev_link = record.fingerprint;
    later.fingerprint = later.recompute_fingerprint();
    // Chain integrity is intentionally separate from Bootstrap certificate authentication.
    let later = AuditLinkedRecord::NotaryKey(Box::new(later));
    verify_linked_chain(&[parsed.clone(), later.clone()]).unwrap();
    assert!(verify_linked_chain(std::slice::from_ref(&later)).is_err());
    verify_linked_window(std::slice::from_ref(&later)).unwrap();
    assert!(verify_linked_window(&[later, parsed]).is_err());
    let head = busbar_kernel_audit::head_from_journal_body(&body)
        .unwrap()
        .unwrap();
    assert_eq!(head.node, record.node);
    assert_eq!(head.head.seq, record.seq);
    assert_eq!(head.head.hash, record.fingerprint.to_string());
    assert_eq!(head.prev_hash, "");
}
