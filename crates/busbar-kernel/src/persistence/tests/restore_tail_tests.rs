// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 §B10.3: the tail's canonical encoding and digest (R20's encoding half).

use super::*;
use busbar_kernel_wal::journal::{body_digest, RecordClass};

/// Record `node_seq` of `node`, chained onto `prev`, sealed the way the store journal seals.
fn sealed(node: u64, node_seq: u64, prev: [u8; 32]) -> JournalRecord {
    let body = vec![node as u8, node_seq as u8];
    let mut record = JournalRecord {
        class: RecordClass::Transaction,
        node,
        node_seq,
        lease_epoch: 1,
        policy_epoch: 1,
        wall: 1_800_000_000 + node_seq,
        mono: node_seq,
        body_hash: body_digest(&body),
        body,
        prev_hash: prev,
        hash: [0u8; 32],
    };
    record.hash = record.digest_of_chain();
    record
}

fn chain(node: u64, first: u64, len: u64) -> NodeChain {
    let mut prev = [0u8; 32];
    let records = (first..first + len)
        .map(|seq| {
            let record = sealed(node, seq, prev);
            prev = record.hash;
            record
        })
        .collect();
    NodeChain { node, records }
}

fn two_nodes() -> Tail {
    Tail {
        chains: vec![chain(3, 5, 2), chain(9, 1, 3)],
    }
}

#[test]
fn a_tail_round_trips_through_its_canonical_encoding() {
    let tail = two_nodes();
    let bytes = encode(&tail);
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(decode(&bytes), Ok(tail));
}

#[test]
fn the_digest_is_of_the_canonical_bytes_and_domain_separated() {
    let bytes = encode(&two_nodes());
    assert_eq!(digest(&bytes), digest(&bytes.clone()));
    assert_ne!(
        digest(&bytes),
        busbar_contract::abi::sdk::digest::sha256(&bytes)
    );
    let mut other = two_nodes();
    other.chains.pop();
    assert_ne!(digest(&encode(&other)), digest(&bytes));
}

#[test]
fn every_non_canonical_tail_is_refused() {
    let good = encode(&two_nodes());
    // Trailing bytes, a wrong magic, a truncation.
    let mut refused: Vec<Vec<u8>> = vec![
        [good.clone(), vec![0]].concat(),
        [b"BSRT2\0\0\0".as_slice(), &good[8..]].concat(),
        good[..good.len() - 1].to_vec(),
    ];
    // Nodes out of order, a duplicate node, an empty chain.
    refused.push(encode(&Tail {
        chains: vec![chain(9, 1, 1), chain(3, 1, 1)],
    }));
    refused.push(encode(&Tail {
        chains: vec![chain(3, 1, 1), chain(3, 2, 1)],
    }));
    refused.push(encode(&Tail {
        chains: vec![NodeChain {
            node: 3,
            records: Vec::new(),
        }],
    }));
    // A record of another node, records out of order.
    let mut foreign = chain(3, 1, 1);
    foreign.records[0] = sealed(4, 1, [0u8; 32]);
    refused.push(encode(&Tail {
        chains: vec![foreign],
    }));
    let mut reversed = chain(3, 1, 2);
    reversed.records.reverse();
    refused.push(encode(&Tail {
        chains: vec![reversed],
    }));
    for bytes in refused {
        assert_eq!(decode(&bytes), Err(TailError::Encoding));
    }
}

#[test]
fn a_tail_over_the_limit_is_too_large() {
    let bytes = vec![0u8; MAX_RESTORE_TAIL_BYTES + 1];
    assert_eq!(decode(&bytes), Err(TailError::TooLarge));
    assert_eq!(TailError::TooLarge.reason(), "restore_tail_too_large");
    assert_eq!(TailError::Encoding.reason(), "tail_encoding_invalid");
}

fn chain_from(node: u64, first: u64, mut prev: [u8; 32], len: u64) -> NodeChain {
    let records = (first..first + len)
        .map(|seq| {
            let record = sealed(node, seq, prev);
            prev = record.hash;
            record
        })
        .collect();
    NodeChain { node, records }
}

/// DES-331 §B3.1: node 3 existed at the backup (its restored head is record 4); node 9 was born after it.
#[test]
fn each_chain_continues_from_its_restored_head_or_from_genesis() {
    let restored = sealed(3, 4, [7u8; 32]).hash;
    let heads = std::collections::BTreeMap::from([(3, (4, restored))]);
    let good = Tail {
        chains: vec![
            chain_from(3, 5, restored, 2),
            chain_from(9, 1, [0u8; 32], 3),
        ],
    };
    assert_eq!(verify_continuity(&good, &heads), Ok(()));

    let broken = |chains: Vec<NodeChain>, node: u64| {
        assert_eq!(
            verify_continuity(&Tail { chains }, &heads),
            Err(VerifyError::ChainBroken { node })
        );
    };
    // A gap after the restored head, the wrong predecessor, a post-backup node not from genesis.
    broken(vec![chain_from(3, 6, restored, 1)], 3);
    broken(vec![chain_from(3, 5, [1u8; 32], 1)], 3);
    broken(vec![chain_from(9, 2, [0u8; 32], 1)], 9);
    // A link broken inside the chain.
    let mut cut = chain_from(3, 5, restored, 3);
    cut.records[2].prev_hash = [2u8; 32];
    cut.records[2].hash = cut.records[2].digest_of_chain();
    broken(vec![cut], 3);
    assert_eq!(
        VerifyError::ChainBroken { node: 3 }.reason(),
        "tail_chain_broken"
    );
}

/// Record `node_seq` of `node` carrying `body`, chained onto `prev`.
fn carrying(node: u64, node_seq: u64, prev: [u8; 32], body: Vec<u8>) -> JournalRecord {
    let mut record = sealed(node, node_seq, prev);
    record.body_hash = body_digest(&body);
    record.body = body;
    record.hash = record.digest_of_chain();
    record
}

/// The deployment Bootstrap key (an audit signing key and the same seed as a seam signer).
fn bootstrap_key() -> busbar_kernel_audit::AuditSigningKey {
    busbar_kernel_audit::AuditSigningKey::from_seed(&[42; 32])
}

fn trusted() -> AuditVerifyingKey {
    AuditVerifyingKey::from_hex(&bootstrap_key().public_key_hex()).unwrap()
}

/// A `notary_key` v2 certificate line of `node` at chain `seq` after `prev`, signed by the
/// Bootstrap seed `by`.
fn cert_line(node: u64, seq: u64, prev: Fingerprint, by: [u8; 32]) -> NotaryKeyRecord {
    use busbar_contract::crypto::{LocalSigner, Signer};
    let signer = LocalSigner::from_seed(&by).unwrap();
    let delegate = LocalSigner::from_seed(&[9; 32]).unwrap();
    let public = delegate.public_key();
    let mut certificate = busbar_kernel_audit::NotaryKeyCertificate {
        key_id: public.key_id.to_string(),
        sig_alg: public.alg.as_str().to_owned(),
        public_key: public.bytes.to_vec(),
        signed_by: signer.public_key().key_id.to_string(),
        signature: Vec::new(),
    };
    signer
        .sign(
            &certificate.preimage(node, seq, prev),
            &mut certificate.signature,
        )
        .unwrap();
    let mut record = NotaryKeyRecord {
        node,
        seq,
        linked_ms: 1_700_000_000_000,
        prev_link: prev,
        fingerprint: Fingerprint::ZERO,
        certificate,
    };
    record.fingerprint = record.recompute_fingerprint();
    record
}

/// A live page of `node` over chain `from ..= to` ending at `endpoint`, signed under the Bootstrap
/// key, after `edit` changes it (a tamper lands after the signature).
fn signed_page(
    node: u64,
    from: u64,
    to: u64,
    endpoint: Fingerprint,
    edit: impl FnOnce(&mut Stamp),
) -> Vec<u8> {
    let (notary, _) = bootstrap_key()
        .into_grants(busbar_kernel_audit::LiveSigner::SameAsBootstrap)
        .unwrap();
    let mut stamp = busbar_kernel_audit::Notary::new(notary)
        .sign_stamp(Stamp {
            node,
            from,
            to,
            fingerprint: endpoint,
            kind: busbar_kernel_audit::StampKind::Live,
            sealer: node,
            host: "host-a".into(),
            every: 1,
            stamped_ms: 1_700_000_000_001,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: String::new(),
            sig_alg: String::new(),
            key_id: String::new(),
            key_cert: 0,
            signature: Vec::new(),
        })
        .unwrap();
    edit(&mut stamp);
    busbar_kernel_audit::stamp_body(&stamp).unwrap()
}

/// Node 3, born after the backup: three certificate lines (journal records 1..=3, chain 1..=3)
/// and a stamp over chain `1 ..= sealed_to` (journal record 4), signed by `by`.
fn sealed_chain(by: [u8; 32], sealed_to: u64, edit: impl FnOnce(&mut Stamp)) -> Tail {
    let mut certs = Vec::new();
    let mut prev = Fingerprint::ZERO;
    for seq in 1..=3 {
        let cert = cert_line(3, seq, prev, by);
        prev = cert.fingerprint;
        certs.push(cert);
    }
    let mut records = Vec::new();
    let mut hash = [0u8; 32];
    for (index, cert) in certs.iter().enumerate() {
        let body = busbar_kernel_audit::notary_key::notary_key_body(cert).unwrap();
        let record = carrying(3, index as u64 + 1, hash, body);
        hash = record.hash;
        records.push(record);
    }
    let endpoint = certs[sealed_to as usize - 1].fingerprint;
    records.push(carrying(
        3,
        4,
        hash,
        signed_page(3, 1, sealed_to, endpoint, edit),
    ));
    Tail {
        chains: vec![NodeChain { node: 3, records }],
    }
}

/// DES-331 §B3.1: every notary v2 seal verifies under the one Bootstrap key, through the audit
/// verifier's own rules.
#[test]
fn the_tail_seals_verify_under_the_bootstrap_key() {
    let verdicts = verify_seals(
        &sealed_chain([42; 32], 3, |_| {}),
        &trusted(),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(verdicts[&3].last_sealed, 3);
    assert_eq!(verdicts[&3].authenticated_records, 3);
}

#[test]
fn a_tampered_stamp_is_tail_seal_invalid() {
    let error = verify_seals(
        &sealed_chain([42; 32], 3, |stamp| stamp.host = "rewritten".into()),
        &trusted(),
        &BTreeMap::new(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        VerifyError::SealInvalid {
            node: 3,
            why: "a stamp signature is invalid"
        }
    );
    assert_eq!(error.reason(), "tail_seal_invalid");
}

#[test]
fn a_chain_that_does_not_end_at_a_sealed_line_is_tail_unsealed_end() {
    let error = verify_seals(
        &sealed_chain([42; 32], 2, |_| {}),
        &trusted(),
        &BTreeMap::new(),
    )
    .unwrap_err();
    assert_eq!(error, VerifyError::UnsealedEnd { node: 3 });
    assert_eq!(error.reason(), "tail_unsealed_end");
}

#[test]
fn the_tail_reaches_every_witnessed_node() {
    let tail = sealed_chain([42; 32], 3, |_| {});
    let head = tail.chains[0].records[3].hash;
    let none = BTreeMap::new();
    let entry = |node, node_seq, hash| WitnessEntry {
        node,
        node_seq,
        hash,
    };
    assert_eq!(verify_reach(&tail, &none, &[entry(3, 4, head)]), Ok(()));
    // A witnessed node with no chain, a chain short of its witnessed position, another history.
    assert_eq!(
        verify_reach(&tail, &none, &[entry(5, 1, head)]),
        Err(VerifyError::MissingChain { node: 5 })
    );
    assert_eq!(
        verify_reach(&tail, &none, &[entry(3, 9, head)]),
        Err(VerifyError::MissingChain { node: 3 })
    );
    assert_eq!(
        verify_reach(&tail, &none, &[entry(3, 4, [1u8; 32])]),
        Err(VerifyError::ChainBroken { node: 3 })
    );
    // An entry the restored head already covers needs no chain.
    let heads = BTreeMap::from([(5, (7, [2u8; 32]))]);
    assert_eq!(verify_reach(&tail, &heads, &[entry(5, 7, head)]), Ok(()));
    assert_eq!(
        VerifyError::MissingChain { node: 5 }.reason(),
        "tail_missing_chain"
    );
}

/// R19's verification half: the checks run in order and answer the digest, covered nodes and
/// bridges the declaration would commit.
#[test]
fn verify_tail_runs_every_check_and_reports_the_bridges() {
    let tail = sealed_chain([42; 32], 3, |_| {});
    let bytes = encode(&tail);
    let head = tail.chains[0].records[3].hash;
    let none = BTreeMap::new();
    let no_certs = RestoredCerts::new();
    let verified = verify_tail(&bytes, &none, &no_certs, &[], &trusted()).unwrap();
    assert_eq!(verified.tail_digest, digest(&bytes));
    assert_eq!(verified.covered_nodes, vec![3]);
    assert_eq!(
        verified.bridges,
        vec![Bridge {
            node: 3,
            restored: None,
            pre_restore: (4, head),
        }]
    );
    assert_eq!(verified.tail, tail);

    assert_eq!(
        verify_tail(&bytes[..bytes.len() - 1], &none, &no_certs, &[], &trusted())
            .unwrap_err()
            .reason(),
        "tail_encoding_invalid"
    );
    // A stamp field rewritten after signing, then a chain that does not continue its restored head.
    let other = encode(&sealed_chain([42; 32], 3, |stamp| stamp.every = 2));
    assert_eq!(
        verify_tail(&other, &none, &no_certs, &[], &trusted())
            .unwrap_err()
            .reason(),
        "tail_seal_invalid"
    );
    let heads = BTreeMap::from([(3, (1, [3u8; 32]))]);
    assert_eq!(
        verify_tail(&bytes, &heads, &no_certs, &[], &trusted())
            .unwrap_err()
            .reason(),
        "tail_chain_broken"
    );
}

/// R20: chunks assemble in order into the canonical bytes, independent of the chunk boundaries;
/// a digest mismatch, an out-of-order chunk and an oversized chunk are refused.
#[test]
fn chunked_uploads_assemble_and_check_their_digest() {
    let bytes = encode(&sealed_chain([42; 32], 3, |_| {}));
    let named = digest(&bytes);
    for split in [1, bytes.len() / 2, bytes.len() - 1] {
        let uploads = TailUploads::default();
        uploads.put(named, 0, &bytes[..split]).unwrap();
        uploads.put(named, 1, &bytes[split..]).unwrap();
        assert_eq!(uploads.take(named), Ok(bytes.clone()));
        // Taken once: the upload is dropped.
        assert_eq!(uploads.take(named), Err(UploadError::DigestMismatch));
    }

    let uploads = TailUploads::default();
    assert_eq!(uploads.put(named, 1, &bytes), Err(UploadError::OutOfOrder));
    uploads.put(named, 0, &bytes[..10]).unwrap();
    assert_eq!(uploads.take(named), Err(UploadError::DigestMismatch));
    assert_eq!(uploads.take(named), Err(UploadError::DigestMismatch));
    assert_eq!(
        uploads.put(named, 0, &vec![0u8; MAX_CHUNK_BYTES + 1]),
        Err(UploadError::TooLarge)
    );
    assert_eq!(UploadError::TooLarge.reason(), "restore_tail_too_large");
    assert_eq!(UploadError::OutOfOrder.reason(), "tail_encoding_invalid");
    assert_eq!(UploadError::DigestMismatch.reason(), "tail_digest_mismatch");
}
