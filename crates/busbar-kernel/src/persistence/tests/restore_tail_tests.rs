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
    let mut refused: Vec<Vec<u8>> = Vec::new();
    // Trailing bytes, a wrong magic, a truncation.
    refused.push([good.clone(), vec![0]].concat());
    refused.push([b"BSRT2\0\0\0".as_slice(), &good[8..]].concat());
    refused.push(good[..good.len() - 1].to_vec());
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
