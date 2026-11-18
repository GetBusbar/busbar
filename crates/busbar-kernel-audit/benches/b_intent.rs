// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-INTENT: one `verify_response_intent` (the request-path check of a response's final intent
//! checkpoint before its release is confirmed) on one signed record, beside a key set of 1 and of 8
//! keys (a node that has rotated).
//!
//! Calls are timed in batches of `B_INTENT_BATCH` (default 64), so the clock's own cost is spread
//! over the batch. It prints, for each of `B_INTENT_RUNS` runs (default 5), the median and p99 of
//! `B_INTENT_SAMPLES` samples (default 2,000) in ns per call. System allocator.

use std::hint::black_box;
use std::time::Instant;

use busbar_contract::response_delivery::{FinalResponseIntent, ResponseDisposition, ResponseKey};
use busbar_kernel_audit::response_intent::{
    verify_response_intent, PreparedResponseIntent, ResponseIntentStamp,
};
use busbar_kernel_audit::{
    AuditKeySet, AuditSigningKey, AuditVerifyingKey, BootstrapSigner, LiveSigner,
};

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let at = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[at.min(sorted.len() - 1)]
}

fn intent() -> FinalResponseIntent {
    FinalResponseIntent {
        key: ResponseKey {
            node: 9,
            incarnation: 3,
            unit: Some(busbar_contract::ids::UnitKey::new(13)),
            connection_generation: 4,
            stream: 7,
        },
        final_publication_ordinal: 11,
        disposition: ResponseDisposition::End { status: Some(200) },
    }
}

fn stamp() -> ResponseIntentStamp {
    ResponseIntentStamp {
        lease_epoch: 2,
        policy_epoch: 5,
        wall: 100,
        mono: 8,
    }
}

/// One signed record, and a key set of `keys` keys that holds its signer last.
fn record(keys: u8) -> (Vec<u8>, AuditKeySet) {
    let mut set = AuditKeySet::new();
    for seed in 1..keys {
        let other = AuditSigningKey::from_seed(&[seed; 32]);
        set.insert(AuditVerifyingKey::from_hex(&other.public_key_hex()).expect("a public key"));
    }
    let key = AuditSigningKey::from_seed(&[41; 32]);
    set.insert(AuditVerifyingKey::from_hex(&key.public_key_hex()).expect("a public key"));
    let (_, grant) = key
        .into_grants(LiveSigner::SameAsBootstrap)
        .expect("the bootstrap grant");
    let signer = BootstrapSigner::new(grant);
    let prepared =
        PreparedResponseIntent::new(intent(), stamp(), signer.key_id()).expect("a valid intent");
    let signatures = signer
        .sign_checkpoint(&[prepared.signing_body()])
        .expect("a signature");
    (prepared.signed_body(&signatures[0]).expect("a body"), set)
}

fn main() {
    let runs: usize = env_or("B_INTENT_RUNS", 5);
    let samples: usize = env_or("B_INTENT_SAMPLES", 2_000);
    let batch: usize = env_or("B_INTENT_BATCH", 64);
    for keys in [1u8, 8] {
        let (body, set) = record(keys);
        assert!(matches!(
            verify_response_intent(&body, 9, stamp(), &set),
            Ok(Some(_))
        ));
        for _ in 0..samples / 10 {
            black_box(verify_response_intent(black_box(&body), 9, stamp(), &set).is_ok());
        }
        for run in 1..=runs {
            let mut times = Vec::with_capacity(samples);
            for _ in 0..samples {
                let start = Instant::now();
                for _ in 0..batch {
                    black_box(verify_response_intent(black_box(&body), 9, stamp(), &set).is_ok());
                }
                times.push(start.elapsed().as_nanos() as f64 / batch as f64);
            }
            times.sort_by(f64::total_cmp);
            println!(
                "B-INTENT keys={keys} run {run}: median {:.0} ns, p99 {:.0} ns per verify",
                percentile(&times, 0.5),
                percentile(&times, 0.99)
            );
        }
    }
}
