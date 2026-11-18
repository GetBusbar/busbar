// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-VERIFY: one inbound `verify` through the auth door, on the spot (`AuthCalls::verify_now`), as the kernel
//! identifies a request whose point an auth plugin serves.
//!
//! The instance is a linked in-process verifier opened as core opens one (`AuthRows::open`): it answers every
//! request with an identity (a subject and four groups), so each call runs the whole host side: the request's
//! input copied for the crossing, the identity buffer, group spans and strip names lent to the plugin, one
//! crossing, and the identity read back. The request carries no credential and no header lines (no host seal
//! needed); its method, authority and path are a chat completion's. Same allocator as the shipped binary
//! (jemalloc).
//!
//! It prints the median and p99 per call on one thread, then on `B_VERIFY_THREADS` threads (default 8) sharing
//! the one instance, and the clock's own cost per timed call. `B_VERIFY_CALLS` sets the calls per thread
//! (default 200,000).

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::Instant;

use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::auth_door::{
    verify_tail, with_tail, Answer, SyncVerifyPlugin, Verdict, VerifiedIdentity, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::auth_calls::{AuthCalls, VerifyRequest};
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{DispatchConfig, Dispatcher};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A verifier that identifies every request.
struct Identifies;

impl SyncVerifyPlugin for Identifies {
    fn open_refusing(_: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self)
    }

    fn carriers(&self) -> Option<Vec<String>> {
        None
    }

    fn verify(&self, _: &VerifyView<'_>) -> Answer {
        Verdict::Identity(VerifiedIdentity {
            subject: "user-1234".into(),
            groups: vec![
                "readers".into(),
                "writers".into(),
                "ops".into(),
                "billing".into(),
            ],
            ..VerifiedIdentity::default()
        })
        .into()
    }

    fn reload(&self, _: &[u8], _: &[&[u8]]) -> Result<u64, Refusal> {
        Ok(0)
    }
}

mod identifies {
    use super::*;

    const TAIL: &busbar_contract::abi::auth::AuthTail =
        &verify_tail(0, busbar_contract::abi::auth::AuthPoints::HEAD);

    busbar_contract::auth_verify_door!(
        Identifies,
        with_tail(
            Statement {
                ..statement("bench-identifies", "1.0.0", 8)
            },
            TAIL
        )
    );
}

fn main() {
    let calls = std::env::var("B_VERIFY_CALLS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000_usize);
    let threads = std::env::var("B_VERIFY_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8_usize);

    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door_named(
            "bench-identifies",
            "bench-identifies",
            identifies::door,
        )])
        .expect("the linked verifier registers");
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    // The host settings seal, lent as boot lends the kernel's (an auth opening requires one).
    assert!(dispatcher.lend_seal(busbar_contract::plugin::TestKernelSeal));
    let rows = AuthRows::new(Arc::new(registry), dispatcher);
    let calls_on: Arc<dyn AuthCalls> = rows
        .open(
            "bench-identifies",
            "bench",
            &busbar_contract::plugin_settings::ResolvedSettings::default(),
        )
        .expect("the verifier opens");
    let request = {
        let mut r = VerifyRequest::default();
        r.method = "POST".into();
        r.authority = "api.example.test".into();
        r.path = "/v1/chat/completions".into();
        r
    };
    let answer = calls_on.verify_now(&request).expect("the verifier answers");
    assert!(
        matches!(&answer.verified, busbar_contract::auth_calls::Verified::Identity(id) if id.groups.len() == 4),
        "the bench verifier must identify the request: {answer:?}"
    );

    report("clock (an empty timed call)", &[timed(calls, || {})]);
    report(
        "verify_now, 1 thread",
        &[timed(calls, || {
            black_box(calls_on.verify_now(black_box(&request)));
        })],
    );
    let start = Arc::new(Barrier::new(threads));
    let request = Arc::new(request);
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let (calls_on, start, request) = (
                Arc::clone(&calls_on),
                Arc::clone(&start),
                Arc::clone(&request),
            );
            std::thread::spawn(move || {
                start.wait();
                timed(calls, || {
                    black_box(calls_on.verify_now(black_box(&request)));
                })
            })
        })
        .collect();
    let samples: Vec<Vec<u64>> = workers
        .into_iter()
        .map(|w| w.join().expect("bench thread"))
        .collect();
    report(
        &format!("verify_now, {threads} threads, one instance"),
        &samples,
    );
}

/// Nanoseconds per call of `call`, one sample per call.
fn timed(calls: usize, mut call: impl FnMut()) -> Vec<u64> {
    let mut samples = Vec::with_capacity(calls);
    for _ in 0..calls {
        let start = Instant::now();
        call();
        samples.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    samples
}

/// The worst thread's median and p99.
fn report(name: &str, threads: &[Vec<u64>]) {
    let mut worst = (0, 0);
    for samples in threads {
        let mut s = samples.clone();
        s.sort();
        let at = |q: usize| s.get(s.len() * q / 100).copied().unwrap_or(0);
        worst = (worst.0.max(at(50)), worst.1.max(at(99)));
    }
    println!("B-VERIFY {name}: median {} ns, p99 {} ns", worst.0, worst.1);
}
