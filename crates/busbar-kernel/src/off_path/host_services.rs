// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for the request-path `host_services` tree: what a services instance needs once
//! as it is built, as an instance is admitted, as an operator decides trust, as a carrier line
//! opens, or on the flusher's tick, the recovery scheduler's poll and the shutdown drain. None of
//! it runs per request.

use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use busbar_contract::Secret;

use crate::host_services::InstanceFacts;
use crate::host_work::{RecoveryBinding, Reference, Work};

/// The monotonic origin a services instance measures `mono_ns` from, read once as it is built.
pub(crate) fn boot_instant() -> Instant {
    Instant::now()
}

/// A served plane's ticket prefix, read once as its routes are built.
pub(crate) fn ticket_prefix(facts: &InstanceFacts) -> Option<String> {
    facts.ticket_prefix.clone()
}

/// The demotion rows an operator's approving trust decision clears: the instance's prefixed row,
/// and for the default instance its unprefixed one too.
pub(crate) fn decision_clears(instance: &str, counterparty: &str, default: bool) -> Vec<String> {
    let mut clear = Vec::new();
    clear.push(crate::host_services::demotion_key(instance, counterparty));
    if default {
        clear.push(counterparty.to_owned());
    }
    clear
}

/// The shutdown drain of the write-behind queue: flush until idle, every 2 ms until the deadline.
pub(crate) fn drain_until(
    deadline: Duration,
    mut idle: impl FnMut() -> bool,
    mut flush: impl FnMut(),
) -> bool {
    let until = Instant::now() + deadline;
    loop {
        if idle() {
            return true;
        }
        let now = Instant::now();
        if now >= until {
            return false;
        }
        flush();
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// One bounded batch of recoverable work from the recovery scheduler's scan page: each live,
/// recovery-bound row with a poll target that `claim` takes ownership of, made by `make`. The
/// unconsumed part of the page stays in `pending`, so slow polls cannot starve later records.
pub(crate) fn recovery_batch<W>(
    instance: &Arc<str>,
    pending: &mut VecDeque<(Vec<u8>, Secret<Vec<u8>>)>,
    batch: usize,
    mut claim: impl FnMut(Reference) -> bool,
    mut make: impl FnMut(Reference, RecoveryBinding, String) -> W,
) -> Vec<W> {
    let mut ready = Vec::new();
    while ready.len() < batch {
        let Some((reference, bytes)) = pending.pop_front() else {
            break;
        };
        let Ok(reference) = Reference::try_from(reference.as_slice()) else {
            continue;
        };
        let Some(work) = Work::read(instance, reference, bytes.expose(&crate::seal::lend())) else {
            continue;
        };
        if !work.live {
            continue;
        }
        let Some(binding) = work.recovery else {
            continue;
        };
        let Some(target) = busbar_contract::abi::sdk::recovery::poll_target(&work.record)
            .ok()
            .flatten()
        else {
            continue;
        };
        if claim(reference) {
            ready.push(make(reference, binding, target.into()));
        }
    }
    ready
}
