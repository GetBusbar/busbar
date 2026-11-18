// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::worker`'s unit-cancel orphan sorting: once per wedged worker, at its replacement
//! (`off_path::watchdog::replace` -> `Worker::orphans`, its one caller), never per request.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::dispatch::plugin::Instance;
use crate::dispatch::worker::{Entry, Orphan, Worker};

pub(crate) fn group_orphans(
    worker: &Worker,
    gone: Vec<Entry>,
    wedged: &Arc<Instance>,
) -> (Vec<Orphan>, Vec<Entry>) {
    // A wedged worker's entries are sorted into orphans once, at its replacement.
    let mut entries = crate::cold::dispatch::runtime::orphan_slots(gone, |(idx, entry)| {
        Some((worker.ticket(idx as u32, entry.generation), entry))
    });
    let orphans = crate::cold::dispatch::runtime::orphan_groups(entries.len(), |idx| {
        let Some((_, entry)) = &entries[idx] else {
            return None;
        };
        let pending = entry.driver.is_none()
            && entry.current.as_ref().is_some_and(|current| {
                current.pending
                    && current.job.is_some()
                    && !Arc::ptr_eq(&current.meta.instance, wedged)
                    && !current.meta.instance.faulted.load(Ordering::Acquire)
            });
        if !pending {
            return None;
        }
        let key = entry
            .unit_binding
            .as_ref()
            .map(|binding| (Arc::clone(&binding.instance), binding.unit));
        let mut group = vec![entries[idx].take().expect("pending orphan")];
        if let Some((instance, unit)) = key {
            for sibling in &mut entries {
                if sibling.as_ref().is_some_and(|(_, entry)| {
                    entry
                        .unit_binding
                        .as_ref()
                        .is_some_and(|b| b.matches(&instance, unit))
                }) {
                    group.push(sibling.take().expect("bound sibling"));
                }
            }
        }
        Some(Orphan { entries: group })
    });
    // A wedged worker's remaining entries, forgotten once at its replacement.
    let rest = crate::cold::dispatch::runtime::orphan_rest(entries, |(ticket, entry)| {
        for id in &entry.conns {
            drop(crate::dispatch::conn_services::forget(*id, ticket));
        }
        entry
    });
    (orphans, rest)
}
