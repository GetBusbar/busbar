// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The telemetry bank's off-path code: the per-`App` metric bank built at config load, the
//! process's translation slot table, slot interning, recorder-handle minting, a worker thread's
//! bank release at its exit, and the scrape/maintenance flush. None of it runs per request; the
//! request path only reads (or bumps) the slots this builds.

use foldhash::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::diag_warn;
use crate::diagnostics::TELEMETRY_SLOT_TABLE_FULL;
use crate::telemetry::{
    bank_key, counter_slot, declared_dialects, histogram_slot, phase_duration_slot, registry,
    AppSlots, CounterSlot, HistogramSlot, LaneFamily, LocalBank, MountedFamily, RequestFamily,
    SlotDesc, SlotTable, COUNTER_CHUNK, DISPOSITIONS, HIST_CHUNK, HIST_PARKED, KEY_SEP, OUTCOMES,
    POOL_LABEL_UNRESOLVED, PRODUCER_DRIVE, REASONS, RESPONSE_READY,
};

/// The process's translation slot table: one slot per ordered pair of the model plane's declared
/// dialects. Built once per process, on the first translation.
pub(crate) fn translation_slots() -> Vec<(&'static str, &'static str, CounterSlot)> {
    let mut v = Vec::new();
    let dialects = declared_dialects(crate::plane_driver::dispatch::fallback_key());
    for f in dialects {
        for t in dialects {
            if f != t {
                v.push((
                    *f,
                    *t,
                    counter_slot(
                        crate::snapshot::TRANSLATIONS_TOTAL,
                        &[("from", f), ("to", t)],
                    ),
                ));
            }
        }
    }
    v
}

impl AppSlots {
    /// One duration histogram per lane, keyed by the lane id alone at record time. The labels
    /// `pool`, `target`, `model` and `instance` are read from the lane table here, once, so the
    /// request path hashes no label. Lanes past `telemetry.max_lane_series` fold into
    /// `target="other"` and are counted (`dropped.lane_series`).
    pub(crate) fn attach_lane_durations<'a>(
        &mut self,
        lane_model: impl Fn(usize) -> Option<&'a str>,
        lane_provider: impl Fn(usize) -> Option<&'a str>,
        cap: usize,
    ) {
        use crate::snapshot::LANE_REQUEST_DURATION_SECONDS;

        let mut lane_pool: std::collections::BTreeMap<usize, &str> = Default::default();
        for (pool, lanes) in &self.lane {
            for &idx in lanes.keys() {
                let held = lane_pool.entry(idx).or_insert(&**pool);
                if &**pool < *held {
                    *held = &**pool;
                }
            }
        }
        let mut durations =
            vec![HistogramSlot::INVALID; lane_pool.keys().next_back().map_or(0, |max| max + 1)];
        let mut folded = 0u64;
        for (n, (&idx, &pool)) in lane_pool.iter().enumerate() {
            let Some(model) = lane_model(idx) else {
                continue;
            };
            let (instance, name) = model
                .split_once('\u{1f}')
                .unwrap_or_else(|| (crate::plane_driver::dispatch::fallback_key(), model));
            let (target, model_label) = if n < cap {
                (lane_provider(idx).unwrap_or(""), name)
            } else {
                folded += 1;
                ("other", "other")
            };
            durations[idx] = histogram_slot(
                LANE_REQUEST_DURATION_SECONDS,
                &[
                    ("pool", pool),
                    ("target", target),
                    ("model", model_label),
                    ("instance", instance),
                ],
            );
        }
        crate::telemetry::count_lane_series_dropped(folded);
        self.lane_duration = durations.into();
    }

    pub(crate) fn build<'a>(
        pools: &[(&'a str, Vec<usize>)],
        by_model: &[(&'a str, usize)],
        lane_model: impl Fn(usize) -> Option<&'a str>,
        plane: &'static str,
    ) -> AppSlots {
        use crate::snapshot::{
            BREAKER_TRIPS_TOTAL, FAILOVERS_TOTAL, PLANE_REQUESTS_TOTAL,
            PLANE_REQUEST_DURATION_SECONDS, REQUESTS_TOTAL, REQUEST_DURATION_SECONDS,
            UPSTREAM_ATTEMPTS_TOTAL, UPSTREAM_FAILURES_TOTAL,
        };

        let mut ingress_labels: Vec<&str> = pools.iter().map(|(pool, _)| *pool).collect();
        ingress_labels.extend(by_model.iter().map(|(model, _)| *model));
        ingress_labels.push(POOL_LABEL_UNRESOLVED);
        ingress_labels.sort();
        ingress_labels.dedup();

        let mut request =
            HashMap::with_capacity_and_hasher(ingress_labels.len(), Default::default());
        for pool in &ingress_labels {
            let families: Box<[RequestFamily]> = declared_dialects(plane)
                .iter()
                .map(|proto| RequestFamily {
                    requests: std::array::from_fn(|oi| {
                        counter_slot(
                            REQUESTS_TOTAL,
                            &[
                                ("ingress_protocol", proto),
                                ("pool", pool),
                                ("outcome", OUTCOMES[oi]),
                            ],
                        )
                    }),
                    producer_duration: phase_duration_slot(plane, PRODUCER_DRIVE, proto, pool),
                    duration: histogram_slot(
                        REQUEST_DURATION_SECONDS,
                        &[("ingress_protocol", proto), ("pool", pool)],
                    ),
                })
                .collect();
            let pool: Box<str> = Box::from(*pool);
            request.insert(pool, families);
        }

        let mut lane_map: HashMap<Box<str>, HashMap<usize, LaneFamily>> = HashMap::default();
        let engine_labels: Vec<(&str, Vec<usize>)> = pools
            .iter()
            .map(|(pool, member_idxs)| (*pool, member_idxs.clone()))
            .chain(by_model.iter().map(|(model, idx)| (*model, vec![*idx])))
            .collect();

        let mut failover =
            HashMap::with_capacity_and_hasher(engine_labels.len(), Default::default());
        for (pool, member_idxs) in &engine_labels {
            let mut per_lane =
                HashMap::with_capacity_and_hasher(member_idxs.len(), Default::default());
            for &idx in member_idxs {
                let Some(lane_label) = lane_model(idx) else {
                    continue;
                };
                per_lane.insert(
                    idx,
                    LaneFamily {
                        attempts: counter_slot(
                            UPSTREAM_ATTEMPTS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                        failures: std::array::from_fn(|di| {
                            counter_slot(
                                UPSTREAM_FAILURES_TOTAL,
                                &[
                                    ("pool", pool),
                                    ("lane", lane_label),
                                    ("disposition", DISPOSITIONS[di]),
                                ],
                            )
                        }),
                        trips: counter_slot(
                            BREAKER_TRIPS_TOTAL,
                            &[("pool", pool), ("lane", lane_label)],
                        ),
                    },
                );
            }
            let key: Box<str> = Box::from(*pool);
            lane_map.entry(key).or_default().extend(per_lane);
            let key: Box<str> = Box::from(*pool);
            failover.entry(key).or_insert_with(|| {
                std::array::from_fn(|ri| {
                    counter_slot(FAILOVERS_TOTAL, &[("pool", pool), ("reason", REASONS[ri])])
                })
            });
        }

        // Mounted ingress currently observes response-ready at its middleware boundary, before
        // body consumption, with the fixed unresolved pool label. Never infer producer completion.
        // Mounted planes bank the same way: their request series are bounded by the plane's
        // declared dialects at that one pool label, so the request path never builds a key.
        let pool = POOL_LABEL_UNRESOLVED;
        let mounted = crate::plane_driver::dispatch::plane_keys()
            .filter(|key| !crate::plane_driver::dispatch::is_fallback(key))
            .map(|key| {
                let families = declared_dialects(key)
                    .iter()
                    .map(|proto| MountedFamily {
                        requests: std::array::from_fn(|oi| {
                            counter_slot(
                                PLANE_REQUESTS_TOTAL,
                                &[
                                    ("plane", key),
                                    ("ingress_protocol", proto),
                                    ("pool", pool),
                                    ("outcome", OUTCOMES[oi]),
                                ],
                            )
                        }),
                        duration: histogram_slot(
                            PLANE_REQUEST_DURATION_SECONDS,
                            &[("plane", key), ("ingress_protocol", proto), ("pool", pool)],
                        ),
                        phase: phase_duration_slot(key, RESPONSE_READY, proto, pool),
                    })
                    .collect();
                (key, families)
            })
            .collect();

        AppSlots {
            mounted,
            banked_plane: plane,
            request,
            lane: lane_map,
            failover,
            lane_duration: Box::default(),
        }
    }
}

impl Drop for LocalBank {
    fn drop(&mut self) {
        let reg = registry();
        if crate::snapshot::retaining() {
            reg.exited
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(Arc::clone(&self.0));
            return;
        }

        let _flush = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());
        reg.threads
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&bank_key(&self.0));
        let descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
        for (i, desc) in descs.iter().enumerate() {
            if let Some(chunk) = self.counters[i / COUNTER_CHUNK].get() {
                desc.retired.fetch_add(
                    chunk[i % COUNTER_CHUNK].load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
            }
        }
    }
}

impl<H> SlotTable<H> {
    pub(crate) fn intern(
        &self,
        name: &'static str,
        labels: &[(&'static str, &str)],
        max: usize,
    ) -> Option<u32> {
        let mut key = String::with_capacity(name.len() + labels.len() * 16);
        key.push_str(name);
        for (k, v) in labels {
            key.push(KEY_SEP);
            key.push_str(k);
            key.push(KEY_SEP);
            key.push_str(v);
        }
        let mut index = self.index.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(&id) = index.get(key.as_str()) {
            return Some(id);
        }
        let mut descs = self.descs.write().unwrap_or_else(|p| p.into_inner());
        if descs.len() >= max {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                diag_warn!(
                    TELEMETRY_SLOT_TABLE_FULL,
                    metric = name,
                    cap = max,
                    "telemetry bank slot table full; further label sets fall back to the metrics macros"
                );
            }
            return None;
        }
        let id = descs.len() as u32;
        descs.push(Arc::new(SlotDesc {
            name,
            labels: labels.iter().map(|(k, v)| (*k, (*v).to_string())).collect(),
            handle: OnceLock::new(),
            flushed: AtomicU64::new(0),
            retired: AtomicU64::new(0),
        }));
        index.insert(key, id);
        Some(id)
    }
}

/// The bank's handles keep the telemetry module's metadata target, wherever they are minted.
const TELEMETRY_MODULE: &str = "busbar_kernel::telemetry";

static METADATA: metrics::Metadata<'static> = metrics::Metadata::new(
    TELEMETRY_MODULE,
    metrics::Level::INFO,
    Some(TELEMETRY_MODULE),
);

fn key_of<H>(desc: &SlotDesc<H>) -> metrics::Key {
    let labels = desc
        .labels
        .iter()
        .map(|(k, v)| metrics::Label::new(*k, v.clone()));
    metrics::Key::from_parts(desc.name, labels.collect::<Vec<_>>())
}

fn mint_counter(desc: &SlotDesc<metrics::Counter>) -> metrics::Counter {
    metrics::with_recorder(|r| r.register_counter(&key_of(desc), &METADATA))
}

pub(crate) fn mint_histogram(desc: &SlotDesc<metrics::Histogram>) -> metrics::Histogram {
    metrics::with_recorder(|r| r.register_histogram(&key_of(desc), &METADATA))
}

pub(crate) fn flush_to_recorder() {
    #[cfg(any(test, feature = "test-support"))]
    let _serial = crate::telemetry::drain_serial::lock();
    if !crate::snapshot::recorder_installed() {
        return;
    }
    let reg = registry();
    let _guard = reg.flush_lock.lock().unwrap_or_else(|p| p.into_inner());

    let mut banks = reg.threads.lock().unwrap_or_else(|p| p.into_inner());
    let exited = std::mem::take(&mut *reg.exited.lock().unwrap_or_else(|p| p.into_inner()));
    for bank in &exited {
        banks.remove(&bank_key(bank));
    }
    let threads: Vec<_> = banks.values().cloned().collect();
    drop(banks);
    std::sync::atomic::fence(Ordering::Acquire);

    let counter_descs = reg.counters.descs.read().unwrap_or_else(|p| p.into_inner());
    for (i, desc) in counter_descs.iter().enumerate() {
        let (chunk_i, off) = (i / COUNTER_CHUNK, i % COUNTER_CHUNK);
        let mut sum: u64 = desc.retired.load(Ordering::Relaxed);
        for bank in threads.iter().chain(&exited) {
            if let Some(chunk) = bank.counters[chunk_i].get() {
                sum = sum.wrapping_add(chunk[off].load(Ordering::Relaxed));
            }
        }

        let gone = exited.iter().filter_map(|b| b.counters[chunk_i].get());
        let gone = gone.fold(0u64, |t, c| t.wrapping_add(c[off].load(Ordering::Relaxed)));
        desc.retired.fetch_add(gone, Ordering::Relaxed);
        let prev = desc.flushed.load(Ordering::Relaxed);
        if sum > prev {
            let handle = desc.handle.get_or_init(|| mint_counter(desc));
            handle.increment(sum - prev);
            desc.flushed.store(sum, Ordering::Relaxed);
        }
    }
    drop(counter_descs);

    let hist_descs = reg.hists.descs.read().unwrap_or_else(|p| p.into_inner());
    let parked = {
        let mut held = HIST_PARKED.lock().unwrap_or_else(|p| p.into_inner());
        held.per_slot.fill(0);
        std::mem::take(&mut held.buffers)
    };
    for (slot, samples) in parked {
        let Some(desc) = hist_descs.get(slot as usize) else {
            continue;
        };
        let handle = desc.handle.get_or_init(|| mint_histogram(desc));
        for s in samples {
            handle.record(s);
        }
    }
    for (i, desc) in hist_descs.iter().enumerate() {
        let (chunk_i, off) = (i / HIST_CHUNK, i % HIST_CHUNK);
        for bank in threads.iter().chain(&exited) {
            let Some(chunk) = bank.hists[chunk_i].get() else {
                continue;
            };
            let samples = {
                let mut buf = chunk[off].lock().unwrap_or_else(|p| p.into_inner());
                if buf.is_empty() {
                    continue;
                }
                std::mem::take(&mut *buf)
            };
            let handle = desc.handle.get_or_init(|| mint_histogram(desc));
            for s in samples {
                handle.record(s);
            }
        }
    }
}
